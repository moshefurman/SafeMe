import type { FastifyInstance } from "fastify";
import type pg from "pg";
import { z } from "zod";

import { withPlatform } from "../db/client.ts";
import { createGuards } from "../auth/guards.ts";
import type { Config } from "../config.ts";
import type { Signer } from "../crypto/signing.ts";
import {
  buildSigningInput,
  hwidHashHex,
  parseChallenge,
  type UninstallChallenge,
} from "../crypto/challenge.ts";

/**
 * הנפקת קודי הסרה למוקד.
 *
 * זו הפעולה הרגישה ביותר במוצר. קוד הסרה מפרק את ההגנה על מחשב
 * מסוים — וכל שאר המנגנון, מהמחגר ועד השמירה ההדדית, נשען על כך
 * שאי אפשר להשיג אותו בלי לעבור כאן.
 *
 * ולכן שני מסלולים ולא אחד:
 *
 *   lookup   מפענח את האתגר ואומר של מי המחשב. אינו מנפיק דבר.
 *   issue    מנפיק, ורק אחרי שהנציג אישר שהוא אימת זהות.
 *
 * ההפרדה אינה בירוקרטיה. נציג שמקבל קוד באותה קריאה שבה הוא רואה
 * את פרטי החשבון עלול להנפיק לפני שאימת — והפיצול הופך את האימות
 * לצעד שקורה, ולא לצעד שמניחים שקרה.
 *
 * צוות החברה בלבד. הורה שיכול להנפיק לעצמו קוד הסרה מחזיק מוצר
 * שאינו מגן על דבר, ובדיוק מפני זה נבנה כל השאר.
 */

const lookupBody = z.object({
  challenge: z.string().trim().min(20).max(80),
});

const issueBody = z.object({
  challenge: z.string().trim().min(20).max(80),

  /*
   * אישור מפורש שהזהות אומתה.
   *
   * הוא אינו מוודא דבר טכנית — נציג יכול לסמן בלי לאמת. מה שהוא
   * כן עושה הוא להפוך את האימות לפעולה שנרשמת בשמו ביומן הביקורת,
   * ולכן ניתנת לבדיקה בדיעבד כשמתברר שמחשב שוחרר שלא כדין.
   */
  identityVerified: z.literal(true),

  reason: z.string().trim().min(3).max(300),
});

const SYSTEM = {
  userId: "00000000-0000-0000-0000-000000000000",
  reason: "הנפקת קוד הסרה",
};

interface Deps {
  pool: pg.Pool;
  config: Config;
  uninstallSigner: Signer;
}

export async function registerUninstallRoutes(
  app: FastifyInstance,
  deps: Deps,
): Promise<void> {
  const { pool, config, uninstallSigner } = deps;
  const guards = createGuards(pool, config);

  const base = [
    guards.requireSession,
    guards.requirePlatformMfa,
    guards.requirePermission("providers.manage"),
  ];

  /**
   * מוצא את המחשב שהאתגר שייך לו.
   *
   * האתגר נושא שמונה בתים של גיבוב מזהה החומרה, ולא את המזהה עצמו,
   * ולכן החיפוש הוא על גיבוב שמחושב מכל מחשב במסד. בהיקף של אלפי
   * מחשבים זו סריקה זולה, והיא נמנעת מלשמור עמודה נוספת שכל
   * תפקידה לשרת את המסלול הזה.
   */
  async function findDevice(challenge: UninstallChallenge) {
    return withPlatform(pool, SYSTEM, async (tx) => {
      const r = await tx.query<{
        id: string;
        hwid: string;
        name: string;
        tenant_name: string;
        owner_email: string | null;
        status: string;
        last_seen_at: Date | null;
      }>(
        `SELECT d.id, d.hwid, d.status,
                COALESCE(d.display_name, d.machine_name, 'מחשב ללא שם') AS name,
                t.name AS tenant_name,
                (SELECT email FROM users
                  WHERE tenant_id = d.tenant_id AND role = 'tenant_owner'
                  ORDER BY created_at LIMIT 1) AS owner_email,
                s.last_seen_at
           FROM devices d
           JOIN tenants t ON t.id = d.tenant_id
           LEFT JOIN device_state s ON s.device_id = d.id`,
      );

      return r.rows.find(
        (row) => hwidHashHex(row.hwid) === challenge.hwidHash.toString("hex").toUpperCase(),
      ) ?? null;
    });
  }

  app.post("/api/portal/v1/uninstall/lookup", { preHandler: base }, async (request, reply) => {
    const parsed = lookupBody.safeParse(request.body);

    if (!parsed.success) return reply.code(400).send({ error: "קוד אתגר חסר" });

    let challenge: UninstallChallenge;

    try {
      challenge = parseChallenge(parsed.data.challenge);
    } catch (error) {
      return reply.code(400).send({
        error: error instanceof Error ? error.message : "קוד האתגר אינו תקין",
      });
    }

    const device = await findDevice(challenge);

    return reply.send({
      /*
       * גיל האתגר, ולא רק חותמת.
       *
       * הוא תקף שלושים דקות, והנציג צריך לדעת מיד אם הוא מדבר עם
       * מישהו שהפיק קוד ישן — כי אז ההנפקה תיכשל אצל הלקוח והשיחה
       * תתחיל מחדש.
       */
      issuedUtc: challenge.issuedUtc.toISOString(),
      ageMinutes: Math.round((Date.now() - challenge.issuedUtc.getTime()) / 60_000),
      offlineEmergency: challenge.offlineEmergency,

      device: device === null ? null : {
        name: device.name,
        tenantName: device.tenant_name,
        ownerEmail: device.owner_email,
        status: device.status,
        lastSeenAt: device.last_seen_at,
      },
    });
  });

  app.post("/api/portal/v1/uninstall/issue", { preHandler: base }, async (request, reply) => {
    const session = request.portal!.session;
    const parsed = issueBody.safeParse(request.body);

    if (!parsed.success) {
      return reply.code(400).send({
        error: "יש לאשר שהזהות אומתה ולציין סיבה",
      });
    }

    let challenge: UninstallChallenge;

    try {
      challenge = parseChallenge(parsed.data.challenge);
    } catch (error) {
      return reply.code(400).send({
        error: error instanceof Error ? error.message : "קוד האתגר אינו תקין",
      });
    }

    const device = await findDevice(challenge);

    /*
     * הקוד נחתם דרך ה-Signer ולא ממפתח מקומי.
     *
     * בייצור המפתח הפרטי יושב ב-KMS ואינו יוצא ממנו לעולם, ולכן
     * החתימה מתבצעת שם. זהו גם מפתח נפרד ממפתח המדיניות: שרת שנפרץ
     * ויכול לחתום מדיניות אינו יכול לחתום הסרות.
     */
    const signature = await uninstallSigner.sign(buildSigningInput(challenge));
    const code = signature.toString("base64");

    await withPlatform(pool, SYSTEM, async (tx) => {
      await tx.query(
        `INSERT INTO audit_log
           (actor_type, actor_id, action, target_type, target_id, tenant_id, payload)
         VALUES ('platform_user', $1, 'uninstall.code.issued', 'device', $2, NULL, $3)`,
        [
          session.user.userId,
          device?.id ?? null,
          JSON.stringify({
            hwidHash: challenge.hwidHash.toString("hex").toUpperCase(),
            nonce: challenge.nonce.toString("hex"),
            reason: parsed.data.reason,
            deviceName: device?.name ?? null,
            tenantName: device?.tenant_name ?? null,
            matched: device !== null,
          }),
        ],
      );
    });

    app.log.warn(
      { hwidHash: challenge.hwidHash.toString("hex").toUpperCase(), by: session.user.email },
      "הונפק קוד הסרה",
    );

    return reply.send({
      code,
      note: device === null
        ? "הקוד הונפק, אך המחשב אינו מוכר במערכת. ההנפקה תועדה."
        : `הקוד הונפק עבור ${device.name} (${device.tenant_name}). ההנפקה תועדה.`,
    });
  });
}
