import type { FastifyInstance } from "fastify";
import type pg from "pg";
import { z } from "zod";

import { withPlatform, withTenant } from "../db/client.ts";
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

  /*
   * שער המוקד. פלטפורמה בלבד, עם אימות שני טרי.
   */
  const base = [
    guards.requireSession,
    guards.requirePlatformMfa,
    guards.requirePermission("providers.manage"),
  ];

  /*
   * שער ההורה.
   *
   * מי שבחר בהתקנה "הסרה עצמית" מנפיק לעצמו, ואינו זקוק למוקד.
   * מי שבחר "רק דרך המוקד" מקבל כאן סירוב — וזו כל הנקודה של
   * הבחירה ההיא. הבדיקה עצמה למטה, כי היא תלויה בדייר ולא בתפקיד.
   */
  const ownerBase = [
    guards.requireSession,
    guards.requirePermission("devices.viewOwn"),
  ];

  /**
   * אופן ההסרה של הדייר, כפי שנבחר בהתקנה.
   */
  async function uninstallPolicyOf(tenantId: string): Promise<"self_service" | "support_only"> {
    return withTenant(pool, tenantId, async (tx) => {
      const r = await tx.query<{ uninstall_policy: "self_service" | "support_only" }>(
        "SELECT uninstall_policy FROM tenants WHERE id = $1",
        [tenantId],
      );

      // חשבון שלא נמצא נחשב מחמיר. היעדר תשובה אינו היתר.
      return r.rows[0]?.uninstall_policy ?? "support_only";
    });
  }

  /**
   * רושם את ההנפקה. הנפקת מוקד היא תמיד בתשלום, והאילוץ במסד אוכף זאת.
   */
  async function recordIssuance(
    tenantId: string,
    deviceId: string | null,
    issuedBy: string,
    channel: "self_service" | "support",
    reason: string | null,
  ): Promise<void> {
    await withPlatform(pool, SYSTEM, async (tx) => {
      await tx.query(
        `INSERT INTO uninstall_issuances
           (tenant_id, device_id, issued_by, channel, billable, reason)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [tenantId, deviceId, issuedBy, channel, channel === "support", reason],
      );
    });
  }

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
        tenant_id: string;
        tenant_name: string;
        owner_email: string | null;
        status: string;
        last_seen_at: Date | null;
      }>(
        `SELECT d.id, d.hwid, d.status, d.tenant_id,
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

    /*
     * הנפקת מוקד היא תמיד בתשלום.
     *
     * נרשמת כאן ולא במערכת חיוב חיצונית, כי מה שקובע שמגיע חיוב
     * הוא שאדם במוקד הנפיק קוד — והעובדה הזו ידועה בדיוק ברגע
     * הזה. הגבייה נעשית מחוץ למערכת, וצריך מקום אחד שיודע כמה
     * ולמי.
     */
    if (device?.tenant_id) {
      await recordIssuance(
        device.tenant_id, device.id, session.user.userId, "support", parsed.data.reason);
    }

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

  /*
   * ---------------------------------------------------------------- ההורה
   *
   * הנפקה עצמית, למי שבחר בה בהתקנה.
   *
   * אין כאן identityVerified ואין סיבה חופשית: ההורה מאמת את עצמו
   * בכניסה לפורטל, ואין לו למי להסביר. מה שכן נשמר הוא הרישום —
   * כל הנפקה מתועדת, גם כשאיש לא צריך לאשר אותה.
   *
   * המחשב חייב להיות שלו. אתגר של מחשב מדייר אחר נדחה באותה
   * תשובה כמו אתגר שאינו מוכר, כדי שלא ניתן יהיה למפות מחשבים
   * של אחרים דרך ההבדל.
   */
  app.post("/api/portal/v1/uninstall/self", { preHandler: ownerBase }, async (request, reply) => {
    const session = request.portal!.session;
    const tenantId = session.user.tenantId;

    if (!tenantId) return reply.code(403).send({ error: "אין חשבון משויך" });

    const parsed = z.object({ challenge: z.string().trim().min(20).max(80) })
      .safeParse(request.body);

    if (!parsed.success) return reply.code(400).send({ error: "קוד הזיהוי אינו תקין" });

    const policy = await uninstallPolicyOf(tenantId);

    if (policy !== "self_service") {
      /*
       * זו הסירוב שההורה ביקש לעצמו.
       *
       * הניסוח מזכיר לו שזו הבחירה שלו ולא מגבלה שהוטלה עליו —
       * ברגע שבו הוא הכי מתפתה, זה ההבדל בין "המערכת מציקה לי"
       * לבין "החלטתי כך כשהייתי צלול".
       */
      return reply.code(403).send({
        error: "בהתקנה נבחר שההסרה תיעשה דרך המוקד בלבד. יש לפנות אליו.",
        policy,
      });
    }

    let challenge: UninstallChallenge;

    try {
      challenge = parseChallenge(parsed.data.challenge);
    } catch (error) {
      return reply.code(400).send({
        error: error instanceof Error ? error.message : "קוד הזיהוי אינו תקין",
      });
    }

    const device = await findDevice(challenge);

    if (device === null || device.tenant_id !== tenantId) {
      return reply.code(404).send({ error: "הקוד אינו שייך למחשב בחשבון הזה" });
    }

    const signature = await uninstallSigner.sign(buildSigningInput(challenge));

    await withPlatform(pool, SYSTEM, async (tx) => {
      await tx.query(
        `INSERT INTO audit_log
           (actor_type, actor_id, action, target_type, target_id, tenant_id, payload)
         VALUES ('tenant_user', $1, 'uninstall.code.selfIssued', 'device', $2, $3, $4)`,
        [
          session.user.userId,
          device.id,
          tenantId,
          JSON.stringify({
            hwidHash: challenge.hwidHash.toString("hex").toUpperCase(),
            deviceName: device.name,
          }),
        ],
      );
    });

    await recordIssuance(tenantId, device.id, session.user.userId, "self_service", null);

    app.log.warn(
      { device: device.id, by: session.user.email },
      "הורה הנפיק לעצמו קוד הסרה",
    );

    return reply.send({
      code: signature.toString("base64"),
      note: `הקוד הונפק עבור ${device.name}. ההנפקה תועדה.`,
    });
  });

  /*
   * ---------------------------------------------------------------- ההגדרה
   *
   * מה נבחר, והאם עוד אפשר לשנות.
   *
   * locked אינו נגזר בממשק אלא נשלח מכאן, כי הוא נאכף בטריגר במסד
   * ולא בקוד. שני מקומות שמחשבים את אותו כלל מתפצלים בסוף, ואז
   * הממשק מציג כפתור שהמסד ידחה.
   */
  app.get("/api/portal/v1/uninstall/policy", { preHandler: ownerBase }, async (request, reply) => {
    const tenantId = request.portal!.session.user.tenantId;

    if (!tenantId) return reply.code(403).send({ error: "אין חשבון משויך" });

    const row = await withTenant(pool, tenantId, async (tx) => {
      const r = await tx.query<{ policy: string; changed_at: Date | null }>(
        `SELECT uninstall_policy AS policy, uninstall_policy_changed_at AS changed_at
           FROM tenants WHERE id = $1`,
        [tenantId],
      );

      return r.rows[0] ?? null;
    });

    if (row === null) return reply.code(404).send({ error: "החשבון לא נמצא" });

    return reply.send({
      policy: row.policy,
      locked: row.changed_at !== null,
      chosenAt: row.changed_at,
    });
  });

  /*
   * הבחירה עצמה. פעם אחת, בהתקנה.
   *
   * הבקשה אינה בודקת נעילה לפני הכתיבה, ובכוונה: הטריגר במסד הוא
   * הסמכות, ובדיקה מקדימה כאן הייתה יוצרת מרוץ בין שתי לשוניות
   * פתוחות. מה שכן נעשה כאן הוא לתרגם את שגיאת המסד להסבר.
   */
  app.post("/api/portal/v1/uninstall/policy", { preHandler: ownerBase }, async (request, reply) => {
    const session = request.portal!.session;
    const tenantId = session.user.tenantId;

    if (!tenantId) return reply.code(403).send({ error: "אין חשבון משויך" });

    const parsed = z.object({
      policy: z.enum(["self_service", "support_only"]),
    }).safeParse(request.body);

    if (!parsed.success) return reply.code(400).send({ error: "בחירה אינה תקינה" });

    try {
      await withTenant(pool, tenantId, async (tx) => {
        await tx.query(
          `UPDATE tenants
              SET uninstall_policy = $2::uninstall_policy,
                  uninstall_policy_changed_by = $3
            WHERE id = $1`,
          [tenantId, parsed.data.policy, session.user.userId],
        );
      });
    } catch (error) {
      /*
       * check_violation הוא הטריגר, ולא תקלה.
       *
       * ההודעה שלו כתובה למשתמש, ולכן היא מועברת כפי שהיא במקום
       * להיבלע ולהפוך ל"שגיאה פנימית".
       */
      const code = (error as { code?: string }).code;

      if (code === "23514") {
        return reply.code(409).send({
          error: "שינוי אופן ההסרה מחייב פנייה למוקד. הבחירה נעשית פעם אחת.",
        });
      }

      throw error;
    }

    await withPlatform(pool, SYSTEM, async (tx) => {
      await tx.query(
        `INSERT INTO audit_log
           (actor_type, actor_id, action, target_type, target_id, tenant_id, payload)
         VALUES ('tenant_user', $1, 'uninstall.policy.chosen', 'tenant', $2, $2, $3)`,
        [session.user.userId, tenantId, JSON.stringify({ policy: parsed.data.policy })],
      );
    });

    return reply.send({ ok: true, policy: parsed.data.policy, locked: true });
  });
}
