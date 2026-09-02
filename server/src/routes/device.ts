import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type pg from "pg";
import { z } from "zod";
import { withPlatform, withTenant } from "../db/client.ts";
import { hashEnrollToken, issueDeviceToken, verifyDeviceToken } from "../auth/device-token.ts";
import { buildEnvelope, envelopeFromStored, type Signer } from "../crypto/signing.ts";
import type { Config } from "../config.ts";
import { sampleReason, type DeviceSnapshot } from "../telemetry/retention.ts";
import { severityFor } from "../telemetry/severity.ts";
import { trackNetwork } from "../network/track.ts";
import { buildUpdateOffer } from "../updates/offer.ts";
import { isAtLeastAsStrict, type PolicyFloor } from "../policy/floor.ts";
import { hwidHashHex } from "../crypto/challenge.ts";
import { billingVerdict } from "../billing/gate.ts";
import { compareVersions, parseVersion } from "../updates/decide.ts";
import type { DeviceSecretDeriver } from "../crypto/device-secret.ts";

/**
 * ממשק המחשב. שישה מסלולים שהסוכן ב-Windows מדבר איתם.
 *
 * כל המסלולים פרט ל-health ול-enroll דורשים אסימון מחשב תקף,
 * ופועלים בהקשר הדייר של אותו מחשב בלבד.
 */

const SYSTEM_ACTOR = {
  userId: "00000000-0000-0000-0000-000000000000",
  reason: "רישום מחשב",
};

/**
 * הגרסה הראשונה שקוראת את שדרוג קוד ההסרה מהפעימה.
 *
 * מתחת לה השדה נזרק בשקט, ושדרוג במסד היה מנתק את ההנפקה מהאימות.
 */
const UPGRADE_MIN_AGENT = { major: 1, minor: 1, patch: 34 };

// ---------------------------------------------------------------- סכמות

const enrollBody = z.object({
  enrollToken: z.string().min(8),
  hwid: z.string().min(10).max(64),
  machineName: z.string().max(128).optional(),
  osVersion: z.string().max(128).optional(),
  agentVersion: z.string().max(32).optional(),
  installId: z.string().uuid().optional(),

  /*
   * מה נבחר בהתקנה לגבי אופן ההסרה.
   *
   * מוחל רק אם טרם נבחר לדייר הזה. התקנה שנייה באותו חשבון אינה
   * דרך לשנות את ההגדרה — לשם כך יש את המוקד, בתשלום.
   */
  uninstallPolicy: z.enum(["self_service", "support_only"]).optional(),
});

const adapterSchema = z.object({
  name: z.string().max(128),
  ssid: z.string().max(64).nullish(),
  gateway: z.string().max(64).nullish(),
  // מזהה את הנתב הפיזי. זה מה שמבדיל בין רשת ביתית לבין טלפון
  // שמשתף אינטרנט, גם כששם הרשת זהה.
  gatewayMac: z.string().max(32).nullish(),
  localIp: z.string().max(64).nullish(),
  isVirtualVpn: z.boolean().optional(),
});

const heartbeatBody = z.object({
  hwid: z.string(),
  agentVersion: z.string().max(32).optional(),
  policyVersion: z.number().int().nonnegative().optional(),
  sentUtc: z.string().datetime({ offset: true }).optional(),
  sequence: z.number().int().nonnegative(),
  status: z.enum(["unknown", "safe", "lowFilter", "unfiltered", "blocked"]),
  score: z.number().int().min(0).max(100),
  activeAdapters: z.array(adapterSchema).max(16).default([]),
  publicIp: z.string().max(64).nullish(),
  detectedProvider: z.string().max(64).nullish(),

  /*
   * ספק האינטרנט שמאחורי הרשת.
   *
   * מפתח ה-ASN הוא מה שמושווה; השם הוא לתצוגה. חסר פירושו שהסוכן
   * לא הצליח לקרוא — ולא שאין ספק, וזו ההבחנה שמונעת נעילה של
   * מחשב שהרשת שלו חסומה ולכן גם הקריאה שלו נכשלה.
   */
  ispKey: z.string().max(128).nullish(),
  ispName: z.string().max(256).nullish(),
  failedProbes: z.array(z.string().max(64)).max(64).default([]),
  tamperEvents: z
    .array(
      z.object({
        kind: z.string().max(64),
        utc: z.string().datetime({ offset: true }).optional(),
        detail: z.string().max(1024).nullish(),
      }),
    )
    .max(50)
    .default([]),
  wfpFilterCount: z.number().int().nonnegative().optional(),
  uptimeSec: z.number().int().nonnegative().optional(),
  lockoutActive: z.boolean().default(false),
});

const eventsBody = z.array(
  z.object({
    kind: z.string().max(64),
    utc: z.string().datetime({ offset: true }).optional(),
    detail: z.string().max(1024).nullish(),
  }),
).max(200);

/** שמות הפקודות כפי שהסוכן מצפה להם ב-RemoteCommand.Type. */
const TYPE_MAP: Record<string, string> = {
  lockout: "Lockout",
  release_lockout: "ReleaseLockout",
  run_audit: "RunAudit",
  refresh_policy: "RefreshPolicy",
  collect_logs: "CollectLogs",
};

/** הסוכן שולח camelCase, בסיס הנתונים משתמש ב-snake_case. */
const STATUS_MAP: Record<string, string> = {
  unknown: "unknown",
  safe: "safe",
  lowFilter: "low_filter",
  unfiltered: "unfiltered",
  blocked: "blocked",
};

/**
 * ממיר את כל ערכי הארגומנטים למחרוזות.
 *
 * RemoteCommand.Args בסוכן הוא Dictionary<string, string>. jsonb מחזיר
 * מספרים כמספרים, ו-System.Text.Json זורק כשהוא פוגש מספר במקום
 * מחרוזת. בלי ההמרה הזו כל פקודת נעילה הייתה מפילה את הפעימה בסוכן —
 * וזה היה מתגלה רק בשטח.
 */
function stringifyArgs(args: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};

  for (const [key, value] of Object.entries(args)) {
    if (value === null || value === undefined) continue;
    out[key] = typeof value === "string" ? value : String(value);
  }

  return out;
}

// ---------------------------------------------------------------- הקשר בקשה

export interface DeviceContext {
  deviceId: string;
  tenantId: string;
  hwid: string;
}

declare module "fastify" {
  interface FastifyRequest {
    device?: DeviceContext;
  }
}

export interface DeviceRoutesDeps {
  pool: pg.Pool;
  signer: Signer;
  looseningSigner: Signer;
  uninstallSigner: Signer;
  updateSigner: Signer;
  config: Config;

  /**
   * גוזר סוד ההסרה. חסר פירושו שהמצב נשאר Rsa.
   *
   * לא חובה, ובכוונה: פריסה בלי KMS עדיין עובדת, פשוט עם קוד
   * ארוך. עדיף קוד שאי אפשר להכתיב מקוד שאי אפשר לאמת.
   */
  deriver?: DeviceSecretDeriver | undefined;
}

// ---------------------------------------------------------------- מסלולים

export async function registerDeviceRoutes(
  app: FastifyInstance,
  deps: DeviceRoutesDeps,
): Promise<void> {
  const { pool, signer, looseningSigner, uninstallSigner, updateSigner, config, deriver } = deps;

  /** אימות אסימון מחשב. נכשל בשקט אחיד כדי לא לדלוף מידע לתוקף. */
  async function requireDevice(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    const header = request.headers.authorization;

    if (!header?.startsWith("Bearer ")) {
      await reply.code(401).send({ error: "נדרש אסימון מחשב" });
      return;
    }

    const claims = await verifyDeviceToken(config.DEVICE_TOKEN_SECRET, header.slice(7).trim());

    if (!claims) {
      await reply.code(401).send({ error: "אסימון מחשב אינו תקף" });
      return;
    }

    // כותרת ה-HWID חייבת להתאים לאסימון. אסימון שהועתק למכונה אחרת נדחה.
    const hwidHeader = request.headers["x-safeme-hwid"];

    if (typeof hwidHeader !== "string" || hwidHeader !== claims.hwid) {
      await reply.code(401).send({ error: "אי התאמה בין האסימון למזהה החומרה" });
      return;
    }

    const active = await withTenant(pool, claims.tenantId, async (tx) => {
      const r = await tx.query(
        `SELECT 1 FROM device_tokens
         WHERE jti = $1 AND revoked_at IS NULL AND expires_at > now()`,
        [claims.jti],
      );
      return r.rows.length === 1;
    });

    if (!active) {
      await reply.code(401).send({ error: "האסימון בוטל או פג תוקפו" });
      return;
    }

    request.device = {
      deviceId: claims.deviceId,
      tenantId: claims.tenantId,
      hwid: claims.hwid,
    };
  }

  // ---------------------------------------------------------------- health

  /*
   * שורש ה-API.
   *
   * הוא אינו מגיש דבר, וזה נכון — אבל 404 כאן שולח כל מי שהדביק
   * את הכתובת בדפדפן לחשוב שהשירות שבור. ההפניה עולה שורה אחת
   * וחוסכת את הבלבול, ובדרך גם מנקה את יומן הבקשות מבדיקות
   * הבריאות של Render שפוגעות בשורש.
   */
  app.get("/", async (_request, reply) => reply.redirect(config.PORTAL_URL, 302));

  /*
   * בריאות, ומה בדיוק פרוס.
   *
   * עד כאן הוא החזיר ok ושעה בלבד, ולכן לא הייתה שום דרך מבחוץ
   * לדעת איזה קוד רץ. שלוש פעמים הלילה הזה עלה: "פרסתי" מול
   * התנהגות שמתאימה לקוד ישן, ובכל פעם נדרש סבב שלם כדי לגלות
   * שהפריסה עוד לא הסתיימה — או שהיא כן, והבעיה במקום אחר.
   *
   * commit מגיע מ-Render. מחוץ לסביבה שלה הוא פשוט לא ידוע, וזה
   * עדיף על ערך שנראה אמיתי ואינו.
   */
  const deployedCommit = process.env["RENDER_GIT_COMMIT"]?.slice(0, 7) ?? null;
  const startedUtc = new Date().toISOString();

  app.get("/api/v1/health", async () => ({
    ok: true,
    serverUtc: new Date().toISOString(),
    commit: deployedCommit,
    startedUtc,
  }));

  // ---------------------------------------------------------------- enroll

  app.post("/api/v1/enroll", async (request, reply) => {
    const parsed = enrollBody.safeParse(request.body);

    if (!parsed.success) {
      return reply.code(400).send({ error: "בקשת רישום אינה תקינה" });
    }

    const body = parsed.data;
    const tokenHash = hashEnrollToken(body.enrollToken);

    const result = await withPlatform(pool, SYSTEM_ACTOR, async (tx) => {
      const tokenRow = await tx.query<{
        id: string;
        tenant_id: string;
        install_profile: string;
        enforcement_mode: string;
        policy_floor: unknown;
      }>(
        `SELECT id, tenant_id, install_profile, enforcement_mode, policy_floor
         FROM enroll_tokens
         WHERE token_hash = $1
           AND revoked_at IS NULL
           AND expires_at > now()
           AND uses < max_uses
         FOR UPDATE`,
        [tokenHash],
      );

      const token = tokenRow.rows[0];
      if (!token) return { kind: "bad-token" as const };

      /*
       * לקוח מושעה אינו רושם מחשבים חדשים.
       *
       * tenant_status היה מוגדר בסכמה ולא נקרא בשום מקום, כלומר
       * השעיה הייתה שינוי שאינו משנה דבר. כפתור שנראה כאילו הוא
       * עושה משהו ואינו עושה גרוע מהיעדרו — מי שלוחץ עליו מפסיק
       * לחפש דרך אחרת.
       *
       * מה שהיא חוסמת: רישום חדש וכניסה לפורטל. מה שהיא אינה
       * נוגעת בו: מחשבים שכבר מוגנים. שרת שיכול לפרק הגנה מרחוק
       * הופך פריצה אליו לכיבוי כל הצי בבת אחת.
       */
      const tenantState = await tx.query<{ status: string }>(
        "SELECT status::text AS status FROM tenants WHERE id = $1",
        [token.tenant_id],
      );

      if (tenantState.rows[0]?.status !== "active") {
        return { kind: "tenant-inactive" as const };
      }

      /*
       * מגבלת המחשבים של המנוי.
       *
       * max_devices יושב בטבלת הרישיונות מהיום הראשון ולא נאכף
       * מעולם — כלומר כל חשבון יכול היה לרשום בלי גבול, ומנוי
       * לשלושה מחשבים היה מספר על מסך בלבד.
       *
       * הספירה מדלגת על מחשבים שהוסרו: מי שהסיר מחשב פינה מקום,
       * ואחרת החלפת מחשב הייתה שורפת רישיון לצמיתות.
       *
       * ורישום חוזר של אותו מחשב אינו נספר. מחשב שנרשם מחדש —
       * אחרי מחיקת מצב או התקנה חוזרת — אינו מחשב נוסף, וספירה
       * שלא מבחינה הייתה נועלת דווקא את מי שכבר משלם.
       */
      const limit = await tx.query<{ device_limit: number; used: number }>(
        `SELECT s.device_limit,
                (SELECT count(*) FROM devices d
                  WHERE d.tenant_id = s.tenant_id
                    AND d.status <> 'uninstalled'
                    AND d.hwid <> $2)::int AS used
           FROM subscriptions s
          WHERE s.tenant_id = $1 AND s.status <> 'canceled'`,
        [token.tenant_id, body.hwid],
      );

      /*
       * מצב החיוב, אחרי המגבלה ולפני היצירה.
       *
       * ניסיון שפג חוסם רישום מחשב חדש — וזה כל מה שהוא חוסם.
       * מחשבים קיימים ממשיכים להגן, כי שרת שמפרק הגנה על סמך
       * חיוב הוא שרת שפריצה אליו מכבה את כל הצי.
       */
      const billing = await billingVerdict(pool, token.tenant_id);

      if (!billing.mayExpand) {
        return { kind: "billing" as const, reason: billing.reason ?? "" };
      }

      const quota = limit.rows[0];

      if (quota && quota.used >= quota.device_limit) {
        return {
          kind: "device-limit" as const,
          limit: quota.device_limit,
        };
      }

      // הרצפה הנוכחית, כדי להשוות אליה. שורה חסרה היא מחשב חדש.
      const existing = await tx.query<{ policy_floor: unknown; status: string }>(
        "SELECT policy_floor, status FROM devices WHERE tenant_id = $1 AND hwid = $2",
        [token.tenant_id, body.hwid],
      );

      /*
       * רישום חוזר של אותו מחשב אינו יוצר כפילות. זה קורה בשגרה
       * אחרי התקנה מחדש, ואין סיבה להכשיל אותו.
       *
       * הרצפה מתעדכנת רק כשהאסימון החדש **מחמיר** לפחות כמו
       * הקיימת. זהו אותו מחגר שחל על המדיניות, ומאותה סיבה: מי
       * שמשיג קישור התקנה לפרופיל מקל לא אמור להוריד בו מחשב
       * שכבר מוגן. ילד שמצא קישור הוא בדיוק התרחיש.
       *
       * להרפיה אמיתית יש להסיר את המחשב מהפורטל ואז להתקין
       * מחדש — פעולה מאומתת של ההורה, ולא תופעת לוואי של הרצת
       * קובץ.
       *
       * הבאג שזה מתקן: קודם הרצפה לא התעדכנה כלל, ולכן מחשב
       * נשאר לנצח ברצפה שאיתה נרשם בפעם הראשונה — גם כשההורה
       * יצר קישור חדש במפורש.
       */
      /*
       * מחשב שהוסר מהחשבון נחשב חדש.
       *
       * זה מה שהופך את ההסרה בפורטל לפעולה בעלת משמעות. בלי
       * התנאי הזה היא סימנה את השורה ותו לא: רישום חוזר פגע
       * באותה שורה, הפעיל אותה מחדש, ושמר את הרצפה הישנה — כי
       * הרפיה נדחית. ההורה עשה בדיוק את מה שנאמר לו, ושום דבר
       * לא השתנה.
       *
       * ההרפיה מותרת כאן משום שההסרה עצמה היא הפעולה המאומתת:
       * היא דורשת התחברות לפורטל והרשאה, ומי שביצע אותה הצהיר
       * שהוא רוצה להתחיל מחדש עם המחשב הזה.
       */
      const retired = existing.rows[0]?.status === "uninstalled";

      const tighter = retired || isAtLeastAsStrict(
        token.policy_floor as PolicyFloor,
        existing.rows[0]?.policy_floor as PolicyFloor | undefined,
      );

      const device = await tx.query<{ id: string; policy_floor: unknown }>(
        `INSERT INTO devices
           (tenant_id, hwid, machine_name, os_version, agent_version,
            install_profile, enforcement_mode, policy_floor)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (tenant_id, hwid) DO UPDATE SET
           machine_name  = EXCLUDED.machine_name,
           os_version    = EXCLUDED.os_version,
           agent_version = EXCLUDED.agent_version,
           status        = 'active',
           install_profile  = CASE WHEN $9 THEN EXCLUDED.install_profile
                                   ELSE devices.install_profile END,
           enforcement_mode = CASE WHEN $9 THEN EXCLUDED.enforcement_mode
                                   ELSE devices.enforcement_mode END,
           policy_floor     = CASE WHEN $9 THEN EXCLUDED.policy_floor
                                   ELSE devices.policy_floor END
         RETURNING id, policy_floor`,
        [
          token.tenant_id,
          body.hwid,
          body.machineName ?? null,
          body.osVersion ?? null,
          body.agentVersion ?? null,
          token.install_profile,
          token.enforcement_mode,
          JSON.stringify(token.policy_floor),
          tighter,
        ],
      );

      await tx.query("UPDATE enroll_tokens SET uses = uses + 1 WHERE id = $1", [token.id]);

      /*
       * רישום מאפס את מונה הפעימות.
       *
       * המונה נשמר אצל הסוכן בקובץ המצב. מחשב שהמצב שלו נמחק —
       * הסרה שלא הושלמה, התקנה נקייה — מתחיל למנות מאפס, בזמן
       * שהשרת זוכר מספר גבוה. הגנת הרצף בפעימה דוחה אז כל דיווח
       * כ"ישן", last_seen_at לא מתעדכן לעולם, והמחשב מוצג כמנותק
       * לנצח בזמן שהוא מדווח כל דקה.
       *
       * זה נצפה בשטח, והוא הטעה במיוחד: הצעות עדכון כן חזרו בתשובה,
       * ולכן נראה שהתקשורת תקינה לגמרי.
       *
       * רישום הוא הרגע היחיד שבו אנחנו יודעים בוודאות שהצד השני
       * התחיל מחדש, ולכן זה המקום לאפס.
       */
      await tx.query(
        `INSERT INTO device_state (device_id, tenant_id) VALUES ($1, $2)
         ON CONFLICT (device_id) DO UPDATE SET heartbeat_seq = 0`,
        [device.rows[0]!.id, token.tenant_id],
      );

      /*
       * הבחירה שנעשתה בהתקנה, אם עוד לא נבחרה.
       *
       * התנאי על uninstall_policy_changed_at הוא מה שהופך את זה
       * לחד-פעמי: התקנה שנייה באותו חשבון תשלח ערך ולא תשנה דבר.
       * זה מכוון — שינוי עובר דרך המוקד בתשלום, ולא דרך התקנה
       * חוזרת שכל אחד יכול להריץ.
       *
       * הטריגר במסד חוסם ממילא, אבל הוא היה זורק שגיאה ומפיל את
       * הרישום כולו. כאן זה פשוט לא קורה, וההתקנה ממשיכה.
       */
      if (body.uninstallPolicy) {
        await tx.query(
          `UPDATE tenants
              SET uninstall_policy = $2::uninstall_policy
            WHERE id = $1 AND uninstall_policy_changed_at IS NULL`,
          [token.tenant_id, body.uninstallPolicy],
        );
      }

      return {
        kind: "ok" as const,
        deviceId: device.rows[0]!.id,
        tenantId: token.tenant_id,
        installProfile: token.install_profile,
        enforcementMode: token.enforcement_mode,
        policyFloor: device.rows[0]!.policy_floor,
      };
    });

    if (result.kind === "bad-token") {
      return reply.code(403).send({ error: "אסימון הרישום אינו תקף, נוצל או פג תוקפו" });
    }

    if (result.kind === "billing") {
      return reply.code(403).send({ error: result.reason });
    }

    if (result.kind === "device-limit") {
      /*
       * מספר במפורש, ולא "חרגת מהמכסה".
       *
       * ההורה צריך לדעת כמה מותר לו וכמה יש לו כדי להחליט — להסיר
       * מחשב ישן או להרחיב את המנוי. הודעה בלי מספר שולחת אותו
       * למוקד.
       */
      return reply.code(403).send({
        error: `המנוי כולל ${result.limit} מחשבים, וכולם בשימוש. `
          + "אפשר להסיר מחשב שאינו בשימוש, או להרחיב את המנוי במרכז הניהול.",
      });
    }

    if (result.kind === "tenant-inactive") {
      /*
       * ניסוח שאומר מה קרה ולמי לפנות.
       *
       * "אסימון לא תקף" היה שולח את ההורה לחפש קישור חדש, והקישור
       * תקין לגמרי — החשבון הוא שמושעה.
       */
      return reply.code(403).send({
        error: "החשבון מושעה. יש לפנות לתמיכה כדי לחדש אותו לפני התקנת מחשבים נוספים.",
      });
    }

    const issued = await issueDeviceToken(
      config.DEVICE_TOKEN_SECRET,
      config.DEVICE_TOKEN_TTL_DAYS,
      { deviceId: result.deviceId, tenantId: result.tenantId, hwid: body.hwid },
    );

    await withTenant(pool, result.tenantId, async (tx) =>
      tx.query(
        `INSERT INTO device_tokens (device_id, tenant_id, jti, expires_at)
         VALUES ($1, $2, $3, $4)`,
        [result.deviceId, result.tenantId, issued.jti, issued.expiresAt],
      ),
    );

    // רצפת המדיניות נשלחת חתומה. המחשב מאמת אותה ושומר אותה מוגנת,
    // ומכאן והלאה דוחה כל מדיניות שנמוכה ממנה. ראה 3.2.3.
    const floor = await buildEnvelope(signer, {
      hwid: body.hwid,
      floor: result.policyFloor,
      issuedUtc: new Date().toISOString(),
    });

    /*
     * סוד ההסרה של המחשב, נגזר ולא נשמר.
     *
     * הוא מה שמאפשר קוד של עשרים וארבעה תווים במקום חתימת RSA
     * בת שש מאות — כלומר קוד שאפשר להכתיב בטלפון. זה חשוב בדיוק
     * במצב שבשבילו המוקד קיים: מחשב חסום, בלי אינטרנט, והורה
     * שמחייג.
     *
     * נשלח פעם אחת בלבד, ברישום. השרת אינו שומר אותו ויכול לגזור
     * אותו שוב מה-hwid, ולכן דליפת מסד אינה פותחת אף מחשב.
     *
     * כשאין גוזר מוגדר, המצב נשאר Rsa. עדיף קוד ארוך מקוד שאי
     * אפשר לאמת.
     */
    const deviceSecret = deriver ? await deriver.derive(body.hwid) : null;

    if (deviceSecret) {
      await withPlatform(pool, SYSTEM_ACTOR, async (tx) => {
        await tx.query(
          "UPDATE devices SET uninstall_key_mode = 'hmac' WHERE id = $1",
          [result.deviceId],
        );
      });
    }

    return reply.send({
      deviceId: result.deviceId,
      deviceToken: issued.token,
      installProfile: result.installProfile,
      enforcementMode: result.enforcementMode,
      policyFloor: floor.envelope,
      uninstallKeyMode: deviceSecret ? "Hmac" : "Rsa",
      deviceSecret: deviceSecret?.toString("base64") ?? null,
      serverPublicKeyPem: await signer.publicKeyPem(),
      // מפתח שלישי ונפרד. קוד ההסרה מאומת בו בלבד, כדי שמי שיכול
      // לחתום מדיניות לא יוכל בכך גם להסיר מחשבים.
      uninstallPublicKeyPem: await uninstallSigner.publicKeyPem(),
      // מפתח נפרד. הסוכן מאמת בו היתרי הקלה בלבד, ולעולם לא
      // מקבל הקלה מתחת לרצפה שנחתמה במפתח המדיניות.
      looseningPublicKeyPem: await looseningSigner.publicKeyPem(),
      // מפתח רביעי ונפרד. עדכון הוא הרצת קוד ב-SYSTEM, ולכן הוא
      // מאומת במפתח שאינו חותם דבר אחר.
      updatePublicKeyPem: await updateSigner.publicKeyPem(),
      signingKid: signer.kid,
    });
  });

  // ---------------------------------------------------------------- policy

  app.get("/api/v1/policy", { preHandler: requireDevice }, async (request, reply) => {
    const device = request.device!;

    const policy = await withTenant(pool, device.tenantId, async (tx) => {
      const r = await tx.query<{
        id: string;
        version: number;
        etag: string;
        signed_bytes: Buffer;
        signature: Buffer;
        signing_kid: string;
      }>(
        `SELECT p.id, p.version, p.etag, p.signed_bytes, p.signature, p.signing_kid
         FROM policies p
         LEFT JOIN device_policy_assignments a ON a.policy_id = p.id AND a.device_id = $1
         /*
          * שכבה של מחשב אחר אינה מדיניות הדייר.
          *
          * מדיניות מחשב נכתבת עם tenant_id, ולכן היא נראית כאן
          * בדיוק כמו מדיניות של הדייר כולו — ועם מספר גרסה גבוה
          * יותר, כי היא נוצרת מאוחר. בלי הסינון, מחשב אחד היה
          * מקבל את השכבה של מחשב אחר, או שארית של שכבה שכבר
          * בוטלה.
          */
         WHERE a.device_id IS NOT NULL
            OR ((p.tenant_id = $2 OR p.tenant_id IS NULL)
                AND NOT EXISTS (
                  SELECT 1 FROM device_policy_assignments x WHERE x.policy_id = p.id
                ))
         ORDER BY (a.device_id IS NOT NULL) DESC,
                  (p.tenant_id IS NOT NULL) DESC,
                  p.version DESC
         LIMIT 1`,
        [device.deviceId, device.tenantId],
      );

      return r.rows[0] ?? null;
    });

    if (!policy) {
      return reply.code(404).send({ error: "טרם הוגדרה מדיניות עבור המחשב" });
    }

    if (request.headers["if-none-match"] === policy.etag) {
      return reply.code(304).send();
    }

    return reply
      .header("ETag", policy.etag)
      .send(envelopeFromStored(policy.signing_kid, policy.signed_bytes, policy.signature));
  });

  // ---------------------------------------------------------------- heartbeat

  app.post("/api/v1/heartbeat", { preHandler: requireDevice }, async (request, reply) => {
    const device = request.device!;
    const parsed = heartbeatBody.safeParse(request.body);

    if (!parsed.success) {
      return reply.code(400).send({ error: "פעימה אינה תקינה" });
    }

    const body = parsed.data;
    const status = STATUS_MAP[body.status] ?? "unknown";
    const ssid = body.activeAdapters.find((a) => a.ssid)?.ssid ?? null;

    const outcome = await withTenant(pool, device.tenantId, async (tx) => {
      // פעימה ישנה שהגיעה באיחור לא תדרוס מצב עדכני יותר
      // המצב הקודם נשלף באותה שאילתה שדורסת אותו, דרך צילום שנלקח
      // לפני העדכון. בלי זה היה צריך סבב נוסף לבסיס הנתונים בכל
      // פעימה — בדיוק העלות שהדגימה באה לחסוך.
      const state = await tx.query<{
        prev_status: string;
        prev_score: number | null;
        prev_provider: string | null;
        prev_lockout: boolean;
        prev_policy_version: number | null;
        prev_sample_at: Date | null;
      }>(
        `UPDATE device_state SET
           last_seen_at = now(),
           last_status  = $2::security_status,
           last_score   = $3,
           detected_provider = $4,
           public_ip    = NULLIF($5, '')::inet,
           wifi_ssid    = $6,
           lockout_active = $7,
           wfp_filter_count = $8,
           policy_version = $9,
           /*
            * המספר שהתקבל, ולא הגבוה מבין השניים.
            *
            * GREATEST היה משמר את המונה הישן גם כשהתקבלה פעימה
            * מסוכן שהתחיל מחדש — כלומר המחשב היה משתחרר לרגע דרך
            * מילוט חמש הדקות ונתקע מיד שוב, ומהבהב בפורטל בין
            * מדווח למנותק.
            *
            * השמירה על הסדר נעשית בתנאי WHERE למטה. כאן רק רושמים
            * מה נאמר.
            */
           heartbeat_seq = $10,
           -- פעימה מחזירה לתקינות, אך אינה מוחקת סימון חבלה:
           -- מחשב שהוכח שחובל אינו נקי רק מפני שהוא מדווח שוב.
           health = CASE WHEN device_state.health = 'tampered'
                        THEN device_state.health
                        ELSE 'healthy'::dead_man_state END,
           updated_at   = now()
         FROM (
           SELECT last_status, last_score, detected_provider,
                  lockout_active, policy_version, last_sample_at
           FROM device_state WHERE device_id = $1
         ) AS prev
         /*
          * הרצף שומר על סדר, לא על זהות.
          *
          * שינוי סדר בין פעימות קורה בשניות, לא בדקות. מחשב שלא
          * נשמע חמש דקות ושולח מספר נמוך אינו פעימה שהגיעה באיחור
          * אלא סוכן שהמונה שלו התחיל מחדש — וזה קורה בכל מחיקת
          * מצב.
          *
          * בלי המילוט הזה מחשב כזה נשאר תקוע לנצח: כל דיווח נדחה,
          * ואין שום אירוע שישחרר אותו חוץ מרישום מחדש. הזהות ממילא
          * נשמרת על ידי אסימון המחשב, ולא על ידי המספר הזה.
          */
         WHERE device_state.device_id = $1
           AND (device_state.heartbeat_seq <= $10
                OR device_state.last_seen_at < now() - interval '5 minutes')
         RETURNING prev.last_status        AS prev_status,
                   prev.last_score         AS prev_score,
                   prev.detected_provider  AS prev_provider,
                   prev.lockout_active     AS prev_lockout,
                   prev.policy_version     AS prev_policy_version,
                   prev.last_sample_at     AS prev_sample_at`,
        [
          device.deviceId,
          status,
          body.score,
          body.detectedProvider ?? null,
          body.publicIp ?? "",
          ssid,
          body.lockoutActive,
          body.wfpFilterCount ?? null,
          body.policyVersion ?? null,
          body.sequence,
        ],
      );

      // ---- היסטוריה: נשמרת רק כשיש בה מידע ----
      //
      // device_state לעיל כבר מחזיקה את המצב החי, וזה מה שהדשבורד
      // קורא. שורה כאן נכתבת רק בשינוי מצב או אחת לשעה. ראה
      // src/telemetry/retention.ts ומיגרציה 0014.
      const row = state.rows[0];

      const prev: DeviceSnapshot | null = row
        ? {
            status: row.prev_status,
            score: row.prev_score,
            provider: row.prev_provider,
            lockoutActive: row.prev_lockout,
            policyVersion: row.prev_policy_version,
            lastSampleAt: row.prev_sample_at,
          }
        : null;

      const reason = sampleReason(
        prev,
        {
          status,
          score: body.score,
          provider: body.detectedProvider ?? null,
          lockoutActive: body.lockoutActive,
          policyVersion: body.policyVersion ?? null,
          hasTamperEvents: body.tamperEvents.length > 0,
        },
        new Date(),
      );

      if (reason !== null) {
        // ההכנסה וסימון זמן הדגימה באותה שאילתה: אם אחת מהן תיכשל
        // ייווצר פער שבו סימן החיים השעתי לא יופעל שוב לעולם.
        await tx.query(
          `WITH sample AS (
             INSERT INTO heartbeats
               (device_id, tenant_id, sent_at, sequence, status, score,
                policy_version, lockout_active, payload)
             VALUES ($1, $2, $3, $4, $5::security_status, $6, $7, $8, $9)
             RETURNING device_id
           )
           UPDATE device_state SET last_sample_at = now()
           WHERE device_id = (SELECT device_id FROM sample)`,
          [
            device.deviceId,
            device.tenantId,
            body.sentUtc ?? null,
            body.sequence,
            status,
            body.score,
            body.policyVersion ?? null,
            body.lockoutActive,
            JSON.stringify({
              adapters: body.activeAdapters,
              failedProbes: body.failedProbes,
              uptimeSec: body.uptimeSec ?? null,
              agentVersion: body.agentVersion ?? null,
              sampleReason: reason,
            }),
          ],
        );
      }

      for (const event of body.tamperEvents) {
        await tx.query(
          // החומרה נגזרת מהסוג ואינה קבועה. אירוע שמשמעותו שההגנה
          // לא פעלה בפועל חייב לבלוט מול ניסיון שנחסם.
          `INSERT INTO events (device_id, tenant_id, kind, severity, detail, occurred_at)
           VALUES ($1, $2, $3, $4, $5, COALESCE($6::timestamptz, now()))`,
          [
            device.deviceId,
            device.tenantId,
            event.kind,
            severityFor(event.kind),
            event.detail ?? null,
            event.utc ?? null,
          ],
        );
      }

      const policy = await tx.query<{ etag: string }>(
        /*
         * אותו כלל, וגם כאן.
         *
         * ה-ETag שנשלח בפעימה הוא מה שמפעיל את משיכת המדיניות.
         * אם הוא מגיע משורה אחרת מזו שתוגש בפועל, המחשב ימשוך
         * שוב ושוב או לא ימשוך כלל.
         */
        `SELECT p.etag FROM policies p
          LEFT JOIN device_policy_assignments a
                 ON a.policy_id = p.id AND a.device_id = $2
         WHERE a.device_id IS NOT NULL
            OR ((p.tenant_id = $1 OR p.tenant_id IS NULL)
                AND NOT EXISTS (
                  SELECT 1 FROM device_policy_assignments x WHERE x.policy_id = p.id
                ))
         ORDER BY (a.device_id IS NOT NULL) DESC,
                  (p.tenant_id IS NOT NULL) DESC,
                  p.version DESC LIMIT 1`,
        [device.tenantId, device.deviceId],
      );

      // פקודות ישנות פוקעות לפני האיסוף, כדי שמחשב שחזר אחרי
      // שבוע לא ייחסם בגלל בקשה ששכחו ממנה
      await tx.query(
        `UPDATE device_commands SET status = 'expired'
         WHERE device_id = $1 AND status = 'pending' AND expires_at <= now()`,
        [device.deviceId],
      );

      // איסוף וסימון כנמסר באותה שאילתה: פקודה לא תימסר פעמיים
      const commands = await tx.query<{
        id: string;
        type: string;
        args: Record<string, string>;
        reason: string | null;
      }>(
        `UPDATE device_commands SET status = 'delivered', delivered_at = now()
         WHERE id IN (
           SELECT id FROM device_commands
           WHERE device_id = $1 AND status = 'pending'
           ORDER BY created_at
           LIMIT 10
           FOR UPDATE SKIP LOCKED
         )
         RETURNING id, type::text AS type, args, reason`,
        [device.deviceId],
      );

      // ---- הרשת שהמחשב מחובר אליה ----
      //
      // רשת חדשה אינה מאושרת. ההכרעה חוזרת לסוכן בתשובה, והוא זה
      // שאוכף — השרת אינו יכול לחסום תעבורה במחשב מרוחק.
      /*
       * מצב האכיפה של המחשב.
       *
       * אינו משפיע על ההכרעה — רשת שצריך לחסום היא רשת שצריך לחסום —
       * אלא על מה שנרשם שקרה. במצב תצפית שום דבר לא נחסם בפועל,
       * ורישום "נחסם" הוא דיווח על מה שלא קרה.
       */
      const mode = await tx.query<{ enforcement_mode: string }>(
        "SELECT enforcement_mode FROM devices WHERE id = $1",
        [device.deviceId],
      );

      const network = await trackNetwork(
        tx,
        { deviceId: device.deviceId, tenantId: device.tenantId },
        body.activeAdapters,
        body.detectedProvider ?? null,
        { key: body.ispKey ?? null, name: body.ispName ?? null },
        mode.rows[0]?.enforcement_mode ?? "monitor",
      );

      /*
       * הגרסה המדווחת, כשהיא משתנה.
       *
       * היא נכתבה ברישום בלבד, ולכן השורה במסד נשארה תקועה על
       * הגרסה שהותקנה פעם ראשונה — לנצח. הפורטל הציג אותה, וכך
       * גם כלי האבחון, ושניהם היו משקרים בדיוק אחרי עדכון מוצלח:
       * הסוכן מתעדכן, המסד ממשיך לומר את הישנה, ומי שבודק מסיק
       * שהעדכון נכשל.
       *
       * ההחלטה על העדכון עצמה מסתמכת על מה שהפעימה מדווחת ולא על
       * המסד, ולכן לא נוצרה לולאת עדכון — רק עיוורון.
       *
       * IS DISTINCT FROM כדי שפעימה רגילה לא תכתוב שורה סתם.
       */
      if (body.agentVersion) {
        await tx.query(
          `UPDATE devices SET agent_version = $2
            WHERE id = $1 AND agent_version IS DISTINCT FROM $2`,
          [device.deviceId, body.agentVersion],
        );
      }

      /*
       * מחשב שמסומן כמוסר וממשיך לדווח חוזר לרשימה.
       *
       * הסימון מגיע מהסוכן ברגע שההסרה אושרה, לפני שהיא בוצעה. אם
       * המחיקה נכשלה — והיא כבר נכשלה, פעמיים — המחשב ממשיך לאכוף
       * בזמן שהוא נעלם מהפורטל. כלומר ההורה מאבד את הדבר היחיד
       * שמראה לו מה מוגן, בדיוק כשמשהו השתבש.
       *
       * פעימה היא הוכחה שהסוכן חי. אין מצב שבו נכון להסתיר אותו.
       */
      const revived = await tx.query(
        `UPDATE devices SET status = 'active', uninstalled_at = NULL
          WHERE id = $1 AND status = 'uninstalled'`,
        [device.deviceId],
      );

      if (revived.rowCount) {
        request.log.warn(
          { device: device.deviceId },
          "מחשב שסומן כמוסר ממשיך לדווח. הוחזר לרשימה.",
        );
      }

      // ---- הצעת עדכון ----
      //
      // ההצעה אינה רק "יש גרסה חדשה". היא גם ההיתר היחיד שבגללו
      // השמירה הכפולה תסבול עצירה של השירות בלי לזעוק חבלה, ולכן
      // היא חתומה במפתח נפרד, קשורה למחשב, ובעלת תוקף קצר.
      const update = await buildUpdateOffer(
        tx,
        updateSigner,
        { deviceId: device.deviceId, hwidHash: hwidHashHex(body.hwid) },
        body.agentVersion ?? null,
        new Date(),
      );

      return {
        stale: state.rows.length === 0,
        policyEtag: policy.rows[0]?.etag ?? null,
        commands: commands.rows,
        update,
        network,
      };
    });

    /*
     * שדרוג מחשב שנרשם לפני שהיה מי שיגזור סוד.
     *
     * המצב נקבע ברישום בלבד, והתקנה מעל התקנה קיימת היא שדרוג —
     * היא אינה עוברת דרך enroll. כלומר מחשב שנרשם לפני שהמפתח
     * הוגדר היה נשאר rsa לנצח, גם אחרי עשר התקנות, ומקבל קוד
     * הסרה בן שש מאות תווים שאי אפשר להכתיב בטלפון.
     *
     * נצפה בשטח בדיוק כך: הכול הוגדר, הגזירה פעילה, והפורטל
     * המשיך להנפיק חתימת RSA.
     *
     * הפעימה היא המקום היחיד שכל מחשב עובר בו תמיד. השדרוג קורה
     * פעם אחת — התנאי על rsa דואג לכך — והסוד נשלח בתשובה כדי
     * שהסוכן ישמור אותו, בדיוק כמו ברישום.
     */
    /*
     * רק סוכן שיודע לקלוט את השדרוג.
     *
     * 1.1.34 היא הראשונה שקוראת את uninstallKeyMode מהפעימה. סוכן
     * ישן יזרוק את השדה בשקט — ואז המסד אומר hmac, הפורטל מנפיק
     * קוד קצר, והסוכן ממשיך לאמת ב-RSA. כלומר הסרה שאינה אפשרית
     * בשום מסלול, גרוע בהרבה מקוד ארוך.
     *
     * הבדיקה כאן ולא בסוכן, כי הצד שאינו יודע לקרוא את השדה הוא
     * גם הצד שאינו יכול לסרב לו.
     *
     * גרסה שאינה נפרשת נחשבת ישנה. ניחוש לטובה כאן עולה בדיוק
     * במקרה שהגנו עליו.
     */
    const agent = parseVersion(body.agentVersion ?? "");
    const agentKnowsUpgrade =
      agent !== null && compareVersions(agent, UPGRADE_MIN_AGENT) >= 0;

    const upgrade = deriver && agentKnowsUpgrade
      ? await withTenant(pool, device.tenantId, async (tx) => {
          const r = await tx.query<{ hwid: string }>(
            `UPDATE devices SET uninstall_key_mode = 'hmac'
              WHERE id = $1 AND uninstall_key_mode = 'rsa'
              RETURNING hwid`,
            [device.deviceId],
          );

          return r.rows[0] ?? null;
        })
      : null;

    /*
     * הגזירה מהעמודה ולא מ-body.hwid, למרות שהם אמורים להיות זהים.
     *
     * ההנפקה בפורטל גוזרת מ-device.hwid, וסוד שנגזר ממקור אחר היה
     * מייצר קוד תקין לחלוטין שפשוט אינו מתאים — בלי שגיאה בשום צד.
     */
    const upgradedSecret = upgrade ? await deriver!.derive(upgrade.hwid) : null;

    if (upgradedSecret) {
      request.log.warn(
        { device: device.deviceId },
        "המחשב שודרג לקוד הסרה קצר. הסוד נשלח בפעימה.",
      );
    }

    return reply.send({
      ok: true,
      serverUtc: new Date().toISOString(),
      policyEtag: outcome.policyEtag,
      licenseValid: true,

      /*
       * נשלח פעם אחת, ורק בשדרוג. פעימה רגילה אינה נושאת סוד —
       * אין סיבה שהוא יעבור ברשת שוב ושוב אחרי שהגיע.
       */
      ...(upgradedSecret
        ? {
            uninstallKeyMode: "Hmac",
            deviceSecret: upgradedSecret.toString("base64"),
          }
        : {}),

      // מעטפה חתומה במפתח העדכונים, או null כשאין מה להציע.
      // הסוכן מאמת אותה במפתח שקיבל ברישום, ולעולם לא במפתח אחר.
      update: outcome.update,

      // ההכרעה על הרשת הנוכחית. null כשאין מתאם מזוהה.
      network: outcome.network,
      commands: outcome.commands.map((c) => ({
        id: c.id,
        // הסוכן מצפה ל-PascalCase, בסיס הנתונים שומר snake_case
        type: TYPE_MAP[c.type] ?? c.type,
        args: stringifyArgs({ ...c.args, ...(c.reason ? { reason: c.reason } : {}) }),
      })),
      ...(outcome.stale ? { note: "התקבלה פעימה ישנה; המצב לא עודכן" } : {}),
    });
  });

  // ---------------------------------------------------------------- audit

  app.post("/api/v1/audit", { preHandler: requireDevice }, async (request, reply) => {
    const device = request.device!;
    const report = request.body;

    await withTenant(pool, device.tenantId, async (tx) =>
      tx.query(
        `INSERT INTO events (device_id, tenant_id, kind, severity, detail, occurred_at)
         VALUES ($1, $2, 'audit.report', 'info', $3, now())`,
        [device.deviceId, device.tenantId, JSON.stringify(report).slice(0, 1024)],
      ),
    );

    return reply.send({ ok: true });
  });

  // ---------------------------------------------------------------- events

  app.post("/api/v1/events", { preHandler: requireDevice }, async (request, reply) => {
    const device = request.device!;
    const parsed = eventsBody.safeParse(request.body);

    if (!parsed.success) {
      return reply.code(400).send({ error: "רשימת אירועים אינה תקינה" });
    }

    await withTenant(pool, device.tenantId, async (tx) => {
      for (const event of parsed.data) {
        await tx.query(
          `INSERT INTO events (device_id, tenant_id, kind, severity, detail, occurred_at)
           VALUES ($1, $2, $3, 'warning', $4, COALESCE($5::timestamptz, now()))`,
          [device.deviceId, device.tenantId, event.kind, event.detail ?? null, event.utc ?? null],
        );
      }
    });

    return reply.send({ ok: true, accepted: parsed.data.length });
  });

  /**
   * המחשב מודיע שהוא מוסר.
   *
   * בלי זה מחשב שהוסר בהצלחה נשאר ברשימה לנצח, וההורה רואה מכשירים
   * שכבר אינם קיימים — כלומר הרשימה מפסיקה להיות תמונה של מה שמוגן,
   * וזו התמונה היחידה שיש לו.
   *
   * הדיווח מגיע רק אחרי אימות קוד הסרה תקף, ולכן הוא אינו דרך לחמוק
   * מהרשימה: מי שיכול לשלוח אותו כבר קיבל אישור להסיר. וגם אילו נשלח
   * בזדון, הוא אינו מכבה אכיפה בשום מחשב — הוא רק מסמן שורה.
   *
   * הסימון ולא מחיקה, כמו ב-retire הידני. מחשב שנעלם מהמאגר בלי
   * עקבות הוא בדיוק מה שמסתיר הסרה לא מורשית.
   */
  app.post("/api/v1/uninstalled", { preHandler: requireDevice }, async (request, reply) => {
    const device = request.device!;

    const marked = await withTenant(pool, device.tenantId, async (tx) => {
      const r = await tx.query<{ machine_name: string | null }>(
        `UPDATE devices
            SET status = 'uninstalled', uninstalled_at = now()
          WHERE id = $1 AND status <> 'uninstalled'
      RETURNING machine_name`,
        [device.deviceId],
      );

      return r.rows[0] ?? null;
    });

    request.log.warn(
      { device: device.deviceId, machine: marked?.machine_name ?? null },
      marked ? "המחשב דיווח על הסרה וסומן." : "דיווח הסרה על מחשב שכבר מסומן.",
    );

    return reply.send({ ok: true });
  });

  /**
   * יומן שנאסף מהמחשב, בעקבות בקשה מפורשת.
   *
   * הגוף הוא gzip גולמי ולא JSON: יומן אירועים של יממה הוא מאות
   * קילובייטים של שורות חוזרות, והוא מתכווץ פי עשרה. עטיפה
   * ב-base64 בתוך JSON הייתה מנפחת אותו בשליש בדיוק בכיוון הלא
   * נכון.
   *
   * הגבול נאכף כאן וגם בסוכן. צד אחד שסומך על השני הוא צד אחד
   * שאפשר לעקוף, ובקשה בת מאה מגה-בייט אינה תקלה אלא התקפה.
   */
  app.post(
    "/api/v1/logs",
    {
      preHandler: requireDevice,
      bodyLimit: 4 * 1024 * 1024,
    },
    async (request, reply) => {
      const device = request.device!;
      const body = request.body;

      if (!Buffer.isBuffer(body) || body.length === 0) {
        return reply.code(400).send({ error: "גוף הבקשה אינו יומן דחוס" });
      }

      const commandId = typeof request.headers["x-safeme-command"] === "string"
        ? request.headers["x-safeme-command"]
        : null;

      const stored = await withTenant(pool, device.tenantId, async (tx) => {
        const r = await tx.query<{ id: string }>(
          `INSERT INTO device_logs
             (device_id, tenant_id, command_id, agent_version, body, byte_length, collected_at)
           VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7::timestamptz, now()))
        RETURNING id`,
          [
            device.deviceId,
            device.tenantId,
            /*
             * מזהה שאינו uuid נשמר כ-NULL ולא מפיל את הקליטה.
             *
             * היומן הוא מה שחשוב כאן. כותרת פגומה שגורמת לאיבוד
             * הראיה היא בדיוק ההפך ממה שהמנגנון נועד לו.
             */
            commandId && /^[0-9a-f-]{36}$/i.test(commandId) ? commandId : null,
            typeof request.headers["x-safeme-agent"] === "string"
              ? request.headers["x-safeme-agent"].slice(0, 32)
              : null,
            body,
            body.length,
            typeof request.headers["x-safeme-collected"] === "string"
              ? request.headers["x-safeme-collected"]
              : null,
          ],
        );

        return r.rows[0]!.id;
      });

      request.log.warn(
        { device: device.deviceId, bytes: body.length },
        "התקבל יומן מהמחשב.",
      );

      return reply.send({ ok: true, id: stored });
    },
  );
}
