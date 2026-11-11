import { createHash, randomBytes } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type pg from "pg";
import { z } from "zod";
import { withPlatform, withTenant } from "../db/client.ts";
import { createGuards } from "../auth/guards.ts";
import { spendCredit } from "../billing/entitlements.ts";
import { issueLooseningGrant } from "../policy/loosening.ts";
import { looseningReasons, type PolicyFloor } from "../policy/floor.ts";
import type { Signer } from "../crypto/signing.ts";
import { isPlatformRole } from "../auth/rbac.ts";
import { hashEnrollToken } from "../auth/device-token.ts";
import type { Config } from "../config.ts";
import type { ActiveSession } from "../auth/session.ts";
import { fileNameForToken } from "../installer/filename.ts";

/**
 * מסלולי הפורטל: רשימת מחשבים, מצב חי, נעילה, ואסימוני רישום.
 *
 * הערה על בידוד: כל שאילתה כאן רצה בהקשר הדייר של המשתמש, ולכן RLS
 * מסנן את השורות עוד לפני שהקוד רואה אותן. משתמש פלטפורמה רץ בהקשר
 * פלטפורמה ורואה הכול — וזה מתועד ביומן.
 */

const SYSTEM_ACTOR = { userId: "system", reason: "פעולת פורטל" };

const lockoutBody = z.object({
  // הטווח מעוגן גם ב-CHECK בבסיס הנתונים. כאן זה רק כדי להחזיר
  // שגיאה מובנת במקום חריגת מסד נתונים.
  minutes: z.number().int().min(1).max(1440),
  reason: z.string().min(2).max(200),
});

/** כמה זמן קישור הורדה נשאר תקף. */
const INSTALLER_LINK_DAYS = 14;

/**
 * הרצפה שנקבעת להתקנה מהאתר.
 *
 * שמרנית במכוון: קישור שמופק בלחיצה אחת אינו המקום להגדיר מדיניות
 * מקלה. אפשר תמיד להחמיר אחר כך מרחוק, ולהקל אי אפשר בלי היתר
 * חתום — וזה בדיוק הסדר הרצוי.
 */
const DEFAULT_FLOOR = {
  mode: "enforce",
  onRedAction: "lockout",
  minScoreForGreen: 85,
} as const;

const installerBody = z.object({
  tenantId: z.string().uuid().optional(),
  installProfile: z
    .enum(["family_child", "individual", "organization"])
    .default("family_child"),
  enforcementMode: z.enum(["monitor", "warn", "enforce"]).default("monitor"),
  maxUses: z.number().int().min(1).max(50).default(1),
});

/*
 * הסכימה שכפתור "צור קישור התקנה" בפורטל משתמש בה.
 *
 * זו שקובעת בפועל מה קורה על מחשב אמיתי — ולא installerBody
 * שמעליה, שנראית דומה ומשמשת מסלול אחר. ההערה על מצב התצפית
 * נחתה בטעות על השנייה, וברירת המחדל כאן נשארה enforce.
 *
 * להפעלת אכיפה: כאן, ב-portal-signup, ב-portal-google,
 * וב-baseline. ארבעה מקומות, תמיד יחד.
 */
const enrollTokenBody = z.object({
  installProfile: z.enum(["family_child", "individual", "organization"]),
  enforcementMode: z.enum(["monitor", "warn", "enforce"]).default("monitor"),
  maxUses: z.number().int().min(1).max(100).default(1),
  expiresInDays: z.number().int().min(1).max(30).default(7),
  policyFloor: z
    .object({
      mode: z.enum(["monitor", "warn", "enforce"]).default("monitor"),
      onRedAction: z.enum(["none", "warn", "lockout"]).default("warn"),
      minScoreForGreen: z.number().int().min(0).max(100).default(85),
      minScoreForYellow: z.number().int().min(0).max(100).default(60),
      requireProvider: z.array(z.string().max(64)).max(16).default([]),
    })
    .default({}),
});

export interface PortalDeviceDeps {
  pool: pg.Pool;
  config: Config;

  /*
   * החותם של ההיתרים בלבד.
   *
   * מפתח המדיניות אינו מגיע לכאן בכוונה: אם אותו מפתח היה חותם
   * גם היתרי הקלה, ההפרדה שהסוכן אוכף הייתה חסרת משמעות — והוא
   * ידחה כל היתר שנחתם באותו מפתח.
   */
  looseningSigner: Signer;
}

/**
 * מריץ שאילתה בהקשר הנכון: דייר רגיל בהקשר שלו, ומשתמש פלטפורמה
 * מעל הבידוד. זו הנקודה היחידה שבה ההבחנה נעשית, ולכן קל לבקר אותה.
 */
async function inScope<T>(
  pool: pg.Pool,
  session: ActiveSession,
  action: string,
  fn: (tx: { query: pg.ClientBase["query"] }) => Promise<T>,
): Promise<T> {
  if (isPlatformRole(session.user.role)) {
    return withPlatform(pool, { userId: session.user.userId, reason: action }, fn);
  }

  return withTenant(pool, session.user.tenantId!, fn);
}

async function audit(
  pool: pg.Pool,
  session: ActiveSession,
  entry: { action: string; targetId?: string; tenantId?: string | null; payload?: unknown },
): Promise<void> {
  await withPlatform(pool, SYSTEM_ACTOR, async (tx) => {
    await tx.query(
      `INSERT INTO audit_log
         (actor_type, actor_id, action, target_type, target_id, tenant_id, payload)
       VALUES ($1, $2, $3, 'device', $4, $5, $6)`,
      [
        isPlatformRole(session.user.role) ? "platform_user" : "tenant_user",
        session.user.userId,
        entry.action,
        entry.targetId ?? null,
        entry.tenantId ?? session.user.tenantId,
        JSON.stringify(entry.payload ?? {}),
      ],
    );
  });
}

/*
 * אותה צורה בדיוק כמו policyFloor בקישור ההתקנה.
 *
 * הסוכן משווה את from שבהיתר לרצפה שיש לו שדה-שדה, ושדה שחסר
 * כאן היה מגיע כברירת מחדל ומכשיל את ההתאמה בלי הסבר.
 */
const lowerFloorBody = z.object({
  floor: z.object({
    mode: z.enum(["monitor", "warn", "enforce"]),
    onRedAction: z.enum(["none", "warn", "lockout"]),
    minScoreForGreen: z.number().int().min(0).max(100),
    minScoreForYellow: z.number().int().min(0).max(100),
    requireProvider: z.array(z.string().trim().min(1).max(64)).max(16).default([]),
  }),

  reason: z.string().trim().max(200).optional(),
  waiveCredit: z.boolean().optional(),
});

export async function registerPortalDeviceRoutes(
  app: FastifyInstance,
  deps: PortalDeviceDeps,
): Promise<void> {
  /*
   * החותם של ההיתרים, ולא זה של המדיניות.
   *
   * ההפרדה היא כל ההגנה: שרת שנפרץ ויכול לחתום מדיניות אינו יכול
   * בכך גם להוריד רצפות, והסוכן אוכף את ההפרדה בעצמו ודוחה היתר
   * שנחתם באותו מפתח.
   */
  const { pool, config, looseningSigner } = deps;
  const guards = createGuards(pool, config);

  const base = [guards.requireSession, guards.requirePlatformMfa];

  // ---------------------------------------------------------------- רשימה

  app.get(
    "/api/portal/v1/devices",
    { preHandler: [...base, guards.requirePermission("devices.viewOwn")] },
    async (request, reply) => {
      const session = request.portal!.session;

      const devices = await inScope(pool, session, "צפייה במחשבים", async (tx) => {
        const r = await tx.query(
          `SELECT d.id, d.hwid, d.display_name, d.machine_name, d.install_profile,
                  d.enforcement_mode, d.status, d.enrolled_at, d.agent_version, d.os_version, d.tenant_id,
                  t.name AS tenant_name,
                  s.last_seen_at, s.last_status, s.last_score, s.detected_provider,
                  s.wifi_ssid, s.lockout_active, s.lockout_until, s.health,
                  s.policy_version, s.wfp_filter_count,
                  (SELECT count(*) FROM events e
                    WHERE e.device_id = d.id AND e.acknowledged_at IS NULL) AS open_events
           FROM devices d
           JOIN tenants t ON t.id = d.tenant_id
           LEFT JOIN device_state s ON s.device_id = d.id
           WHERE d.status <> 'uninstalled'
           ORDER BY
             CASE s.last_status
               WHEN 'unfiltered' THEN 0
               WHEN 'blocked' THEN 1
               WHEN 'low_filter' THEN 2
               WHEN 'unknown' THEN 3
               ELSE 4
             END,
             s.last_seen_at DESC NULLS LAST`,
        );

        return r.rows;
      });

      return reply.send({ devices, count: devices.length });
    },
  );

  // ---------------------------------------------------------------- פרטי מחשב

  app.get(
    "/api/portal/v1/devices/:id",
    { preHandler: [...base, guards.requirePermission("devices.viewOwn")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const { id } = request.params as { id: string };

      const device = await inScope(pool, session, "צפייה במחשב", async (tx) => {
        const r = await tx.query(
          `SELECT d.*, s.last_seen_at, s.last_status, s.last_score, s.detected_provider,
                  s.public_ip, s.wifi_ssid, s.lockout_active, s.lockout_until,
                  s.health, s.policy_version, s.wfp_filter_count, s.heartbeat_seq
           FROM devices d
           LEFT JOIN device_state s ON s.device_id = d.id
           WHERE d.id = $1`,
          [id],
        );

        return r.rows[0] ?? null;
      });

      // RLS כבר סינן מחשב של דייר אחר, ולכן "לא נמצא" מכסה גם
      // מחשב קיים שאינו שייך למשתמש — בלי להסגיר את ההבדל
      if (!device) return reply.code(404).send({ error: "המחשב לא נמצא" });

      return reply.send(device);
    },
  );

  // ---------------------------------------------------------------- ציר זמן

  app.get(
    "/api/portal/v1/devices/:id/timeline",
    { preHandler: [...base, guards.requirePermission("devices.viewOwn")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const { id } = request.params as { id: string };

      const timeline = await inScope(pool, session, "צפייה בציר זמן", async (tx) => {
        const events = await tx.query(
          `SELECT 'event' AS kind, id::text, kind AS name, severity, detail, occurred_at AS at
           FROM events WHERE device_id = $1
           ORDER BY occurred_at DESC LIMIT 50`,
          [id],
        );

        const beats = await tx.query(
          `SELECT 'heartbeat' AS kind, id::text, status AS name, score, received_at AS at
           FROM heartbeats WHERE device_id = $1
           ORDER BY received_at DESC LIMIT 50`,
          [id],
        );

        const commands = await tx.query(
          `SELECT 'command' AS kind, id::text, type::text AS name, status::text AS detail,
                  reason, created_at AS at
           FROM device_commands WHERE device_id = $1
           ORDER BY created_at DESC LIMIT 25`,
          [id],
        );

        return { events: events.rows, heartbeats: beats.rows, commands: commands.rows };
      });

      return reply.send(timeline);
    },
  );

  // ---------------------------------------------------------------- נעילה

  app.post(
    "/api/portal/v1/devices/:id/lockout",
    { preHandler: [...base, guards.requirePermission("devices.lockout")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const { id } = request.params as { id: string };
      const parsed = lockoutBody.safeParse(request.body);

      if (!parsed.success) {
        return reply.code(400).send({
          error: "נדרש משך בין דקה ל-24 שעות, וסיבה",
        });
      }

      const created = await inScope(pool, session, "נעילה יזומה", async (tx) => {
        // אימות קיום בתוך אותו הקשר, כדי ש-RLS יסנן מחשב של דייר אחר
        const owner = await tx.query<{ tenant_id: string }>(
          "SELECT tenant_id FROM devices WHERE id = $1 AND status = 'active'",
          [id],
        );

        if (owner.rows.length === 0) return null;

        // פקודה קודמת שממתינה מבוטלת, כדי שלא יצטברו שתי נעילות
        await tx.query(
          `UPDATE device_commands SET status = 'cancelled'
           WHERE device_id = $1 AND status = 'pending' AND type IN ('lockout', 'release_lockout')`,
          [id],
        );

        const r = await tx.query<{ id: string }>(
          `INSERT INTO device_commands (device_id, tenant_id, type, args, reason, created_by)
           VALUES ($1, $2, 'lockout', $3, $4, $5)
           RETURNING id`,
          [
            id,
            owner.rows[0]!.tenant_id,
            JSON.stringify({ minutes: parsed.data.minutes }),
            parsed.data.reason,
            session.user.userId,
          ],
        );

        return { commandId: r.rows[0]!.id, tenantId: owner.rows[0]!.tenant_id };
      });

      if (!created) return reply.code(404).send({ error: "המחשב לא נמצא" });

      await audit(pool, session, {
        action: "device.lockout.requested",
        targetId: id,
        tenantId: created.tenantId,
        payload: { minutes: parsed.data.minutes, reason: parsed.data.reason },
      });

      return reply.send({
        ok: true,
        commandId: created.commandId,
        // הפקודה תיאסף בפעימה הבאה, לא מיידית
        note: "הפקודה תגיע למחשב בפעימה הבאה, תוך עד שלוש דקות",
      });
    },
  );

  app.post(
    "/api/portal/v1/devices/:id/release",
    { preHandler: [...base, guards.requirePermission("devices.lockout")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const { id } = request.params as { id: string };

      const created = await inScope(pool, session, "שחרור נעילה", async (tx) => {
        const owner = await tx.query<{ tenant_id: string }>(
          "SELECT tenant_id FROM devices WHERE id = $1",
          [id],
        );

        if (owner.rows.length === 0) return null;

        await tx.query(
          `UPDATE device_commands SET status = 'cancelled'
           WHERE device_id = $1 AND status = 'pending' AND type = 'lockout'`,
          [id],
        );

        const r = await tx.query<{ id: string }>(
          `INSERT INTO device_commands (device_id, tenant_id, type, created_by)
           VALUES ($1, $2, 'release_lockout', $3) RETURNING id`,
          [id, owner.rows[0]!.tenant_id, session.user.userId],
        );

        return { commandId: r.rows[0]!.id, tenantId: owner.rows[0]!.tenant_id };
      });

      if (!created) return reply.code(404).send({ error: "המחשב לא נמצא" });

      await audit(pool, session, {
        action: "device.lockout.released",
        targetId: id,
        tenantId: created.tenantId,
      });

      return reply.send({ ok: true, commandId: created.commandId });
    },
  );

  app.post(
    "/api/portal/v1/devices/:id/audit",
    { preHandler: [...base, guards.requirePermission("devices.audit")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const { id } = request.params as { id: string };

      const created = await inScope(pool, session, "בקשת ביקורת", async (tx) => {
        const owner = await tx.query<{ tenant_id: string }>(
          "SELECT tenant_id FROM devices WHERE id = $1",
          [id],
        );

        if (owner.rows.length === 0) return null;

        const r = await tx.query<{ id: string }>(
          `INSERT INTO device_commands (device_id, tenant_id, type, created_by)
           VALUES ($1, $2, 'run_audit', $3) RETURNING id`,
          [id, owner.rows[0]!.tenant_id, session.user.userId],
        );

        return r.rows[0]!.id;
      });

      if (!created) return reply.code(404).send({ error: "המחשב לא נמצא" });

      await audit(pool, session, { action: "device.audit.requested", targetId: id });

      return reply.send({ ok: true, commandId: created });
    },
  );

  // ---------------------------------------------------------------- אסימוני רישום

  /**
   * מפיק קישור הורדה למתקין.
   *
   * מנפיק אסימון חדש בכל פעם ולא מחזיר קיים: האסימון הגולמי נשמר
   * כגיבוב בלבד ואינו ניתן לשחזור, וזה מכוון. קישור ישן שדלף אינו
   * הופך לתקף מחדש רק מפני שמישהו ביקש קישור.
   */
  app.post(
    "/api/portal/v1/installer",
    { preHandler: [...base, guards.requirePermission("enrollTokens.create")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const parsed = installerBody.safeParse(request.body ?? {});

      if (!parsed.success) return reply.code(400).send({ error: "בקשה לא תקינה" });

      const tenantId = session.user.tenantId ?? parsed.data.tenantId;

      if (!tenantId) {
        return reply.code(400).send({ error: "יש לציין דייר עבור ההורדה" });
      }

      const raw = `ENR-${randomBytes(12).toString("hex").toUpperCase()}`;
      const expiresAt = new Date(Date.now() + INSTALLER_LINK_DAYS * 86_400_000);

      const id = await inScope(pool, session, "הפקת קישור הורדה", async (tx) => {
        const r = await tx.query<{ id: string }>(
          `INSERT INTO enroll_tokens
             (tenant_id, token_hash, install_profile, enforcement_mode, policy_floor,
              max_uses, expires_at, created_by)
           VALUES ($1, $2, $3::install_profile, $4::enforcement_mode, $5, $6, $7, $8)
           RETURNING id`,
          [
            tenantId,
            hashEnrollToken(raw),
            parsed.data.installProfile,
            parsed.data.enforcementMode,
            JSON.stringify(DEFAULT_FLOOR),
            parsed.data.maxUses,
            expiresAt,
            session.user.userId,
          ],
        );

        return r.rows[0]!.id;
      });

      await audit(pool, session, {
        action: "installer.linkIssued",
        targetId: id,
        tenantId,
        payload: { profile: parsed.data.installProfile, maxUses: parsed.data.maxUses },
      });

      return reply.send({
        // קישור יחסי: הפורטל והשרת חולקים מקור, ולכן אין צורך
        // שהשרת ידע מהי הכתובת הציבורית שלו.
        fileName: fileNameForToken(raw),
        url: `/d/${fileNameForToken(raw)}`,
        maxUses: parsed.data.maxUses,
        expiresAt: expiresAt.toISOString(),
      });
    },
  );
  app.post(
    "/api/portal/v1/enroll-tokens",
    { preHandler: [...base, guards.requirePermission("enrollTokens.create")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const parsed = enrollTokenBody.safeParse(request.body ?? {});

      if (!parsed.success) return reply.code(400).send({ error: "בקשה לא תקינה" });

      const tenantId = session.user.tenantId
        ?? (request.body as { tenantId?: string } | undefined)?.tenantId;

      if (!tenantId) {
        return reply.code(400).send({ error: "יש לציין דייר עבור אסימון הרישום" });
      }

      // האסימון הגולמי מוצג פעם אחת בלבד ואינו נשמר בשום מקום
      const raw = `ENR-${randomBytes(12).toString("hex").toUpperCase()}`;
      const expiresAt = new Date(Date.now() + parsed.data.expiresInDays * 86_400_000);

      const id = await inScope(pool, session, "יצירת אסימון רישום", async (tx) => {
        const r = await tx.query<{ id: string }>(
          `INSERT INTO enroll_tokens
             (tenant_id, token_hash, install_profile, enforcement_mode, policy_floor,
              max_uses, expires_at, created_by)
           VALUES ($1, $2, $3::install_profile, $4::enforcement_mode, $5, $6, $7, $8)
           RETURNING id`,
          [
            tenantId,
            hashEnrollToken(raw),
            parsed.data.installProfile,
            parsed.data.enforcementMode,
            JSON.stringify(parsed.data.policyFloor),
            parsed.data.maxUses,
            expiresAt,
            session.user.userId,
          ],
        );

        return r.rows[0]!.id;
      });

      await audit(pool, session, {
        action: "enrollToken.created",
        targetId: id,
        tenantId,
        payload: { profile: parsed.data.installProfile, maxUses: parsed.data.maxUses },
      });

      /*
       * הקישור נבנה כאן ולא בפורטל.
       *
       * שם הקובץ הוא מה שקושר את המחשב לחשבון, והתבנית שלו מוגדרת
       * בשרת. בנייתו בצד הלקוח הייתה יוצרת מקור אמת שני שיסטה
       * ביום שהתבנית תשתנה — וזה כבר קרה פעם אחת עם דגל ה-i
       * בביטוי הרגולרי.
       */
      return reply.send({
        id,
        token: raw,
        fileName: fileNameForToken(raw),
        downloadPath: `/d/${fileNameForToken(raw)}`,
        expiresAt: expiresAt.toISOString(),
        maxUses: parsed.data.maxUses,
        warning: "האסימון מוצג פעם אחת בלבד ואינו ניתן לשחזור",
      });
    },
  );


  /**
   * הסרת מחשב מהחשבון.
   *
   * נדרשת לשני דברים: מחשב שיצא משימוש, ומחשב שצריך להירשם מחדש
   * עם רצפה **מקלה** מזו שיש לו. רישום חוזר מרשה רק להחמיר —
   * אחרת קישור התקנה שדלף היה כלי להורדת ההגנה — ולכן הרפיה
   * מחייבת פעולה מאומתת של ההורה, וזו היא.
   *
   * המחשב מסומן ואינו נמחק. ההיסטוריה שלו היא ראיה: מחשב שנעלם
   * מהמאגר בלי עקבות הוא בדיוק מה שמסתיר הסרה לא מורשית.
   *
   * הסימון אינו מסיר את הסוכן מהמחשב. הוא ימשיך לאכוף לפי מה שיש
   * לו עד שיוסר שם — וזה מכוון: השרת אינו יכול לפרק הגנה מרחוק,
   * כי אז מי שמשיג גישה לשרת מפרק את כולן.
   */
  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/devices/:id/retire",
    { preHandler: [...base, guards.requirePermission("enrollTokens.create")] },
    async (request, reply) => {
      const session = request.portal!.session;

      const retired = await inScope(pool, session, "הסרת מחשב", async (tx) => {
        const r = await tx.query<{ machine_name: string | null; hwid: string }>(
          `UPDATE devices SET status = 'uninstalled'
            WHERE id = $1 AND status <> 'uninstalled'
        RETURNING machine_name, hwid`,
          [request.params.id],
        );

        return r.rows[0] ?? null;
      });

      if (retired === null) {
        return reply.code(404).send({ error: "המחשב אינו קיים או שכבר הוסר" });
      }

      await audit(pool, session, {
        action: "device.retired",
        targetId: request.params.id,
        payload: { machineName: retired.machine_name },
      });

      return reply.send({
        ok: true,
        note:
          "המחשב הוסר מהחשבון. התקנה חדשה על אותו מחשב תירשם מחדש "
          + "ותקבל את הרצפה של הקישור החדש.",
      });
    },
  );


  /**
   * הקישורים הפעילים.
   *
   * האסימון עצמו אינו נשמר — רק גיבוב שלו — ולכן אי אפשר להציג
   * אותו שוב. מה שכן מוצג הוא מה שצריך כדי להחליט אם לבטל: מתי
   * נוצר, כמה נוצל, ובאיזו רצפה.
   *
   * הרצפה היא השדה שבאמת חשוב כאן. היא נקבעת ברגע היצירה ונחתמת
   * עם האסימון, ולכן קישור ישן נושא הגדרות ישנות לנצח — ומחשב
   * שנרשם דרכו נתקע בהן. זה נראה בפורטל כי אחרת אין שום דרך לדעת.
   */
  app.get(
    "/api/portal/v1/enroll-tokens",
    { preHandler: [...base, guards.requirePermission("enrollTokens.create")] },
    async (request, reply) => {
      const session = request.portal!.session;

      const tokens = await inScope(pool, session, "צפייה בקישורי התקנה", async (tx) => {
        const r = await tx.query(
          `SELECT id, install_profile, enforcement_mode, policy_floor,
                  uses, max_uses, expires_at, created_at,
                  expires_at <= now() AS expired
             FROM enroll_tokens
            WHERE revoked_at IS NULL
            ORDER BY created_at DESC
            LIMIT 50`,
        );

        return r.rows;
      });

      return reply.send({ tokens });
    },
  );

  /**
   * הנפקת קישור מחדש, באותן הגדרות.
   *
   * הקישור המקורי אינו ניתן לשחזור: האסימון נשמר מגובב בלבד, והגולמי
   * מוצג פעם אחת. זו אינה מגבלה שנשכחה אלא הגנה — מסד שדלף אינו
   * מקנה יכולת לרשום מחשבים לחשבונות של אחרים.
   *
   * אבל ההורה שסגר את החלון צריך קישור, ולא הרצאה. הפעולה הזו יוצרת
   * אסימון חדש עם אותן הגדרות בדיוק — פרופיל, מצב אכיפה, ורצפה —
   * ומבטלת את הישן באותה עסקה.
   *
   * הביטול אינו ויתור אלא היגיינה: שני קישורים חיים לאותה מטרה
   * פירושם שאחד מהם שוכב במקום שאיש אינו זוכר, והוא זה שידלוף.
   *
   * מה שנשמר מהמקורי הוא **הרצפה**, וזה העיקר. קישור חדש עם רצפה
   * מקלה יותר היה מאפשר לרשום מחשב בהגדרות רכות מאלה שההורה קבע.
   */
  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/enroll-tokens/:id/reissue",
    { preHandler: [...base, guards.requirePermission("enrollTokens.create")] },
    async (request, reply) => {
      const session = request.portal!.session;

      const raw = `ENR-${randomBytes(12).toString("hex").toUpperCase()}`;

      const issued = await inScope(pool, session, "הנפקת קישור מחדש", async (tx) => {
        const old = await tx.query<{
          tenant_id: string;
          install_profile: string;
          enforcement_mode: string;
          policy_floor: unknown;
          max_uses: number;
          uses: number;
        }>(
          `SELECT tenant_id, install_profile, enforcement_mode, policy_floor,
                  max_uses, uses
             FROM enroll_tokens
            WHERE id = $1 AND revoked_at IS NULL`,
          [request.params.id],
        );

        const source = old.rows[0];

        if (source === undefined) return null;

        /*
         * מספר השימושים מתחיל מחדש, ובכוונה.
         *
         * ההורה שמנפיק מחדש מתכוון להתקין עכשיו. גרירת המונה הישן
         * הייתה יוצרת קישור שנגמר אחרי התקנה אחת בלי שאיש הבין למה.
         */
        const created = await tx.query<{ id: string; expires_at: Date }>(
          `INSERT INTO enroll_tokens
             (tenant_id, token_hash, install_profile, enforcement_mode, policy_floor,
              max_uses, expires_at, created_by)
           VALUES ($1, $2, $3::install_profile, $4::enforcement_mode, $5, $6,
                   now() + interval '30 days', $7)
           RETURNING id, expires_at`,
          [
            source.tenant_id,
            hashEnrollToken(raw),
            source.install_profile,
            source.enforcement_mode,
            JSON.stringify(source.policy_floor),
            source.max_uses,
            session.user.userId,
          ],
        );

        await tx.query(
          "UPDATE enroll_tokens SET revoked_at = now() WHERE id = $1",
          [request.params.id],
        );

        return { ...created.rows[0]!, replacedUses: source.uses };
      });

      if (issued === null) {
        return reply.code(404).send({ error: "הקישור אינו קיים או שכבר בוטל" });
      }

      await audit(pool, session, {
        action: "enrollToken.reissued",
        targetId: issued.id,
        payload: { replaced: request.params.id, replacedUses: issued.replacedUses },
      });

      return reply.send({
        id: issued.id,
        token: raw,
        fileName: fileNameForToken(raw),
        downloadPath: `/d/${fileNameForToken(raw)}`,
        expiresAt: issued.expires_at.toISOString(),
        note: "הקישור הקודם בוטל. מחשבים שכבר נרשמו דרכו ממשיכים לפעול.",
      });
    },
  );

  /**
   * ביטול קישור.
   *
   * מסומן ואינו נמחק: השורה היא הראיה שהקישור הונפק ומי הנפיק
   * אותו, וזה בדיוק מה שצריך כשמחשב לא מוכר מופיע בחשבון.
   *
   * ביטול אינו נוגע במחשבים שכבר נרשמו דרכו. הם ממשיכים לפעול,
   * וזה מכוון — אחרת ביטול קישור היה מפרק הגנה על מחשבים בשטח.
   */
  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/enroll-tokens/:id/revoke",
    { preHandler: [...base, guards.requirePermission("enrollTokens.create")] },
    async (request, reply) => {
      const session = request.portal!.session;

      const revoked = await inScope(pool, session, "ביטול קישור התקנה", async (tx) => {
        const r = await tx.query<{ uses: number }>(
          `UPDATE enroll_tokens SET revoked_at = now()
            WHERE id = $1 AND revoked_at IS NULL
        RETURNING uses`,
          [request.params.id],
        );

        return r.rows[0] ?? null;
      });

      if (revoked === null) {
        return reply.code(404).send({ error: "הקישור אינו קיים או שכבר בוטל" });
      }

      await audit(pool, session, {
        action: "enrollToken.revoked",
        targetId: request.params.id,
        payload: { uses: revoked.uses },
      });

      return reply.send({
        ok: true,
        note: revoked.uses > 0
          ? `הקישור בוטל. ${revoked.uses} מחשבים שנרשמו דרכו ממשיכים לפעול.`
          : "הקישור בוטל.",
      });
    },
  );

  // ---------------------------------------------------------------- רצפה

  /**
   * הורדת רצפת המדיניות של מחשב.
   *
   * הרצפה נקבעת בהתקנה ונחתמת, והסוכן דוחה כל מדיניות שמקלה ממנה —
   * זו ההגנה החזקה במוצר, כי גם שרת שנפרץ אינו יכול לכבות אכיפה.
   *
   * ההרשאה policy.lowerFloor קיימת מהיום הראשון ולא היה מסלול
   * שמשתמש בה, וכל מנגנון האימות בסוכן היה בנוי ומעולם לא נקרא.
   * הצד הקשה היה גמור, והצינור חסר.
   *
   * ---
   *
   * הקרדיט נצרך לפני ההנפקה.
   *
   * זו ההקלה המשמעותית ביותר שיש — היא מרשה למחשב לרדת מתחת למה
   * שנקבע בהתקנה — ולכן היא הפנייה שהכי ראוי שתעלה משהו.
   */
  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/devices/:id/lower-floor",
    { preHandler: [...base, guards.requirePermission("policy.lowerFloor")] },
    async (request, reply) => {
      const parsed = lowerFloorBody.safeParse(request.body);

      if (!parsed.success) return reply.code(400).send({ error: "רצפה לא תקינה" });

      const session = request.portal!.session;

      const device = await inScope(pool, session, "קריאת רצפת מחשב", async (tx) => {
        const r = await tx.query<{
          hwid: string; tenant_id: string; policy_floor: unknown; machine_name: string | null;
        }>(
          `SELECT hwid, tenant_id, policy_floor, machine_name
             FROM devices WHERE id = $1 AND status <> 'uninstalled'`,
          [request.params.id],
        );

        return r.rows[0] ?? null;
      });

      if (device === null) return reply.code(404).send({ error: "המחשב אינו קיים" });

      /*
       * ההיתר חייב לצאת מהרצפה הנוכחית בדיוק.
       *
       * הסוכן דוחה היתר שמתיימר לרדת מרצפה אחרת — וזו לא קפדנות
       * לשמה: היא מה שמונע מהיתר ישן, שנלכד או נשמר, לחול על מחשב
       * שהרצפה שלו כבר שונתה.
       */
      const from = device.policy_floor as PolicyFloor;
      const reasons = looseningReasons(from, parsed.data.floor);

      /*
       * לפני הקרדיט.
       *
       * הסוכן דוחה היתר שאינו מקל (NotALoosening), ולכן לגבות עליו
       * הוא לגבות על דבר שלא יקרה. החמרה אינה דורשת היתר כלל —
       * מפרסמים מדיניות מחמירה והמחשב מקבל אותה.
       */
      if (reasons.length === 0) {
        return reply.code(400).send({
          error: "הרצפה המבוקשת אינה מקלה בדבר. החמרה אינה דורשת היתר — "
            + "מפרסמים מדיניות מחמירה והמחשב מקבל אותה.",
        });
      }

      if (!parsed.data.waiveCredit) {
        const paid = await spendCredit(
          pool, device.tenant_id, 1, "הורדת רצפת מדיניות");

        if (!paid) {
          return reply.code(402).send({
            error: "אין קרדיט לשינוי. יש לטעון קרדיט או לחייב את הלקוח.",
          });
        }
      }

      const issued = await issueLooseningGrant(pool, looseningSigner, {
        deviceId: request.params.id,
        tenantId: device.tenant_id,
        hwid: device.hwid,
        from: from as never,
        to: parsed.data.floor as never,
        approvedBy: session.user.userId,
        reason: parsed.data.reason,
      });

      await audit(pool, session, {
        action: "device.floorLowered",
        targetId: request.params.id,
        payload: { from, to: parsed.data.floor, reasons, reason: parsed.data.reason ?? null },
      });

      return reply.send({
        ok: true,
        expiresAt: issued.expiresAt.toISOString(),
        reasons,

        /*
         * נאמר במפורש שההיתר עדיין לא הוחל.
         *
         * הוא נמסר בפעימה הבאה והסוכן מאמת אותו בעצמו — כלומר יש
         * רגע שבו המוקד כבר "אישר" והמחשב עוד לא השתנה, ומי שלא
         * יידע את זה יחשוב שהפעולה נכשלה.
         */
        note: "ההיתר הונפק ויימסר למחשב בפעימה הבאה, בדרך כלל תוך שלוש דקות. "
          + "הוא תקף לשעה, והמחשב מאמת אותו בעצמו לפני שהוא מחיל.",
      });
    },
  );

  // ---------------------------------------------------------------- יומנים

  /**
   * בקשת יומן מהמחשב.
   *
   * כשמשהו נשבר אצל לקוח אין דרך לדעת מה קרה: יומן האירועים יושב
   * על המחשב שלו, הוא לא יידע לפתוח אותו, ואנחנו לא נהיה שם. כל
   * אבחון עד היום דרש גישה למכונה, ובשדה לא תהיה כזו.
   *
   * הבקשה נכנסת כפקודה רגילה ומגיעה בפעימה הבאה — כלומר מחשב כבוי
   * או מנותק פשוט יענה כשיחזור, ואין כאן שום ערוץ נוסף שצריך
   * להיות פתוח.
   *
   * בקשה אחת ממתינה בכל רגע. לחיצה חוזרת בזמן שהקודמת לא נענתה
   * מייצרת תור של פקודות זהות, והמחשב היה שולח את אותו יומן שוב
   * ושוב.
   */
  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/devices/:id/logs/request",
    { preHandler: [...base, guards.requirePermission("devices.audit")] },
    async (request, reply) => {
      const session = request.portal!.session;

      const queued = await inScope(pool, session, "בקשת יומן ממחשב", async (tx) => {
        // ה-tenant נלקח מהמחשב, לא מהסשן. תמיכה מתחברת בתפקיד
        // פלטפורמה, ואז session.user.tenantId ריק — וההכנסה נשברה
        // על not-null. זהו בדיוק הזמן שבו צריך את היומן, וזה בדיוק
        // מה שנחסם. שאר הפקודות כאן כבר לוקחות את ה-tenant מהמחשב.
        const owner = await tx.query<{ tenant_id: string }>(
          "SELECT tenant_id FROM devices WHERE id = $1 AND status = 'active'",
          [request.params.id],
        );

        if (owner.rows.length === 0) return { outcome: "missing" as const };

        const pending = await tx.query(
          `SELECT 1 FROM device_commands
            WHERE device_id = $1 AND type = 'collect_logs'
              AND status = 'pending' AND expires_at > now()`,
          [request.params.id],
        );

        if (pending.rowCount) return { outcome: "duplicate" as const };

        const r = await tx.query<{ id: string }>(
          `INSERT INTO device_commands (device_id, tenant_id, type, reason, created_by)
           VALUES ($1, $2, 'collect_logs', $3, $4)
        RETURNING id`,
          [
            request.params.id,
            owner.rows[0]!.tenant_id,
            "בקשת תמיכה",
            session.user.userId,
          ],
        );

        return { outcome: "queued" as const, id: r.rows[0]!.id };
      });

      if (queued.outcome === "missing") {
        return reply.code(404).send({ error: "המחשב לא נמצא" });
      }

      if (queued.outcome === "duplicate") {
        return reply.code(409).send({ error: "כבר יש בקשת יומן שממתינה למחשב הזה" });
      }

      await audit(pool, session, { action: "device.logs.requested", targetId: request.params.id });

      return reply.send({
        ok: true,
        note: "הבקשה נשלחה. היומן יגיע בפעימה הבאה, בדרך כלל תוך שלוש דקות.",
      });
    },
  );

  /** מה הגיע. בלי התוכן — רק מתי, כמה, ומאיזו גרסה. */
  app.get<{ Params: { id: string } }>(
    "/api/portal/v1/devices/:id/logs",
    { preHandler: [...base, guards.requirePermission("devices.viewOwn")] },
    async (request, reply) => {
      const session = request.portal!.session;

      const rows = await inScope(pool, session, "רשימת יומנים", async (tx) => {
        const r = await tx.query(
          `SELECT id, agent_version, byte_length, collected_at, received_at, expires_at
             FROM device_logs WHERE device_id = $1
            ORDER BY received_at DESC LIMIT 20`,
          [request.params.id],
        );

        return r.rows;
      });

      return reply.send({ logs: rows });
    },
  );

  /**
   * הורדת יומן.
   *
   * נשלח דחוס כפי שהתקבל, בלי לפרוס בשרת: פריסה הייתה מכניסה
   * לזיכרון תוכן שגודלו נקבע על ידי המחשב ששלח, וזה הצד שאין לנו
   * שליטה עליו.
   */
  app.get<{ Params: { id: string; logId: string } }>(
    "/api/portal/v1/devices/:id/logs/:logId",
    { preHandler: [...base, guards.requirePermission("devices.audit")] },
    async (request, reply) => {
      const session = request.portal!.session;

      const row = await inScope(pool, session, "הורדת יומן", async (tx) => {
        const r = await tx.query<{ body: Buffer; collected_at: Date }>(
          "SELECT body, collected_at FROM device_logs WHERE id = $1 AND device_id = $2",
          [request.params.logId, request.params.id],
        );

        return r.rows[0] ?? null;
      });

      if (row === null) return reply.code(404).send({ error: "היומן אינו קיים" });

      const stamp = row.collected_at.toISOString().replace(/[:.]/g, "-").slice(0, 19);

      return reply
        .header("Content-Type", "application/gzip")
        .header("Content-Disposition", `attachment; filename="safeme-${stamp}.log.gz"`)
        .send(row.body);
    },
  );

  // ---------------------------------------------------------------- התראות

  app.get(
    "/api/portal/v1/alerts",
    { preHandler: [...base, guards.requirePermission("devices.viewOwn")] },
    async (request, reply) => {
      const session = request.portal!.session;

      const alerts = await inScope(pool, session, "צפייה בהתראות", async (tx) => {
        const r = await tx.query(
          `SELECT a.id, a.kind, a.state, a.first_seen_at, a.notify_count,
                  d.display_name, d.hwid
           FROM alerts a
           JOIN devices d ON d.id = a.device_id
           WHERE a.state <> 'resolved'
           ORDER BY a.first_seen_at DESC LIMIT 100`,
        );

        return r.rows;
      });

      return reply.send({ alerts, count: alerts.length });
    },
  );

  // ---------------------------------------------------------------- סיכום

  app.get(
    "/api/portal/v1/summary",
    { preHandler: [...base, guards.requirePermission("devices.viewOwn")] },
    async (request, reply) => {
      const session = request.portal!.session;

      const summary = await inScope(pool, session, "סיכום", async (tx) => {
        const r = await tx.query<{
          total: string;
          safe: string;
          low: string;
          unfiltered: string;
          blocked: string;
          whitelist: string;
          offline: string;
        }>(
          `SELECT
             count(*) AS total,
             count(*) FILTER (WHERE s.last_status = 'safe') AS safe,
             count(*) FILTER (WHERE s.last_status = 'low_filter') AS low,
             count(*) FILTER (WHERE s.last_status = 'unfiltered') AS unfiltered,
             count(*) FILTER (WHERE s.last_status = 'blocked') AS blocked,
             count(*) FILTER (WHERE s.last_status = 'whitelist') AS whitelist,
             count(*) FILTER (WHERE s.health IN ('missing','offline')) AS offline
           FROM devices d
           LEFT JOIN device_state s ON s.device_id = d.id
           WHERE d.status <> 'uninstalled'`,
        );

        return r.rows[0]!;
      });

      return reply.send({
        total: Number(summary.total),
        safe: Number(summary.safe),
        lowFilter: Number(summary.low),
        unfiltered: Number(summary.unfiltered),
        blocked: Number(summary.blocked),
        /*
         * נספר בנפרד, לא בתוך "מוגנים" ולא בתוך "לא מסוננים".
         *
         * מחשב ברשימה לבנה מוגן, אבל בדרך אחרת מספק סינון — והורה
         * שסופר את המחשבים שלו צריך שהמספרים יסתכמו לסך הכול.
         */
        whitelist: Number(summary.whitelist),
        offline: Number(summary.offline),
      });
    },
  );
}

/** משמש את הבדיקות כדי לחשב hash של אסימון בלי לייבא את המסלול. */
export function enrollTokenHash(raw: string): Buffer {
  return createHash("sha256").update(raw.trim().toUpperCase(), "utf8").digest();
}
