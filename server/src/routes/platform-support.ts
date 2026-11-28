import { createHash, randomBytes } from "node:crypto";

import type { FastifyInstance } from "fastify";
import type pg from "pg";
import { z } from "zod";

import { createGuards } from "../auth/guards.ts";
import type { Config } from "../config.ts";
import { withPlatform } from "../db/client.ts";
import { passwordResetMessage, type Mailer } from "../notify/mailer.ts";

/**
 * כרטיס לקוח ופעולות תמיכה, לפורטל הניהול.
 *
 * עד כאן המוקד ראה כל לקוח כשורה אחת בטבלה. כשלקוח מתקשר, השאלה
 * הראשונה היא "מה המצב אצלו": אילו מחשבים, מי המשתמשים, מה קרה
 * לאחרונה. הכרטיס עונה על זה במסך אחד.
 *
 * הפעולות מחולקות לפי הנזק שהן יכולות לגרום, ולא לפי נוחות:
 *
 *   שליחת קישור איפוס סיסמה פתוחה לכל הצוות. הקישור נשלח לכתובת
 *   של המשתמש עצמו, ואיש בצוות אינו רואה אותו.
 *
 *   ביטול אימות דו-שלבי, שחרור בקשה שממתינה לנאמן והסרת נאמן הן
 *   הקלות של ממש, ולכן הן למנהל מערכת בלבד, מחייבות סיבה כתובה,
 *   ונרשמות ביומן.
 */

interface Deps {
  pool: pg.Pool;
  config: Config;
  mailer: Mailer;
}

const reasonBody = z.object({
  reason: z.string().trim().min(5, "יש לכתוב סיבה, לפחות כמה מילים").max(300),
});

function tokenHash(raw: string): Buffer {
  return createHash("sha256").update(raw, "utf8").digest();
}

function missingTable(error: unknown): boolean {
  return (error as { code?: string }).code === "42P01";
}

const uuid = z.string().uuid();

export async function registerPlatformSupportRoutes(app: FastifyInstance, deps: Deps): Promise<void> {
  const { pool, config, mailer } = deps;
  const guards = createGuards(pool, config);

  const view = [
    guards.requireSession,
    guards.requirePlatformMfa,
    guards.requirePermission("tenants.viewAll"),
  ];

  const manage = [
    guards.requireSession,
    guards.requirePlatformMfa,
    guards.requirePermission("licenses.manage"),
  ];

  // ---------------------------------------------------------------- כרטיס לקוח

  app.get<{ Params: { id: string } }>(
    "/api/portal/v1/platform/tenants/:id/card",
    { preHandler: view },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = request.params.id;

      if (!uuid.safeParse(tenantId).success) return reply.code(404).send({ error: "הלקוח אינו קיים" });

      const actor = { userId: session.user.userId, reason: "כרטיס לקוח" };

      const card = await withPlatform(pool, actor, async (tx) => {
        const tenant = await tx.query(
          `SELECT id, name, type::text AS type, status::text AS status, plan::text AS plan,
                  contact_email, created_at, trial_ends_at, paid_until,
                  network_policy::text AS network_policy,
                  network_policy_floor::text AS network_policy_floor,
                  uninstall_policy::text AS uninstall_policy,
                  (SELECT COALESCE(sum(c.amount), 0)
                     FROM credit_entries c WHERE c.tenant_id = tenants.id)::int AS credit
             FROM tenants WHERE id = $1`,
          [tenantId],
        );

        if (!tenant.rows[0]) return null;

        const users = await tx.query(
          `SELECT id, email::text AS email, display_name, role::text AS role,
                  status::text AS status, mfa_enrolled_at, last_login_at, created_at,
                  google_sub IS NOT NULL AS google
             FROM users WHERE tenant_id = $1 ORDER BY created_at`,
          [tenantId],
        );

        const devices = await tx.query(
          `SELECT d.id, d.display_name, d.machine_name, d.status::text AS status,
                  d.agent_version, d.os_version, d.enrolled_at, g.name AS group_name,
                  s.last_seen_at, s.last_status::text AS last_status, s.detected_provider,
                  s.health::text AS health, s.lockout_active
             FROM devices d
             LEFT JOIN device_groups g ON g.id = d.group_id
             LEFT JOIN device_state s ON s.device_id = d.id
            WHERE d.tenant_id = $1
            ORDER BY (d.status = 'uninstalled'), d.enrolled_at DESC`,
          [tenantId],
        );

        const audit = await tx.query(
          `SELECT a.at, a.actor_type::text AS actor_type, a.action, a.payload,
                  u.email::text AS actor_email
             FROM audit_log a
             LEFT JOIN users u ON u.id = a.actor_id
            WHERE a.tenant_id = $1
            ORDER BY a.at DESC LIMIT 60`,
          [tenantId],
        );

        return { tenant: tenant.rows[0], users: users.rows, devices: devices.rows, audit: audit.rows };
      });

      if (card === null) return reply.code(404).send({ error: "הלקוח אינו קיים" });

      /*
       * הנאמנים בטרנזקציה משלהם.
       *
       * הטבלאות שלהם נוספו במיגרציה מאוחרת, ושאילתה שנכשלת מבטלת
       * את כל הטרנזקציה שסביבה. כרטיס לקוח אינו אמור להיעלם רק
       * כי המיגרציה הזו עוד לא רצה.
       */
      let trustees: unknown = { mode: null, list: [], requests: [] };

      try {
        trustees = await withPlatform(pool, actor, async (tx) => {
          const mode = await tx.query<{ mode: string }>(
            "SELECT mode FROM trustee_settings WHERE tenant_id = $1", [tenantId]);

          const list = await tx.query(
            `SELECT id, name, email, verified_at, removal_effective_at, created_at
               FROM trustees WHERE tenant_id = $1 ORDER BY created_at`,
            [tenantId],
          );

          const requests = await tx.query(
            `SELECT r.id, r.summary, r.status, r.created_at, r.decided_at, t.name AS decided_by
               FROM trustee_requests r
               LEFT JOIN trustees t ON t.id = r.decided_by
              WHERE r.tenant_id = $1
              ORDER BY r.created_at DESC LIMIT 30`,
            [tenantId],
          );

          return { mode: mode.rows[0]?.mode ?? "approve", list: list.rows, requests: requests.rows };
        });
      } catch (error) {
        if (!missingTable(error)) throw error;
      }

      return reply.send({ ...card, trustees });
    },
  );

  // ---------------------------------------------------------------- איפוס סיסמה

  /**
   * שולח למשתמש קישור לאיפוס סיסמה.
   *
   * אותו קישור שהמשתמש מקבל כשהוא לוחץ "שכחתי סיסמה". הצוות אינו
   * קובע סיסמה ואינו רואה את הקישור: הוא רק גורם לו להישלח.
   */
  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/platform/users/:id/send-reset",
    { preHandler: view },
    async (request, reply) => {
      const session = request.portal!.session;

      if (!uuid.safeParse(request.params.id).success) {
        return reply.code(404).send({ error: "המשתמש אינו קיים" });
      }

      const raw = randomBytes(32).toString("base64url");

      const user = await withPlatform(
        pool,
        { userId: session.user.userId, reason: "שליחת קישור איפוס ללקוח" },
        async (tx) => {
          const r = await tx.query<{ id: string; email: string; status: string; tenant_id: string | null }>(
            `SELECT id, email::text AS email, status::text AS status, tenant_id
               FROM users WHERE id = $1 AND tenant_id IS NOT NULL`,
            [request.params.id],
          );

          const found = r.rows[0];

          if (!found) return null;
          if (found.status !== "active" && found.status !== "invited") return { ...found, blocked: true };

          await tx.query(
            "UPDATE password_resets SET used_at = now() WHERE user_id = $1 AND used_at IS NULL",
            [found.id],
          );

          await tx.query(
            "INSERT INTO password_resets (user_id, token_hash, requested_ip) VALUES ($1, $2, $3)",
            [found.id, tokenHash(raw), request.ip],
          );

          await tx.query(
            `INSERT INTO audit_log (actor_type, actor_id, actor_ip, action, tenant_id, payload)
             VALUES ('platform_user', $1, $2::inet, 'support.password_reset_sent', $3, $4)`,
            [session.user.userId, request.ip, found.tenant_id, JSON.stringify({ user: found.email })],
          );

          return { ...found, blocked: false };
        },
      );

      if (user === null) return reply.code(404).send({ error: "המשתמש אינו קיים" });

      if (user.blocked) {
        return reply.code(409).send({ error: "החשבון מושעה או סגור, ולכן אינו יכול לאפס סיסמה." });
      }

      try {
        await mailer.send(passwordResetMessage({
          to: user.email,
          resetUrl: `${config.PORTAL_URL.replace(/\/+$/, "")}/reset?token=${raw}`,
          minutes: 60,
        }));
      } catch (error) {
        request.log.error({ err: error }, "שליחת קישור איפוס מטעם התמיכה נכשלה.");

        return reply.code(502).send({ error: "שליחת הדוא\"ל נכשלה. כדאי לבדוק את הגדרות הדואר היוצא." });
      }

      return reply.send({ ok: true, note: `נשלח קישור איפוס אל ${user.email}. הוא תקף לשעה.` });
    },
  );

  // ---------------------------------------------------------------- ביטול אימות דו-שלבי

  /**
   * מבטל אימות דו-שלבי של לקוח שאיבד את הטלפון.
   *
   * זו ההקלה המסוכנת ביותר שהמוקד יכול לבצע: היא מסירה את מה שמגן
   * על החשבון מפני מי שהשיג את הסיסמה. לכן היא למנהל מערכת בלבד,
   * מחייבת סיבה, ומנתקת את כל ההפעלות הפתוחות של המשתמש.
   */
  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/platform/users/:id/reset-mfa",
    { preHandler: manage },
    async (request, reply) => {
      const session = request.portal!.session;
      const parsed = reasonBody.safeParse(request.body);

      if (!parsed.success) {
        return reply.code(400).send({ error: parsed.error.issues[0]?.message ?? "חסרה סיבה" });
      }

      if (!uuid.safeParse(request.params.id).success) {
        return reply.code(404).send({ error: "המשתמש אינו קיים" });
      }

      const done = await withPlatform(
        pool,
        { userId: session.user.userId, reason: "ביטול אימות דו-שלבי ללקוח" },
        async (tx) => {
          // רק משתמשי לקוח. אימות דו-שלבי של צוות הוא חובה ואינו מתבטל מכאן.
          const r = await tx.query<{ email: string; tenant_id: string }>(
            `UPDATE users SET mfa_secret = NULL, mfa_enrolled_at = NULL
              WHERE id = $1 AND tenant_id IS NOT NULL
          RETURNING email::text AS email, tenant_id`,
            [request.params.id],
          );

          if (!r.rows[0]) return null;

          await tx.query(
            "UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
            [request.params.id],
          );

          await tx.query(
            `INSERT INTO audit_log (actor_type, actor_id, actor_ip, action, tenant_id, payload)
             VALUES ('platform_user', $1, $2::inet, 'support.mfa_reset', $3, $4)`,
            [session.user.userId, request.ip, r.rows[0].tenant_id,
              JSON.stringify({ user: r.rows[0].email, reason: parsed.data.reason })],
          );

          return r.rows[0];
        },
      );

      if (done === null) return reply.code(404).send({ error: "המשתמש אינו קיים" });

      return reply.send({
        ok: true,
        note: `האימות הדו-שלבי של ${done.email} בוטל, וכל ההפעלות שלו נותקו. הוא ייכנס עם סיסמה בלבד.`,
      });
    },
  );

  // ---------------------------------------------------------------- נאמנים

  /**
   * משחרר בקשה שממתינה לנאמן שאינו עונה.
   *
   * בקשות לנאמן אינן פוקעות, וזו ההחלטה: מי שמחכה אינו עוקף את
   * הנאמן. המוצא היחיד הוא המוקד, והוא עושה כאן את מה שהנאמן היה
   * עושה: מאשר את הפעולה האחת הזו. בעל החשבון עדיין צריך לבצע
   * אותה בעצמו.
   */
  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/platform/trustee-requests/:id/release",
    { preHandler: manage },
    async (request, reply) => {
      const session = request.portal!.session;
      const parsed = reasonBody.safeParse(request.body);

      if (!parsed.success) {
        return reply.code(400).send({ error: parsed.error.issues[0]?.message ?? "חסרה סיבה" });
      }

      if (!uuid.safeParse(request.params.id).success) {
        return reply.code(404).send({ error: "הבקשה אינה קיימת" });
      }

      const done = await withPlatform(
        pool,
        { userId: session.user.userId, reason: "שחרור בקשה לנאמן" },
        async (tx) => {
          const r = await tx.query<{ tenant_id: string; summary: string }>(
            `UPDATE trustee_requests
                SET status = 'approved', decided_at = now(), decide_hash = NULL
              WHERE id = $1 AND status = 'pending'
          RETURNING tenant_id, summary`,
            [request.params.id],
          );

          if (!r.rows[0]) return null;

          await tx.query(
            `INSERT INTO audit_log (actor_type, actor_id, actor_ip, action, tenant_id, payload)
             VALUES ('platform_user', $1, $2::inet, 'support.trustee_request_released', $3, $4)`,
            [session.user.userId, request.ip, r.rows[0].tenant_id,
              JSON.stringify({ summary: r.rows[0].summary, reason: parsed.data.reason })],
          );

          return r.rows[0];
        },
      );

      if (done === null) return reply.code(404).send({ error: "אין בקשה ממתינה כזו" });

      return reply.send({
        ok: true,
        note: "הבקשה אושרה מטעם המוקד. בעל החשבון יכול לבצע אותה עכשיו, פעם אחת.",
      });
    },
  );

  /** מסיר נאמן מיד, בלי שבעת הימים. למקרה שהנאמן נעלם או שמונה בטעות. */
  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/platform/trustees/:id/remove",
    { preHandler: manage },
    async (request, reply) => {
      const session = request.portal!.session;
      const parsed = reasonBody.safeParse(request.body);

      if (!parsed.success) {
        return reply.code(400).send({ error: parsed.error.issues[0]?.message ?? "חסרה סיבה" });
      }

      if (!uuid.safeParse(request.params.id).success) {
        return reply.code(404).send({ error: "הנאמן אינו קיים" });
      }

      const done = await withPlatform(
        pool,
        { userId: session.user.userId, reason: "הסרת נאמן מטעם המוקד" },
        async (tx) => {
          const r = await tx.query<{ tenant_id: string; name: string; email: string }>(
            "DELETE FROM trustees WHERE id = $1 RETURNING tenant_id, name, email",
            [request.params.id],
          );

          if (!r.rows[0]) return null;

          await tx.query(
            `INSERT INTO audit_log (actor_type, actor_id, actor_ip, action, tenant_id, payload)
             VALUES ('platform_user', $1, $2::inet, 'support.trustee_removed', $3, $4)`,
            [session.user.userId, request.ip, r.rows[0].tenant_id,
              JSON.stringify({ trustee: r.rows[0].email, reason: parsed.data.reason })],
          );

          return r.rows[0];
        },
      );

      if (done === null) return reply.code(404).send({ error: "הנאמן אינו קיים" });

      return reply.send({ ok: true, note: `${done.name} הוסר מתפקיד הנאמן.` });
    },
  );
}
