import type { FastifyInstance } from "fastify";
import type pg from "pg";
import { z } from "zod";

import { withPlatform } from "../db/client.ts";
import { createGuards } from "../auth/guards.ts";
import type { Config } from "../config.ts";

/**
 * מסך הלקוחות של מנהל הפלטפורמה.
 *
 * עד כה היה אפשר לראות מחשבים ולא לקוחות. עם צי של אלפי התקנות זו
 * לא נוחות אלא עיוורון: אין דרך לדעת כמה לקוחות יש, מי מהם ננטש,
 * ואצל מי כל המחשבים הפסיקו לדווח — וזה בדיוק הלקוח שעומד לעזוב.
 *
 * ---
 *
 * הרשאת פלטפורמה בלבד, ובנוסף אימות דו-שלבי. הנתונים כאן חוצים
 * דיירים, ולכן הם המקום היחיד במערכת שבו בקשה אחת רואה את הכול.
 * withPlatform ולא withTenant, וזו בדיוק הסיבה שהוא מוגבל כך.
 */

// ---------------------------------------------------------------- טיפוסים

interface TenantRow {
  id: string;
  name: string;
  type: string;
  status: string;
  plan: string;
  contact_email: string | null;
  created_at: Date;
  trial_ends_at: Date | null;
  devices: string;
  reporting: string;
  silent: string;
  never_reported: string;
  last_seen_at: Date | null;
}

const statusBody = z.object({
  status: z.enum(["active", "suspended"]),
  reason: z.string().trim().max(200).optional(),
});

const trialBody = z.object({
  days: z.number().int().min(1).max(365),
});

// ---------------------------------------------------------------- מסלולים

export async function registerPlatformTenantRoutes(
  app: FastifyInstance,
  deps: { pool: pg.Pool; config: Config },
): Promise<void> {
  const { pool, config } = deps;
  const guards = createGuards(pool, config);

  const base = [
    guards.requireSession,
    guards.requirePlatformMfa,
    guards.requirePermission("tenants.viewAll"),
  ];

  const manage = [
    guards.requireSession,
    guards.requirePlatformMfa,
    guards.requirePermission("licenses.manage"),
  ];

  /**
   * רשימת הלקוחות, עם ספירת מחשבים ומצב דיווח לכל אחד.
   *
   * הסיכום מגיע באותה תשובה ולא בקריאה נפרדת, כדי ששני המספרים
   * ייגזרו מאותו רגע. סיכום שנקרא בנפרד מהרשימה מציג "12 לקוחות"
   * מעל טבלה של 11, ואז איש אינו יודע במי לבטוח.
   */
  app.get("/api/portal/v1/platform/tenants", { preHandler: base }, async (_request, reply) => {
    const rows = await withPlatform(
      pool,
      { userId: _request.portal!.session.user.userId, reason: "מסך לקוחות" },
      async (tx) => {
      const r = await tx.query<TenantRow>(
        `SELECT t.id,
                t.name,
                t.type::text            AS type,
                t.status::text          AS status,
                t.plan::text            AS plan,
                t.contact_email,
                t.created_at,
                t.trial_ends_at,

                /*
                 * מחשבים שהוסרו אינם נספרים.
                 *
                 * לקוח שהסיר את כל המחשבים שלו הוא לקוח עם אפס
                 * מחשבים, ולא לקוח עם חמישה. ספירה שכוללת אותם
                 * מסתירה בדיוק את הנטישה שהמסך הזה נועד להראות.
                 */
                count(d.id) FILTER (WHERE d.status <> 'uninstalled')::text AS devices,

                count(d.id) FILTER (
                  WHERE d.status <> 'uninstalled'
                    AND s.last_seen_at > now() - interval '30 minutes'
                )::text AS reporting,

                count(d.id) FILTER (
                  WHERE d.status <> 'uninstalled'
                    AND s.last_seen_at IS NOT NULL
                    AND s.last_seen_at <= now() - interval '30 minutes'
                )::text AS silent,

                /*
                 * מחשב שנרשם ומעולם לא דיווח הוא סוג כשל אחר לגמרי
                 * ממחשב ששתק. הראשון הוא התקנה שלא עלתה, השני הוא
                 * מחשב שכובה או נותק — ומי שרואה מספר אחד לשניהם
                 * לא ידע במה לטפל.
                 */
                count(d.id) FILTER (
                  WHERE d.status <> 'uninstalled' AND s.last_seen_at IS NULL
                )::text AS never_reported,

                max(s.last_seen_at) AS last_seen_at

           FROM tenants t
           LEFT JOIN devices d      ON d.tenant_id = t.id
           LEFT JOIN device_state s ON s.device_id = d.id
          GROUP BY t.id
          ORDER BY t.created_at DESC`,
      );

        return r.rows;
      },
    );

    const tenants = rows.map((t) => ({
      id: t.id,
      name: t.name,
      type: t.type,
      status: t.status,
      plan: t.plan,
      contactEmail: t.contact_email,
      createdAt: t.created_at.toISOString(),
      trialEndsAt: t.trial_ends_at?.toISOString() ?? null,
      devices: Number(t.devices),
      reporting: Number(t.reporting),
      silent: Number(t.silent),
      neverReported: Number(t.never_reported),
      lastSeenAt: t.last_seen_at?.toISOString() ?? null,
    }));

    return reply.send({
      tenants,
      summary: {
        tenants: tenants.length,
        active: tenants.filter((t) => t.status === "active").length,
        suspended: tenants.filter((t) => t.status === "suspended").length,
        devices: tenants.reduce((n, t) => n + t.devices, 0),
        reporting: tenants.reduce((n, t) => n + t.reporting, 0),
        silent: tenants.reduce((n, t) => n + t.silent, 0),
        neverReported: tenants.reduce((n, t) => n + t.neverReported, 0),

        /*
         * לקוחות שאין להם ולו מחשב אחד שמדווח.
         *
         * המספר הזה הוא התמונה העסקית האמיתית: לקוח שהתקין ולא
         * חזר, או שכל המחשבים שלו הוסרו. הוא נבלע לגמרי בסכום של
         * "כמה מחשבים מדווחים", כי לקוח אחד גדול מכסה על עשרה
         * נטושים.
         */
        withoutReporting: tenants.filter(
          (t) => t.status === "active" && t.reporting === 0,
        ).length,
      },
    });
  });

  /**
   * השעיה והחזרה לפעולה.
   *
   * מה שהיא עושה: חוסמת כניסה לפורטל ורישום מחשבים חדשים.
   *
   * מה שהיא **אינה** עושה: אינה מפרקת הגנה על מחשב קיים. אלה
   * ימשיכו לאכוף לפי המדיניות שיש להם, וזה מכוון — שרת שיכול לכבות
   * הגנה מרחוק הופך כל פריצה לשרת לכיבוי כל הצי בבת אחת.
   *
   * ההבחנה הזו חייבת להיות ברורה גם במסך, אחרת מי שמשעה לקוח
   * שלא שילם יחשוב שהוא הפסיק להגן עליו.
   */
  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/platform/tenants/:id/status",
    { preHandler: manage },
    async (request, reply) => {
      const parsed = statusBody.safeParse(request.body);

      if (!parsed.success) {
        return reply.code(400).send({ error: "מצב חייב להיות active או suspended" });
      }

      const session = request.portal!.session;

      const updated = await withPlatform(
        pool,
        { userId: session.user.userId, reason: "השעיית לקוח" },
        async (tx) => {
        const r = await tx.query<{ name: string; status: string }>(
          `UPDATE tenants SET status = $2::tenant_status, updated_at = now()
            WHERE id = $1 AND status <> 'closed'
        RETURNING name, status::text AS status`,
          [request.params.id, parsed.data.status],
        );

        if (r.rows[0]) {
          await tx.query(
            `INSERT INTO audit_log
               (actor_type, actor_id, action, target_type, target_id, tenant_id, payload)
             VALUES ('platform_user', $1, $2, 'tenant', $3, $3, $4)`,
            [
              session.user.userId,
              parsed.data.status === "suspended" ? "tenant.suspended" : "tenant.reactivated",
              request.params.id,
              JSON.stringify({ reason: parsed.data.reason ?? null }),
            ],
          );
        }

        return r.rows[0] ?? null;
        },
      );

      if (updated === null) {
        return reply.code(404).send({ error: "הלקוח אינו קיים או שסגור" });
      }

      return reply.send({
        status: updated.status,
        note:
          updated.status === "suspended"
            ? `${updated.name} הושעה. מחשבים קיימים ממשיכים להגן; לא ניתן לרשום חדשים או להיכנס לפורטל.`
            : `${updated.name} הוחזר לפעולה.`,
      });
    },
  );

  /**
   * הארכת תקופת ניסיון.
   *
   * מהיום ולא מסוף התקופה הקודמת: לקוח שפנה אחרי שהניסיון פג מקבל
   * את מלוא הימים שסוכמו איתו, ולא שארית של חלון שכבר עבר.
   */
  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/platform/tenants/:id/trial",
    { preHandler: manage },
    async (request, reply) => {
      const parsed = trialBody.safeParse(request.body);

      if (!parsed.success) {
        return reply.code(400).send({ error: "מספר הימים חייב להיות בין 1 ל-365" });
      }

      const session = request.portal!.session;

      const updated = await withPlatform(
        pool,
        { userId: session.user.userId, reason: "הארכת ניסיון" },
        async (tx) => {
        const r = await tx.query<{ name: string; trial_ends_at: Date | null }>(
          `UPDATE tenants
              SET plan          = 'trial',
                  trial_ends_at = GREATEST(COALESCE(trial_ends_at, now()), now())
                                  + make_interval(days => $2::int),
                  updated_at    = now()
            WHERE id = $1
        RETURNING name, trial_ends_at`,
          [request.params.id, parsed.data.days],
        );

        if (r.rows[0]) {
          await tx.query(
            `INSERT INTO audit_log
               (actor_type, actor_id, action, target_type, target_id, tenant_id, payload)
             VALUES ('platform_user', $1, 'tenant.trialExtended', 'tenant', $2, $2, $3)`,
            [session.user.userId, request.params.id, JSON.stringify({ days: parsed.data.days })],
          );
        }

        return r.rows[0] ?? null;
        },
      );

      if (updated === null) return reply.code(404).send({ error: "הלקוח אינו קיים" });

      return reply.send({
        trialEndsAt: updated.trial_ends_at?.toISOString() ?? null,
        note: `הניסיון של ${updated.name} הוארך ב-${parsed.data.days} ימים.`,
      });
    },
  );
}
