import type { FastifyInstance } from "fastify";
import type pg from "pg";
import { z } from "zod";

import { withPlatform } from "../db/client.ts";
import { createGuards } from "../auth/guards.ts";
import type { Config } from "../config.ts";
import { creditBalance, grantCredit, spendCredit } from "../billing/entitlements.ts";

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
  paid_until: Date | null;
  network_policy_floor: string;
  devices: string;
  reporting: string;
  silent: string;
  never_reported: string;
  last_seen_at: Date | null;
  credit: number;
}

const statusBody = z.object({
  status: z.enum(["active", "suspended"]),
  reason: z.string().trim().max(200).optional(),
});

const floorBody = z.object({
  floor: z.enum(["strict", "balanced", "lenient"]),

  /*
   * ויתור על הקרדיט, להחלטת המוקד.
   *
   * לפעמים השינוי נובע מטעות שלנו, ולגבות עליו קרדיט זה להעניש
   * לקוח על משהו שלא עשה.
   */
  waiveCredit: z.boolean().optional(),
});

const creditBody = z.object({
  amount: z.number().int().min(1).max(1000),
  reason: z.string().trim().max(120).optional(),
});

const paidBody = z.object({
  days: z.number().int().min(1).max(1095),

  /*
   * סכום ואמצעי, לתיעוד בלבד.
   *
   * לא חובה, כי מי שמסמן ידנית לא תמיד יודע את שניהם באותו רגע —
   * ושדה חובה שאין לו ערך אמיתי מתמלא בזבל.
   */
  amount: z.number().min(0).max(1_000_000).optional(),
  method: z.string().trim().max(40).optional(),
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
                t.paid_until,
                t.network_policy_floor::text AS network_policy_floor,

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

                max(s.last_seen_at) AS last_seen_at,

                /*
                 * יתרת הקרדיט, כסכום הספר.
                 *
                 * בתת-שאילתה ולא ב-JOIN: צירוף לטבלת התנועות היה
                 * מכפיל את שורות המחשבים וכל הספירות למעלה היו
                 * יוצאות שגויות.
                 */
                (SELECT COALESCE(sum(c.amount), 0)
                   FROM credit_entries c WHERE c.tenant_id = t.id)::int AS credit

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
      paidUntil: t.paid_until?.toISOString() ?? null,
      networkFloor: t.network_policy_floor,
      devices: Number(t.devices),
      reporting: Number(t.reporting),
      silent: Number(t.silent),
      neverReported: Number(t.never_reported),
      lastSeenAt: t.last_seen_at?.toISOString() ?? null,
      credit: t.credit,
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
   * סימון לקוח כמשלם, ידנית.
   *
   * גבייה ידנית היא הדרך הנכונה לעשרות הלקוחות הראשונים: אינטגרציית
   * סליקה עולה זמן וכסף קבוע, והיא לא תלמד דבר שאי אפשר ללמוד
   * מעשרה לקוחות ומהעברה בנקאית.
   *
   * מה שנשמר כאן הוא רק התאריך שעד אליו שולם. מי שילם, איך, וכמה —
   * זה נשאר אצלך עד שתהיה סליקה, ואין טעם לבנות חצי מערכת חשבונאית
   * שתידרס.
   *
   * הסכום נרשם ביומן הביקורת ולא בטבלת התשלומים: זו אינה עסקה
   * שנסלקה, וטבלת התשלומים אמורה לשקף מה באמת נגבה מכרטיס.
   */
  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/platform/tenants/:id/paid",
    { preHandler: manage },
    async (request, reply) => {
      const parsed = paidBody.safeParse(request.body);

      if (!parsed.success) {
        return reply.code(400).send({ error: "מספר הימים חייב להיות בין 1 ל-1095" });
      }

      const session = request.portal!.session;

      const updated = await withPlatform(
        pool,
        { userId: session.user.userId, reason: "סימון תשלום ידני" },
        async (tx) => {
          const r = await tx.query<{ name: string; paid_until: Date | null }>(
            /*
             * מהמאוחר מבין השניים.
             *
             * לקוח שמחדש לפני שפג מקבל את הימים בנוסף למה שנשאר;
             * לקוח שחזר אחרי שפג מקבל אותם מהיום. חישוב מ-now בלבד
             * היה גוזל ימים ממי שהקדים.
             */
            `UPDATE tenants
                SET plan       = 'paid',
                    paid_until = GREATEST(COALESCE(paid_until, now()), now())
                                 + make_interval(days => $2::int),
                    updated_at = now()
              WHERE id = $1
          RETURNING name, paid_until`,
            [request.params.id, parsed.data.days],
          );

          if (r.rows[0]) {
            await tx.query(
              `INSERT INTO audit_log
                 (actor_type, actor_id, action, target_type, target_id, tenant_id, payload)
               VALUES ('platform_user', $1, 'tenant.markedPaid', 'tenant', $2, $2, $3)`,
              [
                session.user.userId,
                request.params.id,
                JSON.stringify({
                  days: parsed.data.days,
                  amount: parsed.data.amount ?? null,
                  method: parsed.data.method ?? null,
                }),
              ],
            );
          }

          return r.rows[0] ?? null;
        },
      );

      if (updated === null) return reply.code(404).send({ error: "הלקוח אינו קיים" });

      return reply.send({
        paidUntil: updated.paid_until?.toISOString() ?? null,
        note: `${updated.name} מסומן כמשלם עד `
          + `${updated.paid_until?.toLocaleDateString("he-IL") ?? "—"}.`,
      });
    },
  );

  /**
   * שינוי רצפת מדיניות הרשתות.
   *
   * זו הפעולה שההורה אינו יכול לעשות בעצמו: הוא קבע בהתקנה מה
   * המצב המתירני ביותר שהוא מרשה, וכל הכוונה היא שההחלטה תחזיק גם
   * ברגע שהיא מפריעה לו. שינוי דורש אדם מהמוקד שיוודא שמי שמבקש
   * הוא באמת בעל החשבון.
   *
   * ---
   *
   * הקרדיט לפני השינוי, לא אחריו.
   *
   * צריכה שנרשמת אחרי פעולה שהצליחה משאירה חשבון שקיבל שינוי בלי
   * לשלם עליו כשמשהו נופל באמצע. וכשאין קרדיט — התשובה אומרת את
   * זה במפורש, כי "אין הרשאה" היה שולח את המוקד לחפש בעיה אחרת.
   */
  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/platform/tenants/:id/network-floor",
    { preHandler: manage },
    async (request, reply) => {
      const parsed = floorBody.safeParse(request.body);

      if (!parsed.success) {
        return reply.code(400).send({ error: "רף לא תקין" });
      }

      const session = request.portal!.session;

      /*
       * החמרה אינה עולה קרדיט.
       *
       * לקוח שמבקש להדק את הרף עושה בדיוק מה שהמוצר קיים בשבילו,
       * ולגבות עליו זה לתמרץ אותו לא לבקש.
       */
      const current = await withPlatform(
        pool,
        { userId: session.user.userId, reason: "קריאת רצפה" },
        async (tx) => {
          const r = await tx.query<{ floor: string }>(
            "SELECT network_policy_floor::text AS floor FROM tenants WHERE id = $1",
            [request.params.id],
          );

          return r.rows[0]?.floor ?? null;
        },
      );

      if (current === null) return reply.code(404).send({ error: "הלקוח אינו קיים" });

      const rank: Record<string, number> = { strict: 1, balanced: 2, lenient: 3 };
      const loosening = (rank[parsed.data.floor] ?? 3) > (rank[current] ?? 3);

      if (loosening && !parsed.data.waiveCredit) {
        const paid = await spendCredit(
          pool, request.params.id, 1, "שינוי רצפת מדיניות רשתות");

        if (!paid) {
          return reply.code(402).send({
            error: "אין קרדיט לשינוי. יש לטעון קרדיט או לחייב את הלקוח.",
          });
        }
      }

      const updated = await withPlatform(
        pool,
        { userId: session.user.userId, reason: "שינוי רצפת רשתות" },
        async (tx) => {
          const r = await tx.query<{ name: string }>(
            `UPDATE tenants
                SET network_policy_floor = $2::network_policy,
                    network_policy_floor_changed_at = now(),
                    network_policy_floor_changed_by = $3,

                    /*
                     * הידוק הרף מהדק גם את המדיניות הנוכחית.
                     *
                     * בלי זה האילוץ במסד היה דוחה את העדכון, והמוקד
                     * היה מקבל שגיאה על משהו שהוא ביקש במפורש.
                     */
                    network_policy = CASE
                      WHEN (CASE network_policy WHEN 'strict' THEN 1 WHEN 'balanced' THEN 2 ELSE 3 END)
                         > (CASE $2::network_policy WHEN 'strict' THEN 1 WHEN 'balanced' THEN 2 ELSE 3 END)
                      THEN $2::network_policy
                      ELSE network_policy
                    END,
                    updated_at = now()
              WHERE id = $1
          RETURNING name`,
            [request.params.id, parsed.data.floor, session.user.userId],
          );

          if (r.rows[0]) {
            await tx.query(
              `INSERT INTO audit_log
                 (actor_type, actor_id, action, target_type, target_id, tenant_id, payload)
               VALUES ('platform_user', $1, 'tenant.networkFloorChanged', 'tenant', $2, $2, $3)`,
              [session.user.userId, request.params.id,
               JSON.stringify({ from: current, to: parsed.data.floor, loosening })],
            );
          }

          return r.rows[0] ?? null;
        },
      );

      if (updated === null) return reply.code(404).send({ error: "הלקוח אינו קיים" });

      return reply.send({
        floor: parsed.data.floor,
        note: `הרף של ${updated.name} עודכן.`
          + (loosening && !parsed.data.waiveCredit ? " נוצל קרדיט אחד." : ""),
      });
    },
  );

  /**
   * טעינת קרדיט לחשבון.
   *
   * הקרדיט אינו כסף ואינו מומר לכסף. הוא מכסה שינויים שדורשים אדם
   * מהמוקד — הורדת רצפת מדיניות, שינוי הגדרת ההסרה — כדי שטעות
   * קטנה לא תהפוך לשיחת טלפון משלמת.
   *
   * החלוקה הזו היא מה שמאפשר לגבות על מה שבאמת עולה בלי להרגיז מי
   * שלא עשה דבר רע.
   */
  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/platform/tenants/:id/credit",
    { preHandler: manage },
    async (request, reply) => {
      const parsed = creditBody.safeParse(request.body);

      if (!parsed.success) {
        return reply.code(400).send({ error: "מספר הקרדיטים חייב להיות בין 1 ל-1000" });
      }

      const session = request.portal!.session;

      /*
       * קיום הדייר נבדק לפני הזיכוי.
       *
       * המפתח הזר היה תופס מזהה שאינו קיים, אבל בשגיאת מסד ולא
       * בהודעה — ומי שהקליד מזהה שגוי אינו אמור לקבל 500.
       */
      const exists = await withPlatform(
        pool,
        { userId: session.user.userId, reason: "בדיקת דייר" },
        async (tx) => {
          const r = await tx.query("SELECT 1 FROM tenants WHERE id = $1", [request.params.id]);

          return (r.rowCount ?? 0) > 0;
        },
      );

      if (!exists) return reply.code(404).send({ error: "הלקוח אינו קיים" });

      await grantCredit(
        pool,
        request.params.id,
        parsed.data.amount,
        parsed.data.reason ?? "טעינה ידנית",
        session.user.userId,
      );

      const balance = await creditBalance(pool, request.params.id);

      return reply.send({
        balance,
        note: `נטענו ${parsed.data.amount} קרדיטים. היתרה: ${balance}.`,
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
