import type { FastifyInstance } from "fastify";
import type pg from "pg";
import { z } from "zod";

import { withPlatform, withTenant } from "../db/client.ts";
import { createGuards } from "../auth/guards.ts";
import { isPlatformRole } from "../auth/rbac.ts";
import type { Config } from "../config.ts";

/**
 * מנויים, מחירון, וביטול.
 *
 * שני קהלים באותו קובץ, ובכוונה: המחירון שמנהל הפלטפורמה עורך הוא
 * בדיוק מה שההורה רואה, ופיצול לשני מקומות היה מזמין את המצב שבו
 * המסך מציג מחיר אחד והחיוב גובה אחר.
 *
 * ---
 *
 * מה שאין כאן: חיוב בפועל.
 *
 * הסליקה מתבצעת מול הספק, והשרת אינו רואה מספר כרטיס בשום שלב —
 * ההורה מזין אותו בעמוד של הסולק, ואנחנו מקבלים אסימון. אינטגרציה
 * שעוברת דרכנו הייתה מכניסה אותנו לתקן PCI שלם בלי שום צורך.
 */

// ---------------------------------------------------------------- טיפוסים

const SYSTEM = { userId: "00000000-0000-0000-0000-000000000000", reason: "מחירון" };

const planBody = z.object({
  name: z.string().trim().min(2).max(80),
  deviceLimit: z.number().int().min(1).max(1000),

  /*
   * שקלים בממשק, אגורות במסד.
   *
   * מנהל שמקליד 39.90 מתכוון ל-3990 אגורות, ומספר עשרוני שנשמר
   * כמות שהוא צובר שגיאות עיגול על פני אלפי חיובים. ההמרה נעשית
   * בגבול אחד ומוגדר.
   */
  monthly: z.number().min(0).max(100_000),
  yearly: z.number().min(0).max(1_000_000),
  active: z.boolean(),
});

const toAgorot = (shekels: number): number => Math.round(shekels * 100);

/**
 * ההנחה השנתית, באחוזים.
 *
 * נגזרת מהסכומים ואינה נשמרת. אחוז ששמור בנפרד מתנתק מהמחירים
 * ברגע שאחד מהם משתנה, ואז המסך מבטיח הנחה שאינה קיימת.
 */
function yearlyDiscount(monthlyAgorot: number, yearlyAgorot: number): number {
  const full = monthlyAgorot * 12;

  if (full <= 0 || yearlyAgorot >= full) return 0;

  return Math.round(((full - yearlyAgorot) / full) * 100);
}

// ---------------------------------------------------------------- מסלולים

export async function registerBillingRoutes(
  app: FastifyInstance,
  deps: { pool: pg.Pool; config: Config },
): Promise<void> {
  const { pool, config } = deps;
  const guards = createGuards(pool, config);

  const session = [guards.requireSession, guards.requirePlatformMfa];

  const platform = [
    ...session,
    guards.requirePermission("licenses.manage"),
  ];

  /**
   * המחירון, לכל מי שמחובר.
   *
   * תוכניות כבויות מוחזרות רק למנהל הפלטפורמה: הוא צריך לראות מה
   * הוא עורך, וההורה אינו אמור לראות מוצר שאינו למכירה.
   */
  app.get("/api/portal/v1/plans", { preHandler: session }, async (request, reply) => {
    const all = isPlatformRole(request.portal!.session.user.role);

    const rows = await withPlatform(pool, SYSTEM, async (tx) => {
      const r = await tx.query(
        `SELECT id, code, name, device_limit, monthly_agorot, yearly_agorot,
                active, sort_order
           FROM plans
          ${all ? "" : "WHERE active"}
          ORDER BY sort_order, name`,
      );

      return r.rows as Array<{
        id: string;
        code: string;
        name: string;
        device_limit: number;
        monthly_agorot: number;
        yearly_agorot: number;
        active: boolean;
      }>;
    });

    return reply.send({
      plans: rows.map((p) => ({
        id: p.id,
        code: p.code,
        name: p.name,
        deviceLimit: p.device_limit,
        monthly: p.monthly_agorot / 100,
        yearly: p.yearly_agorot / 100,
        yearlyDiscountPercent: yearlyDiscount(p.monthly_agorot, p.yearly_agorot),
        active: p.active,

        /*
         * תוכנית פעילה במחיר אפס היא תקלה, לא מתנה.
         *
         * הזריעה יוצרת אותה כבויה ובאפס בדיוק כדי לאלץ החלטה, וזה
         * הדגל שאומר למסך להציג את זה כחסר ולא כ"חינם".
         */
        priceMissing: p.monthly_agorot === 0 && p.yearly_agorot === 0,
      })),
    });
  });

  /**
   * תוכנית חדשה.
   *
   * המזהה נוצר כאן ולא נדרש מהמנהל: הוא משמש בקוד ובקישורים, חייב
   * להיות באנגלית, ולבקש אותו ממי שכותב שם בעברית זה לבקש ממנו
   * להמציא משהו שאין לו דעה עליו.
   *
   * הוא נגזר ממספר המחשבים כי זה מה שמבדיל בין תוכניות בפועל, ואם
   * הוא תפוס — נוסף מספר. שם שנוצר אקראית היה קריא רק למכונה.
   */
  app.post("/api/portal/v1/plans", { preHandler: platform }, async (request, reply) => {
    const parsed = planBody.safeParse(request.body);

    if (!parsed.success) return reply.code(400).send({ error: "נתוני תוכנית לא תקינים" });

    const monthly = toAgorot(parsed.data.monthly);
    const yearly = toAgorot(parsed.data.yearly);

    if (parsed.data.active && monthly === 0 && yearly === 0) {
      return reply.code(400).send({
        error: "אי אפשר להפעיל תוכנית בלי מחיר. יש לקבוע מחיר חודשי או שנתי.",
      });
    }

    const created = await withPlatform(
      pool,
      { userId: request.portal!.session.user.userId, reason: "יצירת תוכנית" },
      async (tx) => {
        const base = `devices-${parsed.data.deviceLimit}`;

        /*
         * חיפוש מזהה פנוי בלולאה מוגבלת.
         *
         * הגבול אינו קישוט: לולאה שמסתמכת על כך שמזהה יימצא היא
         * לולאה שתיתקע ביום שבו משהו אחר נשבר.
         */
        let code = base;

        for (let i = 2; i <= 50; i++) {
          const taken = await tx.query("SELECT 1 FROM plans WHERE code = $1", [code]);

          if (taken.rowCount === 0) break;

          code = `${base}-${i}`;
        }

        const r = await tx.query<{ id: string; code: string }>(
          `INSERT INTO plans
             (code, name, device_limit, monthly_agorot, yearly_agorot, active, sort_order)
           VALUES ($1, $2, $3, $4, $5, $6,
                   COALESCE((SELECT max(sort_order) + 10 FROM plans), 10))
        RETURNING id, code`,
          [code, parsed.data.name, parsed.data.deviceLimit, monthly, yearly, parsed.data.active],
        );

        return r.rows[0]!;
      },
    );

    return reply.send({ ok: true, id: created.id, code: created.code });
  });

  /**
   * מחיקת תוכנית, רק כשאיש לא קנה אותה.
   *
   * מנוי מצביע על התוכנית שנמכרה, ומחיקה הייתה מנתקת את הקשר או
   * נכשלת על מפתח זר — ובשני המקרים ההיסטוריה של מה נמכר ובכמה
   * הולכת לאיבוד. מה שרוצים במקרה כזה הוא לכבות, לא למחוק.
   */
  app.delete<{ Params: { id: string } }>(
    "/api/portal/v1/plans/:id",
    { preHandler: platform },
    async (request, reply) => {
      const outcome = await withPlatform(
        pool,
        { userId: request.portal!.session.user.userId, reason: "מחיקת תוכנית" },
        async (tx) => {
          const used = await tx.query<{ n: string }>(
            "SELECT count(*)::text AS n FROM subscriptions WHERE plan_id = $1",
            [request.params.id],
          );

          if (Number(used.rows[0]?.n ?? 0) > 0) return "in-use" as const;

          const r = await tx.query("DELETE FROM plans WHERE id = $1", [request.params.id]);

          return (r.rowCount ?? 0) > 0 ? "deleted" as const : "missing" as const;
        },
      );

      if (outcome === "in-use") {
        return reply.code(409).send({
          error: "התוכנית נמכרה ללקוחות ולכן אינה נמחקת. אפשר לכבות אותה כדי להסתיר מרכישה.",
        });
      }

      if (outcome === "missing") return reply.code(404).send({ error: "התוכנית אינה קיימת" });

      return reply.send({ ok: true });
    },
  );

  /** עריכת תוכנית. הרשאת פלטפורמה בלבד — זה המחירון. */
  app.put<{ Params: { id: string } }>(
    "/api/portal/v1/plans/:id",
    { preHandler: platform },
    async (request, reply) => {
      const parsed = planBody.safeParse(request.body);

      if (!parsed.success) return reply.code(400).send({ error: "נתוני תוכנית לא תקינים" });

      const monthly = toAgorot(parsed.data.monthly);
      const yearly = toAgorot(parsed.data.yearly);

      /*
       * מחיר שנתי גבוה מ-12 חודשים אינו נחסם, אך גם אינו מוצג
       * כהנחה. יש מקרים לגיטימיים — מחיר חודשי מבצע זמני — ורק
       * החישוב צריך לדעת לא להבטיח הנחה שלילית.
       */
      if (parsed.data.active && monthly === 0 && yearly === 0) {
        return reply.code(400).send({
          error: "אי אפשר להפעיל תוכנית בלי מחיר. יש לקבוע מחיר חודשי או שנתי.",
        });
      }

      const updated = await withPlatform(
        pool,
        { userId: request.portal!.session.user.userId, reason: "עריכת מחירון" },
        async (tx) => {
          const r = await tx.query<{ code: string }>(
            `UPDATE plans
                SET name = $2, device_limit = $3, monthly_agorot = $4,
                    yearly_agorot = $5, active = $6, updated_at = now()
              WHERE id = $1
          RETURNING code`,
            [request.params.id, parsed.data.name, parsed.data.deviceLimit,
             monthly, yearly, parsed.data.active],
          );

          return r.rows[0] ?? null;
        },
      );

      if (updated === null) return reply.code(404).send({ error: "התוכנית אינה קיימת" });

      return reply.send({ ok: true });
    },
  );

  /**
   * המנוי של החשבון הנוכחי.
   *
   * כולל מה שההורה צריך כדי להחליט: כמה מחשבים מותרים, כמה בשימוש,
   * ומתי החיוב הבא.
   */
  app.get("/api/portal/v1/subscription", { preHandler: session }, async (request, reply) => {
    const tenantId = request.portal!.session.user.tenantId;

    if (tenantId === null) return reply.send({ subscription: null, used: 0 });

    const data = await withTenant(pool, tenantId, async (tx) => {
      const sub = await tx.query(
        `SELECT s.id, s.status::text AS status, s.interval_unit::text AS interval_unit,
                s.price_agorot, s.device_limit, s.current_period_end,
                s.cancel_at_period_end, s.card_last4, p.name AS plan_name
           FROM subscriptions s
           JOIN plans p ON p.id = s.plan_id
          WHERE s.tenant_id = $1 AND s.status <> 'canceled'`,
        [tenantId],
      );

      const used = await tx.query<{ n: string }>(
        "SELECT count(*)::text AS n FROM devices WHERE status <> 'uninstalled'",
      );

      return { sub: sub.rows[0] ?? null, used: Number(used.rows[0]?.n ?? 0) };
    });

    const s = data.sub as {
      id: string; status: string; interval_unit: string; price_agorot: number;
      device_limit: number; current_period_end: Date | null;
      cancel_at_period_end: boolean; card_last4: string | null; plan_name: string;
    } | null;

    return reply.send({
      used: data.used,
      subscription: s === null ? null : {
        id: s.id,
        planName: s.plan_name,
        status: s.status,
        interval: s.interval_unit,
        price: s.price_agorot / 100,
        deviceLimit: s.device_limit,
        currentPeriodEnd: s.current_period_end?.toISOString() ?? null,
        cancelAtPeriodEnd: s.cancel_at_period_end,
        cardLast4: s.card_last4,
      },
    });
  });

  /**
   * ביטול מנוי.
   *
   * חובה חוקית, ולא נוחות: עסקה מתמשכת בישראל מחייבת ביטול מקוון
   * פשוט, בלי שיחת טלפון ובלי שימור. הכפתור הזה הוא הדרישה עצמה.
   *
   * הביטול נכנס לתוקף בסוף התקופה ולא מיד — מי שביטל שילם עד הסוף
   * ומגיע לו לקבל את מה ששילם עליו.
   */
  app.post("/api/portal/v1/subscription/cancel", { preHandler: session }, async (request, reply) => {
    const tenantId = request.portal!.session.user.tenantId;

    if (tenantId === null) return reply.code(400).send({ error: "אין מנוי לחשבון זה" });

    const canceled = await withTenant(pool, tenantId, async (tx) => {
      const r = await tx.query<{ current_period_end: Date | null }>(
        `UPDATE subscriptions
            SET cancel_at_period_end = true, canceled_at = now(), updated_at = now()
          WHERE tenant_id = $1 AND status <> 'canceled' AND cancel_at_period_end = false
      RETURNING current_period_end`,
        [tenantId],
      );

      return r.rows[0] ?? null;
    });

    if (canceled === null) {
      return reply.code(404).send({ error: "אין מנוי פעיל, או שהביטול כבר נקלט" });
    }

    const until = canceled.current_period_end;

    return reply.send({
      ok: true,

      /*
       * אומרים גם מה לא קורה.
       *
       * ההגנה על המחשבים אינה נפסקת עם הביטול, וזה לא מובן מאליו
       * — הורה שיבטל ויחשוב שהמחשב נפתח באותו רגע יגלה אחרת
       * בדיוק כשזה יפריע לו.
       */
      note: until
        ? `המנוי יסתיים ב-${until.toLocaleDateString("he-IL")}. עד אז הכול ממשיך כרגיל, `
          + "ולא יבוצע חיוב נוסף. ההגנה על המחשבים אינה נפסקת עם סיום המנוי."
        : "המנוי בוטל. לא יבוצע חיוב נוסף.",
    });
  });

  /**
   * ביטול הביטול, כל עוד התקופה לא הסתיימה.
   *
   * מי שלחץ בטעות או שינה את דעתו לא אמור לעבור דרך רכישה מחדש.
   */
  app.post("/api/portal/v1/subscription/resume", { preHandler: session }, async (request, reply) => {
    const tenantId = request.portal!.session.user.tenantId;

    if (tenantId === null) return reply.code(400).send({ error: "אין מנוי לחשבון זה" });

    const resumed = await withTenant(pool, tenantId, async (tx) => {
      const r = await tx.query(
        `UPDATE subscriptions
            SET cancel_at_period_end = false, canceled_at = NULL, updated_at = now()
          WHERE tenant_id = $1 AND status <> 'canceled' AND cancel_at_period_end = true
      RETURNING id`,
        [tenantId],
      );

      return r.rowCount ?? 0;
    });

    if (resumed === 0) return reply.code(404).send({ error: "אין ביטול ממתין" });

    return reply.send({ ok: true, note: "הביטול בוטל. המנוי ימשיך כרגיל." });
  });

  /** היסטוריית חיובים, כולל קישור לקבלה. */
  app.get("/api/portal/v1/payments", { preHandler: session }, async (request, reply) => {
    const tenantId = request.portal!.session.user.tenantId;

    if (tenantId === null) return reply.send({ payments: [] });

    const rows = await withTenant(pool, tenantId, async (tx) => {
      const r = await tx.query(
        `SELECT amount_agorot, succeeded, failure_reason, receipt_url, charged_at
           FROM payments WHERE tenant_id = $1
          ORDER BY charged_at DESC LIMIT 50`,
        [tenantId],
      );

      return r.rows as Array<{
        amount_agorot: number; succeeded: boolean;
        failure_reason: string | null; receipt_url: string | null; charged_at: Date;
      }>;
    });

    return reply.send({
      payments: rows.map((p) => ({
        amount: p.amount_agorot / 100,
        succeeded: p.succeeded,
        failureReason: p.failure_reason,
        receiptUrl: p.receipt_url,
        chargedAt: p.charged_at.toISOString(),
      })),
    });
  });
}
