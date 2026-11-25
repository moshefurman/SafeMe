import type { FastifyInstance } from "fastify";
import type pg from "pg";
import { z } from "zod";

import { withPlatform } from "../db/client.ts";
import { createGuards } from "../auth/guards.ts";
import type { Config } from "../config.ts";
import type { Mailer } from "../notify/mailer.ts";
import { LiveMailer, readMailSettings } from "../notify/live-mailer.ts";

/**
 * הדואר היוצא.
 *
 * המסך הזה קיים כדי לענות על שאלה אחת שלא הייתה לה תשובה: האם
 * ההתראות בכלל נשלחות. עד כאן הדרך היחידה לדעת הייתה לחכות שהתראה
 * אמיתית לא תגיע — כלומר לגלות בדיוק ברגע שבו זה הכי יקר.
 *
 * גלובלי, ולכן צוות החברה בלבד. דייר שיכול לשנות את כתובת השולח
 * משפיע על ההתראות של כל השאר.
 */

const settingsBody = z.object({
  provider: z.enum(["none", "console", "resend"]),
  fromAddress: z.string().trim().max(200).nullable().optional(),
  replyTo: z.string().trim().max(200).nullable().optional(),

  /*
   * הכתובת שמוצגת למשתמשים, ולא זו שאליה חוזרות תשובות.
   *
   * לרוב זו אותה כתובת, ולא תמיד — ואיחודן היה כובל שתי החלטות
   * שאין ביניהן קשר.
   */
  supportEmail: z.string().trim().max(200).nullable().optional(),
});

const testBody = z.object({
  to: z.string().trim().toLowerCase().email().max(200),
});

const SYSTEM = {
  userId: "00000000-0000-0000-0000-000000000000",
  reason: "ניהול דואר יוצא",
};

/**
 * כתובת שולח תקינה.
 *
 * מקבלת גם "שם <כתובת>", שהיא הצורה שרוצים בפועל — הודעה מ-
 * "FilterPlus <alerts@..." נראית אחרת לגמרי מהודעה מכתובת עירומה.
 */
const SENDER = /^(?:[^<>]{1,80}<\s*)?[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+\s*>?$/;

interface Deps {
  pool: pg.Pool;
  config: Config;
  mailer: Mailer;
}

export async function registerMailRoutes(
  app: FastifyInstance,
  deps: Deps,
): Promise<void> {
  const { pool, config, mailer } = deps;
  const guards = createGuards(pool, config);

  // מנהל פלטפורמה עם אימות שני. אין כאן שום דבר שדייר צריך.
  const base = [
    guards.requireSession,
    guards.requirePlatformMfa,
    guards.requirePermission("providers.manage"),
  ];

  /**
   * כתובת הפניות, לכל מי שרואה מסך.
   *
   * בלי אימות, ובכוונה: היא נדרשת דווקא במקומות שבהם המשתמש אינו
   * מחובר — מסך הכניסה, והודעת חשבון מושעה. כתובת שמוצגת ממילא
   * בכל מסך אינה סוד שיש מה להגן עליו.
   *
   * ריק פירושו שלא הוגדרה, והמסכים פשוט לא יציגו דבר. עדיף על
   * כתובת שהומצאה כברירת מחדל ואיש אינו קורא אותה.
   */
  app.get("/api/portal/v1/support", async (_request, reply) => {
    const row = await readMailSettings(pool);

    return reply
      .header("cache-control", "public, max-age=300")
      .send({ email: row.support_email });
  });

  app.get("/api/portal/v1/mail", { preHandler: base }, async (_request, reply) => {
    const row = await readMailSettings(pool);

    return reply.send({
      provider: row.provider,
      fromAddress: row.from_address,
      replyTo: row.reply_to,
      supportEmail: row.support_email,
      // קיים או לא. לעולם לא הערך עצמו.
      hasApiKey: Boolean(config.RESEND_API_KEY),
      lastOkAt: row.last_ok_at,
      lastErrorAt: row.last_error_at,
      lastError: row.last_error,
    });
  });

  app.put("/api/portal/v1/mail", { preHandler: base }, async (request, reply) => {
    const session = request.portal!.session;
    const parsed = settingsBody.safeParse(request.body);

    if (!parsed.success) return reply.code(400).send({ error: "בקשה לא תקינה" });

    const from = parsed.data.fromAddress?.trim() || null;

    /*
     * ספק אמיתי בלי כתובת שולח הוא הגדרה שנראית תקינה ואינה שולחת
     * דבר. האילוץ במסד תופס את זה, אבל ההודעה כאן אומרת מה חסר.
     */
    if (parsed.data.provider === "resend") {
      if (from === null) {
        return reply.code(400).send({ error: "ספק אמיתי מחייב כתובת שולח" });
      }

      if (!SENDER.test(from)) {
        return reply.code(400).send({
          error: 'כתובת שולח לא תקינה. לדוגמה: FilterPlus <alerts@filterplus.co.il>',
        });
      }

      if (!config.RESEND_API_KEY) {
        return reply.code(400).send({
          error: "חסר RESEND_API_KEY בסביבת השרת. המפתח אינו נשמר כאן במכוון.",
        });
      }
    }

    await withPlatform(pool, SYSTEM, async (tx) => {
      await tx.query(
        `UPDATE mail_settings
            SET provider = $1, from_address = $2, reply_to = $3,
                support_email = $5,
                updated_at = now(), updated_by = $4
          WHERE id = 1`,
        [parsed.data.provider, from, parsed.data.replyTo?.trim() || null,
         session.user.userId, parsed.data.supportEmail?.trim() || null],
      );

      await tx.query(
        `INSERT INTO audit_log
           (actor_type, actor_id, action, target_type, target_id, tenant_id, payload)
         VALUES ('platform_user', $1, 'mail.settings.updated', 'mail', NULL, NULL, $2)`,
        [session.user.userId, JSON.stringify({ provider: parsed.data.provider, from })],
      );
    });

    // המטמון בדוור החי הוא דקה. מנהל שלחץ "שמור" מצפה למיידי.
    if (mailer instanceof LiveMailer) mailer.invalidate();

    return reply.send({ ok: true });
  });

  /**
   * שליחת בדיקה.
   *
   * זו הסיבה שהמסך קיים. בלעדיה ההגדרה נשמרת ואיש אינו יודע אם היא
   * נכונה, עד שהתראה אמיתית לא מגיעה — וזה בדיוק הרגע שבו הכי יקר
   * לגלות.
   */
  app.post("/api/portal/v1/mail/test", { preHandler: base }, async (request, reply) => {
    const session = request.portal!.session;
    const parsed = testBody.safeParse(request.body);

    if (!parsed.success) return reply.code(400).send({ error: "כתובת לא תקינה" });

    /*
     * ספק שאינו שולח אינו "הצלחה".
     *
     * NullMailer ו-ConsoleMailer מחזירים Promise שמתקיים תמיד: אחד
     * אוגר בזיכרון, השני מדפיס ליומן השרת. המסלול ענה "נשלח" בלי
     * לבדוק מי שלח, ולכן מנהל שהגדיר Resend ושכח לשמור קיבל אישור
     * מלא על הודעה שמעולם לא יצאה.
     *
     * זה נצפה בשטח, וזו אותה משפחה בדיוק של תקלות שעלתה כל היום:
     * מנגנון שמדווח הצלחה על מה שלא בדק.
     *
     * הבדיקה כאן ולא בדוור עצמו: ConsoleMailer שימושי בפיתוח, ומה
     * שאסור הוא לקרוא לו הצלחה במסך שכל תכליתו לוודא שדואר יוצא.
     */
    const settings = await readMailSettings(pool);

    if (settings.provider !== "resend") {
      return reply.code(400).send({
        error: settings.provider === "console"
          ? "הספק הנוכחי מדפיס ליומן השרת ואינו שולח דואר. יש לבחור Resend ולשמור."
          : "לא נבחר ספק דואר. יש לבחור Resend ולשמור לפני הבדיקה.",
      });
    }

    try {
      await mailer.send({
        to: parsed.data.to,
        subject: "FilterPlus · בדיקת דואר יוצא",
        body: [
          "שלום,",
          "",
          "ההודעה הזו נשלחה ממסך הדואר היוצא של FilterPlus.",
          "אם היא הגיעה, ההתראות יגיעו גם הן.",
          "",
          "— FilterPlus",
        ].join("\n"),
      });
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);

      await withPlatform(pool, SYSTEM, async (tx) => {
        await tx.query(
          `INSERT INTO audit_log
             (actor_type, actor_id, action, target_type, target_id, tenant_id, payload)
           VALUES ('platform_user', $1, 'mail.test.failed', 'mail', NULL, NULL, $2)`,
          [session.user.userId, JSON.stringify({ to: parsed.data.to, detail })],
        );
      });

      return reply.code(502).send({ error: detail });
    }

    await withPlatform(pool, SYSTEM, async (tx) => {
      await tx.query(
        `INSERT INTO audit_log
           (actor_type, actor_id, action, target_type, target_id, tenant_id, payload)
         VALUES ('platform_user', $1, 'mail.test.sent', 'mail', NULL, NULL, $2)`,
        [session.user.userId, JSON.stringify({ to: parsed.data.to })],
      );
    });

    return reply.send({
      ok: true,
      note: `נשלח דרך ${settings.provider} מהכתובת ${settings.from_address ?? "ללא שולח"}. `
        + "אם ההודעה לא הגיעה תוך דקה, בדוק את תיבת הזבל ואת אימות הדומיין.",
    });
  });
}
