import type pg from "pg";

import { withPlatform } from "../db/client.ts";
import type { Signer } from "../crypto/signing.ts";

import { republishTenantPolicy } from "./compose.ts";
import { composeDeviceOverlay } from "./device-overlay.ts";

/**
 * מרכיב מחדש את המדיניות של מחשבים שיש להם שכבה משלהם.
 *
 * מדיניות ייעודית למחשב נולדה עם שעות הגלישה, והיא נבנתה כעותק של
 * מה שהמחשב קיבל באותו רגע. זה עבד פעם אחת, ואז נשבר בשקט: העותק
 * נותק מהבסיס, וכל כלל זיהוי חדש שנכנס לבסיס לא הגיע אליו לעולם.
 *
 * נצפה בשטח. הבסיס עלה לגרסה 13 עם שני גששי זיהוי חדשים לנטפרי,
 * הכלים הציגו אותם, והמחשב המשיך לקבל גרסה 16 משרשרת אחרת לגמרי.
 * שני המספרים לא היו בני השוואה, ולכן גם לא נראו כתקלה — פשוט
 * כשני מספרים שונים.
 *
 * המבנה הנכון: המדיניות הרשמית היא הבסיס, והשכבה של המחשב מורכבת
 * מעליה בכל פעם מחדש. הרכבה, לא מזלג.
 *
 * ההרכבה עצמה יושבת ב-device-overlay.ts, והיא אותה פונקציה שמסלולי
 * הפורטל קוראים לה בכל שמירה. כאן רק נבחרים המחשבים.
 *
 * נקרא אחרי כל פרסום של הבסיס. מחשב בלי שכבה משלו אינו נוגע כאן
 * בכלל — הוא ממילא מקבל את הבסיס.
 */
export async function rebuildAssignedPolicies(
  pool: pg.Pool,
  signer: Signer,
  publishedBy = "system",
): Promise<number> {
  /*
   * מי בכלל צריך הרכבה מחדש.
   *
   * מי שיש לו שיוך — כולל מי שכבר אין לו סיבה לשיוך, כדי שיוחזר
   * לבסיס — ומי שיש לו סיבה ואין לו שיוך. המקרה השני אינו אמור
   * לקרות, כי כל שמירה מרכיבה מיד; אבל שמירה שהצליחה ופרסום שנכשל
   * אחריה משאירים בדיוק אותו, והעלייה הבאה היא המקום לתקן.
   *
   * הקריאה היא בהקשר פלטפורמה כי היא חוצה דיירים — זו תחזוקה של
   * המערכת, לא פעולה של משתמש.
   */
  const actor = { userId: publishedBy, reason: "הרכבת מדיניות מחשב מחדש" };

  let candidates: Array<{ device_id: string; tenant_id: string }>;

  try {
    candidates = await withPlatform(pool, actor, async (tx) => {
      const r = await tx.query<{ device_id: string; tenant_id: string }>(
        `SELECT d.id AS device_id, d.tenant_id
           FROM devices d
          WHERE EXISTS (SELECT 1 FROM device_policy_assignments a WHERE a.device_id = d.id)
             OR EXISTS (SELECT 1 FROM device_schedules s WHERE s.device_id = d.id)
             OR EXISTS (
               SELECT 1 FROM device_whitelist w
                WHERE w.device_id = d.id AND (w.enabled OR w.learning_until > now())
             )`,
      );

      return r.rows;
    });
  } catch (error) {
    /*
     * מיגרציה 0040 עוד לא הורצה: נופלים לשאילתה בלי הרשימה הלבנה.
     *
     * המיגרציות מורצות ביד, וקוד שעלה לפניהן אינו סיבה שההרכבה של
     * שעות החסימה תפסיק לעבוד. ההודעה על הטבלאות החסרות נכתבת
     * ב-device-overlay.ts, פעם אחת.
     */
    if ((error as { code?: string }).code !== "42P01") throw error;

    candidates = await withPlatform(pool, actor, async (tx) => {
      const r = await tx.query<{ device_id: string; tenant_id: string }>(
        `SELECT d.id AS device_id, d.tenant_id
           FROM devices d
          WHERE EXISTS (SELECT 1 FROM device_policy_assignments a WHERE a.device_id = d.id)
             OR EXISTS (SELECT 1 FROM device_schedules s WHERE s.device_id = d.id)`,
      );

      return r.rows;
    });
  }

  let rebuilt = 0;

  for (const { device_id: deviceId, tenant_id: tenantId } of candidates) {
    try {
      // בלי publishedBy: הוא uuid, ולפרסום מערכת אין משתמש.
      const result = await composeDeviceOverlay(pool, signer, { tenantId, deviceId });

      if (result.action === "published" || result.action === "removed") rebuilt++;
    } catch (error) {
      /*
       * מחשב אחד שנכשל אינו עוצר את השאר.
       *
       * זו תחזוקה שרצה בעליית השרת, ונפילה כאן הייתה מונעת מהשרת
       * לעלות בכלל — מחיר גבוה בהרבה ממחשב אחד שיישאר על מדיניות
       * ישנה עוד סיבוב.
       *
       * אבל היא נרשמת. הבליעה השקטה כאן הפכה כשל אפשרי לבלתי
       * נראה, וזה בדיוק מה שעלה לנו את הלילה: מנגנון שרץ, לא עשה
       * דבר, ולא היה לו איך לומר זאת.
       */
      console.error(`  הרכבת מדיניות למחשב ${deviceId} נכשלה:`, error);
    }
  }

  return rebuilt;
}

/**
 * מרכיב מחדש את מדיניות הדיירים מעל הבסיס.
 *
 * אותה תקלה בדיוק כמו במחשבים, שכבה אחת מעל. מסך חסימת העקיפות
 * מפרסם מדיניות לדייר, ובונה אותה מהגוף שהדייר מקבל כרגע — כלומר
 * מהעותק שלו עצמו. מרגע שדייר שינה שם משהו, הוא נותק מהבסיס.
 *
 * נצפה בשטח מיד אחרי שתוקנה השכבה של המחשבים: השיוך הישיר נמחק,
 * והמחשב נפל למדיניות דייר בגרסה 17 שגם היא בלי הכללים החדשים.
 * שלוש שרשראות, וכל אחת מהן נותקה באותו אופן.
 *
 * מה שהדייר רשאי לשנות הוא כלל היציאה והגדרות הדפדפן, ולכן זו כל
 * השכבה שנשמרת. כל השאר — ספקים, אכיפה, מארחים פתוחים — מגיע
 * מהבסיס ומתרענן איתו.
 */
export async function rebuildTenantPolicies(
  pool: pg.Pool,
  signer: Signer,
  publishedBy = "system",
): Promise<number> {
  console.log("  בודק אם יש מדיניות דייר להרכיב מחדש...");

  const base = await withPlatform(
    pool,
    { userId: publishedBy, reason: "הרכבת מדיניות דייר מחדש" },
    async (tx) => {
      const r = await tx.query<{ body: Record<string, unknown> }>(
        `SELECT body FROM policies
          WHERE tenant_id IS NULL
          ORDER BY version DESC LIMIT 1`,
      );

      return r.rows[0]?.body ?? null;
    },
  );

  if (base === null) return 0;

  const tenants = await withPlatform(
    pool,
    { userId: publishedBy, reason: "הרכבת מדיניות דייר מחדש" },
    async (tx) => {
      const r = await tx.query<{ tenant_id: string }>(
        `SELECT DISTINCT tenant_id FROM policies WHERE tenant_id IS NOT NULL`,
      );

      return r.rows.map((x) => x.tenant_id);
    },
  );

  let rebuilt = 0;

  for (const tenantId of tenants) {
    try {
      /*
       * ההרכבה עצמה — הבסיס ומעליו השכבה של הדייר — יושבת
       * ב-compose.ts, יחד עם ההסבר מה נחשב לשכבה של הדייר.
       */
      const version = await republishTenantPolicy(pool, signer, tenantId);

      if (version === null) {
        console.log(`  מדיניות הדייר ${tenantId} כבר תואמת את הבסיס.`);
        continue;
      }

      rebuilt++;
    } catch (error) {
      // דייר אחד שנכשל אינו עוצר את השאר, ואינו מפיל את עליית השרת —
      // אבל הוא נרשם, כי כשל שקט כאן אינו ניתן לאבחון מבחוץ.
      console.error(`  הרכבת מדיניות לדייר ${tenantId} נכשלה:`, error);
    }
  }

  return rebuilt;
}
