import type pg from "pg";

import { withPlatform, withTenant } from "../db/client.ts";
import type { Signer } from "../crypto/signing.ts";

import { publishPolicy, assignPolicy } from "./publish.ts";
import { loadSchedules, toRules } from "./schedules.ts";

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
   * רק מחשבים שיש להם שיוך. הקריאה היא בהקשר פלטפורמה כי היא
   * חוצה דיירים — זו תחזוקה של המערכת, לא פעולה של משתמש.
   */
  const assigned = await withPlatform(
    pool,
    { userId: publishedBy, reason: "הרכבת מדיניות מחשב מחדש" },
    async (tx) => {
      const r = await tx.query<{ device_id: string; tenant_id: string }>(
        `SELECT a.device_id, a.tenant_id
           FROM device_policy_assignments a
           JOIN devices d ON d.id = a.device_id`,
      );

      return r.rows;
    },
  );

  let rebuilt = 0;

  for (const { device_id: deviceId, tenant_id: tenantId } of assigned) {
    try {
      const schedules = await withTenant(pool, tenantId, (tx) =>
        loadSchedules(tx, deviceId));

      /*
       * מחשב שכבר אין לו שכבה משלו חוזר לבסיס.
       *
       * מחיקת השיוך היא הפעולה הנכונה, ולא פרסום עותק זהה: כל עוד
       * יש שיוך, המחשב יישאר תלוי בהרכבה הזו לנצח. בלעדיו הוא
       * מקבל את הבסיס ישירות, וזה מה שנכון כשאין לו כלום מעליו.
       */
      if (schedules.length === 0) {
        await withTenant(pool, tenantId, async (tx) => {
          await tx.query(
            "DELETE FROM device_policy_assignments WHERE device_id = $1",
            [deviceId],
          );
        });

        rebuilt++;
        continue;
      }

      const base = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query<{ body: Record<string, unknown>; version: number }>(
          `SELECT p.body, p.version
             FROM policies p
            WHERE p.tenant_id = $1 OR p.tenant_id IS NULL
            ORDER BY (p.tenant_id IS NOT NULL) DESC, p.version DESC
            LIMIT 1`,
          [tenantId],
        );

        return r.rows[0] ?? null;
      });

      if (base === null) continue;

      /*
       * מספר הגרסה נלקח מהשרשרת הגבוהה מבין השתיים.
       *
       * הבסיס והשכבות הן שרשראות נפרדות באותה טבלה, ומספר שיורד
       * אחורה היה נראה למחשב כמדיניות ישנה יותר מזו שכבר בידיו.
       */
      const top = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query<{ version: number }>(
          `SELECT COALESCE(max(version), 0) AS version
             FROM policies WHERE tenant_id = $1 OR tenant_id IS NULL`,
          [tenantId],
        );

        return r.rows[0]?.version ?? 0;
      });

      const enforcement = (base.body["enforcement"] ?? {}) as Record<string, unknown>;

      const published = await publishPolicy(pool, signer, {
        tenantId,
        version: top + 1,
        body: {
          ...base.body,
          issuedUtc: new Date().toISOString(),
          enforcement: { ...enforcement, schedules: toRules(schedules) },
        },
        publishedBy,
      });

      await assignPolicy(pool, tenantId, deviceId, published.id);

      rebuilt++;
    } catch {
      /*
       * מחשב אחד שנכשל אינו עוצר את השאר.
       *
       * זו תחזוקה שרצה בעליית השרת, ונפילה כאן הייתה מונעת מהשרת
       * לעלות בכלל — מחיר גבוה בהרבה ממחשב אחד שיישאר על מדיניות
       * ישנה עוד סיבוב.
       */
    }
  }

  return rebuilt;
}
