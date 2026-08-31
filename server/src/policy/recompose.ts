import type pg from "pg";

import { withPlatform, withTenant } from "../db/client.ts";
import type { Signer } from "../crypto/signing.ts";

import { publishPolicy, assignPolicy } from "./publish.ts";
import { loadSchedules, toRules } from "./schedules.ts";

/**
 * השוואה יציבה בין שני גופי מדיניות, בלי חותמת הזמן.
 *
 * issuedUtc משתנה בכל בנייה, ולכן השוואה ישירה הייתה תמיד מוצאת
 * הבדל — וההרכבה שרצה בכל עלייה הייתה מפרסמת גרסה חדשה בכל
 * אתחול של השרת. כל מחשב היה מוריד מדיניות חדשה בלי שדבר השתנה
 * בה, והמספרים היו מטפסים בלי משמעות.
 *
 * המפתחות ממוינים כי סדר המפתחות ב-JSON אינו מובטח, ושני גופים
 * זהים בתוכן יכולים להיכתב אחרת.
 */
function sameBody(a: unknown, b: unknown): boolean {
  return canonical(a) === canonical(b);
}

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";

  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;

  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([k]) => k !== "issuedUtc")
    .sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0));

  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(",")}}`;
}

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
          /*
           * השורה עצמה נמחקת, לא רק השיוך.
           *
           * מדיניות מחשב נכתבת עם tenant_id, ולכן מרגע שהשיוך
           * נמחק היא נראית בדיוק כמו מדיניות דייר — עם מספר גרסה
           * גבוה. כל בחירה של "מדיניות הדייר" לפי הגרסה הגבוהה
           * הייתה נוחתת עליה.
           *
           * זה בדיוק מה שקרה: שאריות של מזלג ישן נבחרו כמדיניות
           * הדייר, וההרכבה שנועדה לתקן את הפיצול הרכיבה מעליהן.
           */
          const orphan = await tx.query<{ policy_id: string }>(
            "SELECT policy_id FROM device_policy_assignments WHERE device_id = $1",
            [deviceId],
          );

          await tx.query(
            "DELETE FROM device_policy_assignments WHERE device_id = $1",
            [deviceId],
          );

          if (orphan.rows[0]) {
            await tx.query("DELETE FROM policies WHERE id = $1", [orphan.rows[0].policy_id]);
          }
        });

        rebuilt++;
        continue;
      }

      const base = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query<{ body: Record<string, unknown>; version: number }>(
          `SELECT p.body, p.version
             FROM policies p
            WHERE (p.tenant_id = $1 OR p.tenant_id IS NULL)
              AND NOT EXISTS (
                SELECT 1 FROM device_policy_assignments a WHERE a.policy_id = p.id
              )
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

      const composed = {
        ...base.body,
        enforcement: { ...enforcement, schedules: toRules(schedules) },
      };

      /*
       * מה שהמחשב מחזיק עכשיו.
       *
       * ההרכבה רצה בכל עליית שרת, ולכן היא חייבת לדעת לא לעשות
       * כלום. בלי הבדיקה הזו כל אתחול היה מפרסם גרסה חדשה וזהה,
       * וכל מחשב היה מוריד אותה — תעבורה, מספרים מטפסים, ושום
       * שינוי אמיתי.
       */
      const assignedNow = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query<{ body: Record<string, unknown> }>(
          `SELECT p.body
             FROM device_policy_assignments a
             JOIN policies p ON p.id = a.policy_id
            WHERE a.device_id = $1`,
          [deviceId],
        );

        return r.rows[0]?.body ?? null;
      });

      if (assignedNow !== null && sameBody(assignedNow, composed)) continue;

      const published = await publishPolicy(pool, signer, {
        tenantId,
        version: top + 1,
        body: { ...composed, issuedUtc: new Date().toISOString() },
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
 * מה שהדייר רשאי לשנות הוא כלל היציאה בלבד, ולכן זו כל השכבה
 * שנשמרת. כל השאר — ספקים, אכיפה, מארחים פתוחים — מגיע מהבסיס
 * ומתרענן איתו.
 */
export async function rebuildTenantPolicies(
  pool: pg.Pool,
  signer: Signer,
  publishedBy = "system",
): Promise<number> {
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
       * מדיניות הדייר, בלי שורות ששייכות למחשב.
       *
       * שתיהן נושאות tenant_id ויושבות באותה טבלה, ולכן בחירה
       * לפי הגרסה הגבוהה בלבד נוחתת על שכבה של מחשב מסוים
       * ומתייחסת אליה כאילו היא של הדייר כולו.
       */
      const own = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query<{ version: number; body: Record<string, unknown> }>(
          `SELECT p.version, p.body FROM policies p
            WHERE p.tenant_id = $1
              AND NOT EXISTS (
                SELECT 1 FROM device_policy_assignments a WHERE a.policy_id = p.id
              )
            ORDER BY p.version DESC LIMIT 1`,
          [tenantId],
        );

        return r.rows[0] ?? null;
      });

      if (own === null) continue;

      const ownEnforcement = (own.body["enforcement"] ?? {}) as Record<string, unknown>;
      const baseEnforcement = (base["enforcement"] ?? {}) as Record<string, unknown>;

      /*
       * השכבה של הדייר, ורק היא.
       *
       * egress חסר פירושו שהדייר מעולם לא נגע בו, ואז אין מה
       * להרכיב מעל הבסיס — הוא יקבל את מה שהבסיס אומר.
       */
      const overlay = ownEnforcement["egress"] === undefined
        ? {}
        : { egress: ownEnforcement["egress"] };

      const composed = {
        ...base,
        enforcement: { ...baseEnforcement, ...overlay },
      };

      if (sameBody(own.body, composed)) continue;

      const top = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query<{ version: number }>(
          `SELECT COALESCE(max(version), 0) AS version
             FROM policies WHERE tenant_id = $1 OR tenant_id IS NULL`,
          [tenantId],
        );

        return r.rows[0]?.version ?? 0;
      });

      await publishPolicy(pool, signer, {
        tenantId,
        version: top + 1,
        body: { ...composed, issuedUtc: new Date().toISOString() },
        publishedBy,
      });

      rebuilt++;
    } catch {
      // דייר אחד שנכשל אינו עוצר את השאר, ואינו מפיל את עליית השרת.
    }
  }

  return rebuilt;
}
