import type pg from "pg";

import { withTenant } from "../db/client.ts";
import type { Signer } from "../crypto/signing.ts";

import { publishPolicy } from "./publish.ts";

/**
 * אבני הבניין המשותפות להרכבת מדיניות.
 *
 * שלוש שכבות חיות באותה טבלה: הבסיס הגלובלי, מדיניות הדייר מעליו,
 * ושכבת המחשב מעליה. כל אחת מהן הורכבה פעם בקוד משלה, וכל אחת
 * נשברה באותו אופן בנפרד — עותק של עותק, מספר גרסה שיורד אחורה,
 * השוואה שתמיד מוצאת הבדל.
 *
 * מה שכאן הוא החלקים שכל השכבות חייבות לעשות אותו דבר: להשוות
 * גופים, לבחור מספר גרסה, ולהרכיב את מדיניות הדייר. השכבה של
 * המחשב יושבת ב-device-overlay.ts ובנויה מעל אלה.
 */

// ---------------------------------------------------------------- השוואה

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
export function sameBody(a: unknown, b: unknown): boolean {
  return canonical(a) === canonical(b);
}

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";

  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;

  /*
   * version מושמט כמו issuedUtc, ומאותה סיבה.
   *
   * הוא נקבע בזמן הפרסום ולא נובע מהתוכן, ולכן שני גופים שנבדלים
   * רק בו הם אותה מדיניות. בלי ההשמטה כל עליית שרת הייתה מפרסמת
   * גרסה חדשה וזהה, וכל מחשב היה מוריד אותה שוב.
   */
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([k]) => k !== "issuedUtc" && k !== "version")
    .sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0));

  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(",")}}`;
}

// ---------------------------------------------------------------- רשת שטרם אושרה

/**
 * האם המדיניות של הדייר חוסמת רשת שטרם אושרה.
 *
 * הדרישה הזו חיה בשרת בלבד — network_policy = 'strict' — והסוכן
 * לא ידע עליה דבר. וכשהרשת מתחלפת הוא מוחק את ההכרעה הקודמת, כי
 * היא נאמרה על רשת אחרת, ומאשר את החדשה עד שתגיע הכרעה: חלון של
 * פעימה שלמה בכל החלפת רשת.
 *
 * זה נצפה בשטח — לקוח שהגדיר שאף רשת לא תאושר עד אישור התחבר
 * לרשת חדשה וגלש. הדגל הוא מה שמעביר את הדרישה למקום שבו היא
 * נאכפת בפועל.
 */
export async function blockUntilApproved(pool: pg.Pool, tenantId: string): Promise<boolean> {
  return withTenant(pool, tenantId, async (tx) => {
    const r = await tx.query<{ network_policy: string }>(
      "SELECT network_policy::text AS network_policy FROM tenants WHERE id = $1",
      [tenantId],
    );

    return r.rows[0]?.network_policy === "strict";
  });
}

// ---------------------------------------------------------------- מספר גרסה

/**
 * המספר הבא, מעל כל השרשראות — כולל גרסאות שנמחקו.
 *
 * הרכבה מחדש עלולה למחוק שורות עם גרסאות גבוהות, ואז max(version)
 * יורד אחורה. הסוכן דוחה מדיניות שגרסתה נמוכה מזו שבידיו, ולכן
 * הגרסה החדשה חייבת לעבור גם את מה שהמחשב מחזיק מקומית.
 *
 * שלוש נקודות מדידה:
 *   1. version (עמודה) — הגרסה הגבוהה בשורות שנותרו
 *   2. body->'version' — הגרסה שנחתמה בגוף (עשויה להיות גבוהה מהעמודה)
 *   3. device_state.policy_version — מה שהסוכנים דיווחו בפעימה האחרונה
 *
 * זו הגרסה היחידה של החישוב. שעות הגלישה השתמשו פעם ב-"הגרסה של
 * הבסיס ועוד אחת", וההרכבה בעליית השרת ב-"הגבוהה בטבלה ועוד אחת" —
 * שתיהן חלשות ממנה, ושתיהן יכלו להפיק מספר שהמחשב ידחה.
 */
export async function nextPolicyVersion(pool: pg.Pool, tenantId: string): Promise<number> {
  return withTenant(pool, tenantId, async (tx) => {
    const r = await tx.query<{ version: number }>(
      `SELECT GREATEST(
         COALESCE((SELECT max(version) FROM policies WHERE tenant_id = $1 OR tenant_id IS NULL), 0),
         COALESCE((SELECT max((body->>'version')::int) FROM policies WHERE tenant_id = $1 OR tenant_id IS NULL), 0),
         COALESCE((SELECT max(ds.policy_version) FROM device_state ds JOIN devices d ON d.id = ds.device_id WHERE d.tenant_id = $1), 0)
       ) AS version`,
      [tenantId],
    );

    return (r.rows[0]?.version ?? 0) + 1;
  });
}

/** הגרסה שהסוכן יקרא מהגוף, ואם אין — זו של השורה. */
export function bodyVersion(row: { version: number; body: Record<string, unknown> }): number {
  const inBody = row.body["version"];

  return typeof inBody === "number" ? Math.max(inBody, row.version) : row.version;
}

/**
 * מפרסם, ומנסה שוב אם המספר נתפס בינתיים.
 *
 * (tenant_id, version) ייחודי. שני פרסומים לאותו דייר באותו רגע —
 * הורה ששומר שני דברים, או שמירה בזמן הרכבה של עליית שרת — בוחרים
 * את אותו מספר, והשני נופל על האילוץ. המספר נבחר מחדש והפרסום
 * חוזר; שלוש פעמים מספיקות לכל מה שאינו תקלה אמיתית.
 */
export async function publishAtNextVersion(
  pool: pg.Pool,
  signer: Signer,
  input: {
    tenantId: string;
    body: Record<string, unknown>;
    publishedBy?: string | null;
  },
): Promise<{ id: string; version: number }> {
  let last: unknown;

  for (let attempt = 0; attempt < 3; attempt++) {
    const version = await nextPolicyVersion(pool, input.tenantId);

    try {
      /*
       * הגרסה נכתבת גם לגוף, לא רק לשורה.
       *
       * הגוף ירש את version מהבסיס והשאיר אותו קפוא: השורה טיפסה
       * ל-22 בזמן שהסוכן קרא 14 בכל פעם. זה נראה כמו שני מספרים
       * שונים, והוא חמור יותר — PolicyStore דוחה מדיניות שגרסתה
       * נמוכה מהפעילה, וזו כל ההגנה מפני החזרה של מדיניות ישנה
       * חתומה. עם מספר קפוא ההשוואה תמיד שווה, ולכן לא מגנה.
       */
      const published = await publishPolicy(pool, signer, {
        tenantId: input.tenantId,
        version,
        body: { ...input.body, version, issuedUtc: new Date().toISOString() },
        /*
         * published_by הוא uuid עם מפתח זר ל-users, ומחרוזת "system"
         * נפסלת בו — invalid input syntax for type uuid. ההרכבה נכשלה
         * פעם בדיוק כאן, בכל דייר ובכל מחשב, וה-catch בלע את זה
         * בשקט. לפרסום מערכת אין משתמש, ו-NULL הוא הערך הנכון.
         */
        publishedBy: input.publishedBy ?? null,
      });

      return { id: published.id, version: published.version };
    } catch (error) {
      if ((error as { code?: string }).code !== "23505") throw error;

      last = error;
    }
  }

  throw last;
}

// ---------------------------------------------------------------- מחיקת שורה

let warnedDeleteBlocked = false;

/**
 * מוחק שורת מדיניות של מחשב, ובודק שהיא באמת נמחקה.
 *
 * הבדיקה אינה טקס. עד מיגרציה 0041 לא הייתה לטבלה מדיניות RLS
 * למחיקה, ו-DELETE החזיר "אפס שורות" בלי שגיאה — המחיקה הזו רצה
 * בכל עליית שרת ולא מחקה דבר אף פעם, ואיש לא ידע.
 *
 * שורה שלא נמחקה אינה תקלה קוסמטית: היא נושאת tenant_id ומספר
 * גבוה, נראית כמו מדיניות הדייר, ונבחרת כבסיס לכל המחשבים שלו.
 */
export async function deletePolicyRow(pool: pg.Pool, tenantId: string, policyId: string): Promise<void> {
  const deleted = await withTenant(pool, tenantId, async (tx) => {
    const r = await tx.query("DELETE FROM policies WHERE id = $1", [policyId]);

    return r.rowCount ?? 0;
  });

  if (deleted === 0 && !warnedDeleteBlocked) {
    warnedDeleteBlocked = true;
    console.error(
      "  ✗ שורת מדיניות של מחשב לא נמחקה. יש להריץ את מיגרציה 0041 (node scripts/migrate.ts).\n" +
      "    עד אז שורות כאלה נשארות בטבלה ועלולות להיבחר כמדיניות הדייר.",
    );
  }
}

// ---------------------------------------------------------------- מדיניות הדייר

export interface PolicyRow {
  id: string;
  version: number;
  body: Record<string, unknown>;
}

/** גוף מדיניות הבסיס הגלובלית, שהוא המקור לכל מה שאינו שכבה. */
export async function loadGlobalPolicy(pool: pg.Pool, tenantId: string): Promise<PolicyRow | null> {
  return withTenant(pool, tenantId, async (tx) => {
    const r = await tx.query<PolicyRow>(
      "SELECT id, version, body FROM policies WHERE tenant_id IS NULL ORDER BY version DESC LIMIT 1",
    );

    return r.rows[0] ?? null;
  });
}

/**
 * מדיניות הדייר, בלי שורות ששייכות למחשב.
 *
 * שתיהן נושאות tenant_id ויושבות באותה טבלה, ולכן בחירה לפי הגרסה
 * הגבוהה בלבד נוחתת על שכבה של מחשב מסוים ומתייחסת אליה כאילו
 * היא של הדייר כולו.
 */
export async function loadTenantPolicy(pool: pg.Pool, tenantId: string): Promise<PolicyRow | null> {
  return withTenant(pool, tenantId, async (tx) => {
    const r = await tx.query<PolicyRow>(
      `SELECT p.id, p.version, p.body FROM policies p
        WHERE p.tenant_id = $1
          AND NOT EXISTS (
            SELECT 1 FROM device_policy_assignments a WHERE a.policy_id = p.id
          )
        ORDER BY p.version DESC LIMIT 1`,
      [tenantId],
    );

    return r.rows[0] ?? null;
  });
}

/**
 * מה שהדייר רשאי לשנות, ולכן מה שנשמר כשהבסיס מתחלף.
 *
 * שני חלקים: כלל היציאה (egress) והגדרות הדפדפן (browser — יוטיוב
 * בשמע בלבד, הסתרת תמונות, ערוצים מותרים). שניהם נכתבים באותו מסך
 * ובאותה שמירה, ב-portal-egress.ts.
 *
 * browser לא היה כאן, וזו הייתה תקלה: השכבה נשאה egress בלבד,
 * הבסיס אינו מכיל browser כלל, ולכן הגוף המורכב יצא בלעדיו, נמצא
 * שונה ממה שהדייר מחזיק — ופורסם. כלומר כל עליית שרת מחקה לכל
 * דייר את הגדרות היוטיוב שלו, בשקט, ובגרסה חדשה וחתומה.
 *
 * חלק שחסר פירושו שהדייר מעולם לא נגע בו, ואז אין מה להרכיב מעל
 * הבסיס — הוא יקבל את מה שהבסיס אומר.
 */
const TENANT_OVERLAY_KEYS = ["egress", "browser"] as const;

/** מרכיב את גוף מדיניות הדייר: הבסיס, ומעליו השכבה של הדייר בלבד. */
export function composeTenantBody(
  base: Record<string, unknown>,
  own: Record<string, unknown> | null,
  hold: boolean,
): Record<string, unknown> {
  const ownEnforcement = ((own ?? {})["enforcement"] ?? {}) as Record<string, unknown>;
  const baseEnforcement = (base["enforcement"] ?? {}) as Record<string, unknown>;
  const baseAllowed = (baseEnforcement["allowedNetworks"] ?? {}) as Record<string, unknown>;

  const overlay: Record<string, unknown> = {};

  for (const key of TENANT_OVERLAY_KEYS) {
    if (ownEnforcement[key] != null) overlay[key] = ownEnforcement[key];
  }

  return {
    ...base,
    enforcement: {
      ...baseEnforcement,
      ...overlay,
      allowedNetworks: { ...baseAllowed, blockUntilApproved: hold },
    },
  };
}

/**
 * מפרסם את מדיניות הדייר מחדש מעל הבסיס, אם היא השתנתה.
 *
 * force מפרסם גם כשהתוכן זהה, וגם לדייר שעוד אין לו מדיניות משלו.
 * זה נדרש במקרה אחד: כשמחשב מאבד את השכבה שלו וחוזר למדיניות
 * הדייר, והמספר שלה נמוך ממה שהוא כבר מחזיק — ראה device-overlay.ts.
 *
 * מחזיר את הגרסה שפורסמה, או null כשלא היה מה לפרסם.
 */
export async function republishTenantPolicy(
  pool: pg.Pool,
  signer: Signer,
  tenantId: string,
  options: { force?: boolean; publishedBy?: string | null } = {},
): Promise<number | null> {
  const base = await loadGlobalPolicy(pool, tenantId);

  if (base === null) return null;

  const own = await loadTenantPolicy(pool, tenantId);

  if (own === null && options.force !== true) return null;

  const composed = composeTenantBody(
    base.body,
    own?.body ?? null,
    await blockUntilApproved(pool, tenantId),
  );

  if (options.force !== true && own !== null && sameBody(own.body, composed)) return null;

  const published = await publishAtNextVersion(pool, signer, {
    tenantId,
    body: composed,
    publishedBy: options.publishedBy ?? null,
  });

  return published.version;
}
