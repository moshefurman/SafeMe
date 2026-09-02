import type pg from "pg";

import { withPlatform } from "../db/client.ts";

/**
 * מה מותר לחשבון הזה, ומה נשאר לו.
 *
 * שני מנגנונים נפרדים שמשרתים את אותה מטרה: להפוך "מה מותר" לנתון
 * ולא לקוד, כדי שמכירת יכולת לא תדרוש פריסה.
 */

const SYSTEM = {
  userId: "00000000-0000-0000-0000-000000000000",
  reason: "בדיקת יכולות",
};

/**
 * הרשימה הסגורה.
 *
 * המסד שומר מערך טקסט, שאינו מאמת דבר. האימות כאן: יכולת שאינה
 * ברשימה נדחית בכתיבה, אחרת שגיאת הקלדה במסך הייתה יוצרת יכולת
 * שאיש לא בודק אותה לעולם — והיא הייתה נראית כמו הרשאה שקיימת.
 */
export const FEATURES = ["per_device_policy"] as const;

export type Feature = (typeof FEATURES)[number];

export function isFeature(value: string): value is Feature {
  return (FEATURES as readonly string[]).includes(value);
}

/**
 * האם לחשבון יש את היכולת.
 *
 * נקראת מהמנוי ולא מהתוכנית: לקוח שקנה תוכנית שכללה אותה ממשיך
 * לקבל אותה גם אחרי שהתוכנית שונתה. קריאה מהתוכנית הייתה שוללת
 * יכולת מלקוח קיים בשקט, וזו בעיה חוקית ולא רק הוגנות.
 *
 * דייר ריק פירושו משתמש פלטפורמה — צוות החברה אינו כפוף למנוי.
 */
export async function hasFeature(
  pool: pg.Pool,
  tenantId: string | null,
  feature: Feature,
): Promise<boolean> {
  if (tenantId === null) return true;

  return withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ ok: boolean }>(
      `SELECT ($2 = ANY(features)) AS ok
         FROM subscriptions
        WHERE tenant_id = $1 AND status <> 'canceled'`,
      [tenantId, feature],
    );

    return r.rows[0]?.ok ?? false;
  });
}

// ---------------------------------------------------------------- קרדיט

export interface CreditState {
  balance: number;
}

/**
 * היתרה, כסכום הספר.
 *
 * ולא מונה שמתעדכן: מונה עונה "כמה נשאר" ואינו עונה "למה", וכשלקוח
 * יטען שנגבה ממנו פעמיים אין ממה לענות. סכום על ספר תנועות אינו
 * יכול להתנתק מהמציאות, כי הוא המציאות.
 */
export async function creditBalance(pool: pg.Pool, tenantId: string): Promise<number> {
  return withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ balance: string }>(
      "SELECT COALESCE(sum(amount), 0)::text AS balance FROM credit_entries WHERE tenant_id = $1",
      [tenantId],
    );

    return Number(r.rows[0]?.balance ?? 0);
  });
}

/**
 * צריכת קרדיט לפעולה.
 *
 * מחזיר true כשנצרך, ו-false כשאין מספיק. הבדיקה והרישום בשאילתה
 * אחת: שתי פעולות נפרדות פותחות חלון שבו שתי בקשות רואות אותה
 * יתרה ושתיהן צורכות — וקרדיט שירד לשלילי הוא בדיוק מה שאי אפשר
 * להסביר ללקוח.
 */
export async function spendCredit(
  pool: pg.Pool,
  tenantId: string,
  amount: number,
  reason: string,
): Promise<boolean> {
  if (amount <= 0) throw new Error("צריכת קרדיט חייבת להיות חיובית.");

  return withPlatform(pool, SYSTEM, async (tx) => {
    /*
     * נעילת השורות של הדייר לפני הסכימה.
     *
     * FOR UPDATE על התנועות הקיימות מונע משתי בקשות מקבילות לקרוא
     * את אותה יתרה. בלי זה, שני שינויים שנשלחו יחד היו עוברים
     * שניהם על קרדיט אחד.
     */
    const current = await tx.query<{ balance: string }>(
      `SELECT COALESCE(sum(amount), 0)::text AS balance
         FROM credit_entries WHERE tenant_id = $1 FOR UPDATE`,
      [tenantId],
    );

    if (Number(current.rows[0]?.balance ?? 0) < amount) return false;

    await tx.query(
      "INSERT INTO credit_entries (tenant_id, amount, reason) VALUES ($1, $2, $3)",
      [tenantId, -amount, reason],
    );

    return true;
  });
}

/** הוספת קרדיט. מנהל פלטפורמה בלבד — הקריאה מגיעה ממסלול מוגן. */
export async function grantCredit(
  pool: pg.Pool,
  tenantId: string,
  amount: number,
  reason: string,
  actorId: string,
): Promise<void> {
  if (amount <= 0) throw new Error("הוספת קרדיט חייבת להיות חיובית.");

  await withPlatform(pool, { userId: actorId, reason: "הוספת קרדיט" }, async (tx) => {
    await tx.query(
      `INSERT INTO credit_entries (tenant_id, amount, reason, actor_id)
       VALUES ($1, $2, $3, $4)`,
      [tenantId, amount, reason, actorId],
    );
  });
}
