import type pg from "pg";

import { withPlatform } from "../db/client.ts";
import { evaluateTrial, type BillingPlan } from "./trial.ts";

/**
 * האם החשבון רשאי להוסיף ולשנות.
 *
 * עד כה evaluateTrial שימש לתצוגה בלבד: הבאנר בפורטל אמר שהניסיון
 * נגמר, ושום דבר לא קרה. חשבון שפג לפני חודשיים המשיך לרשום
 * מחשבים כאילו כלום.
 *
 * ---
 *
 * מה שנחסם ומה שלא, וזו ההחלטה המרכזית כאן.
 *
 * **ההגנה על מחשבים קיימים אינה נפסקת לעולם.** ילד שההגנה נעלמה
 * ממנו כי אבא שכח לשלם הוא בדיוק הכישלון שהמוצר קיים כדי למנוע,
 * והוא גם מה שיגרום לכך שאיש לא יסמוך עליו. השרת אינו מפרק הגנה
 * מרחוק בשום מצב.
 *
 * מה שכן נחסם הוא **הרחבה**: רישום מחשבים חדשים וקישורי התקנה
 * חדשים. זה מספיק כדי שהמנוי יהיה שווה משהו, ואינו פוגע באיש
 * שכבר מוגן.
 *
 * וקריאה נשארת פתוחה תמיד. חשבון שאינו יכול לראות את מצבו אינו
 * יכול גם להבין למה לשלם.
 */

export interface BillingVerdict {
  /** true כשמותר להרחיב: מחשב חדש, קישור חדש. */
  mayExpand: boolean;

  /** הסבר להצגה, כשאסור. */
  reason: string | null;
}

const ALLOWED = { mayExpand: true, reason: null } as const;

/**
 * <paramref name="tenantId"/> ריק פירושו משתמש פלטפורמה — צוות
 * החברה אינו כפוף לחיוב, והוא גם מי שמטפל בלקוח שנתקע.
 */
export async function billingVerdict(
  pool: pg.Pool,
  tenantId: string | null,
  now: Date = new Date(),
): Promise<BillingVerdict> {
  if (tenantId === null) return ALLOWED;

  const row = await withPlatform(
    pool,
    { userId: "00000000-0000-0000-0000-000000000000", reason: "בדיקת מצב חיוב" },
    async (tx) => {
      const r = await tx.query<{
        plan: BillingPlan;
        trial_ends_at: Date | null;
        paid_until: Date | null;
      }>(
        "SELECT plan, trial_ends_at, paid_until FROM tenants WHERE id = $1",
        [tenantId],
      );

      return r.rows[0] ?? null;
    },
  );

  /*
   * דייר שאינו נמצא אינו נחסם כאן.
   *
   * זה מצב שאינו אמור לקרות, והמסלולים עצמם כבר מסננים לפי דייר.
   * חסימה על סמך שאילתה שלא החזירה שורה הייתה הופכת תקלת מסד
   * רגעית לחסימת לקוחות.
   */
  if (row === null) return ALLOWED;

  const trial = evaluateTrial(
    { plan: row.plan, trialEndsAt: row.trial_ends_at, paidUntil: row.paid_until },
    now,
  );

  /*
   * שבוע החסד עדיין מתיר הכול.
   *
   * הוא קיים בדיוק בשביל מי ששכח, ולחסום בתוכו זה להעניש על
   * איחור של יום. מה שנחסם הוא רק אחרי שגם הוא נגמר.
   */
  if (trial.phase === "trial_expired") {
    return {
      mayExpand: false,
      reason: "תקופת הניסיון הסתיימה. המחשבים ממשיכים להיות מוגנים, "
        + "אך אי אפשר להוסיף מחשבים חדשים עד חידוש המנוי.",
    };
  }

  if (trial.phase === "canceled") {
    return {
      mayExpand: false,
      reason: "המנוי בוטל. המחשבים ממשיכים להיות מוגנים, "
        + "אך אי אפשר להוסיף מחשבים חדשים.",
    };
  }

  return ALLOWED;
}
