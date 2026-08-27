/**
 * חומרת אירוע לפי סוגו.
 *
 * החומרה קובעת מה בולט להורה ומה נבלע ברשימה. עד כה כל אירוע חבלה
 * נשמר כ-warning, מה שהשווה בין "אייקון המגש נסגר" לבין "המחשב פעל
 * שעתיים בלי הגנה" — ואת השני אסור להחמיץ.
 */

export type Severity = "info" | "warning" | "critical";

/**
 * אירועים שמשמעותם שההגנה לא פעלה בפועל, ולא שמישהו ניסה משהו.
 * ההבחנה חשובה: ניסיון שנחסם הוא מידע, הצלחה היא אירוע.
 */
const CRITICAL = new Set([
  // תקופה שבה המחשב פעל והסוכן לא. הראיה החזקה ביותר להשבתה.
  "CoverageGap",
  // חוקי האכיפה נעלמו מהמערכת
  "WfpFiltersMissing",
  // מדיניות שנחתמה במפתח לא נכון — שרת מזויף או פגיעה במפתח
  "PolicySignatureInvalid",
  // קובץ המצב נעלם או שונה
  "StateFileMissing",
  "StateFileTampered",
  // השעון הוזז אחורה, לרוב כדי לעקוף תוקף
  "ClockRolledBack",
]);

/** ניסיונות שנחסמו, או מצבים חולפים. מידע, לא אזעקה. */
const INFO = new Set([
  "TrayAppKilled",
  "ServiceCrash",
]);

export function severityFor(kind: string): Severity {
  if (CRITICAL.has(kind)) return "critical";
  if (INFO.has(kind)) return "info";

  return "warning";
}
