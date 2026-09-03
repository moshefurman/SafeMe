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

  /*
   * המחשב מתקרב לפקיעת התוקף.
   *
   * קריטי ולא אזהרה, ובכוונה. זו ההודעה האחרונה לפני שהאכיפה
   * משוחררת מאליה — אחריה המחשב אינו מוגן, ואין הודעה נוספת כי
   * מחשב שאינו מדבר עם השרת אינו יכול לדווח דבר.
   *
   * אירוע שאין אחריו הזדמנות שנייה שייך לרמה הגבוהה.
   */
  "OfflineExpiryNear",
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

// ---------------------------------------------------------------- נוסח להורה

/**
 * מה אירוע חבלה אומר, במילים של הורה.
 *
 * השמות באנגלית הם של המהנדס שכתב את הסוכן. ההורה מקבל אותם במייל,
 * ו-"ServiceStopAttempt" אינו אומר לו אם לדאוג. הנוסח כאן אומר גם
 * מה קרה וגם אם זה נחסם — כי ההבדל בין ניסיון שנכשל להצלחה הוא
 * ההבדל בין "שים לב" ל"המחשב לא מוגן".
 */
const TAMPER_TEXT: Record<string, string> = {
  CoverageGap: "המחשב פעל בזמן שההגנה לא פעלה",
  WfpFiltersMissing: "חוקי האכיפה נעלמו מהמערכת",
  PolicySignatureInvalid: "התקבלה מדיניות עם חתימה לא תקינה",
  StateFileMissing: "קובץ המצב של ההגנה נעלם",
  StateFileTampered: "קובץ המצב של ההגנה שונה",
  ClockRolledBack: "שעון המחשב הוזז אחורה",
  OfflineExpiryNear: "המחשב מנותק מהשרת זמן רב, וההגנה מתקרבת לפקיעה",
  ServiceStopAttempt: "ניסיון לעצור את שירות ההגנה. נחסם",
  UninstallBruteForce: "ניסיונות חוזרים לנחש קוד הסרה",
  BfeUnavailable: "שירות הסינון של Windows אינו זמין",
  PromotionAttempted: "ניסיון להעלות הרשאות. נחסם",
  TrayAppKilled: "אייקון המגש נסגר",
  ServiceCrash: "שירות ההגנה קרס והופעל מחדש",
};

export function describeTamper(kind: string, detail: string | null | undefined): string {
  const text = TAMPER_TEXT[kind] ?? `אירוע חבלה: ${kind}`;
  const extra = detail?.trim();

  return extra ? `${text}. ${extra.slice(0, 200)}` : `${text}.`;
}
