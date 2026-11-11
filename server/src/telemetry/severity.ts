/**
 * חומרת אירוע לפי סוגו.
 *
 * החומרה קובעת מה בולט להורה ומה נבלע ברשימה. עד כה כל אירוע חבלה
 * נשמר כ-warning, מה שהשווה בין "אייקון המגש נסגר" לבין "המחשב פעל
 * שעתיים בלי הגנה" — ואת השני אסור להחמיץ.
 */

export type Severity = "info" | "warning" | "critical";

// ---------------------------------------------------------------- שם קנוני

/**
 * שם אירוע החבלה בצורתו האחת: snake_case, כמו שאר המסד.
 *
 * שלוש צורות כתיב חיו כאן זו לצד זו בלי שאיש שם לב: הסוכן משדר את
 * ה-enum שלו ב-camelCase ("trayAppKilled"), הרשימות כאן נכתבו
 * ב-PascalCase כמו ב-C#, והפורטל מתרגם ב-snake_case כמו העמודות.
 * שום השוואה לא התאימה: כל אירוע קיבל "אזהרה" כברירת מחדל, אירוע
 * מידע העיר הורים במייל עם שם באנגלית, ואירוע קריטי לא בלט.
 *
 * ההמרה מקבלת כל אחת מהצורות ומחזירה אחת. שם שאינו מוכר עובר את
 * אותה המרה ונשאר לא מוכר — הוא מוצג בשמו, לא נבלע.
 */
export function canonicalTamperKind(kind: string): string {
  return kind
    .trim()
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[\s-]+/g, "_")
    .toLowerCase();
}

/**
 * אירועים שמשמעותם שההגנה לא פעלה בפועל, ולא שמישהו ניסה משהו.
 * ההבחנה חשובה: ניסיון שנחסם הוא מידע, הצלחה היא אירוע.
 */
const CRITICAL = new Set([
  // תקופה שבה המחשב פעל והסוכן לא. הראיה החזקה ביותר להשבתה.
  "coverage_gap",
  // חוקי האכיפה נעלמו מהמערכת
  "wfp_filters_missing",
  // מדיניות שנחתמה במפתח לא נכון — שרת מזויף או פגיעה במפתח
  "policy_signature_invalid",
  // קובץ המצב נעלם או שונה
  "state_file_missing",
  "state_file_tampered",
  // השעון הוזז אחורה, לרוב כדי לעקוף תוקף
  "clock_rolled_back",

  /*
   * המחשב מתקרב לפקיעת התוקף.
   *
   * קריטי ולא אזהרה, ובכוונה. זו ההודעה האחרונה לפני שהאכיפה
   * משוחררת מאליה — אחריה המחשב אינו מוגן, ואין הודעה נוספת כי
   * מחשב שאינו מדבר עם השרת אינו יכול לדווח דבר.
   *
   * אירוע שאין אחריו הזדמנות שנייה שייך לרמה הגבוהה.
   */
  "offline_expiry_near",
]);

/** ניסיונות שנחסמו, או מצבים חולפים. מידע, לא אזעקה. */
const INFO = new Set([
  "tray_app_killed",
  "service_crash",
]);

export function severityFor(kind: string): Severity {
  const canonical = canonicalTamperKind(kind);

  if (CRITICAL.has(canonical)) return "critical";
  if (INFO.has(canonical)) return "info";

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
  coverage_gap: "המחשב פעל בזמן שההגנה לא פעלה",
  wfp_filters_missing: "חוקי האכיפה נעלמו מהמערכת",
  policy_signature_invalid: "התקבלה מדיניות עם חתימה לא תקינה",
  state_file_missing: "קובץ המצב של ההגנה נעלם",
  state_file_tampered: "קובץ המצב של ההגנה שונה",
  clock_rolled_back: "שעון המחשב הוזז אחורה",
  offline_expiry_near: "המחשב מנותק מהשרת זמן רב, וההגנה מתקרבת לפקיעה",
  service_stop_attempt: "ניסיון לעצור את שירות ההגנה. נחסם",
  uninstall_brute_force: "ניסיונות חוזרים לנחש קוד הסרה",
  bfe_unavailable: "שירות הסינון של Windows אינו זמין",
  promotion_attempted: "ניסיון להעלות הרשאות. נחסם",
  tray_app_killed: "אייקון המגש נסגר",
  service_crash: "שירות ההגנה קרס והופעל מחדש",
  browser_policy_tampered: "הגדרות תוסף הדפדפן שונו מחוץ לתוכנה. הוחזרו",
  dns_redirect_tampered: "הפניית ה-DNS של הרשימה הלבנה נמחקה. הוחזרה",
};

export function describeTamper(kind: string, detail: string | null | undefined): string {
  const canonical = canonicalTamperKind(kind);
  const text = TAMPER_TEXT[canonical] ?? `אירוע חבלה: ${canonical}`;
  const extra = detail?.trim();

  return extra ? `${text}. ${extra.slice(0, 200)}` : `${text}.`;
}
