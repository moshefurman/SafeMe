/**
 * מנגנון איש-מת: מכשיר ששותק.
 *
 * זו ההגנה היחידה שאינה תלויה בכך שהסוכן שרד. כל שאר המנגנונים
 * מדווחים על מה שקרה בזמן שהתוכנה פעלה; זה מדווח על כך שהיא הפסיקה.
 *
 * העיקרון: **שתיקה היא אזעקה, לא היעדר אזעקה.** מכשיר שדיווח כל
 * שלוש דקות ואז נעלם הוא אירוע — בין אם הקבצים נמחקו, השירות נעצר,
 * או הרשת נותקה. אין צורך לחזות כל דרך השבתה.
 *
 * הלוגיקה מופרדת מהשאילתה כדי שתהיה נבדקת בלי בסיס נתונים.
 */

export type DeadManState = "healthy" | "late" | "missing" | "offline" | "tampered";

/**
 * הספים.
 *
 * מרווח הפעימה הוא שלוש דקות עם ריצוד. עשר דקות הן שלוש פעימות
 * שהוחמצו — מספיק כדי לא להתריע על רשת שנפלה לרגע, ומעט מספיק כדי
 * שהמצב יופיע בדשבורד בזמן אמת.
 */
export const LATE_MINUTES = 10;

/**
 * חצי שעה. מכאן זו כבר לא תקלה רגעית, וההורה מקבל התראה.
 *
 * נבחר גם כדי לא להתריע על כל כיבוי צהריים: מחשב שכובה בשתיים
 * וחוזר בארבע ייצור התראה, וזה מכוון — ההורה צריך לדעת שהמחשב היה
 * כבוי, כי זו גם הדרך להסתיר.
 */
export const MISSING_MINUTES = 30;

/** יממה. המכשיר כנראה כבר לא יחזור מעצמו. */
export const OFFLINE_HOURS = 24;

export interface DeviceSilence {
  deviceId: string;
  lastSeenAt: Date | null;
  currentHealth: DeadManState;
}

export interface Transition {
  deviceId: string;
  from: DeadManState;
  to: DeadManState;
  silentMinutes: number;
  /** האם המעבר הזה מצדיק התראה חדשה להורה. */
  raisesAlert: boolean;
}

/**
 * קובע את המצב הנכון לפי משך השתיקה.
 *
 * 'tampered' אינו מוחזר כאן: הוא נקבע מאירועי חבלה ולא מזמן, ואסור
 * שספירת דקות תדרוס אותו.
 */
export function stateFor(silentMinutes: number): DeadManState {
  if (silentMinutes >= OFFLINE_HOURS * 60) return "offline";
  if (silentMinutes >= MISSING_MINUTES) return "missing";
  if (silentMinutes >= LATE_MINUTES) return "late";

  return "healthy";
}

/**
 * מחשב את המעברים הנדרשים.
 *
 * מכשיר שמעולם לא דיווח מדולג: הוא נרשם ועדיין לא הותקן, ואין
 * להתריע על התקנה שלא הושלמה כאילו היא חבלה.
 */
export function computeTransitions(
  devices: readonly DeviceSilence[],
  now: Date,
): Transition[] {
  const transitions: Transition[] = [];

  for (const device of devices) {
    if (device.lastSeenAt === null) continue;

    // מצב שנקבע מחבלה גובר על ספירת זמן, וזמן לא יבטל אותו
    if (device.currentHealth === "tampered") continue;

    const silentMinutes = Math.floor(
      (now.getTime() - device.lastSeenAt.getTime()) / 60_000,
    );

    const next = stateFor(silentMinutes);

    if (next === device.currentHealth) continue;

    transitions.push({
      deviceId: device.deviceId,
      from: device.currentHealth,
      to: next,
      silentMinutes,

      // התראה נפתחת במעבר להיעדרות, ולא בכל שינוי. חזרה לתקינות
      // או הסלמה מ-missing ל-offline אינן אירוע חדש — הראשונה היא
      // סיום, והשנייה היא אותו אירוע שנמשך.
      raisesAlert: next === "missing" && device.currentHealth !== "offline",
    });
  }

  return transitions;
}

/**
 * נוסח ההתראה, בשפה שהורה מבין בלי הסבר.
 *
 * שעות מוצגות עם שבר. עיגול כלפי מטה הפך 90 דקות ל"שעה", וזו
 * הטעיה: ההפרש בין שעה לשעה וחצי הוא בדיוק מה שההורה שוקל.
 */
export function describeSilence(minutes: number): string {
  if (minutes < 60) return `המחשב לא דיווח כבר ${minutes} דקות.`;

  if (minutes < 1440) {
    const hours = minutes / 60;
    const text = Number.isInteger(hours) ? String(hours) : hours.toFixed(1);

    return hours === 1
      ? "המחשב לא דיווח כבר שעה."
      : `המחשב לא דיווח כבר ${text} שעות.`;
  }

  const days = Math.floor(minutes / 1440);

  return days === 1
    ? "המחשב לא דיווח כבר יממה."
    : `המחשב לא דיווח כבר ${days} ימים.`;
}
