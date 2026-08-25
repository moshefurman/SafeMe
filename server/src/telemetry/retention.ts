/**
 * מתי שורת פעימה שווה שמירה.
 *
 * הכלל מופרד מנתיב ה-HTTP כדי שיהיה אפשר לבדוק אותו בלי שרת ובלי
 * בסיס נתונים, ובעיקר כדי שיהיה קריא: זו החלטת מוצר, לא פרט טכני.
 * ראה מיגרציה 0014 לנימוק המלא.
 */

/**
 * הפרש בציון שנחשב תזוזה אמיתית ולא רעש מדידה.
 *
 * הסף חייב להיות רחב מרוחב הרעש, ולא רק גדול ממנו במעט. ההשוואה
 * נעשית מול הערך האחרון שנשמר, ולכן דגימה שנחתה בקצה אחד של רצועת
 * הרעש הופכת לנקודת הייחוס: מכאן הקצה הנגדי חורג, נשמר, והופך
 * בעצמו לייחוס. סף צר גורם לשמירה לרדוף את עצמה — בסימולציה של
 * רעש ±3 סף של 5 הפיק 132 שורות ביממה במקום 24.
 *
 * 10 נבחר בלי נתוני שדה, ולכן sampleReason מחזיר סיבה ולא בוליאני:
 * אם בייצור יתברר ש-score הוא המקור העיקרי לנפח, יש מה למדוד ולפי
 * מה לכוונן. שינויי הסטטוס — שהם מה שבאמת חשוב — נתפסים בציר נפרד
 * ואינם תלויים בסף הזה כלל.
 */
export const SCORE_EPSILON = 10;

/** כל כמה זמן נשמרת שורה גם כשדבר לא השתנה. */
export const KEEPALIVE_MS = 60 * 60 * 1000;

export interface DeviceSnapshot {
  status: string;
  score: number | null;
  provider: string | null;
  lockoutActive: boolean;
  policyVersion: number | null;
  lastSampleAt: Date | null;
}

export interface HeartbeatFacts {
  status: string;
  score: number;
  provider: string | null;
  lockoutActive: boolean;
  policyVersion: number | null;
  hasTamperEvents: boolean;
}

export type SampleReason =
  | "first"
  | "status"
  | "score"
  | "provider"
  | "lockout"
  | "policy"
  | "tamper"
  | "keepalive"
  | "stale";

/**
 * מחזיר את הסיבה לשמירה, או null אם אין צורך בשורה.
 *
 * מוחזרת סיבה ולא בוליאני כדי שאפשר יהיה למדוד בייצור מה בעצם
 * מייצר את הנפח. בלי זה, כוונון היחס בעתיד יהיה ניחוש.
 */
export function sampleReason(
  prev: DeviceSnapshot | null,
  now: HeartbeatFacts,
  at: Date,
): SampleReason | null {
  // חבלה נשמרת תמיד, לפני כל שיקול אחר. אירוע חד-פעמי שנבלע
  // בדגימה הוא בדיוק מה שנחפש אחר כך ולא נמצא.
  if (now.hasTamperEvents) return "tamper";

  // פעימה שהגיעה מחוץ לסדר לא עדכנה את המצב, ולכן אין ממה לגזור
  // השוואה. נשמרת כראיה — היא נדירה ולא משפיעה על הנפח — אבל
  // מסומנת ככזו ולא כ"ראשונה", כדי שהמדידה תישאר נכונה.
  if (!prev) return "stale";

  // אין דגימה קודמת: אין מול מה להשוות, ולכן נשמר
  if (prev.lastSampleAt === null) return "first";

  if (prev.status !== now.status) return "status";
  if (prev.lockoutActive !== now.lockoutActive) return "lockout";
  if ((prev.provider ?? null) !== (now.provider ?? null)) return "provider";

  // גרסת מדיניות משתנה רק כשהוחלה מדיניות חדשה, וזו נקודת ציון
  // שחייבת להופיע בהיסטוריה כדי לקשור שינוי התנהגות לשינוי מדיניות
  if (now.policyVersion !== null && prev.policyVersion !== now.policyVersion) {
    return "policy";
  }

  if (prev.score === null || Math.abs(prev.score - now.score) >= SCORE_EPSILON) {
    return "score";
  }

  if (at.getTime() - prev.lastSampleAt.getTime() >= KEEPALIVE_MS) {
    return "keepalive";
  }

  return null;
}
