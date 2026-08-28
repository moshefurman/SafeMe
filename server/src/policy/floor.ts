/**
 * השוואת רצפות מדיניות.
 *
 * הרצפה היא ההבטחה שהמכשיר נושא איתו: אף מדיניות, ואף רישום חוזר,
 * לא יורידו אותו מתחתיה. זהו המחגר שמונע משרת שנפרץ — או מקישור
 * התקנה שדלף — להקל על מכשיר שכבר מוגן.
 *
 * הסולמות מסודרים מהמקל למחמיר, ולכן השוואה היא השוואת אינדקסים.
 */

export interface PolicyFloor {
  mode?: string;
  onRedAction?: string;
  minScoreForGreen?: number;
  minScoreForYellow?: number;
}

const MODES = ["monitor", "warn", "enforce"];
const ACTIONS = ["none", "warn", "lockout"];

/** מקום בסולם. ערך שאינו מוכר נחשב למקל ביותר, ולכן לא יחמיר בטעות. */
function rank(scale: readonly string[], value: string | undefined): number {
  const index = scale.indexOf((value ?? "").toLowerCase());

  return index < 0 ? 0 : index;
}

/**
 * האם המועמדת מחמירה לפחות כמו הקיימת.
 *
 * היעדר רצפה קיימת הוא מכשיר חדש, וכל רצפה מתקבלת. זו אינה הרפיה:
 * אין ממה להקל.
 */
export function isAtLeastAsStrict(
  candidate: PolicyFloor | undefined,
  current: PolicyFloor | undefined,
): boolean {
  if (current === undefined || current === null) return true;
  if (candidate === undefined || candidate === null) return false;

  if (rank(MODES, candidate.mode) < rank(MODES, current.mode)) return false;
  if (rank(ACTIONS, candidate.onRedAction) < rank(ACTIONS, current.onRedAction)) return false;

  /*
   * ספי הציון: גבוה יותר הוא מחמיר יותר, כי הוא דורש יותר כדי
   * להיחשב תקין. סף חסר נחשב לאפס — המקל ביותר.
   */
  if ((candidate.minScoreForGreen ?? 0) < (current.minScoreForGreen ?? 0)) return false;
  if ((candidate.minScoreForYellow ?? 0) < (current.minScoreForYellow ?? 0)) return false;

  return true;
}
