/**
 * לאן ההתראות הולכות, ועל מה.
 *
 * הופרד ממסלול ה-HTTP כדי שהכללים — מי מקבל, מתי שולחים, ומה קורה
 * בשעות שקט — יהיו לוגיקה טהורה שאפשר לבדוק בלי שרת. הם החלק
 * שקל לטעות בו בשקט.
 */

export type AlertChannel = "off" | "immediate" | "daily";

/** סוגי ההתראות. השמות זהים לעמודות בטבלה. */
export const ALERT_KINDS = [
  "on_device_silent",
  "on_unfiltered",
  "on_new_network",
  "on_tamper",
  "on_lockout",
] as const;

export type AlertKind = (typeof ALERT_KINDS)[number];

export interface NotificationSettings {
  primaryEmail: string;
  channels: Record<AlertKind, AlertChannel>;
  weeklyDigest: boolean;
  quietFrom: number | null;
  quietTo: number | null;
}

/**
 * התראות שאינן מכבדות שעות שקט.
 *
 * השעות שבהן ההורה ישן הן בדיוק השעות שבהן כדאי לנסות לחבל בתוכנה.
 * שקט הוא נוחות, ולא השתקה של מה שהמוצר קיים בשבילו.
 */
const IGNORES_QUIET_HOURS = new Set<AlertKind>(["on_tamper", "on_lockout"]);

/**
 * האם השעה נופלת בשעות השקט.
 *
 * החלון עשוי לחצות חצות (22 עד 7), ולכן ההשוואה מתפצלת. זו טעות
 * קלאסית: השוואה אחת מחזירה תמיד false בדיוק בחלון הנפוץ ביותר.
 */
export function isQuietHour(hour: number, from: number | null, to: number | null): boolean {
  if (from === null || to === null) return false;
  if (from === to) return false;

  return from < to
    ? hour >= from && hour < to
    : hour >= from || hour < to;
}

export type Delivery =
  | { send: "now" }
  | { send: "digest"; reason: "channel" | "quiet" }
  | { send: "never" };

/**
 * מה לעשות עם התראה אחת.
 *
 * שעות שקט דוחות ולא מוחקות: ההתראה תצא בסיכום, וההורה יראה שהיא
 * הייתה. התראה שנבלעה בשקט גרועה יותר מהתראה מאוחרת.
 */
export function decideDelivery(
  settings: NotificationSettings,
  kind: AlertKind,
  localHour: number,
): Delivery {
  const channel = settings.channels[kind];

  if (channel === "off") return { send: "never" };
  if (channel === "daily") return { send: "digest", reason: "channel" };

  if (!IGNORES_QUIET_HOURS.has(kind)
      && isQuietHour(localHour, settings.quietFrom, settings.quietTo)) {
    return { send: "digest", reason: "quiet" };
  }

  return { send: "now" };
}

/**
 * החלון שבו החלפת כתובת ממתינה.
 *
 * עשרים וארבע שעות אינן מספר שרירותי: הן מבטיחות שההורה יראה את
 * ההודעה במחזור קריאה אחד לפחות, גם אם היא הגיעה בזמן שהוא ישן.
 * חלון קצר יותר היה הופך את ההודעה לתיעוד של מה שכבר קרה.
 */
export const EMAIL_CHANGE_DELAY_MS = 24 * 60 * 60 * 1000;

/** מתי בקשה שהוגשה עכשיו תיכנס לתוקף. */
export function effectiveAt(now: Date): Date {
  return new Date(now.getTime() + EMAIL_CHANGE_DELAY_MS);
}

/**
 * הכתובות שמקבלות התראה בפועל.
 *
 * הראשית תמיד בפנים, גם אם היא מופיעה גם ברשימת הנוספות — ולכן
 * הכפילות מוסרת כאן ולא נסמכת על אילוץ במסד, שאינו יכול להשוות
 * בין שתי טבלאות.
 */
export function recipientsFor(
  primaryEmail: string,
  verifiedExtras: readonly string[],
): string[] {
  const seen = new Set<string>();
  const out: string[] = [];

  for (const address of [primaryEmail, ...verifiedExtras]) {
    const key = address.trim().toLowerCase();

    if (key === "" || seen.has(key)) continue;

    seen.add(key);
    out.push(address.trim());
  }

  return out;
}
