/**
 * חלונות זמן שבהם המחשב חסום.
 *
 * המנגנון קיים בסוכן מזמן — ScheduleRule עם ימים ושעות, ובודק
 * האכיפה שמכריע לפיו. מה שלא היה הוא דרך להגדיר אותו.
 *
 * החלונות נשמרים בטבלה, והמדיניות החתומה **נגזרת** מהם ומתפרסמת
 * מחדש בכל שינוי. כלומר הטבלה היא הכוונה של ההורה, והמדיניות היא
 * תוצר שאפשר לבנות מחדש ממנה בכל רגע.
 */

import type pg from "pg";

/** יום בשבוע לפי DayOfWeek של .NET: 0 ראשון עד 6 שבת. */
export type Weekday = 0 | 1 | 2 | 3 | 4 | 5 | 6;

export interface ScheduleRow {
  id: string;
  days: number[];
  from_time: string;
  to_time: string;
  label: string | null;
  enabled: boolean;
}

/** הצורה שהסוכן מצפה לה ב-PolicyBundle.Enforcement.Schedules. */
export interface ScheduleRule {
  id: string;
  days: number[];
  from: string;
  to: string;
  action: "BlockAll";
}

/**
 * חותך שניות מהשעה.
 *
 * PostgreSQL מחזיר time כ-"22:00:00", והסוכן מפרש HH:mm. השניות
 * אינן מזיקות ל-TimeSpan.TryParse, אבל הן מופיעות בכל מקום שבו
 * הכלל מוצג — ושעה שכתובה אחרת בשני מסכים נראית כמו שתי שעות.
 */
export function toHourMinute(value: string): string {
  return value.slice(0, 5);
}

/**
 * ממיר שורות לכללים שהסוכן מבין.
 *
 * חלונות מושבתים אינם מומרים כלל. השארתם עם דגל הייתה מחייבת את
 * הסוכן להכיר מושג נוסף, וסוכן ישן היה מתעלם מהדגל וחוסם.
 */
export function toRules(rows: readonly ScheduleRow[]): ScheduleRule[] {
  return rows
    .filter((row) => row.enabled)
    .map((row) => ({
      id: row.id,
      days: row.days,
      from: toHourMinute(row.from_time),
      to: toHourMinute(row.to_time),
      action: "BlockAll" as const,
    }));
}

export async function loadSchedules(
  tx: { query: pg.ClientBase["query"] },
  deviceId: string,
): Promise<ScheduleRow[]> {
  const r = await tx.query<ScheduleRow>(
    `SELECT id, days, from_time::text, to_time::text, label, enabled
       FROM device_schedules
      WHERE device_id = $1
      ORDER BY from_time`,
    [deviceId],
  );

  return r.rows;
}

const DAY_NAMES = ["ראשון", "שני", "שלישי", "רביעי", "חמישי", "שישי", "שבת"];

/**
 * מנסח חלון בשפה שהורה קורא.
 *
 * החלון עשוי לחצות חצות — "22:00 עד 06:00" — וזה מבלבל כשקוראים
 * אותו כטווח רגיל. הניסוח אומר זאת במפורש במקום להשאיר את הקורא
 * להסיק.
 */
export function describeSchedule(row: ScheduleRow): string {
  const days = row.days.length === 0
    ? "כל יום"
    : row.days.length === 7
      ? "כל יום"
      : row.days.map((d) => DAY_NAMES[d] ?? "?").join(", ");

  const from = toHourMinute(row.from_time);
  const to = toHourMinute(row.to_time);

  const crosses = from > to;

  return crosses
    ? `${days}, מ-${from} עד ${to} למחרת`
    : `${days}, מ-${from} עד ${to}`;
}
