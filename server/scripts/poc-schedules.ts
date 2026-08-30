/**
 * חלונות הזמן: מהטבלה לכללים שהסוכן מבין.
 *
 * המנגנון בסוכן נבדק מזמן. מה שלא נבדק הוא הצד הזה — ההמרה, הניסוח,
 * וההנחות שהוא עושה על מה שהסוכן מצפה לו. שתי שפות שמסכימות על
 * פרוטוקול נוטות להיפרד בשקט, וכאן ההיפרדות פירושה חלון שההורה
 * הגדיר ושלא נאכף אף פעם.
 */

import { toRules, toHourMinute, describeSchedule, type ScheduleRow } from "../src/policy/schedules.ts";

let passed = 0;
let failed = 0;

function check(ok: boolean, title: string, detail = ""): void {
  if (ok) passed += 1;
  else failed += 1;

  console.log(`  ${ok ? "OK" : "!!"} ${title}${detail ? ` -- ${detail}` : ""}`);
}

function section(title: string): void {
  console.log("");
  console.log(title);
  console.log("-".repeat(64));
}

function row(over: Partial<ScheduleRow> = {}): ScheduleRow {
  return {
    id: "s1",
    days: [],
    from_time: "22:00:00",
    to_time: "07:00:00",
    label: null,
    enabled: true,
    ...over,
  };
}

section("1 · השעה");

check(toHourMinute("22:00:00") === "22:00", "שניות נחתכות");

/*
 * PostgreSQL מחזיר time עם שניות. הסוכן מפרש HH:mm, וגם אם השניות
 * לא היו מזיקות לו — הן מופיעות בכל מקום שבו הכלל מוצג, ושעה
 * שכתובה אחרת בשני מסכים נראית כמו שתי שעות.
 */
check(
  toRules([row()])[0]?.from === "22:00",
  "והכלל שנשלח נושא HH:mm בלבד",
  "זה מה שהסוכן מפרש",
);

section("2 · מה נשלח לסוכן");

check(toRules([row()]).length === 1, "חלון פעיל נשלח");

check(
  toRules([row({ enabled: false })]).length === 0,
  "חלון מושבת אינו נשלח כלל",
  "השארתו עם דגל הייתה מחייבת את הסוכן להכיר מושג נוסף, וסוכן ישן היה חוסם",
);

check(
  toRules([row()])[0]?.action === "BlockAll",
  "הפעולה היא חסימה מלאה",
);

/*
 * המספור חייב להישאר כפי שהוא. הסוכן משווה אותו מול DayOfWeek של
 * .NET, שבו 0 הוא ראשון — ותרגום בדרך היה חוסם ביום הלא נכון.
 */
check(
  JSON.stringify(toRules([row({ days: [0, 5] })])[0]?.days) === "[0,5]",
  "מספור הימים עובר כמו שהוא",
  "0 ראשון, 6 שבת — כמו DayOfWeek ב-.NET",
);

section("3 · הניסוח להורה");

check(
  describeSchedule(row({ days: [] })).startsWith("כל יום"),
  "רשימה ריקה היא כל יום",
);

check(
  describeSchedule(row({ days: [0, 1, 2, 3, 4, 5, 6] })).startsWith("כל יום"),
  "וגם שבעה ימים הם כל יום",
  "לא לספור שבעה שמות כשהמשמעות זהה",
);

check(
  describeSchedule(row({ days: [0, 2] })).includes("ראשון, שלישי"),
  "ימים בודדים נאמרים בשמם",
);

/*
 * חלון שחוצה חצות נקרא כטווח ריק אם לא אומרים זאת. "22:00 עד 07:00"
 * נראה הפוך, וההורה שמגדיר שעת שינה עושה בדיוק את זה.
 */
check(
  describeSchedule(row({ from_time: "22:00:00", to_time: "07:00:00" })).includes("למחרת"),
  "חלון שחוצה חצות נאמר במפורש",
);

check(
  !describeSchedule(row({ from_time: "14:00:00", to_time: "16:00:00" })).includes("למחרת"),
  "וחלון רגיל אינו",
);

console.log("");
console.log("=".repeat(64));
console.log(`עברו ${passed} · נכשלו ${failed}`);
console.log("=".repeat(64));

process.exit(failed === 0 ? 0 : 1);
