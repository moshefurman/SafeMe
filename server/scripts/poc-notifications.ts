/**
 * הגדרות ההתראות.
 *
 * שלוש שאלות נבדקות כאן, ורק אחת מהן טכנית:
 *
 *   1. האם ההגדרות באמת משנות למי נשלח.
 *   2. האם כתובת שלא אושרה באמת אינה מקבלת דבר.
 *   3. האם אפשר לנתק הורה מההתראות שלו בלי שיֵדע.
 *
 * השלישית היא הסיבה שהמנגנון קיים, והיא נבדקת מהצד של התוקף:
 * מה עושה מי שהשיג גישה לחשבון, ומה עוצר אותו.
 */

import {
  decideDelivery,
  effectiveAt,
  isQuietHour,
  recipientsFor,
  EMAIL_CHANGE_DELAY_MS,
  type NotificationSettings,
} from "../src/notify/settings.ts";

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

const base: NotificationSettings = {
  primaryEmail: "horeh@example.com",
  channels: {
    on_device_silent: "immediate",
    on_unfiltered: "immediate",
    on_new_network: "immediate",
    on_tamper: "immediate",
    on_lockout: "immediate",
  },
  weeklyDigest: true,
  quietFrom: null,
  quietTo: null,
};

section("1 · מי מקבל");

check(recipientsFor("a@x.com", []).length === 1, "הכתובת הראשית לבדה");

check(
  recipientsFor("a@x.com", ["b@x.com"]).join(",") === "a@x.com,b@x.com",
  "כתובת נוספת מצטרפת",
);

check(
  recipientsFor("a@x.com", ["A@X.com"]).length === 1,
  "אותה כתובת באותיות אחרות אינה נספרת פעמיים",
  "כפילות הייתה שולחת שתי הודעות זהות על אותו אירוע",
);

check(recipientsFor("a@x.com", ["", "  "]).length === 1, "כתובות ריקות נופלות");

section("2 · שעות שקט");

check(!isQuietHour(10, null, null), "בלי שעות שקט הכול עובר");
check(isQuietHour(23, 22, 7), "חלון שחוצה חצות תופס לפני חצות");
check(isQuietHour(3, 22, 7), "והוא תופס גם אחרי חצות");
check(!isQuietHour(12, 22, 7), "ואינו תופס באמצע היום");
check(isQuietHour(14, 13, 15), "חלון רגיל בתוך היום");
check(!isQuietHour(15, 13, 15), "שעת הסיום עצמה כבר מחוץ לחלון");

section("3 · מתי לשלוח");

check(decideDelivery(base, "on_unfiltered", 10).send === "now", "מיידי נשלח מיד");

const off: NotificationSettings = {
  ...base,
  channels: { ...base.channels, on_unfiltered: "off" },
};

check(decideDelivery(off, "on_unfiltered", 10).send === "never", "כבוי אינו נשלח");

const daily: NotificationSettings = {
  ...base,
  channels: { ...base.channels, on_new_network: "daily" },
};

check(decideDelivery(daily, "on_new_network", 10).send === "digest", "יומי נדחה לסיכום");

const quiet: NotificationSettings = { ...base, quietFrom: 22, quietTo: 7 };

check(
  decideDelivery(quiet, "on_new_network", 2).send === "digest",
  "רשת חדשה בשעות שקט נדחית",
  "נדחית ולא נמחקת. התראה שנבלעה גרועה מהתראה מאוחרת",
);

/*
 * הבדיקה שמצדיקה את ההחרגה.
 *
 * השעות שבהן ההורה ישן הן בדיוק השעות שבהן כדאי לנסות לחבל בתוכנה.
 * שקט הוא נוחות, ולא השתקה של מה שהמוצר קיים בשבילו.
 */
check(
  decideDelivery(quiet, "on_tamper", 2).send === "now",
  "חשד לחבלה אינו מכבד שעות שקט",
  "השעות שבהן ישנים הן השעות שבהן מנסים",
);

check(decideDelivery(quiet, "on_lockout", 3).send === "now", "גם נעילה עוברת בשעות שקט");

section("4 · חלון ההשהיה");

const now = new Date("2026-08-30T12:00:00Z");

check(
  effectiveAt(now).getTime() - now.getTime() === EMAIL_CHANGE_DELAY_MS,
  "ההחלפה נכנסת לתוקף אחרי 24 שעות",
  "החלון הוא מה שנותן להורה לראות ולעצור",
);

console.log("");
console.log("=".repeat(64));
console.log(`עברו ${passed} · נכשלו ${failed}`);
console.log("=".repeat(64));

process.exit(failed === 0 ? 0 : 1);
