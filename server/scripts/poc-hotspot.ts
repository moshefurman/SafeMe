/**
 * זיהוי נקודה חמה סלולרית.
 *
 * דרך העקיפה מספר אחת. הבדיקות בנויות סביב שני כשלים אפשריים:
 * להחמיץ נקודה חמה אמיתית, ולסמן רשת ביתית לגיטימית בטעות. השני
 * גרוע יותר — הורה שיקבל התראות שווא ילמד לאשר הכול.
 */

import {
  classifyHotspot,
  isLocallyAdministered,
  normalizeMac,
  shouldBlockOutright,
  type NetworkFingerprint,
} from "../src/network/hotspot.ts";

let passed = 0;
let failed = 0;

function check(ok: boolean, name: string, detail = ""): void {
  if (ok) {
    passed++;
    console.log(`  ✓ ${name}${detail ? `\n      ${detail}` : ""}`);
  } else {
    failed++;
    console.log(`  ✗ ${name}${detail ? `\n      ${detail}` : ""}`);
  }
}

function section(title: string): void {
  console.log(`\n${title}`);
  console.log("─".repeat(64));
}

// ─────────────────────────────────────── מה שחייב להיתפס
section("1 · נקודות חמות אמיתיות");

const iphone: NetworkFingerprint = {
  ssid: "iPhone של יוסי",
  gatewayIp: "172.20.10.1",
  gatewayMac: "AC:BC:32:11:22:33",
};

const v1 = classifyHotspot(iphone);
check(v1.confidence === "certain", "iPhone: שער, שם וחומרה", v1.summary);
check(shouldBlockOutright(v1), "ודאות מצדיקה חסימה אוטומטית");

const android = classifyHotspot({
  ssid: "AndroidAP",
  gatewayIp: "192.168.43.1",
});
check(android.confidence === "certain", "אנדרואיד: שער ושם", android.summary);

const windows = classifyHotspot({ gatewayIp: "192.168.137.1" });
check(
  windows.confidence === "likely",
  "שיתוף ממחשב Windows, לפי השער בלבד",
  windows.summary,
);

// שם שהמשתמש שינה, אבל השער מסגיר
const renamed = classifyHotspot({ ssid: "הרשת של הבית", gatewayIp: "172.20.10.1" });
check(
  renamed.confidence === "likely",
  "שם שהוסווה — השער עדיין מסגיר",
  "זו הסיבה שהשער הוא הסימן המוביל",
);

// ─────────────────────────────── מה שאסור להיתפס
section("2 · רשתות ביתיות לגיטימיות");

const homes: Array<[string, NetworkFingerprint]> = [
  // התבנית הקודמת תפסה "של" לבדו, וסימנה את שני אלה
  ["רשת עם 'של' בשם", { ssid: "הרשת של הבית", gatewayIp: "192.168.1.1" }],
  ["עוד אחת", { ssid: "הוויפי של המשפחה", gatewayIp: "10.0.0.138" }],
  ["נתב ביתי רגיל", { ssid: "Cohen-Home", gatewayIp: "192.168.1.1", gatewayMac: "00:1A:2B:3C:4D:5E" }],
  ["נתב בזק", { ssid: "Bezeq-4821", gatewayIp: "10.0.0.138" }],
  ["נתב אחר", { ssid: "HOT-Fiber", gatewayIp: "192.168.0.1" }],
  ["רשת משרד", { ssid: "OFFICE-WIFI", gatewayIp: "10.10.0.1" }],
  ["בלי מידע כלל", {}],
];

for (const [label, fingerprint] of homes) {
  const verdict = classifyHotspot(fingerprint);

  check(
    verdict.confidence === "none",
    `${label} — לא מסומן`,
    verdict.confidence === "none" ? "" : verdict.summary,
  );
}

const hebrewPhone = classifyHotspot({
  ssid: "הטלפון של יוסי",
  gatewayIp: "172.20.10.1",
});
check(
  hebrewPhone.confidence === "certain",
  "שם טלפוני בעברית עדיין נתפס",
  hebrewPhone.summary,
);

// ─────────────────────────────── הדרגות
section("3 · דרגות ביניים");

const ssidOnly = classifyHotspot({ ssid: "Galaxy S23", gatewayIp: "192.168.1.1" });
check(
  ssidOnly.confidence === "possible",
  "שם חשוד עם שער ביתי — אפשרי בלבד",
  "אפשר לקרוא לנתב בבית 'Galaxy'. זה לא מספיק כדי לחסום",
);
check(!shouldBlockOutright(ssidOnly), "ולכן אינו נחסם אוטומטית");

const macOnly = classifyHotspot({ ssid: "MyNet", gatewayIp: "192.168.1.1", gatewayMac: "64:B0:A6:00:11:22" });
check(macOnly.confidence === "possible", "חומרה של יצרן טלפונים בלבד — אפשרי");

// ─────────────────────────────── נרמול
section("4 · נרמול כתובת חומרה");

const forms = ["AC:BC:32:11:22:33", "ac-bc-32-11-22-33", "acbc32112233", "AC BC 32 11 22 33"];

for (const form of forms) {
  check(normalizeMac(form) === "AC:BC:32:11:22:33", `"${form}"`);
}

check(normalizeMac("לא כתובת") === null, "קלט שאינו כתובת מוחזר כ-null");
check(normalizeMac("AC:BC:32") === null, "כתובת חלקית נדחית");

// הבדיקה שמונעת רגרסיה: כתובת בפורמט אחר עדיין מזוהה
const dashed = classifyHotspot({ gatewayIp: "192.168.1.1", gatewayMac: "ac-bc-32-11-22-33" });
check(
  dashed.reasons.some((r) => r.includes("Apple")),
  "פורמט מקפים מזוהה כמו נקודתיים",
  "Windows מדווח כתובות עם מקפים",
);

console.log(`\n${"═".repeat(64)}`);
// ─────────────────────────────── כתובות מוגרלות
section("5 · כתובות חומרה מוגרלות");

check(
  isLocallyAdministered("DA:0F:1F:51:65:32"),
  "כתובת מנוהלת מקומית מזוהה ככזו",
  "נמדדה על מכונת פיתוח אמיתית — שער של רשת ביתית",
);
check(!isLocallyAdministered("AC:BC:32:11:22:33"), "כתובת יצרן אינה מסומנת");

for (const prefix of ["02", "06", "0A", "0E", "DA", "FE"]) {
  check(isLocallyAdministered(`${prefix}:11:22:33:44:55`), `${prefix} — מוגרלת`);
}

for (const prefix of ["00", "AC", "F8", "64"]) {
  check(!isLocallyAdministered(`${prefix}:11:22:33:44:55`), `${prefix} — של יצרן`);
}

const randomized = classifyHotspot({
  ssid: "MyNet",
  gatewayIp: "192.168.1.1",
  gatewayMac: "DA:0F:1F:51:65:32",
});
check(
  randomized.confidence === "none",
  "כתובת מוגרלת אינה מייצרת חשד",
  "חיפוש יצרן עליה היה מחזיר תשובה שגויה",
);

console.log(`עברו ${passed} · נכשלו ${failed}`);
console.log("═".repeat(64));

process.exit(failed === 0 ? 0 : 1);
