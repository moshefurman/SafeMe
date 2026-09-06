/**
 * דגימת פעימות.
 *
 * נבדק כאן כלל ההחלטה עצמו, טהור ובלי בסיס נתונים. השאילתה שמיישמת
 * אותו נבדקת ב-poc-api, שם יש מחשב רשום ופעימות אמיתיות.
 */

import {
  KEEPALIVE_MS,
  SCORE_EPSILON,
  sampleReason,
  type DeviceSnapshot,
  type HeartbeatFacts,
} from "../src/telemetry/retention.ts";
import { canonicalTamperKind, describeTamper, severityFor } from "../src/telemetry/severity.ts";

let passed = 0;
let failed = 0;

function check(name: string, actual: unknown, expected: unknown) {
  if (JSON.stringify(actual) === JSON.stringify(expected)) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failed++;
    console.log(`  ✗ ${name}`);
    console.log(`      התקבל: ${JSON.stringify(actual)}`);
    console.log(`      צפוי:  ${JSON.stringify(expected)}`);
  }
}

const T0 = new Date("2026-08-25T10:00:00Z");
const BASE_SCORE = 90;

function snap(over: Partial<DeviceSnapshot> = {}): DeviceSnapshot {
  return {
    status: "safe",
    score: BASE_SCORE,
    provider: "netfree",
    lockoutActive: false,
    policyVersion: 7,
    lastSampleAt: T0,
    ...over,
  };
}

function beat(over: Partial<HeartbeatFacts> = {}): HeartbeatFacts {
  return {
    status: "safe",
    score: BASE_SCORE,
    provider: "netfree",
    lockoutActive: false,
    policyVersion: 7,
    hasTamperEvents: false,
    ...over,
  };
}

// ---------------------------------------------------------------- הכלל

console.log("\n── כלל ההחלטה ──\n");

const soon = new Date(T0.getTime() + 3 * 60_000);

check("שקט מוחלט — לא נשמר", sampleReason(snap(), beat(), soon), null);
check("שינוי סטטוס", sampleReason(snap(), beat({ status: "unfiltered" }), soon), "status");
check("נעילה נדלקה", sampleReason(snap(), beat({ lockoutActive: true }), soon), "lockout");
check("נעילה כובתה", sampleReason(snap({ lockoutActive: true }), beat(), soon), "lockout");
check("החלפת ספק", sampleReason(snap(), beat({ provider: "rimon" }), soon), "provider");
check("ספק נעלם", sampleReason(snap(), beat({ provider: null }), soon), "provider");
check("מדיניות חדשה", sampleReason(snap(), beat({ policyVersion: 8 }), soon), "policy");
check("חבלה", sampleReason(snap(), beat({ hasTamperEvents: true }), soon), "tamper");

check(
  `ציון זז ${SCORE_EPSILON - 1} — בתוך אזור המת`,
  sampleReason(snap(), beat({ score: BASE_SCORE - (SCORE_EPSILON - 1) }), soon),
  null,
);
check(
  `ציון זז ${SCORE_EPSILON} — נשמר`,
  sampleReason(snap(), beat({ score: BASE_SCORE - SCORE_EPSILON }), soon),
  "score",
);

check("אין דגימה קודמת", sampleReason(snap({ lastSampleAt: null }), beat(), soon), "first");
check("פעימה מחוץ לסדר", sampleReason(null, beat(), soon), "stale");

check(
  "59:59 אחרי — עוד לא",
  sampleReason(snap(), beat(), new Date(T0.getTime() + KEEPALIVE_MS - 1000)),
  null,
);
check(
  "שעה בדיוק — סימן חיים",
  sampleReason(snap(), beat(), new Date(T0.getTime() + KEEPALIVE_MS)),
  "keepalive",
);

// סדר הקדימויות: חבלה נבדקת ראשונה, לפני כל שיקול אחר
check(
  "חבלה גוברת על שקט מוחלט",
  sampleReason(snap(), beat({ hasTamperEvents: true }), soon),
  "tamper",
);

// ---------------------------------------------------------------- הנפח

console.log("\n── יחס הצמצום על יממה מדומה ──\n");

/**
 * יממה של מחשב תקין: 480 פעימות, שום שינוי מצב, ציון שמרחף.
 * זה המקרה השכיח, והוא שקובע את חשבון האחסון.
 */
function quietDay(jitter: number): number {
  let state = snap({ lastSampleAt: T0 });
  let stored = 0;

  for (let i = 1; i <= 480; i++) {
    const at = new Date(T0.getTime() + i * 3 * 60_000);

    // תנודה שסורקת את כל הרצועה, כולל את שני הקצוות — שם נמצא
    // הכשל שסף צר מדי מייצר
    const span = jitter * 2 + 1;
    const b = beat({ score: BASE_SCORE - jitter + (i % span) });

    if (sampleReason(state, b, at) !== null) {
      stored++;
      state = { ...state, score: b.score, lastSampleAt: at };
    }
  }

  return stored;
}

for (const jitter of [0, 3, 4]) {
  const rows = quietDay(jitter);
  console.log(`  רעש ±${jitter}: 480 → ${rows} שורות, פי ${(480 / rows).toFixed(0)} פחות`);
}

check("יממה שקטה לגמרי", quietDay(0), 24);
check("רעש ±3", quietDay(3), 24);
check(`רעש ±4, רצועה 9, בתוך אזור מת של ${SCORE_EPSILON}`, quietDay(4), 24);

// רעש רחב מאזור המת אמור לחרוג. מתועד ולא מוסתר: הסף הוא הנחה,
// וצריך לדעת מה קורה כשההנחה לא מתקיימת.
const wide = quietDay(6);
console.log(`\n  רעש ±6, רצועה 13, רחבה מ-${SCORE_EPSILON}: ${wide} שורות — הסף נחצה, כצפוי`);
check("רעש רחב מהסף אכן מייצר יותר שורות", wide > 24, true);

console.log("\n── חומרת אירועים ──\n");

// החומרה קובעת מה בולט להורה ומה נבלע ברשימה. הבחנה בין ניסיון
// שנחסם לבין הצלחה היא כל ההבדל.
const SEVERITY_CASES: Array<[string, string]> = [
  ["CoverageGap", "critical"],
  ["WfpFiltersMissing", "critical"],
  ["PolicySignatureInvalid", "critical"],
  ["ClockRolledBack", "critical"],
  ["StateFileTampered", "critical"],
  ["ServiceStopAttempt", "warning"],
  ["UninstallBruteForce", "warning"],
  ["TrayAppKilled", "info"],
  ["ServiceCrash", "info"],
  // מה שהסוכן שולח בפועל: ה-enum שלו ב-camelCase
  ["trayAppKilled", "info"],
  ["coverageGap", "critical"],
  ["serviceStopAttempt", "warning"],
  // מה שהמסד והפורטל מכירים
  ["tray_app_killed", "info"],
  ["offline_expiry_near", "critical"],
  ["סוג-לא-מוכר", "warning"],
];

for (const [kind, expected] of SEVERITY_CASES) {
  check(`${kind} → ${expected}`, severityFor(kind), expected);
}

// השם הקנוני אחד לכל שלוש הצורות, ושם זר עובר בלי להישבר
const CANON_CASES: Array<[string, string]> = [
  ["TrayAppKilled", "tray_app_killed"],
  ["trayAppKilled", "tray_app_killed"],
  ["tray_app_killed", "tray_app_killed"],
  ["WfpFiltersMissing", "wfp_filters_missing"],
  ["BfeUnavailable", "bfe_unavailable"],
  ["סוג-לא-מוכר", "סוג_לא_מוכר"],
];

for (const [kind, expected] of CANON_CASES) {
  check(`${kind} ⇒ ${expected}`, canonicalTamperKind(kind), expected);
}

// והנוסח להורה מזהה את מה שהסוכן שולח, לא רק את מה שנכתב בבדיקות
check(
  "trayAppKilled מתורגם להורה",
  describeTamper("trayAppKilled", null),
  "אייקון המגש נסגר.",
);
console.log(`\n${failed === 0 ? "✓" : "✗"} ${passed} עברו, ${failed} נכשלו\n`);
process.exit(failed === 0 ? 0 : 1);
