/**
 * הכרעה על רשת: מותרת, חסומה, או ממתינה לאישור.
 *
 * שלוש הרמות נבדלות רק במה קורה לרשת חדשה שכבר מסוננת. רשת לא
 * מסוננת נחסמת בכולן, ונקודה חמה ודאית נחסמת בכולן תמיד.
 */

import { randomBytes } from "node:crypto";

import { createPool, withPlatform } from "../src/db/client.ts";
import { loadConfig } from "../src/config.ts";
import { trackNetwork, type AdapterInput } from "../src/network/track.ts";
import {
  decideNetwork,
  describeDecision,
  fingerprintOf,
  type NetworkContext,
} from "../src/network/decide.ts";

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

/** רשת ביתית רגילה, לא מוכרת. */
function home(over: Partial<NetworkContext> = {}): NetworkContext {
  return {
    ssid: "Cohen-Home",
    gatewayIp: "192.168.1.1",
    gatewayMac: "00:1A:2B:3C:4D:5E",
    policy: "balanced",
    approval: null,
    ...over,
  };
}

// ───────────────────────────────────── שלוש הרמות
section("1 · רשת חדשה שאינה מסוננת");

for (const policy of ["strict", "balanced"] as const) {
  const d = decideNetwork(home({ policy }));

  check(d.action === "await_approval", `${policy} — ממתינה לאישור`, d.reason);
  check(d.notify, "וההורה מקבל התראה");
}

const lenientUnfiltered = decideNetwork(home({ policy: "lenient" }));
check(lenientUnfiltered.action === "allow", "lenient — מותרת", lenientUnfiltered.reason);
check(lenientUnfiltered.notify, "אך עדיין עם התראה");

section("2 · רשת חדשה שכן מסוננת");

const strictFiltered = decideNetwork(home({ policy: "strict", detectedProvider: "netfree" }));
check(
  strictFiltered.action === "await_approval",
  "strict — ממתינה גם כשהיא מסוננת",
  "זו כל ההגדרה: שום דבר לא נכנס בלי אישור",
);

const balancedFiltered = decideNetwork(home({ policy: "balanced", detectedProvider: "netfree" }));
check(
  balancedFiltered.action === "allow" && balancedFiltered.autoApprove,
  "balanced — מאושרת אוטומטית",
  balancedFiltered.reason,
);
check(
  balancedFiltered.notify,
  "וההורה עדיין מיודע",
  "אישור אוטומטי אינו סיבה להסתיר",
);

// ───────────────────────────────────── נקודה חמה
section("3 · נקודה חמה מטלפון");

const hotspot = {
  ssid: "iPhone של יוסי",
  gatewayIp: "172.20.10.1",
  gatewayMac: "AC:BC:32:11:22:33",
};

for (const policy of ["strict", "balanced", "lenient"] as const) {
  const d = decideNetwork({ ...hotspot, policy, approval: null });

  check(d.action === "block", `${policy} — נחסמת`, policy === "lenient" ? d.reason : "");
}

// גם אם מישהו אישר אותה בעבר
const approvedHotspot = decideNetwork({ ...hotspot, policy: "lenient", approval: "approved" });
check(
  approvedHotspot.action === "block",
  "נחסמת גם אם אושרה בעבר",
  "שיתוף מטלפון לעולם אינו מסונן. אישור ישן לא הופך אותו לבטוח",
);

// ───────────────────────────────────── חסימה מפורשת
section("4 · חסימה מפורשת גוברת");

for (const policy of ["strict", "balanced", "lenient"] as const) {
  const d = decideNetwork(home({ policy, approval: "blocked", detectedProvider: "netfree" }));

  check(d.action === "block", `${policy} — חסומה נשארת חסומה`);
}

const blockedQuiet = decideNetwork(home({ approval: "blocked" }));
check(
  !blockedQuiet.notify,
  "וללא התראה חוזרת",
  "ההורה כבר יודע — הוא זה שחסם",
);

// ───────────────────────────────────── מאושרת
section("5 · רשת מאושרת");

const approved = decideNetwork(home({ approval: "approved" }));
check(approved.action === "allow", "מותרת");
check(!approved.notify, "ובשקט");

// ───────────────────────────────────── טביעת אצבע
section("6 · טביעת האצבע");

const withMac = { ssid: "Home", gatewayIp: "192.168.1.1", gatewayMac: "00:1A:2B:3C:4D:5E" };

check(
  fingerprintOf(withMac) === fingerprintOf({ ...withMac, ssid: "שם אחר לגמרי" }),
  "שינוי שם הרשת אינו משנה את הטביעה",
  "כתובת החומרה מזהה את הנתב הפיזי",
);

check(
  fingerprintOf(withMac) === fingerprintOf({ ...withMac, gatewayMac: "00-1a-2b-3c-4d-5e" }),
  "פורמט כתובת החומרה אינו משנה",
);

check(
  fingerprintOf(withMac) !== fingerprintOf({ ...withMac, gatewayMac: "AA:BB:CC:DD:EE:FF" }),
  "נתב אחר — טביעה אחרת",
);

// בלי MAC נופלים לשם ולשער
const noMac = { ssid: "Cafe", gatewayIp: "10.0.0.1" };

check(
  fingerprintOf(noMac) === fingerprintOf({ ssid: "CAFE", gatewayIp: "10.0.0.1" }),
  "בלי כתובת חומרה — שם ושער, ללא תלות ברישיות",
);
check(
  fingerprintOf(noMac) !== fingerprintOf({ ssid: "Cafe", gatewayIp: "10.0.0.2" }),
  "ושער אחר הוא רשת אחרת",
);

check(
  /^[0-9a-f]{32}$/.test(fingerprintOf(withMac)),
  "הטביעה מגובבת ובאורך קבוע",
  fingerprintOf(withMac),
);

// ───────────────────────────────────── נוסח
section("7 · הנוסח להורה");

const text = describeDecision(
  decideNetwork({ ...hotspot, policy: "balanced", approval: null }),
  hotspot.ssid,
);

check(text.includes("נחסמה"), "אומר מה קרה", text);
check(text.includes("שיתוף אינטרנט מטלפון"), "ולמה");

const noName = describeDecision(decideNetwork(home()), null);
check(noName.includes("רשת ללא שם"), "רשת בלי שם מנוסחת בכבוד", noName);

console.log(`\n${"═".repeat(64)}`);
// ─────────────────────────────────────── מול בסיס נתונים
section("8 · מעקב אמיתי, מול בסיס נתונים");

const config = loadConfig({
  ...process.env,
  NODE_ENV: "test",
  DEVICE_TOKEN_SECRET: process.env["DEVICE_TOKEN_SECRET"] ?? randomBytes(32).toString("hex"),
});

const pool = createPool({ connectionString: config.DATABASE_URL_APP });
const SYSTEM = { userId: "00000000-0000-0000-0000-000000000000", reason: "הרצת POC" };

const ctx = await withPlatform(pool, SYSTEM, async (tx) => {
  const t = await tx.query<{ id: string }>(
    `INSERT INTO tenants (type, name, trial_started_at, trial_ends_at, network_policy)
     VALUES ('family', 'משפחת רשתות', now(), now() + interval '30 days', 'balanced')
     RETURNING id`,
  );

  const tenantId = t.rows[0]!.id;

  const d = await tx.query<{ id: string }>(
    `INSERT INTO devices (tenant_id, hwid, machine_name, install_profile,
                          enforcement_mode, status, policy_floor)
     VALUES ($1, $2, 'מחשב-רשת', 'family_child', 'enforce', 'active', $3)
     RETURNING id`,
    [
      tenantId,
      `HWID${randomBytes(10).toString("hex").toUpperCase()}`,
      JSON.stringify({ mode: "enforce", onRedAction: "lockout", minScoreForGreen: 85 }),
    ],
  );

  return { tenantId, deviceId: d.rows[0]!.id };
});

const HOME: AdapterInput[] = [
  { name: "Wi-Fi", ssid: "Cohen-Home", gateway: "192.168.1.1", gatewayMac: "00:1A:2B:3C:4D:5E" },
];
const PHONE: AdapterInput[] = [
  { name: "Wi-Fi", ssid: "iPhone של יוסי", gateway: "172.20.10.1", gatewayMac: "AC:BC:32:11:22:33" },
];
// המתאם הווירטואלי מופיע ראשון בכוונה: אם הבחירה הייתה "הראשון
// שיש לו שער", היא הייתה נופלת עליו.
const VPN: AdapterInput[] = [
  { name: "WireGuard", ssid: null, gateway: "10.8.0.1", isVirtualVpn: true },
  ...HOME,
];

const track = (adapters: AdapterInput[], provider: string | null) =>
  withPlatform(pool, SYSTEM, (tx) => trackNetwork(tx, ctx, adapters, provider));

// רשת ביתית מסוננת — מאושרת אוטומטית ב-balanced
const first = await track(HOME, "netfree");

check(first?.action === "allow", "רשת ביתית מסוננת מותרת מיד", first?.reason ?? "");
check(first?.isNew === true, "ונרשמת כרשת חדשה");

// אותה רשת שוב — לא חדשה יותר
const second = await track(HOME, "netfree");
check(second?.isNew === false, "בפעימה הבאה היא כבר מוכרת");

// נקודה חמה — נחסמת
const blocked = await track(PHONE, null);
check(blocked?.action === "block", "נקודה חמה נחסמת", blocked?.reason ?? "");

// מתאם וירטואלי מדולג
const throughVpn = await track(VPN, "netfree");
check(
  throughVpn?.ssid === "Cohen-Home",
  "מתאם VPN מדולג — נרשמת הרשת האמיתית",
  "אחרת זהות הרשת הייתה מוחלפת בזהות המנהרה",
);

// ─────────────────────────────────────── הסשנים
section("9 · היסטוריית החיבורים");

const sessions = await withPlatform(pool, SYSTEM, async (tx) => {
  const r = await tx.query<{
    ssid: string | null;
    outcome: string;
    ended: boolean;
  }>(
    `SELECT n.ssid, s.outcome, (s.ended_at IS NOT NULL) AS ended
       FROM network_sessions s
       JOIN known_networks n ON n.id = s.network_id
      WHERE s.device_id = $1
      ORDER BY s.started_at`,
    [ctx.deviceId],
  );

  return r.rows;
});

check(
  sessions.length === 3,
  "שלושה סשנים, לא ארבעה",
  `שתי פעימות באותה רשת הן סשן אחד · נוצרו ${sessions.length}`,
);

check(sessions[0]?.ssid === "Cohen-Home" && sessions[0]?.ended === true, "הראשון נסגר במעבר");
check(sessions[1]?.outcome === "blocked", "השני נרשם כחסום");
check(sessions[2]?.ended === false, "האחרון עדיין פתוח");

// ─────────────────────────────────────── המדיניות משנה
section("10 · שינוי המדיניות משנה את התוצאה");

await withPlatform(pool, SYSTEM, (tx) =>
  tx.query("UPDATE tenants SET network_policy = 'strict' WHERE id = $1", [ctx.tenantId]));

const strictNew = await track(
  [{ name: "Wi-Fi", ssid: "Saba-Home", gateway: "192.168.5.1", gatewayMac: "00:AA:BB:CC:DD:EE" }],
  "rimon",
);

check(
  strictNew?.action === "await_approval",
  "ב-strict, רשת מסוננת חדשה ממתינה לאישור",
  strictNew?.reason ?? "",
);

const pending = await withPlatform(pool, SYSTEM, async (tx) => {
  const r = await tx.query<{ n: string }>(
    "SELECT count(*) AS n FROM known_networks WHERE tenant_id = $1 AND approval = 'pending'",
    [ctx.tenantId],
  );

  return Number(r.rows[0]!.n);
});

check(pending >= 2, "רשתות ממתינות מופיעות לאישור", `${pending} ממתינות`);

await pool.end();

console.log(`עברו ${passed} · נכשלו ${failed}`);
console.log("═".repeat(64));

process.exit(failed === 0 ? 0 : 1);
