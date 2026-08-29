/**
 * מנגנון איש-מת: מחשב ששותק.
 *
 * זו ההגנה היחידה שאינה תלויה בכך שהסוכן שרד. כל השאר מדווח על מה
 * שקרה בזמן שהתוכנה פעלה; זה מדווח על כך שהיא הפסיקה.
 */

import { randomBytes, randomUUID } from "node:crypto";

import { createPool, withPlatform } from "../src/db/client.ts";
import { loadConfig } from "../src/config.ts";
import { scanOnce } from "../src/workers/deadman-worker.ts";
import { NullMailer } from "../src/notify/mailer.ts";
import {
  LATE_MINUTES,
  MISSING_MINUTES,
  OFFLINE_HOURS,
  computeTransitions,
  describeSilence,
  stateFor,
  type DeadManState,
} from "../src/telemetry/deadman.ts";

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

const SYSTEM = { userId: "00000000-0000-0000-0000-000000000000", reason: "הרצת POC" };
const NOW = new Date("2026-08-27T12:00:00Z");

function agoMinutes(m: number): Date {
  return new Date(NOW.getTime() - m * 60_000);
}

async function main(): Promise<void> {
  // ─────────────────────────────────────── הספים
  section("1 · הספים");

  check(stateFor(0) === "healthy", "מחשב שדיווח עכשיו תקין");
  check(stateFor(LATE_MINUTES - 1) === "healthy", `${LATE_MINUTES - 1} דקות — עדיין תקין`);
  check(stateFor(LATE_MINUTES) === "late", `${LATE_MINUTES} דקות — מאחר`);
  check(stateFor(MISSING_MINUTES) === "missing", `${MISSING_MINUTES} דקות — נעדר`);
  check(stateFor(OFFLINE_HOURS * 60) === "offline", `${OFFLINE_HOURS} שעות — מנותק`);

  // ─────────────────────────────────────── המעברים
  section("2 · מתי נפתחת התראה");

  const late = computeTransitions(
    [{ deviceId: "a", lastSeenAt: agoMinutes(15), currentHealth: "healthy" }],
    NOW,
  );
  check(late[0]?.to === "late", "מעבר לאיחור");
  check(
    late[0]?.raisesAlert === false,
    "איחור אינו פותח התראה",
    "רשת שנפלה לרגע אינה אירוע. התראה על כל הפרעה מאמנת להתעלם",
  );

  const missing = computeTransitions(
    [{ deviceId: "a", lastSeenAt: agoMinutes(45), currentHealth: "late" }],
    NOW,
  );
  check(missing[0]?.to === "missing", "מעבר להיעדרות");
  check(missing[0]?.raisesAlert === true, "והיא כן פותחת התראה");

  const escalation = computeTransitions(
    [{ deviceId: "a", lastSeenAt: agoMinutes(48 * 60), currentHealth: "missing" }],
    NOW,
  );
  check(escalation[0]?.to === "offline", "הסלמה לניתוק");
  check(
    escalation[0]?.raisesAlert === false,
    "הסלמה אינה פותחת התראה נוספת",
    "זו אותה היעדרות שנמשכת, לא אירוע חדש",
  );

  const recovered = computeTransitions(
    [{ deviceId: "a", lastSeenAt: agoMinutes(1), currentHealth: "missing" }],
    NOW,
  );
  check(recovered[0]?.to === "healthy", "חזרה לתקינות");
  check(recovered[0]?.raisesAlert === false, "וחזרה אינה התראה");

  // ─────────────────────────────────────── מה שלא נסרק
  section("3 · מה שאינו נסרק");

  const never = computeTransitions(
    [{ deviceId: "a", lastSeenAt: null, currentHealth: "healthy" }],
    NOW,
  );
  check(
    never.length === 0,
    "מחשב שמעולם לא דיווח מדולג",
    "הוא נרשם ועדיין לא הותקן. זו לא חבלה",
  );

  const tampered = computeTransitions(
    [{ deviceId: "a", lastSeenAt: agoMinutes(500), currentHealth: "tampered" }],
    NOW,
  );
  check(
    tampered.length === 0,
    "מחשב מסומן כמחובל אינו משתנה לפי זמן",
    "ספירת דקות לא תדרוס קביעה שנעשתה מראיה",
  );

  // ─────────────────────────────────────── נוסח
  section("4 · הנוסח להורה");

  const texts: Array<[number, string]> = [
    [25, "25 דקות"],
    [59, "59 דקות"],
    [60, "שעה."],
    // עיגול כלפי מטה היה הופך את זה ל"שעה", וההפרש הוא בדיוק
    // מה שההורה שוקל
    [90, "1.5 שעות"],
    [180, "3 שעות"],
    [1440, "יממה"],
    [4320, "3 ימים"],
  ];

  for (const [minutes, expect] of texts) {
    const text = describeSilence(minutes);
    check(text.includes(expect), `${minutes} דקות → "${text}"`);
  }

  // ─────────────────────────────────────── מול בסיס נתונים
  section("5 · הסריקה, מול בסיס נתונים אמיתי");

  const config = loadConfig({
    ...process.env,
    NODE_ENV: "test",
    DEVICE_TOKEN_SECRET: process.env["DEVICE_TOKEN_SECRET"] ?? randomBytes(32).toString("hex"),
  });

  const pool = createPool({ connectionString: config.DATABASE_URL_APP });

  const ids = await withPlatform(pool, SYSTEM, async (tx) => {
    const t = await tx.query<{ id: string }>(
      `INSERT INTO tenants (type, name, trial_started_at, trial_ends_at)
       VALUES ('family', 'משפחת שתיקה', now(), now() + interval '30 days')
       RETURNING id`,
    );

    const tenantId = t.rows[0]!.id;
    const made: Record<string, string> = {};

    // שלושה מחשבים בשלוש רמות שתיקה
    for (const [label, minutes] of [["fresh", 1], ["late", 15], ["gone", 45]] as const) {
      const hwid = `HWID${randomBytes(10).toString("hex").toUpperCase()}`;

      const d = await tx.query<{ id: string }>(
        `INSERT INTO devices (tenant_id, hwid, machine_name, install_profile,
                              enforcement_mode, status, policy_floor)
         VALUES ($1, $2, $3, 'family_child', 'enforce', 'active', $4)
         RETURNING id`,
        [
          tenantId,
          hwid,
          `מחשב-${label}`,
          JSON.stringify({ mode: "enforce", onRedAction: "lockout", minScoreForGreen: 85 }),
        ],
      );

      const id = d.rows[0]!.id;
      made[label] = id;

      await tx.query(
        `INSERT INTO device_state (device_id, tenant_id, last_seen_at, health)
         VALUES ($1, $2, now() - make_interval(mins => $3), 'healthy')`,
        [id, tenantId, minutes],
      );
    }

    return made;
  });

  const result = await scanOnce(pool);

  check(result.scanned >= 3, "הסריקה עברה על המחשבים", `${result.scanned} מחשבים`);
  check(result.changed >= 2, "שניים שינו מצב", `${result.changed} שינויים`);
  check(result.alerted >= 1, "והתראה אחת נפתחה", `${result.alerted} התראות`);

  const states = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ device_id: string; health: DeadManState }>(
      "SELECT device_id, health FROM device_state WHERE device_id = ANY($1)",
      [Object.values(ids)],
    );

    return new Map(r.rows.map((row) => [row.device_id, row.health]));
  });

  check(states.get(ids["fresh"]!) === "healthy", "מי שדיווח לפני דקה — תקין");
  check(states.get(ids["late"]!) === "late", "מי ששתק רבע שעה — מאחר");
  check(states.get(ids["gone"]!) === "missing", "מי ששתק 45 דקות — נעדר");

  // ─────────────────────────────────────── ההתראה
  section("6 · ההתראה");

  const alerts = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ kind: string; state: string; detail: string }>(
      `SELECT a.kind, a.state,
              (SELECT e.detail FROM events e
                WHERE e.device_id = a.device_id AND e.kind = 'device.silent'
                ORDER BY e.occurred_at DESC LIMIT 1) AS detail
         FROM alerts a WHERE a.device_id = $1`,
      [ids["gone"]],
    );

    return r.rows;
  });

  const alert = alerts[0];

  check(alert?.kind === "device.silent", "התראה נפתחה על המחשב הנכון");
  check(alert?.state === "open", "והיא פתוחה");
  check(
    (alert?.detail ?? "").includes("לא דיווח"),
    "עם נוסח שאפשר להבין",
    alert?.detail ?? "",
  );

  // סריקה חוזרת לא תכפיל את ההתראה
  const again = await scanOnce(pool);

  check(again.alerted === 0, "סריקה חוזרת אינה מכפילה התראה", "אינדקס ייחודי על התראה פתוחה");

  // ─────────────────────────────────────── ההודעה
  section("7 · ההודעה לבעל החשבון");

  const mailer = new NullMailer();

  // מחשב רביעי, שנעלם רק עכשיו, כדי שההתראה תיפתח בסריקה הזו
  const ownerEmail = `horeh-${randomUUID().slice(0, 8)}@example.test`;

  const fresh = await withPlatform(pool, SYSTEM, async (tx) => {
    const t = await tx.query<{ id: string }>(
      `INSERT INTO tenants (type, name, trial_started_at, trial_ends_at)
       VALUES ('family', 'משפחת הודעה', now(), now() + interval '30 days')
       RETURNING id`,
    );

    const tenantId = t.rows[0]!.id;

    await tx.query(
      `INSERT INTO users (tenant_id, email, display_name, role, password_hash)
       VALUES ($1, $2, 'הורה', 'tenant_owner', 'x')`,
      [tenantId, ownerEmail],
    );

    const d = await tx.query<{ id: string }>(
      `INSERT INTO devices (tenant_id, hwid, machine_name, install_profile,
                            enforcement_mode, status, policy_floor)
       VALUES ($1, $2, 'המחשב-של-יוסי', 'family_child', 'enforce', 'active', $3)
       RETURNING id`,
      [
        tenantId,
        `HWID${randomBytes(10).toString("hex").toUpperCase()}`,
        JSON.stringify({ mode: "enforce", onRedAction: "lockout", minScoreForGreen: 85 }),
      ],
    );

    await tx.query(
      `INSERT INTO device_state (device_id, tenant_id, last_seen_at, health)
       VALUES ($1, $2, now() - interval '50 minutes', 'healthy')`,
      [d.rows[0]!.id, tenantId],
    );

    return d.rows[0]!.id;
  });

  void fresh;

  await scanOnce(pool, new Date(), {
    mailer,
    portalUrl: "https://safeme.example",
  });

  const sent = mailer.outbox.find((m) => m.to === ownerEmail);

  check(sent !== undefined, "הודעה הופנתה לבעל החשבון", ownerEmail);
  check(
    (sent?.subject ?? "").includes("הפסיק לדווח"),
    "הנושא אומר מה קרה",
    sent?.subject ?? "",
  );
  check(
    (sent?.body ?? "").includes("עשוי להיות כבוי"),
    "והגוף אומר את מה שידוע ולא יותר",
    "\"המחשב לא מדווח\" הוא עובדה. \"הילד ניתק\" הוא ניחוש",
  );
  check(
    (sent?.body ?? "").includes("יומן האירועים"),
    "ומסביר איך התשובה תתברר",
  );

  // סריקה חוזרת לא תשלח שוב
  const before = mailer.outbox.length;
  await scanOnce(pool, new Date(), { mailer, portalUrl: "https://safeme.example" });

  check(
    mailer.outbox.length === before,
    "סריקה חוזרת אינה שולחת שוב",
    "ההודעה קשורה לפתיחת ההתראה, לא למצב",
  );

  await pool.end();

  console.log(`\n${"═".repeat(64)}`);
  console.log(`עברו ${passed} · נכשלו ${failed}`);
  console.log("═".repeat(64));

  process.exit(failed === 0 ? 0 : 1);
}

await main();
