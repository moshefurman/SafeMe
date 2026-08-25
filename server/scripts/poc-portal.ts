import { randomBytes, randomUUID } from "node:crypto";
import { buildApp } from "../src/app.ts";
import { createPool, withPlatform } from "../src/db/client.ts";
import { LocalSigner } from "../src/crypto/signing.ts";
import { loadConfig } from "../src/config.ts";
import { totp } from "../src/auth/totp.ts";
import { createUser } from "../src/routes/portal-auth.ts";

/**
 * POC לשלב S5: הפורטל.
 *
 * המוקד אינו "הכפתור עובד" אלא שלושה דברים שקשה לראות במסך:
 * שדייר אינו רואה מכשיר של דייר אחר גם כשהוא יודע את המזהה המדויק,
 * שתפקיד ללא הרשאה נחסם בשרת ולא רק ב-UI, ושפקודת נעילה באמת
 * מגיעה למכשיר דרך הפעימה.
 */

let passed = 0;
let failed = 0;

function check(condition: boolean, title: string, detail = ""): void {
  if (condition) {
    passed += 1;
    console.log(`  ✓ ${title}${detail ? ` — ${detail}` : ""}`);
  } else {
    failed += 1;
    console.log(`  ✗ ${title}${detail ? ` — ${detail}` : ""}`);
  }
}

function section(title: string): void {
  console.log(`\n${title}`);
  console.log("─".repeat(64));
}

const SYSTEM = { userId: "system", reason: "הרצת POC" };
const PASSWORD = "Portal-Bdika-2026!";

interface Actor {
  cookie: string;
  csrf: string;
}

async function main(): Promise<void> {
  const config = loadConfig({
    ...process.env,
    NODE_ENV: "test",
    DEVICE_TOKEN_SECRET: process.env["DEVICE_TOKEN_SECRET"] ?? randomBytes(32).toString("hex"),
  });

  const pool = createPool({ connectionString: config.DATABASE_URL_APP });
  const signer = LocalSigner.ephemeral(`poc-portal-${randomBytes(4).toString("hex")}`);
  // חותם ההיתרים חייב מזהה ייחודי להרצה מאותה סיבה כמו חותם
  // המדיניות: מפתח זמני מתחלף בכל הרצה, ורישום מפתח אחר תחת
  // אותו kid נדחה — ובצדק.
  const looseningSigner = LocalSigner.ephemeral(`poc-loosening-${randomUUID().slice(0, 8)}`);

  const app = await buildApp({ config, pool, signer, looseningSigner, logger: false });

  const suffix = randomBytes(3).toString("hex");

  // ─────────────────────────────────────────────── הכנה
  section("הכנה: שתי משפחות, מכשיר לכל אחת, שלושה תפקידים");

  const seed = await withPlatform(pool, SYSTEM, async (tx) => {
    // device_commands אינה ניתנת למחיקה לאפליקציה במכוון: היא חלק
    // מהתיעוד. מחיקת המכשירים גוררת אותן ב-CASCADE.
    await tx.query("DELETE FROM devices");
    await tx.query("DELETE FROM tenants WHERE name LIKE 'POC%'");
    await tx.query("DELETE FROM login_attempts");

    const a = await tx.query<{ id: string }>(
      `INSERT INTO tenants (type, name, trial_started_at, trial_ends_at)
       VALUES ('family', 'POC משפחת כהן', now(), now() + interval '30 days')
       RETURNING id`,
    );
    const b = await tx.query<{ id: string }>(
      `INSERT INTO tenants (type, name, trial_started_at, trial_ends_at)
       VALUES ('family', 'POC משפחת לוי', now(), now() + interval '30 days')
       RETURNING id`,
    );

    const floor = JSON.stringify({ mode: "enforce", onRedAction: "lockout" });

    const deviceA = await tx.query<{ id: string }>(
      `INSERT INTO devices (tenant_id, hwid, display_name, install_profile, enforcement_mode, policy_floor)
       VALUES ($1, 'HWIDPOCAAAAAAAAAAAAAAAAAA1', 'המחשב של יוסי', 'family_child', 'enforce', $2)
       RETURNING id`,
      [a.rows[0]!.id, floor],
    );

    const deviceB = await tx.query<{ id: string }>(
      `INSERT INTO devices (tenant_id, hwid, display_name, install_profile, enforcement_mode, policy_floor)
       VALUES ($1, 'HWIDPOCBBBBBBBBBBBBBBBBBB2', 'המחשב של דוד', 'family_child', 'enforce', $2)
       RETURNING id`,
      [b.rows[0]!.id, floor],
    );

    for (const [deviceId, tenantId] of [
      [deviceA.rows[0]!.id, a.rows[0]!.id],
      [deviceB.rows[0]!.id, b.rows[0]!.id],
    ]) {
      await tx.query(
        `INSERT INTO device_state (device_id, tenant_id, last_seen_at, last_status, last_score)
         VALUES ($1, $2, now(), 'safe', 95) ON CONFLICT (device_id) DO NOTHING`,
        [deviceId, tenantId],
      );
    }

    return {
      tenantA: a.rows[0]!.id,
      tenantB: b.rows[0]!.id,
      deviceA: deviceA.rows[0]!.id,
      deviceB: deviceB.rows[0]!.id,
    };
  });

  const emails = {
    parentA: `parent-a-${suffix}@safeme.test`,
    parentB: `parent-b-${suffix}@safeme.test`,
    member: `member-a-${suffix}@safeme.test`,
    operator: `op-${suffix}@safeme.test`,
  };

  await createUser(pool, { email: emails.parentA, password: PASSWORD, role: "tenant_owner", tenantId: seed.tenantA });
  await createUser(pool, { email: emails.parentB, password: PASSWORD, role: "tenant_owner", tenantId: seed.tenantB });
  await createUser(pool, { email: emails.member, password: PASSWORD, role: "tenant_member", tenantId: seed.tenantA });
  await createUser(pool, { email: emails.operator, password: PASSWORD, role: "support_operator", tenantId: null });

  ok("נוצרו שני דיירים, שני מכשירים וארבעה משתמשים");

  /** מתחבר ומשלים אימות שני כשנדרש. */
  async function signIn(email: string): Promise<Actor> {
    const login = await app.fastify.inject({
      method: "POST",
      url: "/api/portal/v1/auth/login",
      payload: { email, password: PASSWORD },
    });

    const body = login.json<{ csrfToken: string; mfaRequired: boolean }>();
    const cookie = String(login.headers["set-cookie"]).split(";")[0]!;
    const actor: Actor = { cookie, csrf: body.csrfToken };

    if (!body.mfaRequired) return actor;

    const enroll = await app.fastify.inject({
      method: "POST",
      url: "/api/portal/v1/auth/mfa/enroll",
      headers: { cookie, "x-safeme-csrf": actor.csrf },
    });

    const secret = enroll.json<{ secret: string }>().secret;

    await app.fastify.inject({
      method: "POST",
      url: "/api/portal/v1/auth/mfa/confirm",
      headers: { cookie, "x-safeme-csrf": actor.csrf },
      payload: { code: totp(secret) },
    });

    return actor;
  }

  const get = (actor: Actor, url: string) =>
    app.fastify.inject({ method: "GET", url, headers: { cookie: actor.cookie } });

  const post = (actor: Actor, url: string, payload: object = {}) =>
    app.fastify.inject({
      method: "POST",
      url,
      headers: { cookie: actor.cookie, "x-safeme-csrf": actor.csrf },
      payload,
    });

  const parentA = await signIn(emails.parentA);
  const parentB = await signIn(emails.parentB);
  const member = await signIn(emails.member);
  const operator = await signIn(emails.operator);

  // ─────────────────────────────────────────────── בידוד
  section("1 · בידוד דיירים דרך הפורטל");

  const listA = await get(parentA, "/api/portal/v1/devices");
  const devicesA = listA.json<{ devices: Array<{ id: string; display_name: string }> }>().devices;

  check(
    devicesA.length === 1 && devicesA[0]!.display_name === "המחשב של יוסי",
    "הורה רואה רק את המכשיר שלו",
    devicesA.map((d) => d.display_name).join(", "),
  );

  const crossRead = await get(parentA, `/api/portal/v1/devices/${seed.deviceB}`);

  check(
    crossRead.statusCode === 404,
    "גישה למכשיר של משפחה אחרת מחזירה 404",
    "אותה תשובה כמו מכשיר שאינו קיים",
  );

  const crossLock = await post(parentA, `/api/portal/v1/devices/${seed.deviceB}/lockout`, {
    minutes: 30,
    reason: "ניסיון חוצה דיירים",
  });

  check(crossLock.statusCode === 404, "נעילת מכשיר של משפחה אחרת נחסמת");

  const listOperator = await get(operator, "/api/portal/v1/devices");

  check(
    listOperator.json<{ count: number }>().count === 2,
    "מוקדן רואה את כל המכשירים",
    `${listOperator.json<{ count: number }>().count} מכשירים`,
  );

  // ─────────────────────────────────────────────── הרשאות
  section("2 · הרשאות נאכפות בשרת");

  const memberLock = await post(member, `/api/portal/v1/devices/${seed.deviceA}/lockout`, {
    minutes: 15,
    reason: "צופה מנסה לנעול",
  });

  check(memberLock.statusCode === 403, "צופה אינו יכול לנעול", `סטטוס ${memberLock.statusCode}`);

  const memberList = await get(member, "/api/portal/v1/devices");

  check(memberList.statusCode === 200, "צופה כן יכול לצפות");

  const memberToken = await post(member, "/api/portal/v1/enroll-tokens", {
    installProfile: "family_child",
  });

  check(memberToken.statusCode === 403, "צופה אינו יכול ליצור אסימון רישום");

  // ─────────────────────────────────────────────── אימות קלט
  section("3 · אימות קלט הנעילה");

  const noDuration = await post(parentA, `/api/portal/v1/devices/${seed.deviceA}/lockout`, {
    reason: "בלי משך",
  });

  check(noDuration.statusCode === 400, "נעילה בלי משך נדחית", "לכל נעילה יש זמן סיום");

  const tooLong = await post(parentA, `/api/portal/v1/devices/${seed.deviceA}/lockout`, {
    minutes: 100_000,
    reason: "משך חורג",
  });

  check(tooLong.statusCode === 400, "משך שחורג מ-24 שעות נדחה");

  // ─────────────────────────────────────────────── פקודה עד המכשיר
  section("4 · פקודת נעילה מגיעה למכשיר");

  const lock = await post(parentA, `/api/portal/v1/devices/${seed.deviceA}/lockout`, {
    minutes: 45,
    reason: "שעת שינה",
  });

  check(lock.statusCode === 200, "ההורה יצר פקודת נעילה");

  // הנפקת אסימון מכשיר, כדי לדמות פעימה אמיתית
  const enrollToken = `ENR-${randomBytes(8).toString("hex").toUpperCase()}`;

  await withPlatform(pool, SYSTEM, async (tx) => {
    const { hashEnrollToken } = await import("../src/auth/device-token.ts");

    await tx.query(
      `INSERT INTO enroll_tokens
         (tenant_id, token_hash, install_profile, enforcement_mode, policy_floor, max_uses, expires_at)
       VALUES ($1, $2, 'family_child', 'enforce', '{}'::jsonb, 5, now() + interval '1 day')`,
      [seed.tenantA, hashEnrollToken(enrollToken)],
    );
  });

  const enrolled = await app.fastify.inject({
    method: "POST",
    url: "/api/v1/enroll",
    payload: { enrollToken, hwid: "HWIDPOCAAAAAAAAAAAAAAAAAA1" },
  });

  const deviceToken = enrolled.json<{ deviceToken: string }>().deviceToken;

  const beat = await app.fastify.inject({
    method: "POST",
    url: "/api/v1/heartbeat",
    headers: {
      authorization: `Bearer ${deviceToken}`,
      "x-safeme-hwid": "HWIDPOCAAAAAAAAAAAAAAAAAA1",
    },
    payload: {
      hwid: "HWIDPOCAAAAAAAAAAAAAAAAAA1",
      sequence: 10,
      status: "safe",
      score: 95,
      activeAdapters: [],
      failedProbes: [],
      tamperEvents: [],
      lockoutActive: false,
    },
  });

  const commands = beat.json<{
    commands: Array<{ id: string; type: string; args: Record<string, string> }>;
  }>().commands;

  check(
    commands.length === 1 && commands[0]!.type === "Lockout",
    "המכשיר קיבל את הפקודה בפעימה",
    `type=${commands[0]?.type}`,
  );

  check(
    commands[0]!.args["minutes"] === "45" && commands[0]!.args["reason"] === "שעת שינה",
    "המשך והסיבה הועברו כמו שהם",
    JSON.stringify(commands[0]!.args),
  );

  // פעימה שנייה: הפקודה כבר נמסרה ולא תחזור
  const beat2 = await app.fastify.inject({
    method: "POST",
    url: "/api/v1/heartbeat",
    headers: {
      authorization: `Bearer ${deviceToken}`,
      "x-safeme-hwid": "HWIDPOCAAAAAAAAAAAAAAAAAA1",
    },
    payload: {
      hwid: "HWIDPOCAAAAAAAAAAAAAAAAAA1",
      sequence: 11,
      status: "blocked",
      score: 0,
      activeAdapters: [],
      failedProbes: [],
      tamperEvents: [],
      lockoutActive: true,
    },
  });

  check(
    beat2.json<{ commands: unknown[] }>().commands.length === 0,
    "פקודה שנמסרה אינה נמסרת שוב",
    "מונע נעילה כפולה",
  );

  // ─────────────────────────────────────────────── שחרור
  section("5 · שחרור מבטל נעילה ממתינה");

  await post(parentA, `/api/portal/v1/devices/${seed.deviceA}/lockout`, {
    minutes: 60,
    reason: "נעילה שתבוטל",
  });

  await post(parentA, `/api/portal/v1/devices/${seed.deviceA}/release`);

  const statuses = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ type: string; status: string }>(
      `SELECT type::text, status::text FROM device_commands
       WHERE device_id = $1 ORDER BY created_at DESC LIMIT 2`,
      [seed.deviceA],
    );

    return r.rows;
  });

  check(
    statuses[0]?.type === "release_lockout" && statuses[0]?.status === "pending",
    "פקודת שחרור ממתינה",
  );

  check(
    statuses[1]?.type === "lockout" && statuses[1]?.status === "cancelled",
    "הנעילה שטרם נאספה בוטלה",
    "אחרת המכשיר היה נועל ומיד משתחרר",
  );

  // ─────────────────────────────────────────────── סיכום ותיעוד
  section("6 · מסך סיכום ותיעוד");

  const summary = await get(parentA, "/api/portal/v1/summary");
  const summaryBody = summary.json<{ total: number; safe: number }>();

  check(summaryBody.total === 1, "הסיכום מוגבל לדייר", `${summaryBody.total} מכשירים`);

  const timeline = await get(parentA, `/api/portal/v1/devices/${seed.deviceA}/timeline`);
  const timelineBody = timeline.json<{ commands: unknown[]; heartbeats: unknown[] }>();

  check(timelineBody.commands.length >= 2, "ציר הזמן מציג את הפקודות");
  check(timelineBody.heartbeats.length >= 2, "ציר הזמן מציג פעימות");

  const audited = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ action: string }>(
      `SELECT DISTINCT action FROM audit_log
       WHERE action LIKE 'device.%' OR action LIKE 'enrollToken.%'`,
    );

    return r.rows.map((x) => x.action);
  });

  check(audited.includes("device.lockout.requested"), "בקשת נעילה תועדה");
  check(audited.includes("device.lockout.released"), "שחרור תועד");

  // ─────────────────────────────────────────────── אסימון רישום
  section("7 · אסימון רישום");

  const token = await post(parentA, "/api/portal/v1/enroll-tokens", {
    installProfile: "family_child",
    maxUses: 3,
  });

  const tokenBody = token.json<{ token: string; warning: string }>();

  check(token.statusCode === 200 && tokenBody.token.startsWith("ENR-"), "הורה יצר אסימון רישום");

  const stored = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ n: string }>(
      "SELECT count(*) AS n FROM enroll_tokens WHERE token_hash = $1",
      [(await import("../src/auth/device-token.ts")).hashEnrollToken(tokenBody.token)],
    );

    return Number(r.rows[0]!.n);
  });

  check(stored === 1, "האסימון נשמר כ-hash בלבד", "הערך הגולמי אינו במאגר");

  console.log("\n" + "═".repeat(64));
  console.log(`עברו ${passed} · נכשלו ${failed}`);
  console.log("═".repeat(64));

  await app.close();
  await pool.end();

  if (failed > 0) process.exitCode = 1;
}

function ok(title: string): void {
  passed += 1;
  console.log(`  ✓ ${title}`);
}

main().catch((error: unknown) => {
  console.error("\nה-POC נכשל:", error instanceof Error ? error.stack : error);
  process.exitCode = 1;
});
