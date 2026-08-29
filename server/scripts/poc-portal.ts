import pg from "pg";
import { randomBytes, randomUUID } from "node:crypto";
import { buildApp } from "../src/app.ts";
import { trackNetwork } from "../src/network/track.ts";
import { alwaysAllowHosts } from "../src/policy/baseline.ts";
import { seedProviders } from "../src/policy/providers.ts";
import { isAtLeastAsStrict } from "../src/policy/floor.ts";
import { inCidr } from "../src/network/blocklist.ts";
import { fileNameForToken, tokenFromFileName } from "../src/installer/filename.ts";
import { createPool, sslFor, withPlatform } from "../src/db/client.ts";
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

  const uninstallSigner = LocalSigner.ephemeral(`poc-uninstall-${randomUUID().slice(0, 8)}`);
  const updateSigner = LocalSigner.ephemeral(`poc-update-${randomUUID().slice(0, 8)}`);


  const suffix = randomBytes(3).toString("hex");

  // ─────────────────────────────────────────────── הכנה
  section("הכנה: שתי משפחות, מכשיר לכל אחת, שלושה תפקידים");

  /*
   * ספקי בדיקה משאריות של הרצות קודמות.
   *
   * הטבלה גלובלית ואינה נמחקת בזריעה, והרצה שנפלה באמצע משאירה
   * בה שורות. הן מזהמות את מסך המצב ואת המדיניות שמתפרסמת.
   */
  {
    const ownerUrl = process.env["DATABASE_URL"];

    if (ownerUrl) {
      const owner = new pg.Client({ connectionString: ownerUrl, ssl: sslFor(ownerUrl) });

      await owner.connect();
      await owner.query("DELETE FROM providers WHERE key LIKE 'poc%'");
      await owner.end();
    }
  }

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
    admin: `admin-${suffix}@safeme.test`,
  };

  await createUser(pool, { email: emails.parentA, password: PASSWORD, role: "tenant_owner", tenantId: seed.tenantA });
  await createUser(pool, { email: emails.parentB, password: PASSWORD, role: "tenant_owner", tenantId: seed.tenantB });
  await createUser(pool, { email: emails.member, password: PASSWORD, role: "tenant_member", tenantId: seed.tenantA });
  await createUser(pool, { email: emails.operator, password: PASSWORD, role: "support_operator", tenantId: null });
  await createUser(pool, { email: emails.admin, password: PASSWORD, role: "platform_admin", tenantId: null });

  ok("נוצרו שני דיירים, שני מכשירים וארבעה משתמשים");

  /*
   * השרת עולה רק אחרי הזריעה, ובמכוון.
   *
   * buildApp מפעיל את סורק המכשירים ששתקו, והסריקה הראשונה יוצאת
   * מיד. כשהוא עלה קודם, ה-UPDATE שלו על device_state התנגש
   * ב-DELETE FROM devices של הזריעה — והתוצאה הייתה deadlock
   * שנראה כמו כשל אקראי בבדיקה.
   */
  const app = await buildApp({
    config,
    pool,
    signer,
    looseningSigner,
    uninstallSigner,
    updateSigner,
    logger: false,
  });


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

  const patch = (actor: Actor, url: string, payload: object = {}) =>
    app.fastify.inject({
      method: "PATCH",
      url,
      headers: { cookie: actor.cookie, "x-safeme-csrf": actor.csrf },
      payload,
    });

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

  const tokenBody = token.json<{
    token: string;
    fileName: string;
    downloadPath: string;
    warning: string;
  }>();

  check(token.statusCode === 200 && tokenBody.token.startsWith("ENR-"), "הורה יצר אסימון רישום");

  /*
   * הקישור מגיע מהשרת ולא נבנה בפורטל.
   *
   * שם הקובץ הוא מה שקושר את המחשב לחשבון, ובנייתו בשני מקומות
   * הייתה יוצרת מקור אמת שני שיסטה — בדיוק מה שקרה עם דגל ה-i
   * בביטוי הרגולרי.
   */
  check(
    tokenBody.downloadPath === `/d/${fileNameForToken(tokenBody.token)}`,
    "הקישור להורדה מגיע מוכן מהשרת",
    tokenBody.downloadPath,
  );

  check(
    tokenFromFileName(tokenBody.fileName) === tokenBody.token,
    "והמתקין יקרא מהשם בחזרה את אותו אסימון",
  );

  const stored = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ n: string }>(
      "SELECT count(*) AS n FROM enroll_tokens WHERE token_hash = $1",
      [(await import("../src/auth/device-token.ts")).hashEnrollToken(tokenBody.token)],
    );

    return Number(r.rows[0]!.n);
  });

  check(stored === 1, "האסימון נשמר כ-hash בלבד", "הערך הגולמי אינו במאגר");


  // ─────────────────────────────────────────────── רשתות
  section("7 · אישור רשתות");

  /*
   * שתי רשתות ממתינות אצל הורה A ואחת אצל B. הבידוד נבדק כאן
   * מחדש ולא נסמך על הסעיף הראשון: מסלול חדש הוא הזדמנות חדשה
   * לשכוח את tenant_id.
   */
  const netIds = await withPlatform(pool, SYSTEM, async (tx) => {
    const rows: Record<string, string> = {};

    for (const [key, tenantId, ssid, confidence] of [
      ["a1", seed.tenantA, "Cafe-Free", "none"],
      ["a2", seed.tenantA, "iPhone של דני", "certain"],
      ["b1", seed.tenantB, "Shchenim", "none"],
    ] as const) {
      const r = await tx.query<{ id: string }>(
        `INSERT INTO known_networks (tenant_id, fingerprint, ssid, gateway_ip, hotspot_confidence)
         VALUES ($1, $2, $3, '10.0.0.1', $4) RETURNING id`,
        [tenantId, `fp-${key}-${randomBytes(6).toString("hex")}`, ssid, confidence],
      );

      rows[key] = r.rows[0]!.id;
    }

    return rows;
  });

  const listNets = await get(parentA, "/api/portal/v1/networks");
  const netsA = listNets.json<{ networks: Array<{ id: string }>; policy: string }>();

  check(
    netsA.networks.length === 2 && !netsA.networks.some((n) => n.id === netIds["b1"]),
    "הורה רואה רק את הרשתות של הדייר שלו",
    `${netsA.networks.length} רשתות, ללא זו של דייר B`,
  );

  check(netsA.policy === "balanced", "מדיניות ברירת המחדל היא מאוזן", netsA.policy);

  // הרשאה: אישור מתיר, ולכן אינו נגזר מהרשאת הצפייה
  const memberTry = await post(member, `/api/portal/v1/networks/${netIds["a1"]}/decide`, {
    approval: "approved",
  });

  check(memberTry.statusCode === 403, "בן משפחה אינו מאשר רשתות", `סטטוס ${memberTry.statusCode}`);

  const crossTenant = await post(parentA, `/api/portal/v1/networks/${netIds["b1"]}/decide`, {
    approval: "approved",
  });

  check(
    crossTenant.statusCode === 404,
    "הורה אינו מכריע על רשת של דייר אחר",
    `סטטוס ${crossTenant.statusCode}`,
  );

  const approve = await post(parentA, `/api/portal/v1/networks/${netIds["a1"]}/decide`, {
    approval: "approved",
  });

  check(approve.statusCode === 200, "הורה אישר רשת", approve.json<{ ssid: string }>().ssid);

  /*
   * אישור של נקודה חמה ודאית מצליח, אבל מוחזרת בו אזהרה: הסוכן
   * יחסום אותה בכל מקרה, וכפתור שמצליח בלי להשפיע הוא שקר.
   */
  const futile = await post(parentA, `/api/portal/v1/networks/${netIds["a2"]}/decide`, {
    approval: "approved",
  });

  check(
    futile.statusCode === 200 && futile.json<{ warning: string | null }>().warning !== null,
    "אישור של שיתוף אינטרנט מטלפון מחזיר אזהרה",
    futile.json<{ warning: string | null }>().warning ?? "ללא אזהרה",
  );

  // המגבלה בסכימה: הכרעה חייבת להיות עם זמן
  const decidedAt = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ decided_at: Date | null }>(
      "SELECT decided_at FROM known_networks WHERE id = $1",
      [netIds["a1"]],
    );

    return r.rows[0]!.decided_at;
  });

  check(decidedAt !== null, "מועד ההכרעה נשמר", "המגבלה בסכימה מחייבת זאת");

  const policyByMember = await post(member, "/api/portal/v1/settings/network-policy", {
    networkPolicy: "lenient",
  });

  check(
    policyByMember.statusCode === 403,
    "בן משפחה אינו מרפה את המדיניות",
    `סטטוס ${policyByMember.statusCode}`,
  );

  const setStrict = await post(parentA, "/api/portal/v1/settings/network-policy", {
    networkPolicy: "strict",
  });

  const afterPolicy = await get(parentA, "/api/portal/v1/networks");

  check(
    setStrict.statusCode === 200 && afterPolicy.json<{ policy: string }>().policy === "strict",
    "הורה שינה את מדיניות הרשתות",
    afterPolicy.json<{ policy: string }>().policy,
  );

  const badPolicy = await post(parentA, "/api/portal/v1/settings/network-policy", {
    networkPolicy: "off",
  });

  check(badPolicy.statusCode === 400, "ערך מדיניות לא מוכר נדחה", `סטטוס ${badPolicy.statusCode}`);

  const netAudit = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ action: string }>(
      `SELECT action FROM audit_log
        WHERE tenant_id = $1 AND action LIKE 'network.%'
        ORDER BY at DESC`,
      [seed.tenantA],
    );

    return r.rows.map((x) => x.action);
  });

  check(
    netAudit.length === 2 && netAudit.every((a) => a === "network.approved"),
    "כל הכרעה נרשמה ביומן הביקורת",
    netAudit.join(", "),
  );


  // ─────────────────────────────────────────────── חסימת עקיפות
  section("8 · הגדרת default-deny");

  /*
   * ההגדרה הזו אינה כותבת שורה אלא מפרסמת מדיניות חתומה. הבדיקות
   * כאן מוודאות שהיא באמת מפרסמת, ושהיא לא פותחת דרך לנעול משפחה
   * שלמה בטופס שנשלח חצי.
   */

  const egBefore = await get(parentA, "/api/portal/v1/settings/egress");
  const egBody = egBefore.json<{ rule: { enabled: boolean }; version: number | null }>();

  check(
    egBefore.statusCode === 200 && egBody.rule.enabled === false,
    "ברירת המחדל כבויה",
    "סוכן קיים אינו משנה התנהגות כשהשרת מתעדכן",
  );

  const egByMember = await post(member, "/api/portal/v1/settings/egress", { enabled: true });

  check(
    egByMember.statusCode === 403,
    "בן משפחה אינו משנה את ההגדרה",
    `סטטוס ${egByMember.statusCode}`,
  );

  const egBadCidr = await post(parentA, "/api/portal/v1/settings/egress", {
    enabled: true,
    resolvers: ["לא כתובת"],
  });

  check(
    egBadCidr.statusCode === 400,
    "כתובת לא תקינה נדחית",
    egBadCidr.json<{ error: string }>().error,
  );

  const egEmptyProxy = await post(parentA, "/api/portal/v1/settings/egress", {
    enabled: true,
    mode: "proxyEndpoint",
    providerCidrs: [],
  });

  check(
    egEmptyProxy.statusCode === 400,
    "מצב שרתי ספק בלי כתובות נדחה",
    "אחרת כל המכשירים היו ננעלים בגלל טופס חסר",
  );

  const egOn = await post(parentA, "/api/portal/v1/settings/egress", {
    enabled: true,
    mode: "ispLevel",
    resolvers: ["198.51.100.5/32"],
  });

  const egOnBody = egOn.json<{ version: number; rule: { blockedPorts: unknown[] } }>();

  check(
    egOn.statusCode === 200 && egOnBody.version > 0,
    "ההגדרה פורסמה כגרסת מדיניות",
    `גרסה ${egOnBody.version}`,
  );

  // הבדיקה המרכזית: מה שנשמר הוא מה שנחתם ונשלח למכשיר
  const signedEgress = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ signed_bytes: Buffer }>(
      `SELECT signed_bytes FROM policies
        WHERE tenant_id = $1 ORDER BY version DESC LIMIT 1`,
      [seed.tenantA],
    );

    if (!r.rows[0]) return null;

    const parsed = JSON.parse(r.rows[0].signed_bytes.toString("utf8")) as {
      enforcement?: { egress?: { enabled?: boolean; resolvers?: string[] } };
    };

    return parsed.enforcement?.egress ?? null;
  });

  check(
    signedEgress?.enabled === true && signedEgress.resolvers?.[0] === "198.51.100.5/32",
    "הכלל נמצא בתוך הבתים החתומים",
    "הגדרה שאינה חתומה אינה משנה דבר על אף מחשב",
  );

  check(
    Array.isArray(egOnBody.rule.blockedPorts) && egOnBody.rule.blockedPorts.length > 0,
    "רשימת החסימות נשלחת עם הכלל",
    `${egOnBody.rule.blockedPorts.length} פורטים`,
  );

  const egAgain = await get(parentA, "/api/portal/v1/settings/egress");

  check(
    egAgain.json<{ rule: { enabled: boolean } }>().rule.enabled === true,
    "ההגדרה נקראת בחזרה מהמדיניות שפורסמה",
  );

  const egOff = await post(parentA, "/api/portal/v1/settings/egress", { enabled: false });

  check(
    egOff.statusCode === 200 && egOff.json<{ version: number }>().version > egOnBody.version,
    "כיבוי מפרסם גרסה חדשה ולא מוחק",
    "היסטוריית המדיניות נשמרת במלואה",
  );


  // ─────────────────────────────────────────────── רשימה שחורה
  section("9 · רשימה שחורה");

  const ruleByMember = await post(member, "/api/portal/v1/networks/rules", {
    kind: "category",
    pattern: "open",
  });

  check(
    ruleByMember.statusCode === 403,
    "בן משפחה אינו מוסיף כללים",
    `סטטוס ${ruleByMember.statusCode}`,
  );

  const wideRule = await post(parentA, "/api/portal/v1/networks/rules", {
    kind: "ssid",
    pattern: "*",
  });

  check(
    wideRule.statusCode === 400,
    'התבנית "*" נדחית ברמת ה-API',
    "היא חוסמת גם את הרשת הביתית, והמשפחה נשארת בלי אינטרנט",
  );

  const goodRule = await post(parentA, "/api/portal/v1/networks/rules", {
    kind: "category",
    pattern: "unfiltered",
    note: "בלי סינון, בלי אינטרנט",
  });

  const ruleId = goodRule.json<{ id: string }>().id;

  check(goodRule.statusCode === 200 && typeof ruleId === "string", "כלל נוסף");

  const dupRule = await post(parentA, "/api/portal/v1/networks/rules", {
    kind: "category",
    pattern: "unfiltered",
  });

  check(dupRule.statusCode === 409, "כלל כפול נדחה", `סטטוס ${dupRule.statusCode}`);

  const rulesList = await get(parentA, "/api/portal/v1/networks/rules");
  const rulesBody = rulesList.json<{ rules: Array<{ id: string }>; categories: object }>();

  check(
    rulesBody.rules.some((r) => r.id === ruleId) && Object.keys(rulesBody.categories).length === 3,
    "הכללים והקטגוריות מוחזרים",
    `${rulesBody.rules.length} כללים`,
  );

  const rulesForB = await get(parentB, "/api/portal/v1/networks/rules");

  check(
    !rulesForB.json<{ rules: Array<{ id: string }> }>().rules.some((r) => r.id === ruleId),
    "כללים אינם דולפים בין דיירים",
  );

  /*
   * ביטול כלל משחרר את הרשתות שנחסמו בגללו — אבל להמתנה לאישור,
   * לא לאישור. הן נחסמו פעם אחת מסיבה כלשהי, וההחלטה מה לעשות
   * איתן עכשיו היא של ההורה.
   */
  const captured = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ id: string }>(
      `INSERT INTO known_networks
         (tenant_id, fingerprint, ssid, approval, blocked_by_rule, decided_at)
       VALUES ($1, $2, 'Shchenim', 'blocked', $3, now())
       RETURNING id`,
      [seed.tenantA, `fp-rule-${randomBytes(6).toString("hex")}`, ruleId],
    );

    return r.rows[0]!.id;
  });

  const removed = await post(parentA, `/api/portal/v1/networks/rules/${ruleId}/delete`);

  check(
    removed.statusCode === 200 && removed.json<{ freed: number }>().freed === 1,
    "ביטול כלל משחרר את הרשתות שנחסמו בגללו",
    removed.json<{ note: string | null }>().note ?? "",
  );

  const freedState = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ approval: string; blocked_by_rule: string | null }>(
      "SELECT approval, blocked_by_rule FROM known_networks WHERE id = $1",
      [captured],
    );

    return r.rows[0]!;
  });

  check(
    freedState.approval === "pending" && freedState.blocked_by_rule === null,
    "והן חוזרות להמתנה, לא לאישור",
    "הן נחסמו פעם אחת מסיבה כלשהי",
  );

  const removeAgain = await post(parentA, `/api/portal/v1/networks/rules/${ruleId}/delete`);

  check(removeAgain.statusCode === 404, "ביטול כלל שאינו קיים מחזיר 404");


  // ─────────────────────────────────────────────── שלוש התקלות מהשטח
  section("10 · תקלות שנפלו בהתקנה אמיתית");

  /*
   * 1. הרשת שממנה מתקינים.
   *
   * ההתקנה הראשונה חסמה את הרשת שממנה היא עצמה הורדה. ההורה עמד
   * מול מחשב חסום, והדרך לאשר עברה בפורטל שהמחשב כבר לא הגיע אליו.
   */
  const freshTenant = await withPlatform(pool, SYSTEM, async (tx) => {
    const t = await tx.query<{ id: string }>(
      `INSERT INTO tenants (type, name, trial_started_at, trial_ends_at)
       VALUES ('family', 'POC רשת ראשונה', now(), now() + interval '30 days')
       RETURNING id`,
    );

    const tenantId = t.rows[0]!.id;

    const d = await tx.query<{ id: string }>(
      `INSERT INTO devices (tenant_id, hwid, machine_name, install_profile,
                            enforcement_mode, status, policy_floor)
       VALUES ($1, $2, 'PC', 'family_child', 'enforce', 'active', '{}'::jsonb)
       RETURNING id`,
      [tenantId, randomBytes(16).toString("hex")],
    );

    return { tenantId, deviceId: d.rows[0]!.id };
  });

  const firstSeen = await withPlatform(pool, SYSTEM, async (tx) =>
    trackNetwork(
      tx,
      { deviceId: freshTenant.deviceId, tenantId: freshTenant.tenantId },
      [{ name: "Wi-Fi", ssid: "Moshe", gateway: "192.168.1.1" }],
      // בלי ספק מזוהה — בדיוק המצב שחסם בשטח
      null,
    ));

  check(
    firstSeen?.action === "allow",
    "הרשת שממנה מתקינים מאושרת מאליה",
    firstSeen?.reason ?? "",
  );

  const secondSeen = await withPlatform(pool, SYSTEM, async (tx) =>
    trackNetwork(
      tx,
      { deviceId: freshTenant.deviceId, tenantId: freshTenant.tenantId },
      [{ name: "Wi-Fi", ssid: "Shchenim", gateway: "192.168.9.1" }],
      null,
    ));

  check(
    secondSeen?.action === "await_approval",
    "אבל השנייה כבר נשאלת",
    "האישור האוטומטי הוא לרשת ההתקנה בלבד, לא לכל רשת",
  );

  /*
   * 2. אסימון CSRF שאבד.
   *
   * הוא נשמר ב-sessionStorage, שמת עם סגירת הלשונית — בעוד
   * שעוגיית ההפעלה שורדת. התוצאה: משתמש מחובר שכל פעולת כתיבה
   * שלו נדחית, בלי דרך להתאושש.
   */
  const meWithout = await app.fastify.inject({
    method: "GET",
    url: "/api/portal/v1/auth/me",
    headers: { cookie: parentA.cookie },
  });

  const recovered = meWithout.json<{ csrfToken?: string }>().csrfToken;

  check(
    typeof recovered === "string" && recovered.length > 20,
    "לקוח בלי אסימון מקבל חדש",
    "בלי זה, לשונית שנפתחה מחדש הופכת לחשבון לקריאה בלבד",
  );

  const writeWithNew = await app.fastify.inject({
    method: "POST",
    url: "/api/portal/v1/settings/network-policy",
    headers: { cookie: parentA.cookie, "x-safeme-csrf": recovered! },
    payload: { networkPolicy: "balanced" },
  });

  check(writeWithNew.statusCode === 200, "והאסימון החדש עובד");

  const meWith = await app.fastify.inject({
    method: "GET",
    url: "/api/portal/v1/auth/me",
    headers: { cookie: parentA.cookie, "x-safeme-csrf": recovered! },
  });

  check(
    meWith.json<{ csrfToken?: string }>().csrfToken === undefined,
    "לקוח עם אסימון תקף אינו מקבל חדש",
    "סיבוב בכל טעינה היה פוסל בקשת כתיבה שיצאה במקביל",
  );

  // האסימון הקודם של parentA כבר אינו תקף — הוא סובב
  parentA.csrf = recovered!;

  /*
   * 3. מדיניות בסיס.
   *
   * מכשיר שנרשם לחשבון חדש קיבל 404 ורץ בלי הגדרות כלל.
   */
  const baseline = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{
      version: number;
      body: { baselineVersion?: number; enforcement?: { mode?: string } };
    }>(
      "SELECT version, body FROM policies WHERE tenant_id IS NULL ORDER BY version DESC LIMIT 1",
    );

    return r.rows[0] ?? null;
  });

  check(baseline !== null, "קיימת תבנית מדיניות גלובלית", `גרסה ${baseline?.version}`);

  /*
   * הסימון בתוך הגוף, ולא מספר הגרסה.
   *
   * מספר הגרסה מטפס בכל עריכת ספק, ולכן הוא עוקף במהרה את מספר
   * התבנית — ומאותו רגע שום שינוי בקוד לא היה מגיע למכשירים.
   */
  check(
    typeof baseline?.body.baselineVersion === "number",
    "והיא נושאת סימון תוכן ולא רק מספר גרסה",
    `סימון ${baseline?.body.baselineVersion}`,
  );

  /*
   * enforce ולא monitor.
   *
   * הבדיקה הזו דרשה monitor, מתוך מחשבה שמכשיר שהרגע הותקן אינו
   * המקום להתחיל בחסימה. בשטח הסוכן דחה את החבילה כולה: המכשיר
   * נרשם עם רצפת enforce, והרצפה אינה מרשה לרדת מתחתיה.
   *
   * התוצאה הייתה הגרועה משתי האפשרויות — לא רק שלא הקלנו, אלא
   * ששום דבר בחבילה לא חל, כולל כללי זיהוי הספקים.
   */
  check(
    baseline?.body.enforcement?.mode === "monitor",
    "והיא במצב תצפית, לשלב הפיילוט",
    "מודדת ומדווחת, ואינה חוסמת על סמך מסקנה שהסוכן הסיק בעצמו",
  );


  /*
   * 4. הפורטל נשאר נגיש גם בחסימה.
   *
   * הסוכן התיר רק את מארח ה-API, והפורטל יושב על מארח אחר. מחשב
   * חסום יכול היה לדווח על עצמו, וההורה שישב מולו לא יכול היה
   * להגיע למסך שמסיר את החסימה. חסימה שאין ממנה יציאה מהמחשב
   * עצמו היא מלכודת, לא הגנה.
   */
  const allowed = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ body: { enforcement?: { alwaysAllow?: { hosts?: string[] } } } }>(
      "SELECT body FROM policies WHERE tenant_id IS NULL ORDER BY version DESC LIMIT 1",
    );

    return r.rows[0]?.body.enforcement?.alwaysAllow?.hosts ?? [];
  });

  check(
    allowed.length > 0,
    "מדיניות הבסיס מתירה מארח גם בחסימה",
    allowed.join(", "),
  );

  check(
    allowed.includes(new URL(config.PORTAL_URL).host),
    "והמארח הוא זה של מרכז הניהול",
    "בלעדיו, חסימה נועלת גם את המסך שמסיר אותה",
  );

  check(
    alwaysAllowHosts("https://portal.example.test").includes("portal.example.test"),
    "המארח נגזר מהכתובת המוגדרת",
  );

  check(
    alwaysAllowHosts("לא כתובת").length === 0,
    "כתובת לא תקינה אינה מפילה את התבנית",
    "עלייה שנכשלת גרועה מתבנית עם מארח חסר",
  );


  section("11 · שכחת רשת");

  {
    const target = netIds["a1"]!;

    const byMember = await post(member, `/api/portal/v1/networks/${target}/forget`);

    check(byMember.statusCode === 403, "בן משפחה אינו שוכח רשתות", `סטטוס ${byMember.statusCode}`);

    const crossTenant = await post(parentA, `/api/portal/v1/networks/${netIds["b1"]}/forget`);

    check(crossTenant.statusCode === 404, "ואי אפשר לשכוח רשת של דייר אחר");

    // סשן פתוח, כדי לוודא שהמחיקה גוררת אותו ואינה נופלת על מפתח זר
    await withPlatform(pool, SYSTEM, async (tx) => {
      await tx.query(
        `INSERT INTO network_sessions (device_id, tenant_id, network_id, outcome)
         VALUES ($1, $2, $3, 'allowed')`,
        [seed.deviceA, seed.tenantA, target],
      );
    });

    const forgotten = await post(parentA, `/api/portal/v1/networks/${target}/forget`);

    check(forgotten.statusCode === 200, "הורה שכח רשת", forgotten.json<{ ssid: string }>().ssid);

    const left = await withPlatform(pool, SYSTEM, async (tx) => {
      const net = await tx.query("SELECT 1 FROM known_networks WHERE id = $1", [target]);
      const ses = await tx.query("SELECT 1 FROM network_sessions WHERE network_id = $1", [target]);

      return { net: net.rowCount ?? 0, ses: ses.rowCount ?? 0 };
    });

    check(
      left.net === 0 && left.ses === 0,
      "והיסטוריית החיבורים הלכה איתה",
      "מי ששוכח רשת מבקש להתחיל מחדש, לא להשאיר חצי תיעוד",
    );

    const again = await post(parentA, `/api/portal/v1/networks/${target}/forget`);

    check(again.statusCode === 404, "שכחה חוזרת מחזירה 404");
  }


  section("12 · כללי זיהוי הספקים");

  {
    /*
     * הגרסה הראשונה של התבנית מנתה ספקים בשם בלבד, ולכן שום ספק
     * לא זוהה אף פעם — הסוכן דיווח "לא זוהה ספק" על מחשב מסונן
     * לגמרי. הבדיקה הזו קיימת כדי שזה לא יחזור בשקט.
     */
    const body = await withPlatform(pool, SYSTEM, async (tx) => {
      const r = await tx.query<{
        body: {
          providers?: Array<{
            id: string;
            rootCa?: { thumbprints?: string[]; subjectPatterns?: string[] };
            network?: { cidrs?: string[] };
          }>;
        };
      }>("SELECT body FROM policies WHERE tenant_id IS NULL ORDER BY version DESC LIMIT 1");

      return r.rows[0]?.body ?? null;
    });

    const providers = body?.providers ?? [];

    check(providers.length >= 4, "התבנית מונה את הספקים", `${providers.length} ספקים`);

    const withRules = providers.filter(
      (p) => (p.rootCa?.thumbprints?.length ?? 0) > 0 || (p.network?.cidrs?.length ?? 0) > 0,
    );

    check(
      withRules.length >= 2,
      "ולפחות לשניים יש כללי זיהוי בפועל",
      withRules.map((p) => p.id).join(", "),
    );

    const netfree = providers.find((p) => p.id === "netfree");

    check(
      (netfree?.rootCa?.thumbprints?.length ?? 0) >= 10,
      "לנטפרי טביעות אצבע של תעודות השורש",
      "הן הסימן החזק ביותר: בלעדיהן הדפדפן לא היה סומך על הסינון",
    );

    check(
      netfree?.rootCa?.thumbprints?.every((t) => /^[0-9A-F]{40}$/.test(t)) === true,
      "וכולן בצורת SHA-1 תקינה",
      "טביעה שגויה אינה נכשלת — היא פשוט לעולם לא מתאימה",
    );

    const rimon = providers.find((p) => p.id === "rimon");

    check(
      rimon?.network?.cidrs?.includes("213.151.48.0/20") === true,
      "לרימון טווח הכתובות שממנו המחשב יוצא",
      "רימון מסננת ברמת הספק, ואין לה תעודה להתקין",
    );

    // הכתובת שנמדדה בפועל על מכונה מחוברת
    check(
      inCidr("213.151.63.84", rimon?.network?.cidrs?.[0] ?? ""),
      "והכתובת שנמדדה בשטח נופלת בתוכו",
      "213.151.63.84 → RIMON1-NET",
    );
  }


  section("13 · ניהול ספקים");

  {
    /*
     * הרשאת פלטפורמה בלבד. דייר שיכול להגדיר מה נחשב "ספק מאושר"
     * יכול לאשר לעצמו כל חיבור שהוא, ובכך לבטל את המוצר מבפנים.
     */
    const byParent = await get(parentA, "/api/portal/v1/providers");

    check(byParent.statusCode === 403, "הורה אינו מנהל ספקים", `סטטוס ${byParent.statusCode}`);

    const list = await get(operator, "/api/portal/v1/providers");

    check(list.statusCode === 403, "וגם לא נציג תמיכה", `סטטוס ${list.statusCode}`);

    const admin = await signIn(emails.admin);
    const asAdmin = await get(admin, "/api/portal/v1/providers");

    const providers = asAdmin.json<{
      providers: Array<{ key: string; hasRules: boolean; verified: boolean }>;
    }>().providers;

    check(asAdmin.statusCode === 200 && providers.length >= 4, "מנהל פלטפורמה רואה את הרשימה");

    /*
     * ההבחנה שקובעת אינה "יש כללים" אלא "אומתו".
     *
     * המיגרציה זרעה לכל הספקים שלד — "CN=Etrog*" ודומיו — שנראה
     * ברשימה בדיוק כמו טביעת אצבע אמיתית ולא יתאים לעולם. בלי
     * ההבחנה, פער נראה כמו כלל שעובד.
     */
    check(
      providers.find((p) => p.key === "netfree")?.verified === true
        && providers.find((p) => p.key === "etrog")?.verified === false,
      "ומסומן למי הנתונים אומתו ולמי לא",
      "שלד נראה כמו כלל עובד, וזה מה שמסתיר את הפער",
    );

    // ---- בדיקות תקינות ----

    /*
     * המוטציות רצות על ספק בדיקה ולא על rimon או netfree.
     *
     * טבלת הספקים גלובלית ומשותפת, ושינוי שלה בבדיקה דורס נתונים
     * שאומתו בשטח — ואז המדיניות שמתפרסמת בסוף ההרצה נושאת את
     * הערכים של הבדיקה. זה בדיוק מה שקרה: כלל ה-TLS של רימון נמחק
     * בכל הרצה.
     */
    const scratch = `poc${suffix}x`;

    await post(admin, "/api/portal/v1/providers", {
      key: scratch,
      displayName: "ספק בדיקה",
      detection: { network: { cidrs: ["203.0.113.0/24"] } },
    });

    const badThumb = await patch(admin, `/api/portal/v1/providers/${scratch}`, {
      detection: { rootCa: { thumbprints: ["לא-טביעה"] } },
    });

    check(
      badThumb.statusCode === 400,
      "טביעת אצבע שגויה נדחית",
      "היא אינה נכשלת בשימוש — היא פשוט לעולם לא מתאימה",
    );

    const wideCidr = await patch(admin, `/api/portal/v1/providers/${scratch}`, {
      detection: { network: { cidrs: ["0.0.0.0/0"] } },
    });

    check(
      wideCidr.statusCode === 400,
      "טווח רחב מדי נדחה",
      "הוא היה מזהה כל מחשב בעולם כמסונן",
    );

    // ---- עדכון אמיתי ----

    const before = await withPlatform(pool, SYSTEM, async (tx) => {
      const r = await tx.query<{ n: string }>(
        "SELECT COALESCE(max(version),0) AS n FROM policies WHERE tenant_id IS NULL",
      );

      return Number(r.rows[0]!.n);
    });

    const added = await patch(admin, `/api/portal/v1/providers/${scratch}`, {
      detection: {
        network: { cidrs: ["213.151.48.0/20", "185.99.32.0/22"], reverseDnsPatterns: [] },
      },
    });

    const version = added.json<{ policyVersion: number }>().policyVersion;

    check(added.statusCode === 200, "מנהל הוסיף טווח לספק");

    check(
      version > before,
      "והמדיניות פורסמה מחדש",
      "כלל ששמור במאגר ולא נחתם אינו משנה דבר על אף מחשב",
    );

    const inPolicy = await withPlatform(pool, SYSTEM, async (tx) => {
      const r = await tx.query<{ signed_bytes: Buffer }>(
        "SELECT signed_bytes FROM policies WHERE tenant_id IS NULL ORDER BY version DESC LIMIT 1",
      );

      const parsed = JSON.parse(r.rows[0]!.signed_bytes.toString("utf8")) as {
        providers?: Array<{ id: string; network?: { cidrs?: string[] } }>;
      };

      return parsed.providers?.find((p) => p.id === scratch)?.network?.cidrs ?? [];
    });

    check(
      inPolicy.includes("185.99.32.0/22"),
      "והטווח החדש נמצא בבתים החתומים",
      inPolicy.join(", "),
    );

    // ---- היסטוריה ----

    const history = await get(admin, `/api/portal/v1/providers/${scratch}/history`);
    const entries = history.json<{ history: Array<{ detection: unknown }> }>().history;

    check(
      entries.length >= 1,
      "השינוי נשמר בהיסטוריה",
      "כלל שגוי מנתק משפחות, וצריך לדעת מה היה קודם ומי שינה",
    );

    // ---- ספק חדש ----

    const created = await post(admin, "/api/portal/v1/providers", {
      key: `poc${suffix}a`,
      displayName: "אתרוג בדיקה",
      detection: { network: { cidrs: ["203.0.113.0/24"] } },
    });

    check(created.statusCode === 200, "מנהל הוסיף ספק חדש");

    const dup = await post(admin, "/api/portal/v1/providers", {
      key: `poc${suffix}a`,
      displayName: "כפול",
    });

    check(dup.statusCode === 409, "מזהה כפול נדחה");

    const badKey = await post(admin, "/api/portal/v1/providers", {
      key: "Etrog Three",
      displayName: "רווחים ורישיות",
    });

    check(
      badKey.statusCode === 400,
      "מזהה עם רווחים ורישיות נדחה",
      "הוא נכנס לחבילת המדיניות ומושווה בסוכן",
    );

    const noRules = await post(admin, "/api/portal/v1/providers", {
      key: `poc${suffix}b`,
      displayName: "ספק בלי כללים",
      detection: {},
    });

    check(
      noRules.statusCode === 200 && noRules.json<{ note: string | null }>().note !== null,
      "ספק בלי כללים נשמר — עם אמירה מפורשת",
      noRules.json<{ note: string | null }>().note ?? "",
    );

    /*
     * ניקוי בהרשאת הבעלים.
     *
     * לאפליקציה אין DELETE על providers, וזה נכון: ספק מכובה ולא
     * נמחק — מחיקה הייתה מייתמת את ההיסטוריה שלו ואת ההפניות אליו
     * מחבילות מדיניות שכבר נחתמו. הבדיקה היא היוצא מן הכלל, והיא
     * מנקה רק את מה שהיא עצמה יצרה.
     */
    const ownerUrl = process.env["DATABASE_URL"];

    if (ownerUrl) {
      const owner = new pg.Client({ connectionString: ownerUrl, ssl: sslFor(ownerUrl) });

      await owner.connect();
      await owner.query("DELETE FROM providers WHERE key LIKE 'poc%'");
      await owner.end();
    } else {
      console.log("      (בלי DATABASE_URL — ספקי הבדיקה נשארו)");
    }
  }


  section("14 · התבנית מול רצפת המכשיר");

  {
    /*
     * הסוכן דוחה חבילה שמקלה מתחת לרצפה שאיתה המכשיר נרשם — וזה
     * כל תפקידה של הרצפה. אבל תבנית שנמוכה מהרצפה אינה "מקלה":
     * היא פשוט לא חלה, ואיתה נופלים גם כללי זיהוי הספקים שאין
     * להם שום קשר להחמרה.
     *
     * זה קרה בשטח: גרסה 3 נדחתה בכל פעימה, והספקים לא זוהו.
     */
    const body = await withPlatform(pool, SYSTEM, async (tx) => {
      const r = await tx.query<{
        body: { enforcement?: { mode?: string; onRedAction?: string;
                               minScoreForGreen?: number; minScoreForYellow?: number } };
      }>("SELECT body FROM policies WHERE tenant_id IS NULL ORDER BY version DESC LIMIT 1");

      return r.rows[0]?.body.enforcement ?? {};
    });

    /*
     * הרצפה נקראת מהאסימון שנוצר בהרשמה, ולא מרשימה קבועה כאן.
     *
     * זו הנקודה: התבנית והרצפה חייבות לזוז יחד. השוואה מול ערכים
     * שכתובים בבדיקה הייתה עוברת גם כששני הצדדים סטו יחד לכיוון
     * שגוי — וזה בדיוק מה שקרה כשהתבנית ירדה ל-monitor והרצפה
     * נשארה enforce.
     */
    const floor = await withPlatform(pool, SYSTEM, async (tx) => {
      const r = await tx.query<{ policy_floor: { mode?: string; onRedAction?: string } }>(
        `SELECT policy_floor FROM enroll_tokens
          WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1`,
        [seed.tenantA],
      );

      return r.rows[0]?.policy_floor ?? {};
    });

    const MODES = ["monitor", "warn", "enforce"];
    const ACTIONS = ["none", "warn", "lockout"];

    check(
      MODES.indexOf(body.mode ?? "") >= MODES.indexOf(floor.mode ?? "monitor"),
      "מצב האכיפה אינו נמוך מהרצפה",
      `${body.mode} מול רצפה ${floor.mode}`,
    );

    check(
      ACTIONS.indexOf(body.onRedAction ?? "") >= ACTIONS.indexOf(floor.onRedAction ?? "warn"),
      "והפעולה במצב אדום אינה נמוכה ממנה",
      `${body.onRedAction} מול רצפה ${floor.onRedAction}`,
    );

    check(
      (body.minScoreForGreen ?? 0) >= 85 && (body.minScoreForYellow ?? 0) >= 60,
      "וגם ספי הציון",
      `${body.minScoreForGreen}/${body.minScoreForYellow}`,
    );
  }



  section("15 · סנכרון הספקים מהקוד");

  {
    const owner = new pg.Client({
      connectionString: process.env["DATABASE_URL"]!,
      ssl: sslFor(process.env["DATABASE_URL"]!),
    });

    await owner.connect();

    try {
      /*
       * שורה שנזרעה ומעולם לא נערכה מקבלת נתונים חדשים מהקוד.
       *
       * זה נשבר בייצור: הניסיון הראשון השווה סימון dataStatus,
       * ופריסה אחת שסימנה verified חסמה מאותו רגע כל נתון חדש.
       * שני וקטורי זיהוי שהתגלו אחר כך לא הגיעו לאף מכשיר.
       */
      await owner.query(
        `UPDATE providers
            SET detection = jsonb_build_object('dataStatus', 'verified'),
                updated_by = NULL
          WHERE key = 'rimon'`,
      );

      const touched = await seedProviders(pool);

      check(touched > 0, "זריעה מעדכנת שורה שלא נערכה בממשק", `${touched} שורות`);

      const after = await owner.query<{ d: { tlsIssuer?: unknown; httpMarkers?: unknown } }>(
        "SELECT detection AS d FROM providers WHERE key = 'rimon'",
      );

      check(
        after.rows[0]!.d.tlsIssuer !== undefined && after.rows[0]!.d.httpMarkers !== undefined,
        "וכל הווקטורים מהקוד הגיעו",
        "כולל אלה שהתגלו אחרי שהשורה כבר סומנה מאומתת",
      );

      /*
       * והצד השני: שורה שאדם ערך אינה נדרסת.
       *
       * בלי זה, כל עלייה של השרת הייתה מוחקת את עבודתו.
       */
      const someone = await owner.query<{ id: string }>(
        "SELECT id FROM users WHERE role = 'platform_admin' LIMIT 1",
      );

      if (someone.rows[0]) {
        await owner.query(
          `UPDATE providers
              SET detection = jsonb_build_object('network',
                    jsonb_build_object('cidrs', jsonb_build_array('198.51.100.0/24'))),
                  updated_by = $1
            WHERE key = 'rimon'`,
          [someone.rows[0].id],
        );

        await seedProviders(pool);

        const kept = await owner.query<{ d: { network?: { cidrs?: string[] } } }>(
          "SELECT detection AS d FROM providers WHERE key = 'rimon'",
        );

        check(
          kept.rows[0]!.d.network?.cidrs?.includes("198.51.100.0/24") === true,
          "ושורה שאדם ערך אינה נדרסת",
          "אחרת כל עלייה של השרת מוחקת את עבודתו",
        );

        // החזרה למצב הנכון, כדי שהמדיניות שתתפרסם תהיה האמיתית
        await owner.query("UPDATE providers SET updated_by = NULL WHERE key = 'rimon'");
        await seedProviders(pool);
      }
    } finally {
      await owner.end();
    }
  }


  section("16 · רצפת המכשיר ברישום חוזר");

  {
    /*
     * הבאג שנתפס בשטח: ON CONFLICT DO UPDATE ריענן שם ומערכת
     * הפעלה ולא את הרצפה, ולכן מכשיר נשאר לנצח ברצפה שאיתה נרשם
     * בפעם הראשונה — גם כשההורה יצר קישור חדש במפורש.
     */
    check(
      isAtLeastAsStrict({ mode: "enforce", onRedAction: "lockout" },
                        { mode: "monitor", onRedAction: "warn" }),
      "רישום חוזר רשאי להחמיר",
    );

    check(
      !isAtLeastAsStrict({ mode: "monitor", onRedAction: "warn" },
                         { mode: "enforce", onRedAction: "lockout" }),
      "ואינו רשאי להקל",
      "קישור התקנה שדלף היה כלי להורדת ההגנה",
    );

    check(
      isAtLeastAsStrict({ mode: "monitor", onRedAction: "warn" }, undefined),
      "מכשיר חדש מקבל כל רצפה",
      "אין ממה להקל",
    );

    check(
      !isAtLeastAsStrict({ minScoreForGreen: 50 }, { minScoreForGreen: 85 }),
      "וגם הורדת סף ציון היא הרפיה",
    );

    // ---- ההסרה מהפורטל, שהיא הדרך היחידה להקל ----

    const retireByMember = await post(member, `/api/portal/v1/devices/${seed.deviceA}/retire`);

    check(
      retireByMember.statusCode === 403,
      "בן משפחה אינו מסיר מכשירים",
      `סטטוס ${retireByMember.statusCode}`,
    );

    const retired = await post(parentA, `/api/portal/v1/devices/${seed.deviceA}/retire`);

    check(retired.statusCode === 200, "הורה הסיר מכשיר מהחשבון");

    const state = await withPlatform(pool, SYSTEM, async (tx) => {
      const r = await tx.query<{ status: string }>(
        "SELECT status FROM devices WHERE id = $1",
        [seed.deviceA],
      );

      return r.rows[0]!.status;
    });

    check(
      state === "uninstalled",
      "והוא מסומן ולא נמחק",
      "מכשיר שנעלם בלי עקבות הוא בדיוק מה שמסתיר הסרה לא מורשית",
    );

    const again = await post(parentA, `/api/portal/v1/devices/${seed.deviceA}/retire`);

    check(again.statusCode === 404, "הסרה חוזרת מחזירה 404");
  }


  section("17 · ביטול קישורי התקנה");

  {
    const fresh = await post(parentA, "/api/portal/v1/enroll-tokens", {
      installProfile: "family_child",
      maxUses: 2,
    });

    const freshId = fresh.json<{ id: string }>().id;

    const list = await get(parentA, "/api/portal/v1/enroll-tokens");
    const rows = list.json<{
      tokens: Array<{ id: string; policy_floor: { mode?: string } | null; uses: number }>;
    }>().tokens;

    check(
      rows.some((t) => t.id === freshId),
      "הקישורים הפעילים מוצגים",
      `${rows.length} קישורים`,
    );

    /*
     * הרצפה מוצגת, וזה השדה שבאמת חשוב: קישור ישן נושא הגדרות
     * ישנות לנצח, ומכשיר שנרשם דרכו נתקע בהן. בלי התצוגה אין שום
     * דרך לדעת איזה קישור בטוח לשימוש.
     */
    check(
      rows.find((t) => t.id === freshId)?.policy_floor?.mode !== undefined,
      "עם הרצפה שהם נושאים",
      "קישור ישן נושא הגדרות ישנות, ואין דרך אחרת לדעת",
    );

    const byMember = await post(member, `/api/portal/v1/enroll-tokens/${freshId}/revoke`);

    check(byMember.statusCode === 403, "בן משפחה אינו מבטל קישורים", `סטטוס ${byMember.statusCode}`);

    const revoked = await post(parentA, `/api/portal/v1/enroll-tokens/${freshId}/revoke`);

    check(revoked.statusCode === 200, "הורה ביטל קישור");

    const after = await get(parentA, "/api/portal/v1/enroll-tokens");

    check(
      !after.json<{ tokens: Array<{ id: string }> }>().tokens.some((t) => t.id === freshId),
      "והוא נעלם מהרשימה",
    );

    /*
     * וההורדה דרכו נחסמת. זו הבדיקה שקובעת: קישור שבוטל ברשימה
     * אך עדיין מוריד קובץ אינו מבוטל.
     */
    const token = fresh.json<{ token: string }>().token;

    const download = await app.fastify.inject({
      method: "GET",
      url: `/d/${fileNameForToken(token)}`,
    });

    check(
      download.statusCode === 410,
      "וההורדה דרכו נחסמת",
      `סטטוס ${download.statusCode}`,
    );

    const again = await post(parentA, `/api/portal/v1/enroll-tokens/${freshId}/revoke`);

    check(again.statusCode === 404, "ביטול חוזר מחזיר 404");
  }

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
