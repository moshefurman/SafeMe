import { randomBytes, randomUUID } from "node:crypto";
import { buildApp } from "../src/app.ts";
import { createPool, withPlatform } from "../src/db/client.ts";
import { hashEnrollToken } from "../src/auth/device-token.ts";
import {
  LocalSigner,
  decodeEnvelope,
  verifyEnvelope,
  type SignedEnvelope,
} from "../src/crypto/signing.ts";
import { publishPolicy } from "../src/policy/publish.ts";
import { loadConfig } from "../src/config.ts";

/**
 * POC לשלב S2: מוכיח שממשק המחשב עובד מקצה לקצה, ושהחתימה
 * שהשרת מייצר אכן ניתנת לאימות באותה שיטה שהסוכן ב-C# משתמש בה.
 *
 * רץ בתוך התהליך (fastify.inject), בלי לפתוח פורט.
 */

let passed = 0;
let failed = 0;

function ok(title: string, detail = ""): void {
  passed += 1;
  console.log(`  ✓ ${title}`);
  if (detail) console.log(`      ${detail}`);
}

function bad(title: string, detail: string): void {
  failed += 1;
  console.log(`  ✗ ${title}`);
  console.log(`      ${detail}`);
}

function check(condition: boolean, title: string, detail: string): void {
  if (condition) ok(title, detail);
  else bad(title, detail);
}

function section(title: string): void {
  console.log(`\n${title}`);
  console.log("─".repeat(64));
}

const SYSTEM = { userId: "00000000-0000-0000-0000-000000000000", reason: "הרצת POC" };

async function main(): Promise<void> {
  const config = loadConfig({
    ...process.env,
    NODE_ENV: "test",
    DEVICE_TOKEN_SECRET: process.env["DEVICE_TOKEN_SECRET"] ?? randomBytes(32).toString("hex"),
  });

  // מפתח זמני חייב מזהה זמני: registerSigningKey דוחה שני מפתחות
  // שונים תחת אותו kid, ובצדק — זה היה פוסל חתימות ישנות בשקט.
  const signer = LocalSigner.ephemeral(`poc-policy-${randomUUID().slice(0, 8)}`);
  const pool = createPool({ connectionString: config.DATABASE_URL_APP });
  // חותם ההיתרים חייב מזהה ייחודי להרצה מאותה סיבה כמו חותם
  // המדיניות: מפתח זמני מתחלף בכל הרצה, ורישום מפתח אחר תחת
  // אותו kid נדחה — ובצדק.
  const looseningSigner = LocalSigner.ephemeral(`poc-loosening-${randomUUID().slice(0, 8)}`);

  const uninstallSigner = LocalSigner.ephemeral(`poc-uninstall-${randomUUID().slice(0, 8)}`);
  const updateSigner = LocalSigner.ephemeral(`poc-update-${randomUUID().slice(0, 8)}`);

  const app = await buildApp({
    config,
    pool,
    signer,
    looseningSigner,
    uninstallSigner,
    updateSigner,
    logger: false,
  });

  const publicPem = await signer.publicKeyPem();

  // ─────────────────────────────────────────────── הכנה
  section("הכנה: דייר, אסימון רישום ומדיניות חתומה");

  const enrollTokenRaw = `ENR-${randomUUID().toUpperCase()}`;
  const floor = { mode: "enforce", onRedAction: "lockout", minScoreForGreen: 85 };

  const seed = await withPlatform(pool, SYSTEM, async (tx) => {
    await tx.query("DELETE FROM devices");
    await tx.query("DELETE FROM policies");
    await tx.query("DELETE FROM enroll_tokens");
    await tx.query("DELETE FROM tenants");

    const tenant = await tx.query<{ id: string }>(
      `INSERT INTO tenants (type, name, trial_started_at, trial_ends_at)
       VALUES ('family', 'משפחת כהן', now(), now() + interval '30 days')
       RETURNING id`,
    );
    const other = await tx.query<{ id: string }>(
      `INSERT INTO tenants (type, name, trial_started_at, trial_ends_at)
       VALUES ('family', 'משפחת לוי', now(), now() + interval '30 days')
       RETURNING id`,
    );

    await tx.query(
      `INSERT INTO enroll_tokens
         (tenant_id, token_hash, install_profile, enforcement_mode, policy_floor,
          max_uses, expires_at)
       VALUES ($1, $2, 'family_child', 'enforce', $3, 5, now() + interval '7 days')`,
      [tenant.rows[0]!.id, hashEnrollToken(enrollTokenRaw), JSON.stringify(floor)],
    );

    return { tenantId: tenant.rows[0]!.id, otherTenantId: other.rows[0]!.id };
  });

  const policyBody = {
    version: 42,
    issuedUtc: new Date().toISOString(),
    ttlMinutes: 240,
    graceMinutes: 720,
    providers: [{ id: "netfree", displayName: "נטפרי", trustLevel: "high" }],
    enforcement: { mode: "enforce", minScoreForGreen: 85, onRedAction: "lockout" },
  };

  const published = await publishPolicy(pool, signer, {
    tenantId: seed.tenantId,
    version: 42,
    body: policyBody,
  });

  ok("מדיניות פורסמה ונחתמה", `גרסה ${published.version} · ${published.byteLength} בתים · ${published.etag}`);

  // ─────────────────────────────────────────────── בריאות
  section("1 · זמינות");

  const health = await app.fastify.inject({ method: "GET", url: "/api/v1/health" });
  check(health.statusCode === 200, "GET /health מחזיר 200", `סטטוס ${health.statusCode}`);

  // ─────────────────────────────────────────────── רישום
  section("2 · רישום מחשב");

  const badEnroll = await app.fastify.inject({
    method: "POST",
    url: "/api/v1/enroll",
    payload: { enrollToken: "ENR-NOT-A-REAL-TOKEN", hwid: "HWID0000000000000000000001" },
  });

  check(badEnroll.statusCode === 403, "אסימון רישום שגוי נדחה", `סטטוס ${badEnroll.statusCode}`);

  const hwid = "HWID0000000000000000000001";
  const enroll = await app.fastify.inject({
    method: "POST",
    url: "/api/v1/enroll",
    payload: {
      enrollToken: enrollTokenRaw,
      hwid,
      machineName: "PC-YOSSI",
      osVersion: "10.0.26100",
      agentVersion: "1.0.0",
    },
  });

  if (enroll.statusCode !== 200) {
    bad("רישום נכשל", `סטטוס ${enroll.statusCode}: ${enroll.body}`);
    await app.close();
    process.exit(1);
  }

  const enrolled = enroll.json() as {
    deviceId: string;
    deviceToken: string;
    enforcementMode: string;
    policyFloor: SignedEnvelope;
    signingKid: string;
  };

  ok("רישום הצליח", `מחשב ${enrolled.deviceId.slice(0, 8)} · מצב ${enrolled.enforcementMode}`);

  // ─────────────────────────────────────────────── רצפת מדיניות חתומה
  section("3 · רצפת המדיניות חתומה ומאומתת");

  check(
    verifyEnvelope(enrolled.policyFloor, publicPem),
    "חתימת הרצפה מאומתת מול המפתח הציבורי",
    `alg=${enrolled.policyFloor.alg} kid=${enrolled.policyFloor.kid}`,
  );

  const floorContent = decodeEnvelope<{ hwid: string; floor: typeof floor }>(enrolled.policyFloor);

  check(
    floorContent.hwid === hwid && floorContent.floor.mode === "enforce",
    "הרצפה קשורה למחשב הזה בלבד",
    `hwid=${floorContent.hwid.slice(0, 12)}... mode=${floorContent.floor.mode}`,
  );

  // רישום חוזר אחרי התקנה מחדש הוא תרחיש שגרתי
  const reEnroll = await app.fastify.inject({
    method: "POST",
    url: "/api/v1/enroll",
    payload: { enrollToken: enrollTokenRaw, hwid, agentVersion: "1.0.1" },
  });

  check(
    reEnroll.statusCode === 200 &&
      (reEnroll.json() as { deviceId: string }).deviceId === enrolled.deviceId,
    "רישום חוזר של אותו מחשב אינו יוצר כפילות",
    "אותו deviceId הוחזר",
  );

  // ─────────────────────────────────────────────── אימות
  section("4 · אימות אסימון");

  const auth = { authorization: `Bearer ${enrolled.deviceToken}`, "x-filterplus-hwid": hwid };

  const noAuth = await app.fastify.inject({ method: "GET", url: "/api/v1/policy" });
  check(noAuth.statusCode === 401, "בקשה בלי אסימון נדחית", `סטטוס ${noAuth.statusCode}`);

  const wrongHwid = await app.fastify.inject({
    method: "GET",
    url: "/api/v1/policy",
    headers: { authorization: `Bearer ${enrolled.deviceToken}`, "x-filterplus-hwid": "HWID-OTHER" },
  });

  check(
    wrongHwid.statusCode === 401,
    "אסימון שהועתק למכונה אחרת נדחה",
    "כותרת HWID אינה תואמת לאסימון",
  );

  const forged = await app.fastify.inject({
    method: "GET",
    url: "/api/v1/policy",
    headers: { authorization: "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.zzz", "x-filterplus-hwid": hwid },
  });

  check(forged.statusCode === 401, "אסימון מזויף נדחה", `סטטוס ${forged.statusCode}`);

  // ─────────────────────────────────────────────── מדיניות
  section("5 · חלוקת מדיניות");

  const policyRes = await app.fastify.inject({
    method: "GET",
    url: "/api/v1/policy",
    headers: auth,
  });

  if (policyRes.statusCode !== 200) {
    bad("שליפת מדיניות נכשלה", `סטטוס ${policyRes.statusCode}: ${policyRes.body}`);
  } else {
    const envelope = policyRes.json() as SignedEnvelope;

    check(
      verifyEnvelope(envelope, publicPem),
      "חתימת המדיניות מאומתת",
      "אותו נתיב אימות שהסוכן ב-C# מבצע",
    );

    const decoded = decodeEnvelope<typeof policyBody>(envelope);

    check(
      decoded.version === 42 && decoded.providers[0]!.displayName === "נטפרי",
      "התוכן נשמר בדיוק, כולל עברית",
      `גרסה ${decoded.version} · ספק ${decoded.providers[0]!.displayName}`,
    );

    // זו ההוכחה המרכזית של 5.2: שינוי בית אחד שובר את החתימה
    const tampered: SignedEnvelope = {
      ...envelope,
      payload: Buffer.from(
        JSON.stringify({ ...decoded, enforcement: { ...decoded.enforcement, mode: "monitor" } }),
        "utf8",
      ).toString("base64url"),
    };

    check(
      !verifyEnvelope(tampered, publicPem),
      "מדיניות שהוחלפה בדרך נדחית",
      "שינוי mode מ-enforce ל-monitor שובר את החתימה",
    );

    const etag = policyRes.headers["etag"];
    const notModified = await app.fastify.inject({
      method: "GET",
      url: "/api/v1/policy",
      headers: { ...auth, "if-none-match": String(etag) },
    });

    check(
      notModified.statusCode === 304,
      "ETag חוסך הורדה חוזרת",
      `If-None-Match → ${notModified.statusCode}`,
    );
  }

  // ─────────────────────────────────────────────── פעימה
  section("6 · פעימה");

  const beat = await app.fastify.inject({
    method: "POST",
    url: "/api/v1/heartbeat",
    headers: auth,
    payload: {
      hwid,
      agentVersion: "1.0.0",
      policyVersion: 42,
      sequence: 1,
      status: "safe",
      score: 95,
      activeAdapters: [{ name: "Wi-Fi", ssid: "HOME-NETFREE", gateway: "192.168.1.1" }],
      publicIp: "185.32.10.4",
      detectedProvider: "netfree",
      failedProbes: [],
      tamperEvents: [{ kind: "TrayAppKilled", detail: "אייקון המגש נסגר" }],
      wfpFilterCount: 27,
      uptimeSec: 3600,
      lockoutActive: false,
    },
  });

  check(beat.statusCode === 200, "פעימה התקבלה", `סטטוס ${beat.statusCode}`);

  const state = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ last_status: string; last_score: number; wifi_ssid: string }>(
      "SELECT last_status, last_score, wifi_ssid FROM device_state WHERE device_id = $1",
      [enrolled.deviceId],
    );
    return r.rows[0]!;
  });

  check(
    state.last_status === "safe" && state.last_score === 95 && state.wifi_ssid === "HOME-NETFREE",
    "מצב המחשב עודכן",
    `סטטוס ${state.last_status} · ציון ${state.last_score} · רשת ${state.wifi_ssid}`,
  );

  const eventCount = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ n: string }>(
      "SELECT count(*) AS n FROM events WHERE device_id = $1 AND kind = 'TrayAppKilled'",
      [enrolled.deviceId],
    );
    return Number(r.rows[0]!.n);
  });

  check(eventCount === 1, "אירוע חבלה נרשם מתוך הפעימה", `${eventCount} אירוע`);

  // פעימה ישנה שהגיעה באיחור לא תדרוס מצב עדכני
  const stale = await app.fastify.inject({
    method: "POST",
    url: "/api/v1/heartbeat",
    headers: auth,
    payload: {
      hwid, sequence: 0, status: "unfiltered", score: 10,
      activeAdapters: [], failedProbes: [], tamperEvents: [], lockoutActive: false,
    },
  });

  const afterStale = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ last_score: number }>(
      "SELECT last_score FROM device_state WHERE device_id = $1",
      [enrolled.deviceId],
    );
    return r.rows[0]!.last_score;
  });

  check(
    stale.statusCode === 200 && afterStale === 95,
    "פעימה ישנה אינה דורסת מצב עדכני",
    `הציון נשאר ${afterStale} ולא ירד ל-10`,
  );

  // ─────────────────────────────────────────── דגימת פעימות
  //
  // כאן נבדק מה שאי אפשר לבדוק בלי Postgres: השאילתה נשענת על כך
  // ש-UPDATE ... FROM קורא את המצב שלפני העדכון באותה שאילתה
  // שדורסת אותו. אם ההנחה שגויה, כל פעימה תיראה כשינוי והצמצום
  // פשוט לא יקרה — בלי שום שגיאה שתסגיר את זה.

  async function heartbeatRows(): Promise<number> {
    return withPlatform(pool, SYSTEM, async (tx) => {
      const r = await tx.query<{ n: string }>(
        "SELECT count(*) AS n FROM heartbeats WHERE device_id = $1",
        [enrolled.deviceId],
      );
      return Number(r.rows[0]!.n);
    });
  }

  const before = await heartbeatRows();

  // עשר פעימות זהות לחלוטין, פרט למונה. בלי שינוי מצב ובלי חבלה.
  for (let i = 0; i < 10; i++) {
    await app.fastify.inject({
      method: "POST",
      url: "/api/v1/heartbeat",
      headers: auth,
      payload: {
        hwid,
        policyVersion: 42,
        sequence: 10 + i,
        status: "safe",
        score: 95,
        activeAdapters: [{ name: "Wi-Fi", ssid: "HOME-NETFREE", gateway: "192.168.1.1" }],
        detectedProvider: "netfree",
        failedProbes: [],
        tamperEvents: [],
        lockoutActive: false,
      },
    });
  }

  const afterQuiet = await heartbeatRows();

  check(
    afterQuiet === before,
    "עשר פעימות שקטות אינן מייצרות שורות היסטוריה",
    `${afterQuiet - before} שורות נוספו`,
  );

  const liveSeen = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ heartbeat_seq: string }>(
      "SELECT heartbeat_seq FROM device_state WHERE device_id = $1",
      [enrolled.deviceId],
    );
    return Number(r.rows[0]!.heartbeat_seq);
  });

  check(
    liveSeen === 19,
    "המצב החי כן התעדכן בכל אחת מהן",
    `מונה הפעימות הגיע ל-${liveSeen}`,
  );

  // שינוי מצב אמיתי חייב להישמר
  await app.fastify.inject({
    method: "POST",
    url: "/api/v1/heartbeat",
    headers: auth,
    payload: {
      hwid,
      policyVersion: 42,
      sequence: 20,
      status: "unfiltered",
      score: 20,
      activeAdapters: [],
      detectedProvider: null,
      failedProbes: ["netfree-ca"],
      tamperEvents: [],
      lockoutActive: false,
    },
  });

  const afterChange = await heartbeatRows();

  check(
    afterChange === afterQuiet + 1,
    "שינוי סטטוס כן נשמר בהיסטוריה",
    `${afterChange - afterQuiet} שורה נוספה`,
  );

  const reason = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ reason: string | null }>(
      `SELECT payload->>'sampleReason' AS reason FROM heartbeats
        WHERE device_id = $1 ORDER BY received_at DESC, id DESC LIMIT 1`,
      [enrolled.deviceId],
    );
    return r.rows[0]!.reason;
  });

  check(reason === "status", "סיבת הדגימה נרשמה ונכונה", `נרשם "${reason}"`);

  // ─────────────────────────────────────────────── בידוד דרך ה-API
  /*
   * הגרסה שהפעימה מדווחת נשמרת.
   *
   * היא נכתבה ברישום בלבד, ולכן השורה במסד נשארה תקועה על הגרסה
   * שהותקנה פעם ראשונה. הפורטל הציג אותה, וכך גם כלי האבחון —
   * ושניהם היו משקרים בדיוק אחרי עדכון מוצלח.
   */
  const afterFirst = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ agent_version: string | null }>(
      "SELECT agent_version FROM devices WHERE hwid = $1",
      [hwid],
    );

    return r.rows[0]?.agent_version ?? null;
  });

  check(afterFirst === "1.0.0", "הגרסה המדווחת נשמרה", `במסד: ${afterFirst}`);

  const upgraded = await app.fastify.inject({
    method: "POST",
    url: "/api/v1/heartbeat",
    headers: auth,
    payload: {
      hwid,
      agentVersion: "1.1.9",
      sequence: 2,
      status: "safe",
      score: 95,
      activeAdapters: [],
      lockoutActive: false,
    },
  });

  const afterUpgrade = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ agent_version: string | null }>(
      "SELECT agent_version FROM devices WHERE hwid = $1",
      [hwid],
    );

    return r.rows[0]?.agent_version ?? null;
  });

  check(
    upgraded.statusCode === 200 && afterUpgrade === "1.1.9",
    "עדכון גרסה מתעדכן במסד",
    "בלי זה, סוכן שהתעדכן נראה בפורטל כאילו לא התעדכן",
  );


  section("7 · בידוד דיירים גם דרך ה-API");

  const otherDeviceId = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ id: string }>(
      `INSERT INTO devices (tenant_id, hwid, install_profile, enforcement_mode, policy_floor)
       VALUES ($1, 'HWID0000000000000000000002', 'family_child', 'enforce', '{}'::jsonb)
       RETURNING id`,
      [seed.otherTenantId],
    );
    return r.rows[0]!.id;
  });

  const otherPolicy = await publishPolicy(pool, signer, {
    tenantId: seed.otherTenantId,
    version: 99,
    body: { version: 99, secret: "מדיניות של משפחת לוי" },
  });

  const leaked = await app.fastify.inject({
    method: "GET",
    url: "/api/v1/policy",
    headers: auth,
  });

  // בדיקה אמיתית: מפענחים את המעטפה ובודקים איזו מדיניות הוחזרה בפועל.
  // חיפוש מחרוזת בתוך base64 היה נותן תשובה אקראית.
  const served = decodeEnvelope<{ version: number }>(leaked.json() as SignedEnvelope);

  check(
    leaked.statusCode === 200 && served.version === 42,
    "מחשב של משפחה אחת אינו מקבל את המדיניות של האחרת",
    `הוחזרה גרסה ${served.version}, ולא ${otherPolicy.version} של מחשב ${otherDeviceId.slice(0, 8)}`,
  );

  // ─────────────────────────────────────────────── אירועים
  section("8 · דיווח אירועים");

  const events = await app.fastify.inject({
    method: "POST",
    url: "/api/v1/events",
    headers: auth,
    payload: [
      { kind: "WfpFiltersMissing", detail: "חוקי WFP נמחקו" },
      { kind: "ClockRolledBack", detail: "שעון הוזז שעתיים אחורה" },
    ],
  });

  check(
    events.statusCode === 200 && (events.json() as { accepted: number }).accepted === 2,
    "אירועי חבלה נקלטו",
    "שני אירועים",
  );

  // ─────────────────────────────────────────────── סיכום
  console.log("\n" + "═".repeat(64));
  console.log(`עברו ${passed} · נכשלו ${failed}`);
  console.log("═".repeat(64));

  await app.close();
  await pool.end();

  if (failed > 0) process.exitCode = 1;
}

main().catch((error: unknown) => {
  console.error("\nה-POC נכשל:", error instanceof Error ? error.stack : error);
  process.exitCode = 1;
});
