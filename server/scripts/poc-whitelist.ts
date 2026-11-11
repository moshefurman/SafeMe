/**
 * רשימה לבנה: מהקלדת אתר ועד המדיניות החתומה שהמחשב מושך.
 *
 * שלושה דברים נבדקים כאן, וכל אחד מהם נשבר בעבר בתכונה אחרת בלי
 * שאיש ראה:
 *
 *   · מה אסור לאשר. בדיקת התוכן היא השער היחיד, ושער שנפתח כשהרשת
 *     מקרטעת אינו שער. נבדק מול תשובות מבוימות, ופעם אחת מול
 *     Cloudflare האמיתי — כי כל ההנחה נשענת על הצורה שבה הוא עונה.
 *
 *   · ההרכבה. שכבת המחשב הורכבה פעם בשני מקומות שנפרדו בשקט. עכשיו
 *     היא במקום אחד, והבדיקה היא על מה שבאמת נחתם ונמסר למחשב —
 *     לא על מה שהפונקציה מחזירה.
 *
 *   · מספר הגרסה. הסוכן דוחה מדיניות שמספרה נמוך ממה שבידיו, ולכן
 *     "כיביתי" שמגיע במספר נמוך אינו מגיע.
 *
 * דורש מסד מקומי (server/.env). הרצה: npm run poc:whitelist
 */

import { randomBytes, randomUUID } from "node:crypto";

import { buildApp } from "../src/app.ts";
import { createPool, withPlatform } from "../src/db/client.ts";
import { hashEnrollToken } from "../src/auth/device-token.ts";
import { createSession, SESSION_COOKIE } from "../src/auth/session.ts";
import { LocalSigner, decodeEnvelope, type SignedEnvelope } from "../src/crypto/signing.ts";
import { loadConfig } from "../src/config.ts";
import { NullMailer } from "../src/notify/mailer.ts";
import { composeTenantBody, sameBody } from "../src/policy/compose.ts";
import { composeDeviceOverlay } from "../src/policy/device-overlay.ts";
import { rebuildAssignedPolicies, rebuildTenantPolicies } from "../src/policy/recompose.ts";
import {
  REASON_BLOCKED,
  REASON_UNVERIFIED,
  WHITELIST_UPSTREAM_RESOLVERS,
  buildWhitelistRule,
  checkDomainAllowed,
  looksAdult,
  normalizeDomain,
  normalizeObserved,
  registrableDomain,
  splitDomainInput,
} from "../src/policy/whitelist.ts";

const SYSTEM = { userId: "00000000-0000-0000-0000-000000000000", reason: "הרצת POC" };

let passed = 0;
let failed = 0;

function check(ok: boolean, name: string, detail = ""): void {
  if (ok) passed++;
  else failed++;

  console.log(`  ${ok ? "✓" : "✗"} ${name}${detail ? `\n      ${detail}` : ""}`);
}

function section(title: string): void {
  console.log(`\n${title}`);
  console.log("─".repeat(64));
}

/** תשובה בצורה ש-Cloudflare מחזיר, כפי שנמדדה. */
function dohAnswer(status: number, data: string[], comment?: string): Response {
  return new Response(
    JSON.stringify({
      Status: status,
      Answer: data.map((d) => ({ name: "x", type: 1, TTL: 60, data: d })),
      ...(comment ? { Comment: [comment] } : {}),
    }),
    { status: 200, headers: { "content-type": "application/dns-json" } },
  );
}

/**
 * Cloudflare מבוים. השם קובע את התשובה, כדי שכל בדיקה תאמר בעצמה
 * מה היא מצפה לו.
 */
const asked: string[] = [];

const stubFetch = (async (input: string | URL | Request): Promise<Response> => {
  const name = new URL(String(input)).searchParams.get("name") ?? "";

  asked.push(name);

  if (name.includes("netfail")) throw new Error("ECONNRESET");
  if (name.includes("servfail")) return dohAnswer(2, []);
  if (name.includes("httpfail")) return new Response("busy", { status: 503 });
  if (name.includes("cfblocked")) return dohAnswer(0, ["0.0.0.0"], "EDE(17): Filtered");
  if (name.includes("nxdomain")) return dohAnswer(3, []);

  return dohAnswer(0, ["93.184.216.34"]);
}) as typeof fetch;

async function main(): Promise<void> {
  // ─────────────────────────────────────── נרמול
  section("1 · מה שהוקלד, ומה שנשמר");

  const manual = (s: string) => normalizeDomain(s, { stripWww: true });

  check(manual("https://www.Ynet.co.il/news/article?id=1#top") === "ynet.co.il",
    "קישור מודבק מצטמצם לשם האתר", "סכימה, www, נתיב, שאילתה ורישיות");
  check(manual("example.com:8443/path") === "example.com", "פורט ונתיב בלי סכימה");
  check(manual("*.example.com") === "example.com", "כוכבית מובילה מוסרת",
    "רשומה ממילא כוללת את תת־המתחמים שלה");
  check(manual("user:pass@example.com") === "example.com", "פרטי התחברות מוסרים");
  check(manual("example.com.") === "example.com", "נקודה סופית");
  check(manual("ישראל.co.il") === "xn--4dbrk0ce.co.il", "עברית עוברת ל-punycode",
    String(manual("ישראל.co.il")));
  check(normalizeDomain("www.example.com") === "www.example.com",
    "בלי ההוראה, www נשאר", "שם שנצפה בלמידה מאושר כפי שנצפה");
  check(manual("www.co") === "www.co", "www.co אינו מתקצר לתווית אחת");

  for (const bad of ["1.2.3.4", "http://10.0.0.1/admin", "[::1]", "localhost", "", "exa mple.com",
    "exam_ple.com", "-bad.com", "a..b.com", "example.123"]) {
    check(manual(bad) === null, `נדחה: "${bad}"`);
  }

  check(
    JSON.stringify(splitDomainInput("a.com, b.com\nc.com;d.com   e.com")) ===
      JSON.stringify(["a.com", "b.com", "c.com", "d.com", "e.com"]),
    "פסיקים, רווחים, שורות ונקודה־פסיק — כולם מפרידים",
  );

  check(normalizeObserved("_Dmarc.Example.com.") === "_dmarc.example.com",
    "שם שנצפה רשאי לשאת קו תחתון");
  check(normalizeObserved("bad name!") === null && normalizeObserved("8.8.8.8") === null,
    "אבל לא רווח, סימן קריאה או כתובת");

  section("2 · לאיזה אתר השם שייך");

  const reg: Array<[string, string]> = [
    ["static.cdn.example.co.il", "example.co.il"],
    ["www.example.com", "example.com"],
    ["a.b.c.bbc.co.uk", "bbc.co.uk"],
    ["mail.tau.ac.il", "tau.ac.il"],
    ["www.gov.il", "www.gov.il"],
    ["example.com", "example.com"],
    ["shop.example.com.au", "example.com.au"],
    ["x.y.jerusalem.muni.il", "jerusalem.muni.il"],
  ];

  for (const [host, want] of reg) {
    check(registrableDomain(host) === want, `${host} ← ${want}`, registrableDomain(host) === want ? "" : registrableDomain(host));
  }

  section("3 · השם עצמו מסגיר");

  for (const bad of ["pornhub.com", "www.xvideos.com", "cdn.xnxx-cdn.com", "sex.com", "free-sex.net",
    "example.xxx", "bestpornsite.org", "onlyfans.com", "chaturbate.com", "rule34.paheal.net"]) {
    check(looksAdult(bad), `חסום: ${bad}`);
  }

  for (const fine of ["essex.gov.uk", "middlesex.ac.uk", "sussex.ac.uk", "xxxl-shop.de", "example.com",
    "adult-education.org", "ford-escort-club.com", "webcam.example.cam"]) {
    check(!looksAdult(fine), `תקין: ${fine}`, "מילה תמימה שמכילה רצף חשוד");
  }

  // ─────────────────────────────────────── בדיקת התוכן, מבוימת
  section("4 · בדיקת התוכן מול תשובות מבוימות");

  const stub = { fetch: stubFetch };

  const clean = await checkDomainAllowed("cdn.example.org", stub);
  check(clean.ok, "אתר רגיל מאושר");
  check(asked.includes("cdn.example.org") && asked.includes("example.org"),
    "ונבדקו גם השם וגם המתחם הרשום שמעליו", asked.join(", "));

  asked.length = 0;
  const keyword = await checkDomainAllowed("pornhub.com", stub);
  check(!keyword.ok && keyword.reason === REASON_BLOCKED, "שם שמסגיר את עצמו נדחה");
  check(asked.length === 0, "בלי לצאת לרשת בכלל");

  const cf = await checkDomainAllowed("cfblocked-site.com", stub);
  check(!cf.ok && cf.kind === "blocked" && cf.reason === REASON_BLOCKED,
    "שם תמים למראה שמסווג אצל Cloudflare — נדחה", "A 0.0.0.0");

  const parent = await checkDomainAllowed("img.cfblocked-parent.net", {
    fetch: (async (input: string | URL | Request) => {
      const name = new URL(String(input)).searchParams.get("name");
      return name === "cfblocked-parent.net" ? dohAnswer(0, ["0.0.0.0"]) : dohAnswer(0, ["1.2.3.4"]);
    }) as typeof fetch,
  });
  check(!parent.ok && parent.kind === "blocked",
    "תת־מתחם נקי של אב חסום — נדחה", "האב הוא מה שמעיד על מי עומד מאחורי השם");

  for (const [name, why] of [["netfail.org", "הרשת נפלה"], ["servfail.org", "SERVFAIL"], ["httpfail.org", "503"]] as const) {
    const v = await checkDomainAllowed(name, stub);
    check(!v.ok && v.kind === "unverified" && v.reason === REASON_UNVERIFIED,
      `כשאי אפשר לבדוק (${why}) — נדחה, לא מאושר`, v.ok ? "" : v.reason);
  }

  check((await checkDomainAllowed("nxdomain-thing.org", stub)).ok,
    "שם שאינו קיים ב-DNS מאושר", "אינו מוביל לשום מקום, ושמות CDN נוטים להיות כאלה");

  // ─────────────────────────────────────── מול השירות האמיתי
  section("5 · מול Cloudflare for Families האמיתי");

  const livePorn = await checkDomainAllowed("adultfriendfinder.com");
  const liveClean = await checkDomainAllowed("example.com");

  check(!livePorn.ok && livePorn.kind === "blocked",
    "אתר למבוגרים ששמו אינו מסגיר דבר — נדחה בבדיקה החיה",
    livePorn.ok ? "אושר!" : `${livePorn.kind}: ${livePorn.reason}`);
  check(liveClean.ok, "example.com מאושר", liveClean.ok ? "" : `${liveClean.kind}: ${liveClean.reason}`);

  // ─────────────────────────────────────── הכלל
  section("6 · הכלל שנחתם");

  const t0 = new Date("2026-11-11T12:00:00.000Z");
  const open = buildWhitelistRule({
    enabled: false,
    domains: ["b.com", "a.com", "b.com"],
    learningUntil: new Date("2026-11-11T12:30:00.000Z"),
    now: t0,
  });

  check(open.learnUntilUtc === "2026-11-11T12:30:00.000Z" && !open.enabled,
    "למידה רשאית לרוץ כשהרשימה כבויה");
  check(JSON.stringify(open.domains) === '["a.com","b.com"]', "האתרים ממוינים ובלי כפילויות",
    "כדי ששתי בניות של אותה רשימה יפיקו אותו גוף");
  check(JSON.stringify(open.upstreamResolvers) === JSON.stringify(WHITELIST_UPSTREAM_RESOLVERS)
    && open.upstreamResolvers[0] === "1.1.1.3", "שרתי השמות הם של Cloudflare for Families");
  check(
    buildWhitelistRule({ learningUntil: new Date("2026-11-11T11:59:59.000Z"), now: t0 }).learnUntilUtc === null,
    "חלון שעבר נכתב כ-null",
  );

  // ─────────────────────────────────────── השרת
  const config = loadConfig({
    ...process.env,
    NODE_ENV: "test",
    DEVICE_TOKEN_SECRET: process.env["DEVICE_TOKEN_SECRET"] ?? randomBytes(32).toString("hex"),
    PORTAL_URL: "https://portal.safeme-poc.example",
  });

  const pool = createPool({ connectionString: config.DATABASE_URL_APP });

  const app = await buildApp({
    config,
    pool,
    mailer: new NullMailer(),
    signer: LocalSigner.ephemeral(`poc-policy-${randomUUID().slice(0, 8)}`),
    looseningSigner: LocalSigner.ephemeral(`poc-loosening-${randomUUID().slice(0, 8)}`),
    uninstallSigner: LocalSigner.ephemeral(`poc-uninstall-${randomUUID().slice(0, 8)}`),
    updateSigner: LocalSigner.ephemeral(`poc-update-${randomUUID().slice(0, 8)}`),
    whitelistFetch: stubFetch,
    logger: false,
  });

  /** דייר עם בעלים, חבר, ואסימון רישום. */
  async function makeTenant(name: string) {
    const enrollToken = `ENR-${randomUUID().toUpperCase()}`;

    const ids = await withPlatform(pool, SYSTEM, async (tx) => {
      const t = await tx.query<{ id: string }>(
        `INSERT INTO tenants (type, name, trial_started_at, trial_ends_at)
         VALUES ('family', $1, now(), now() + interval '30 days') RETURNING id`,
        [name],
      );
      const tenantId = t.rows[0]!.id;

      const owner = await tx.query<{ id: string }>(
        `INSERT INTO users (tenant_id, email, display_name, role, password_hash)
         VALUES ($1, $2, 'הורה', 'tenant_owner', 'x') RETURNING id`,
        [tenantId, `owner-${randomUUID().slice(0, 8)}@example.test`],
      );

      const member = await tx.query<{ id: string }>(
        `INSERT INTO users (tenant_id, email, display_name, role, password_hash)
         VALUES ($1, $2, 'חבר', 'tenant_member', 'x') RETURNING id`,
        [tenantId, `member-${randomUUID().slice(0, 8)}@example.test`],
      );

      await tx.query(
        `INSERT INTO enroll_tokens
           (tenant_id, token_hash, install_profile, enforcement_mode, policy_floor, max_uses, expires_at)
         VALUES ($1, $2, 'family_child', 'enforce', $3, 5, now() + interval '7 days')`,
        [tenantId, hashEnrollToken(enrollToken),
          JSON.stringify({ mode: "enforce", onRedAction: "lockout", minScoreForGreen: 85 })],
      );

      return { tenantId, ownerId: owner.rows[0]!.id, memberId: member.rows[0]!.id };
    });

    return { ...ids, enrollToken };
  }

  async function actor(userId: string, tenantId: string) {
    const s = await createSession(pool, { id: userId, tenantId }, { mfaVerified: true });

    return { cookie: `${SESSION_COOKIE}=${s.token}`, "x-safeme-csrf": s.csrfToken };
  }

  type Headers = Record<string, string>;

  async function call(headers: Headers, method: "GET" | "POST" | "DELETE", url: string, payload?: unknown) {
    const r = await app.fastify.inject({
      method,
      url,
      headers,
      ...(payload === undefined ? {} : { payload: payload as object }),
    });

    let json: Record<string, unknown> = {};
    try { json = r.json() as Record<string, unknown>; } catch { /* גוף ריק */ }

    return { status: r.statusCode, json };
  }

  async function enroll(token: string, machine: string) {
    const hwid = `HWID${randomBytes(10).toString("hex").toUpperCase()}`;
    const r = await app.fastify.inject({
      method: "POST",
      url: "/api/v1/enroll",
      payload: { enrollToken: token, hwid, machineName: machine, agentVersion: "1.0.0" },
    });

    if (r.statusCode !== 200) throw new Error(`רישום נכשל: ${r.statusCode} ${r.body}`);

    const body = r.json() as { deviceId: string; deviceToken: string };

    return {
      deviceId: body.deviceId,
      hwid,
      auth: { authorization: `Bearer ${body.deviceToken}`, "x-safeme-hwid": hwid } as Headers,
      sequence: 0,
    };
  }

  type Device = Awaited<ReturnType<typeof enroll>>;

  async function beat(device: Device, status: string, policyVersion: number) {
    device.sequence += 1;

    const r = await app.fastify.inject({
      method: "POST",
      url: "/api/v1/heartbeat",
      headers: device.auth,
      payload: {
        hwid: device.hwid,
        policyVersion,
        sequence: device.sequence,
        status,
        score: status === "unfiltered" ? 10 : 95,
        activeAdapters: [{ name: "Wi-Fi", ssid: "HOME", gateway: "192.168.1.1", gatewayMac: "aa:bb:cc:dd:ee:01" }],
        detectedProvider: status === "safe" ? "netfree" : null,
        failedProbes: [],
        tamperEvents: [],
        lockoutActive: false,
        // שדה שהשרת אינו מכיר, כפי שסוכן חדש עשוי לשלוח
        egressPosture: "Whitelist",
      },
    });

    return r.statusCode;
  }

  /** המדיניות שהמחשב מושך בפועל: מה שנחתם ונמסר, מפוענח. */
  async function pulled(device: Device): Promise<Record<string, unknown>> {
    const r = await app.fastify.inject({ method: "GET", url: "/api/v1/policy", headers: device.auth });

    if (r.statusCode !== 200) throw new Error(`משיכת מדיניות נכשלה: ${r.statusCode} ${r.body}`);

    return decodeEnvelope<Record<string, unknown>>(r.json() as SignedEnvelope);
  }

  const whitelistOf = (body: Record<string, unknown>) =>
    ((body["enforcement"] as Record<string, unknown> | undefined)?.["whitelist"] ?? null) as
      | { enabled: boolean; domains: string[]; systemDomains: string[]; upstreamResolvers: string[]; learnUntilUtc: string | null }
      | null;

  async function assignment(deviceId: string): Promise<string | null> {
    return withPlatform(pool, SYSTEM, async (tx) => {
      const r = await tx.query<{ policy_id: string }>(
        "SELECT policy_id FROM device_policy_assignments WHERE device_id = $1", [deviceId]);
      return r.rows[0]?.policy_id ?? null;
    });
  }

  /** שורות מדיניות של הדייר שאינן משויכות ונושאות שכבת מחשב — שאריות. */
  async function orphans(tenantId: string): Promise<number> {
    return withPlatform(pool, SYSTEM, async (tx) => {
      const r = await tx.query<{ n: string }>(
        `SELECT count(*) AS n FROM policies p
          WHERE p.tenant_id = $1
            AND NOT EXISTS (SELECT 1 FROM device_policy_assignments a WHERE a.policy_id = p.id)
            AND (p.body->'enforcement' ? 'whitelist'
                 OR jsonb_array_length(COALESCE(p.body->'enforcement'->'schedules', '[]'::jsonb)) > 0)`,
        [tenantId]);
      return Number(r.rows[0]!.n);
    });
  }

  const family = await makeTenant("משפחת רשימה לבנה");
  const other = await makeTenant("משפחה אחרת");
  const owner = await actor(family.ownerId, family.tenantId);
  const member = await actor(family.memberId, family.tenantId);
  const stranger = await actor(other.ownerId, other.tenantId);

  const pc = await enroll(family.enrollToken, "PC-DANI");
  const laptop = await enroll(family.enrollToken, "LAPTOP-NOA");
  const wl = `/api/portal/v1/devices/${pc.deviceId}/whitelist`;

  /** כל גרסה שהמחשב משך, בסדר. אסור שתרד. */
  const versions: number[] = [];

  async function pull(device: Device): Promise<Record<string, unknown>> {
    const body = await pulled(device);

    if (device === pc) versions.push(body["version"] as number);

    return body;
  }

  // ─────────────────────────────────────── מחשב בלי הגדרה
  section("7 · מחשב שלא הוגדר לו דבר");

  const fresh = await call(owner, "GET", wl);
  check(fresh.status === 200 && fresh.json["enabled"] === false && fresh.json["learningUntil"] === null,
    "התצוגה: כבוי, בלי למידה");
  check((await assignment(pc.deviceId)) === null, "ואין לו שיוך מדיניות משלו");

  const basePolicy = await pull(pc);
  check(whitelistOf(basePolicy) === null, "המדיניות שהוא מושך היא הבסיס, בלי סעיף רשימה לבנה");

  // ─────────────────────────────────────── הוספת אתרים
  section("8 · הוספת אתרים ביד");

  const added = await call(owner, "POST", `${wl}/domains`, {
    domains: [
      "https://www.Example.com/some/path",
      "cdn.example.net",
      "pornhub.com",
      "cfblocked-games.com",
      "netfail-site.org",
      "localhost",
      "1.2.3.4",
      "example.com",
    ],
  });

  const results = (added.json["results"] ?? []) as Array<{ input: string; domain: string; ok: boolean; reason?: string }>;
  const byDomain = (d: string) => results.find((r) => r.domain === d);

  check(added.status === 200 && added.json["added"] === 2, "שני אתרים נוספו",
    JSON.stringify(results.map((r) => `${r.domain}:${r.ok}`)));
  check(byDomain("example.com")?.ok === true && byDomain("cdn.example.net")?.ok === true,
    "example.com (מהקישור, בלי www) ו-cdn.example.net");
  check(byDomain("pornhub.com")?.reason === REASON_BLOCKED, "pornhub.com נדחה", byDomain("pornhub.com")?.reason);
  check(byDomain("cfblocked-games.com")?.reason === REASON_BLOCKED, "אתר שמסווג אצל Cloudflare נדחה");
  check(byDomain("netfail-site.org")?.reason === REASON_UNVERIFIED,
    "וכשהבדיקה נכשלת — נדחה עם ההודעה לנסות שוב", byDomain("netfail-site.org")?.reason);
  check(byDomain("localhost")?.ok === false && byDomain("1.2.3.4")?.ok === false, "שם בן תווית אחת וכתובת IP נדחים");
  check(results.filter((r) => r.domain === "example.com").length === 1, "אותו אתר פעמיים בבקשה נספר פעם אחת");

  check((await assignment(pc.deviceId)) === null,
    "עדיין אין שיוך", "רשימה שאינה פעילה ואינה בלמידה אינה סיבה לשכבה");

  const again = await call(owner, "POST", `${wl}/domains`, { domains: ["example.com"] });
  check(again.json["added"] === 0 && (again.json["results"] as Array<{ already?: boolean }>)[0]?.already === true,
    "הוספה חוזרת אינה שגיאה ואינה כפילות");

  // ─────────────────────────────────────── הרשאות ובידוד
  section("9 · מי רשאי");

  check((await call(member, "GET", wl)).status === 200, "חבר בחשבון רואה");
  check((await call(member, "POST", `${wl}/domains`, { domains: ["a.com"] })).status === 403, "אך אינו מוסיף");
  check((await call(member, "POST", wl, { enabled: true })).status === 403, "ואינו מפעיל");
  check((await call(member, "POST", `${wl}/learning`, { minutes: 15 })).status === 403, "ואינו פותח למידה");

  check((await call(stranger, "POST", `${wl}/domains`, { domains: ["a.com"] })).status === 404,
    "בעלים של חשבון אחר מקבל 404 על המחשב", "מחשב שאינו שלו אינו קיים מבחינתו");
  const strangerView = await call(stranger, "GET", wl);
  check(strangerView.status === 200 && (strangerView.json["domains"] as unknown[]).length === 0,
    "ובתצוגה אינו רואה את האתרים של משפחה אחרת");

  check((await call(owner, "POST", `${wl}/learning`, { minutes: 3 })).status === 400, "למידה של 3 דקות נדחית");
  check((await call(owner, "POST", `${wl}/learning`, { minutes: 121 })).status === 400, "וגם של 121");
  check((await call(owner, "POST", `/api/portal/v1/devices/not-a-uuid/whitelist`, { enabled: true })).status === 404,
    "מזהה מחשב שאינו uuid נענה 404, לא 500");

  // ─────────────────────────────────────── למידה
  section("10 · למידה לפני הפעלה");

  // המחשב מדווח גרסה גבוהה: כאילו משך פעם שכבה שכבר נמחקה מהשרת.
  check((await beat(pc, "safe", 700)) === 200, "המחשב מדווח שבידיו גרסה 700");

  const before = Date.now();
  const learn = await call(owner, "POST", `${wl}/learning`, { minutes: 15 });
  check(learn.status === 200 && typeof learn.json["learningUntil"] === "string", "הלמידה נפתחה");
  check(String(learn.json["note"]).includes("רענן מהשרת") && String(learn.json["note"]).includes("שלוש דקות"),
    "והתשובה אומרת שהיא תתחיל בפעימה הבאה, ואיך לזרז");

  check((await assignment(pc.deviceId)) !== null, "עכשיו יש למחשב שכבה משלו");

  const learning = await pull(pc);
  const lw = whitelistOf(learning);
  const untilMs = lw?.learnUntilUtc ? Date.parse(lw.learnUntilUtc) - before : 0;

  check(lw !== null && lw.enabled === false, "במדיניות שנמשכה: הרשימה כבויה");
  check(untilMs > 14 * 60_000 && untilMs < 16 * 60_000, "וסוף הלמידה בעוד רבע שעה", lw?.learnUntilUtc ?? "חסר");
  check(JSON.stringify(lw?.domains) === '["cdn.example.net","example.com"]', "האתרים שאושרו בפנים", JSON.stringify(lw?.domains));
  check(JSON.stringify(lw?.upstreamResolvers) === '["1.1.1.3","1.0.0.3"]', "שרתי השמות");
  check(
    !!lw && lw.systemDomains.includes("msftconnecttest.com") && lw.systemDomains.includes("safeme.win")
      && lw.systemDomains.includes("portal.safeme-poc.example"),
    "והשמות שנפתחים תמיד, כולל מארח הפורטל של ההתקנה", JSON.stringify(lw?.systemDomains));
  check((learning["version"] as number) > 700, "הגרסה עוברת את מה שהמחשב דיווח שבידיו", String(learning["version"]));
  // sameBody ולא השוואת מחרוזות: jsonb אינו שומר על סדר המפתחות.
  check(sameBody(learning["providers"], basePolicy["providers"]) && Array.isArray(learning["providers"])
    && (learning["providers"] as unknown[]).length > 0,
    "ושאר המדיניות — הספקים — הגיע מהבסיס בלי שינוי", `${(learning["providers"] as unknown[]).length} ספקים`);

  // ─────────────────────────────────────── מה שנצפה
  section("11 · המחשב מדווח מה ביקש");

  const post = (device: Device, domains: unknown) => call(device.auth, "POST", "/api/v1/whitelist/observed", { domains });

  const first = await post(pc, [
    { name: "static.example.com", count: 12 },
    { name: "STATIC.Example.com.", count: 3 },
    { name: "tracker.adsnet.io", count: 1 },
    { name: "img.xvideos-cdn.com", count: 2 },
    { name: "cfblocked-ads.com", count: 4 },
    { name: "fonts.gstatic.com", count: 7 },
    { name: "bad name!", count: 1 },
    { name: "8.8.8.8", count: 1 },
  ]);

  check(first.status === 200 && first.json["ok"] === true && first.json["accepted"] === 5,
    "חמישה שמות התקבלו", `שניים פגומים דולגו, ושני כתיבים של אותו שם אוחדו · ${JSON.stringify(first.json)}`);

  await post(pc, [{ name: "static.example.com", count: 15 }]);

  const view = await call(owner, "GET", wl);
  const observed = (view.json["observed"] ?? []) as Array<{
    domain: string; registrable: string; hits: number; blocked: boolean; approved: boolean; reason?: string;
  }>;
  const obs = (d: string) => observed.find((o) => o.domain === d);

  check(obs("static.example.com")?.hits === 30, "הספירות מצטברות בין דיווחים", String(obs("static.example.com")?.hits));
  check(observed[0]?.domain === "static.example.com", "והנפוץ ביותר ראשון");
  check(obs("static.example.com")?.registrable === "example.com" && obs("static.example.com")?.approved === true,
    "static.example.com מקובץ תחת example.com, ומסומן כמאושר", "האב שלו כבר ברשימה");
  check(obs("img.xvideos-cdn.com")?.blocked === true && obs("img.xvideos-cdn.com")?.reason === REASON_BLOCKED,
    "שם שמסגיר את עצמו מוצג כחסום, עם הסיבה");
  check(obs("cfblocked-ads.com")?.blocked === false,
    "שם שרק הבדיקה החיה תופסת מוצג בינתיים כניתן לאישור", "הבדיקה החיה רצה ברגע האישור");

  check((await post(laptop, [{ name: "a.example.com", count: 1 }])).json["ignored"] === true,
    "מחשב שאינו בלמידה: 200 עם ignored, לא שגיאה");
  check((await call(laptop.auth, "POST", "/api/v1/whitelist/observed", { domains: "x" })).status === 400,
    "גוף שאינו רשימה נדחה ב-400");
  check((await app.fastify.inject({ method: "POST", url: "/api/v1/whitelist/observed", payload: { domains: [] } })).statusCode === 401,
    "ובלי אסימון מחשב — 401");

  // ─────────────────────────────────────── אישור מתוך הנצפים
  section("12 · אישור מתוך מה שנצפה");

  const approve = await call(owner, "POST", `${wl}/domains`, {
    source: "learned",
    domains: ["tracker.adsnet.io", "img.xvideos-cdn.com", "cfblocked-ads.com", "fonts.gstatic.com"],
  });
  const ar = (approve.json["results"] ?? []) as Array<{ domain: string; ok: boolean; reason?: string }>;

  check(approve.json["added"] === 2, "שניים אושרו", JSON.stringify(ar.map((r) => `${r.domain}:${r.ok}`)));
  check(ar.find((r) => r.domain === "img.xvideos-cdn.com")?.ok === false
    && ar.find((r) => r.domain === "cfblocked-ads.com")?.ok === false,
    "ושני החסומים נדחו גם בנתיב הזה", "אותו שער לשני הנתיבים");

  const view2 = await call(owner, "GET", wl);
  const observed2 = (view2.json["observed"] ?? []) as typeof observed;

  check(observed2.find((o) => o.domain === "cfblocked-ads.com")?.blocked === true,
    "מה שנדחה בבדיקה החיה מוצג מעתה כחסום", "ההכרעה נשמרה על השורה");
  check((view2.json["domains"] as Array<{ domain: string; source: string }>)
    .some((d) => d.domain === "fonts.gstatic.com" && d.source === "learned"),
    "ומה שאושר רשום כנלמד");

  const dismissed = await call(owner, "POST", `${wl}/observed/dismiss`, { domains: ["img.xvideos-cdn.com"] });
  check(dismissed.json["dismissed"] === 1, "הסרה מרשימת הנצפים");
  await post(pc, [{ name: "img.xvideos-cdn.com", count: 9 }]);
  check(!((await call(owner, "GET", wl)).json["observed"] as typeof observed).some((o) => o.domain === "img.xvideos-cdn.com"),
    "ומה שהוסר אינו צץ שוב בדיווח הבא");

  // ─────────────────────────────────────── הפעלה
  section("13 · הפעלה");

  check((await beat(pc, "unfiltered", learning["version"] as number)) === 200, "המחשב עבר לרשת לא מסוננת");

  const openUnfiltered = async () => withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query(
      "SELECT 1 FROM alerts WHERE device_id = $1 AND kind = 'device.unfiltered' AND state <> 'resolved'",
      [pc.deviceId]);
    return (r.rowCount ?? 0) > 0;
  });

  check(await openUnfiltered(), "ונפתחה התראת \"אינו מסונן\"");

  const on = await call(owner, "POST", wl, { enabled: true });
  check(on.status === 200 && on.json["enabled"] === true, "הרשימה הופעלה");

  const enabled = await pull(pc);
  const ew = whitelistOf(enabled);

  check(ew?.enabled === true, "במדיניות שנמשכה: פעילה");
  check(JSON.stringify(ew?.domains) === '["cdn.example.net","example.com","fonts.gstatic.com","tracker.adsnet.io"]',
    "עם ארבעת האתרים", JSON.stringify(ew?.domains));
  check(ew?.learnUntilUtc === lw?.learnUntilUtc, "והלמידה ממשיכה לרוץ עד סופה");

  check((await beat(pc, "whitelist", enabled["version"] as number)) === 200, "המחשב מדווח מצב whitelist — מתקבל");
  check(!(await openUnfiltered()), "והתראת \"אינו מסונן\" נסגרה", "רשימה לבנה היא מצב מוגן");

  const state = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ last_status: string }>(
      "SELECT last_status::text FROM device_state WHERE device_id = $1", [pc.deviceId]);
    return r.rows[0]?.last_status;
  });
  check(state === "whitelist", "המצב נשמר במסד כ-whitelist", String(state));

  const summary = await call(owner, "GET", "/api/portal/v1/summary");
  check(summary.json["whitelist"] === 1 && summary.json["unfiltered"] === 0,
    "ובסיכום: מחשב אחד ברשימה לבנה, אפס לא מסוננים", JSON.stringify(summary.json));

  check((await beat(pc, "unfiltered", enabled["version"] as number)) === 200 && await openUnfiltered(),
    "חזרה ל\"אינו מסונן\" פותחת את ההתראה מחדש");
  await beat(pc, "whitelist", enabled["version"] as number);

  const emptyOn = await call(owner, "POST", `/api/portal/v1/devices/${laptop.deviceId}/whitelist`, { enabled: true });
  check(String(emptyOn.json["note"]).includes("הרשימה ריקה"), "הפעלה עם רשימה ריקה מותרת, ומזהירה",
    String(emptyOn.json["note"]));
  await call(owner, "POST", `/api/portal/v1/devices/${laptop.deviceId}/whitelist`, { enabled: false });

  // ─────────────────────────────────────── עצירת למידה
  section("14 · עצירת הלמידה וחלון החסד");

  const stop = await call(owner, "DELETE", `${wl}/learning`);
  check(stop.status === 200, "הלמידה נעצרה");

  const stopped = await pull(pc);
  check(whitelistOf(stopped)?.learnUntilUtc === null && whitelistOf(stopped)?.enabled === true,
    "במדיניות: אין למידה, הרשימה עדיין פעילה");

  check((await post(pc, [{ name: "late.example.org", count: 2 }])).json["accepted"] === 1,
    "דיווח שמגיע מיד אחרי העצירה עדיין מתקבל", "הסוכן שולח את מה שצבר");

  await withPlatform(pool, SYSTEM, (tx) => tx.query(
    "UPDATE device_whitelist SET learning_until = now() - interval '11 minutes' WHERE device_id = $1", [pc.deviceId]));

  check((await post(pc, [{ name: "toolate.example.org", count: 2 }])).json["ignored"] === true,
    "אחרי עשר דקות — ignored");

  const cleared = await call(owner, "POST", `${wl}/observed/clear`);
  check((cleared.json["cleared"] as number) >= 5
    && ((await call(owner, "GET", wl)).json["observed"] as unknown[]).length === 0, "ניקוי הנצפים מרוקן את הרשימה");

  // ─────────────────────────────────────── הסרת אתר
  section("15 · הסרת אתר");

  const list = ((await call(owner, "GET", wl)).json["domains"] ?? []) as Array<{ id: string; domain: string }>;
  const tracker = list.find((d) => d.domain === "tracker.adsnet.io")!;
  const removed = await call(owner, "DELETE", `${wl}/domains/${tracker.id}`);

  check(removed.status === 200, "האתר הוסר");
  check(!whitelistOf(await pull(pc))!.domains.includes("tracker.adsnet.io"), "ואינו במדיניות שנמשכת");
  check((await call(owner, "DELETE", `${wl}/domains/${tracker.id}`)).status === 404, "הסרה חוזרת — 404");
  check((await orphans(family.tenantId)) === 0,
    "אחרי כל הפרסומים האלה לא נשארה אף שורת מחשב בלי שיוך",
    "שורה כזו נראית כמו מדיניות דייר, והייתה נבחרת כבסיס לכל המחשבים");

  // ─────────────────────────────────────── ההרכבה בעליית השרת
  section("16 · ההרכבה בעליית השרת אינה נוגעת במה שנכון");

  const beforeRebuild = (await pull(pc))["version"] as number;
  await rebuildTenantPolicies(pool, app.signer);
  await rebuildAssignedPolicies(pool, app.signer);
  check(((await pull(pc))["version"] as number) === beforeRebuild,
    "אותה גרסה אחרי הרכבה מחדש", "מה שלא השתנה אינו מתפרסם");

  // ─────────────────────────────────────── כיבוי
  section("17 · כיבוי");

  const heldBeforeOff = (await pull(pc))["version"] as number;
  const off = await call(owner, "POST", wl, { enabled: false });

  check(off.status === 200 && off.json["enabled"] === false, "הרשימה כובתה");
  check((await assignment(pc.deviceId)) === null, "השיוך נמחק: למחשב בלי שעות חסימה אין עוד שכבה");
  check((await orphans(family.tenantId)) === 0, "והשורה שלו נמחקה איתו");

  const afterOff = await pull(pc);

  check(whitelistOf(afterOff) === null, "המדיניות שהוא מושך עכשיו היא של הדייר, בלי רשימה לבנה");
  check((afterOff["version"] as number) > heldBeforeOff,
    "ומספרה גבוה ממה שבידיו — אחרת הסוכן היה דוחה אותה ונשאר חסום",
    `${heldBeforeOff} ← ${afterOff["version"]}`);
  check(off.json["version"] === afterOff["version"], "והתשובה לפורטל נושאת את אותו מספר");
  check(((await call(owner, "GET", wl)).json["domains"] as unknown[]).length === 3,
    "האתרים שאושרו נשמרים להפעלה הבאה");

  // ─────────────────────────────────────── למידה שפגה מעצמה
  section("18 · למידה שפגה בלי שאיש עצר אותה");

  await call(owner, "POST", `${wl}/learning`, { minutes: 5 });
  check((await assignment(pc.deviceId)) !== null, "למידה על מחשב כבוי פותחת שכבה");

  await withPlatform(pool, SYSTEM, (tx) => tx.query(
    "UPDATE device_whitelist SET learning_until = now() - interval '1 minute' WHERE device_id = $1", [pc.deviceId]));

  check(((await call(owner, "GET", wl)).json["learningUntil"]) === null, "התצוגה: אין למידה");

  const expired = await composeDeviceOverlay(pool, app.signer, { tenantId: family.tenantId, deviceId: pc.deviceId });
  check(expired.action === "removed" && (await assignment(pc.deviceId)) === null,
    "וההרכבה הבאה מחזירה את המחשב לבסיס", expired.action);
  await pull(pc);

  // ─────────────────────────────────────── שעות חסימה בלבד
  section("19 · מחשב עם שעות חסימה בלבד");

  const sch = `/api/portal/v1/devices/${laptop.deviceId}/schedules`;
  const s1 = await call(owner, "POST", sch, { days: [], from: "22:00", to: "07:00" });
  const s2 = await call(owner, "POST", sch, { days: [5], from: "14:00", to: "16:00" });

  check(s1.status === 200 && s2.status === 200 && (s2.json["version"] as number) > (s1.json["version"] as number),
    "שני חלונות נשמרו, והגרסה עלתה", `${s1.json["version"]} ← ${s2.json["version"]}`);

  const lp = await pulled(laptop);
  const le = lp["enforcement"] as Record<string, unknown>;
  const rules = le["schedules"] as Array<{ from: string; to: string; action: string }>;

  check(rules.length === 2 && rules.every((r) => r.action === "BlockAll"), "שני הכללים במדיניות", JSON.stringify(rules.map((r) => `${r.from}-${r.to}`)));
  check(JSON.stringify(whitelistOf(lp)) === JSON.stringify({
    enabled: false,
    domains: [],
    systemDomains: whitelistOf(lp)!.systemDomains,
    upstreamResolvers: ["1.1.1.3", "1.0.0.3"],
    learnUntilUtc: null,
  }), "וסעיף רשימה לבנה כבוי וריק", JSON.stringify(whitelistOf(lp)));
  check(sameBody(lp["providers"], basePolicy["providers"])
    && (le["mode"] ?? null) === ((basePolicy["enforcement"] as Record<string, unknown>)["mode"] ?? null),
    "הבסיס — ספקים ומצב אכיפה — כמו שהוא");
  check(typeof (le["allowedNetworks"] as Record<string, unknown>)["blockUntilApproved"] === "boolean",
    "ודגל חסימת הרשתות נישא גם בנתיב הזה", "קודם נוסף רק בעליית השרת, וכל שמירה מחקה אותו");
  check((await orphans(family.tenantId)) === 0, "שמירה שנייה לא השאירה את השורה של הראשונה",
    "זו השארית שנבחרה פעם כמדיניות הדייר");

  const lv = lp["version"] as number;
  await rebuildAssignedPolicies(pool, app.signer);
  check(((await pulled(laptop))["version"] as number) === lv, "הרכבה מחדש אינה מפרסמת כשדבר לא השתנה");

  const pcNow = await pull(pc);
  check(whitelistOf(pcNow) === null && !("schedules" in (pcNow["enforcement"] as Record<string, unknown>)
      && ((pcNow["enforcement"] as Record<string, unknown>)["schedules"] as unknown[]).length > 0),
    "והמחשב השני לא קיבל את השעות של הראשון");

  const ids = [s1.json["id"], s2.json["id"]] as string[];
  await call(owner, "DELETE", `${sch}/${ids[0]}`);
  check((await assignment(laptop.deviceId)) !== null, "חלון אחד נמחק — השכבה נשארת");
  await call(owner, "DELETE", `${sch}/${ids[1]}`);
  check((await assignment(laptop.deviceId)) === null, "האחרון נמחק — השיוך נמחק");
  check(((await pulled(laptop))["version"] as number) > lv, "והמדיניות שהמחשב נופל אליה במספר גבוה יותר");

  // ─────────────────────────────────────── הגדרות הדפדפן של הדייר
  section("20 · הגדרות היוטיוב של הדייר שורדות עליית שרת");

  const egress = await call(owner, "POST", "/api/portal/v1/settings/egress", {
    enabled: false,
    youtubeAudioOnly: true,
    youtubeHideThumbnails: true,
    youtubeAllowedChannels: ["@NatGeo"],
  });
  check(egress.status === 200, "הדייר הגדיר יוטיוב בשמע בלבד", JSON.stringify(egress.json).slice(0, 120));

  const tenantRow = async () => withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ version: number; body: Record<string, unknown> }>(
      `SELECT p.version, p.body FROM policies p
        WHERE p.tenant_id = $1
          AND NOT EXISTS (SELECT 1 FROM device_policy_assignments a WHERE a.policy_id = p.id)
        ORDER BY p.version DESC LIMIT 1`, [family.tenantId]);
    return r.rows[0]!;
  });

  const globalBody = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ body: Record<string, unknown> }>(
      "SELECT body FROM policies WHERE tenant_id IS NULL ORDER BY version DESC LIMIT 1");
    return r.rows[0]!.body;
  });

  /*
   * סיבוב ראשון של ההרכבה, לפני המדידה.
   *
   * מסך ההגדרות אינו כותב את דגל חסימת הרשתות, וההרכבה מוסיפה
   * אותו — ולכן ההרכבה הראשונה אחרי שמירה תמיד מפרסמת פעם אחת.
   * זה היה כך גם קודם, ואינו מה שנבדק כאן. אחרי הסיבוב הזה, כל
   * הבדל שנשאר בין הגופים הוא הגדרות הדפדפן בלבד.
   */
  await rebuildTenantPolicies(pool, app.signer);

  const own = await tenantRow();
  const ownEnf = own.body["enforcement"] as Record<string, unknown>;
  const baseEnf = globalBody["enforcement"] as Record<string, unknown>;

  /*
   * מה שההרכבה הקודמת בנתה: הבסיס, ומעליו egress בלבד.
   * אם זה שונה ממה שהדייר מחזיק — היא הייתה מפרסמת אותו.
   */
  const oldComposed = {
    ...globalBody,
    enforcement: {
      ...baseEnf,
      egress: ownEnf["egress"],
      allowedNetworks: { ...(baseEnf["allowedNetworks"] as object), blockUntilApproved: false },
    },
  };

  check(!("browser" in baseEnf), "לבסיס אין סעיף browser כלל");
  check((ownEnf["browser"] as Record<string, unknown> | undefined)?.["youtubeAudioOnly"] === true,
    "ההרכבה הראשונה שמרה על הגדרות היוטיוב", JSON.stringify(ownEnf["browser"]));
  check(sameBody(own.body, { ...oldComposed, enforcement: { ...oldComposed.enforcement, browser: ownEnf["browser"] } }),
    "וההבדל היחיד בין הגוף של הדייר להרכבה הקודמת הוא סעיף browser");
  check(!sameBody(own.body, oldComposed),
    "ההרכבה הקודמת (egress בלבד) מפיקה גוף שונה ממה שהדייר מחזיק",
    "כלומר הייתה מפרסמת אותו — בלי הגדרות היוטיוב. זו התקלה.");
  check(sameBody(own.body, composeTenantBody(globalBody, own.body, false)),
    "ההרכבה החדשה מפיקה בדיוק את מה שהדייר מחזיק");

  await rebuildTenantPolicies(pool, app.signer);

  const after = await tenantRow();
  const browser = (after.body["enforcement"] as Record<string, unknown>)["browser"] as Record<string, unknown> | undefined;

  check(after.version === own.version, "אחרי הרכבה מחדש: אותה גרסה, דבר לא פורסם", `${own.version} ← ${after.version}`);
  check(browser?.["youtubeAudioOnly"] === true && JSON.stringify(browser?.["youtubeAllowedChannels"]) === '["@natgeo"]',
    "והגדרות היוטיוב במקומן", JSON.stringify(browser));

  // שמירה של כלל היציאה בלי שדות היוטיוב אינה מוחקת אותם
  await call(owner, "POST", "/api/portal/v1/settings/egress", { enabled: false });
  const kept = ((await tenantRow()).body["enforcement"] as Record<string, unknown>)["browser"] as Record<string, unknown>;
  check(kept?.["youtubeAudioOnly"] === true, "וגם שמירה שלא שלחה את שדות היוטיוב אינה מוחקת אותם", JSON.stringify(kept));

  // ─────────────────────────────────────── הגרסה אינה יורדת
  section("21 · מספר הגרסה לאורך כל הדרך");

  versions.push((await pulled(pc))["version"] as number);

  const monotonic = versions.every((v, i) => i === 0 || v >= versions[i - 1]!);
  check(monotonic, "כל מדיניות שהמחשב משך נשאה מספר שאינו נמוך מקודמתה", versions.join(" → "));

  // ─────────────────────────────────────── ביומן הביקורת
  section("22 · יומן הביקורת");

  const actions = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ action: string }>(
      "SELECT DISTINCT action FROM audit_log WHERE tenant_id = $1 AND action LIKE 'device.whitelist.%'",
      [family.tenantId]);
    return r.rows.map((x) => x.action).sort();
  });

  for (const want of ["enabled", "disabled", "domains_added", "domain_removed", "learning_started",
    "learning_stopped", "observed_dismissed", "observed_cleared"]) {
    check(actions.includes(`device.whitelist.${want}`), `נרשם: device.whitelist.${want}`);
  }

  await app.close();
  await pool.end();
}

main()
  .then(() => {
    console.log("");
    console.log("═".repeat(64));
    console.log(`עברו ${passed} · נכשלו ${failed}`);
    console.log("═".repeat(64));
    process.exit(failed === 0 ? 0 : 1);
  })
  .catch((error: unknown) => {
    console.error(error);
    process.exit(1);
  });
