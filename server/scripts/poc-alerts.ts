/**
 * ההתראות, מקצה לקצה.
 *
 * מה שנבדק כאן הוא ההבטחה של מסך ההתראות: חמישה סוגים, שלושה
 * ערוצים, שעות שקט. עד התיקון סוג אחד נשלח, פעם אחת, תמיד מיד.
 *
 * הבדיקה שולחת פעימות לב אמיתיות דרך השרת ובודקת מה יצא בדואר —
 * ולא קוראת לפונקציות הפנימיות — כי הכשל שהתגלה בשטח היה בדיוק
 * "הפונקציה קיימת ואיש לא קורא לה".
 */

import { randomBytes, randomUUID } from "node:crypto";

import { buildApp } from "../src/app.ts";
import { createPool, withPlatform } from "../src/db/client.ts";
import { hashEnrollToken } from "../src/auth/device-token.ts";
import { LocalSigner } from "../src/crypto/signing.ts";
import { publishPolicy } from "../src/policy/publish.ts";
import { loadConfig } from "../src/config.ts";
import { NullMailer, type Mailer, type Message } from "../src/notify/mailer.ts";
import { raiseAlert, resolveAlert, COOLDOWN_MINUTES } from "../src/notify/alerts.ts";
import { deliverPending } from "../src/workers/digest-worker.ts";
import { scanOnce } from "../src/workers/deadman-worker.ts";
import { DIGEST_HOUR, digestDue, localHour } from "../src/notify/settings.ts";

let passed = 0;
let failed = 0;

function check(ok: boolean, title: string, detail = ""): void {
  if (ok) passed += 1;
  else failed += 1;

  console.log(`  ${ok ? "✓" : "✗"} ${title}${detail ? `\n      ${detail}` : ""}`);
}

function section(title: string): void {
  console.log(`\n${title}`);
  console.log("─".repeat(64));
}

const SYSTEM = { userId: "00000000-0000-0000-0000-000000000000", reason: "הרצת POC" };

/** דוור שנכשל תמיד. לבדיקת הניסיון החוזר. */
class FailingMailer implements Mailer {
  readonly name = "failing";
  send(_message: Message): Promise<void> {
    return Promise.reject(new Error("הספק דחה"));
  }
}

/** שעה מקומית (ישראל, קיץ: UTC+3) בתאריך נתון. */
function localAt(day: string, hour: number): Date {
  const [y, m, d] = day.split("-").map(Number) as [number, number, number];

  return new Date(Date.UTC(y, m - 1, d, hour - 3));
}

async function main(): Promise<void> {
  // ─────────────────────────────────────── הכללים הטהורים
  section("1 · שעון מקומי וסיכום יומי");

  check(localHour(localAt("2026-09-10", 3)) === 3, "03:00 מקומי מזוהה כשלוש");
  check(localHour(localAt("2026-09-10", 23)) === 23, "23:00 מקומי מזוהה כעשרים ושלוש");
  check(!digestDue(localAt("2026-09-10", 7), null), "לפני שעת הסיכום — לא");
  check(digestDue(localAt("2026-09-10", DIGEST_HOUR), null), "בשעת הסיכום, מעולם לא נשלח — כן");
  check(
    !digestDue(localAt("2026-09-10", 10), localAt("2026-09-10", 8)),
    "כבר נשלח היום — לא",
  );
  check(
    digestDue(localAt("2026-09-11", 8), localAt("2026-09-10", 8)),
    "יום חדש — כן",
  );
  check(
    digestDue(localAt("2026-09-11", 9), localAt("2026-09-10", 23)),
    "נשלח אתמול מאוחר — עדיין יום חדש",
    "\"פעם ביום\" נמדד לפי תאריך, לא לפי 24 שעות",
  );

  // ─────────────────────────────────────── השרת
  const config = loadConfig({
    ...process.env,
    NODE_ENV: "test",
    DEVICE_TOKEN_SECRET: process.env["DEVICE_TOKEN_SECRET"] ?? randomBytes(32).toString("hex"),
    PORTAL_URL: "https://filterplus.example",
  });

  const pool = createPool({ connectionString: config.DATABASE_URL_APP });
  const mailer = new NullMailer();

  const app = await buildApp({
    config,
    pool,
    mailer,
    signer: LocalSigner.ephemeral(`poc-policy-${randomUUID().slice(0, 8)}`),
    looseningSigner: LocalSigner.ephemeral(`poc-loosening-${randomUUID().slice(0, 8)}`),
    uninstallSigner: LocalSigner.ephemeral(`poc-uninstall-${randomUUID().slice(0, 8)}`),
    updateSigner: LocalSigner.ephemeral(`poc-update-${randomUUID().slice(0, 8)}`),
    logger: false,
  });

  const ownerEmail = `horeh-${randomUUID().slice(0, 8)}@example.test`;
  const enrollTokenRaw = `ENR-${randomUUID().toUpperCase()}`;
  const floor = { mode: "enforce", onRedAction: "lockout", minScoreForGreen: 85 };

  const tenantId = await withPlatform(pool, SYSTEM, async (tx) => {
    const t = await tx.query<{ id: string }>(
      `INSERT INTO tenants (type, name, trial_started_at, trial_ends_at)
       VALUES ('family', 'משפחת התראות', now(), now() + interval '30 days')
       RETURNING id`,
    );
    const id = t.rows[0]!.id;

    // הטריגר יוצר את שורת ההגדרות עם הכתובת הזו
    await tx.query(
      `INSERT INTO users (tenant_id, email, display_name, role, password_hash)
       VALUES ($1, $2, 'הורה', 'tenant_owner', 'x')`,
      [id, ownerEmail],
    );

    await tx.query(
      `INSERT INTO enroll_tokens
         (tenant_id, token_hash, install_profile, enforcement_mode, policy_floor,
          max_uses, expires_at)
       VALUES ($1, $2, 'family_child', 'enforce', $3, 5, now() + interval '7 days')`,
      [id, hashEnrollToken(enrollTokenRaw), JSON.stringify(floor)],
    );

    return id;
  });

  await publishPolicy(pool, app.signer, {
    tenantId,
    version: 1,
    body: {
      version: 1,
      issuedUtc: new Date().toISOString(),
      ttlMinutes: 240,
      graceMinutes: 720,
      providers: [{ id: "netfree", displayName: "נטפרי", trustLevel: "high" }],
      enforcement: { mode: "enforce", minScoreForGreen: 85, onRedAction: "lockout" },
    },
  });

  const hwid = `HWID${randomBytes(10).toString("hex").toUpperCase()}`;

  const enroll = await app.fastify.inject({
    method: "POST",
    url: "/api/v1/enroll",
    payload: { enrollToken: enrollTokenRaw, hwid, machineName: "PC-DANI", agentVersion: "1.0.0" },
  });

  if (enroll.statusCode !== 200) {
    console.log(`רישום נכשל: ${enroll.statusCode} ${enroll.body}`);
    process.exit(1);
  }

  const enrolled = enroll.json() as { deviceId: string; deviceToken: string };
  const auth = { authorization: `Bearer ${enrolled.deviceToken}`, "x-filterplus-hwid": hwid };
  const deviceId = enrolled.deviceId;

  let sequence = 0;

  async function beat(input: {
    status?: string;
    ssid?: string;
    gateway?: string;
    provider?: string | null;
    lockout?: boolean;
    tamper?: Array<{ kind: string; detail?: string }>;
  }): Promise<number> {
    sequence += 1;

    const r = await app.fastify.inject({
      method: "POST",
      url: "/api/v1/heartbeat",
      headers: auth,
      payload: {
        hwid,
        policyVersion: 1,
        sequence,
        status: input.status ?? "safe",
        score: input.status === "unfiltered" ? 10 : 95,
        activeAdapters: [{
          name: "Wi-Fi",
          ssid: input.ssid ?? "HOME",
          gateway: input.gateway ?? "192.168.1.1",
          gatewayMac: "aa:bb:cc:dd:ee:01",
        }],
        detectedProvider: input.provider === undefined ? "netfree" : input.provider,
        failedProbes: [],
        tamperEvents: input.tamper ?? [],
        lockoutActive: input.lockout ?? false,
      },
    });

    return r.statusCode;
  }

  /** ההודעות שיצאו מאז הקריאה הקודמת. */
  let seen = 0;
  function fresh(): Message[] {
    const out = mailer.outbox.slice(seen);
    seen = mailer.outbox.length;
    return out;
  }

  async function openAlerts(): Promise<Array<{ kind: string; state: string; deferred: boolean }>> {
    return withPlatform(pool, SYSTEM, async (tx) => {
      const r = await tx.query<{ kind: string; state: string; deferred: boolean }>(
        `SELECT kind, state, deferred FROM alerts
          WHERE device_id = $1 AND state <> 'resolved' ORDER BY first_seen_at`,
        [deviceId],
      );
      return r.rows;
    });
  }

  // ─────────────────────────────────────── רשת חדשה
  section("2 · רשת חדשה");

  check((await beat({})) === 200, "פעימה ראשונה התקבלה");

  const first = fresh();

  check(
    first.length === 1 && first[0]!.subject.includes("רשת חדשה"),
    "הרשת הראשונה מולידה התראת רשת חדשה",
    first[0]?.subject ?? "לא יצא דבר",
  );
  check(first[0]?.to === ownerEmail, "אל כתובת ההורה", first[0]?.to ?? "");
  check((first[0]?.body ?? "").includes("HOME"), "עם שם הרשת");

  await beat({});
  check(fresh().length === 0, "פעימה נוספת על אותה רשת — שקט");

  check(
    (await openAlerts()).length === 0,
    "רשת חדשה היא אירוע: ההתראה נסגרת מיד",
    "אחרת הרשת הבאה הייתה נבלעת באינדקס הייחודי",
  );

  // ─────────────────────────────────────── חיבור לא מסונן
  section("3 · חיבור לא מסונן");

  await beat({ status: "unfiltered", provider: null });

  const unfiltered = fresh();

  check(
    unfiltered.length === 1 && unfiltered[0]!.subject.includes("בלי סינון"),
    "מעבר ללא מסונן שולח מייל",
    unfiltered[0]?.subject ?? "לא יצא דבר",
  );
  check(
    (unfiltered[0]?.body ?? "").includes("PC-DANI"),
    "עם שם המחשב",
  );
  check(
    (await openAlerts()).some((a) => a.kind === "device.unfiltered" && a.state === "notified"),
    "ההתראה רשומה כנשלחה",
  );

  await beat({ status: "unfiltered", provider: null });
  check(fresh().length === 0, "עדיין לא מסונן — לא מייל נוסף", "זה אותו אירוע שנמשך");

  await beat({ status: "safe" });
  check(fresh().length === 0, "חזרה לסינון — אין מייל");
  check(
    !(await openAlerts()).some((a) => a.kind === "device.unfiltered"),
    "אבל ההתראה נסגרה",
    "בלי סגירה, הפעם הבאה הייתה נבלעת",
  );

  await beat({ status: "unfiltered", provider: null });
  const again = await openAlerts();

  check(
    again.some((a) => a.kind === "device.unfiltered" && a.state === "open"),
    "לא מסונן שוב — התראה חדשה נפתחת",
  );
  check(
    fresh().length === 0,
    `אך בלי מייל: נשלח לפני פחות מ-${COOLDOWN_MINUTES} דקות`,
    "מחשב שמרצד לא ישלח שישים מיילים בשעה",
  );

  await beat({ status: "safe" });
  fresh();

  // ─────────────────────────────────────── נעילה
  section("4 · נעילה ושחרור");

  await beat({ lockout: true });

  const locked = fresh();

  check(
    locked.length === 1 && locked[0]!.subject.includes("ננעל"),
    "נעילה שולחת מייל",
    locked[0]?.subject ?? "לא יצא דבר",
  );

  await beat({ lockout: false });

  const released = fresh();

  check(
    released.length === 1 && released[0]!.subject.includes("שוחרר"),
    "שחרור שולח מייל, כי על הנעילה הודיעו",
    released[0]?.subject ?? "לא יצא דבר",
  );
  check(
    !(await openAlerts()).some((a) => a.kind === "device.lockout"),
    "והתראת הנעילה נסגרה",
  );

  // ─────────────────────────────────────── חבלה
  section("5 · חבלה");

  // הסוכן משדר את ה-enum שלו ב-camelCase. הבדיקה שולחת את מה שהוא
  // שולח, ולא את השם כפי שנכתב ב-C# — אחרת היא עוברת והשטח לא.
  await beat({ tamper: [{ kind: "trayAppKilled" }] });
  check(fresh().length === 0, "אייקון שנסגר הוא מידע, לא מייל");

  await beat({ tamper: [{ kind: "serviceStopAttempt", detail: "sc stop FilterPlus" }, { kind: "clockRolledBack" }] });

  const tamper = fresh();

  check(
    tamper.length === 1 && tamper[0]!.subject.includes("חבלה"),
    "ניסיון עצירה שולח מייל אחד לפעימה",
    tamper[0]?.subject ?? "לא יצא דבר",
  );
  check(
    (tamper[0]?.body ?? "").includes("שעון המחשב הוזז אחורה"),
    "על החמור שבאירועים, במילים של הורה",
  );
  check(
    (tamper[0]?.body ?? "").includes("ועוד 1 אירוע"),
    "ומזכיר שהיו עוד",
  );

  // ─────────────────────────────────────── ערוץ כבוי
  section("6 · ההורה כיבה סוג התראה");

  await withPlatform(pool, SYSTEM, async (tx) => {
    await tx.query(
      "UPDATE notification_settings SET on_tamper = 'off' WHERE tenant_id = $1",
      [tenantId],
    );
  });

  // האירוע הקודם נסגר מיד, ולכן זה חדש. עברה פחות משעה — אבל
  // הכיבוי נבדק לפני הצינון, ומה שנבדק כאן הוא הכיבוי.
  await withPlatform(pool, SYSTEM, async (tx) => {
    await tx.query(
      "UPDATE alerts SET last_notified_at = now() - interval '2 hours' WHERE device_id = $1",
      [deviceId],
    );
  });

  await beat({ tamper: [{ kind: "WfpFiltersMissing" }] });
  check(fresh().length === 0, "חבלה אינה נשלחת כשהערוץ כבוי");

  const recorded = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ n: string }>(
      "SELECT count(*) AS n FROM alerts WHERE device_id = $1 AND kind = 'device.tamper'",
      [deviceId],
    );
    return Number(r.rows[0]!.n);
  });

  check(recorded === 2, "אבל היא נרשמה בפורטל", `${recorded} התראות חבלה`);

  await withPlatform(pool, SYSTEM, async (tx) => {
    await tx.query(
      "UPDATE notification_settings SET on_tamper = 'immediate' WHERE tenant_id = $1",
      [tenantId],
    );
  });

  // ─────────────────────────────────────── שעות שקט
  section("7 · שעות שקט דוחות ולא מוחקות");

  const notify = { mailer, portalUrl: "https://filterplus.example" };
  const day = "2026-09-10";

  await withPlatform(pool, SYSTEM, async (tx) => {
    await tx.query(
      "UPDATE notification_settings SET quiet_from = 22, quiet_to = 7 WHERE tenant_id = $1",
      [tenantId],
    );
    await tx.query("DELETE FROM alerts WHERE device_id = $1", [deviceId]);
  });

  const atNight = await withPlatform(pool, SYSTEM, (tx) =>
    raiseAlert(tx, notify, {
      deviceId,
      kind: "device.unfiltered",
      detail: "המחשב יוצא לאינטרנט שלא דרך ספק סינון מאושר.",
      now: localAt(day, 3),
    }),
  );

  check(atNight.opened && atNight.delivery === "deferred", "בשלוש בלילה — נדחה", atNight.delivery);
  check(fresh().length === 0, "ולא נשלח");

  let run = await deliverPending(pool, notify, localAt(day, 5));
  check(run.sent === 0 && fresh().length === 0, "בחמש עדיין שקט — עדיין ממתין");

  // בינתיים המחשב חזר לסינון
  await withPlatform(pool, SYSTEM, (tx) =>
    resolveAlert(tx, notify, { deviceId, kind: "device.unfiltered", notice: false, now: localAt(day, 6) }),
  );

  run = await deliverPending(pool, notify, localAt(day, 7));

  const morning = fresh();

  check(run.sent === 1 && morning.length === 1, "בשבע השקט נגמר — יוצא", `נשלחו ${run.sent}`);
  check(
    (morning[0]?.body ?? "").includes("הסתיים ב-"),
    "וההודעה אומרת שזה כבר נגמר",
    "\"היה בלי סינון\" שונה מ\"בלי סינון\"",
  );

  const tamperAtNight = await withPlatform(pool, SYSTEM, (tx) =>
    raiseAlert(tx, notify, {
      deviceId,
      kind: "device.tamper",
      detail: "חוקי האכיפה נעלמו מהמערכת.",
      now: localAt(day, 2),
    }),
  );

  check(
    tamperAtNight.delivery === "sent" && fresh().length === 1,
    "חבלה אינה מכבדת שעות שקט",
    "השעות שבהן ההורה ישן הן בדיוק השעות שבהן כדאי לנסות",
  );

  // ─────────────────────────────────────── סיכום יומי
  section("8 · סיכום יומי");

  await withPlatform(pool, SYSTEM, async (tx) => {
    await tx.query(
      `UPDATE notification_settings
          SET quiet_from = NULL, quiet_to = NULL, on_new_network = 'daily', last_digest_at = NULL
        WHERE tenant_id = $1`,
      [tenantId],
    );
  });

  const daily = await withPlatform(pool, SYSTEM, (tx) =>
    raiseAlert(tx, notify, {
      deviceId,
      kind: "network.new",
      detail: "CAFE-WIFI. רשת חדשה. ממתינה לאישור מנהל החשבון.",
      now: localAt(day, 9),
    }),
  );

  check(daily.delivery === "deferred", "ערוץ יומי — נדחה לסיכום", daily.delivery);

  run = await deliverPending(pool, notify, localAt(day, 9));
  const digest = fresh();

  check(
    run.sent === 1 && digest.length === 1 && digest[0]!.subject.includes("ממתינה"),
    "הסיכום הראשון יוצא מיד אחרי שעת הסיכום",
    digest[0]?.subject ?? "לא יצא דבר",
  );
  check((digest[0]?.body ?? "").includes("CAFE-WIFI"), "עם מה שקרה");

  await withPlatform(pool, SYSTEM, (tx) =>
    raiseAlert(tx, notify, {
      deviceId,
      kind: "network.new",
      detail: "BUS-WIFI. רשת חדשה. ממתינה לאישור מנהל החשבון.",
      now: localAt(day, 10),
    }),
  );

  run = await deliverPending(pool, notify, localAt(day, 11));
  check(run.sent === 0 && fresh().length === 0, "עוד אחת באותו יום — ממתינה למחר");

  run = await deliverPending(pool, notify, localAt("2026-09-11", 7));
  check(run.sent === 0 && fresh().length === 0, "למחרת לפני שמונה — עדיין");

  run = await deliverPending(pool, notify, localAt("2026-09-11", 8));
  const nextDay = fresh();
  check(
    run.sent === 1 && nextDay.length === 1 && (nextDay[0]?.body ?? "").includes("BUS-WIFI"),
    "למחרת בשמונה — יוצא",
  );

  // ─────────────────────────────────────── ניסיון חוזר
  section("9 · ספק שנפל");

  await withPlatform(pool, SYSTEM, async (tx) => {
    await tx.query(
      "UPDATE notification_settings SET on_new_network = 'immediate' WHERE tenant_id = $1",
      [tenantId],
    );
    await tx.query(
      "UPDATE alerts SET last_notified_at = now() - interval '2 hours' WHERE device_id = $1",
      [deviceId],
    );
  });

  const broken = { mailer: new FailingMailer(), portalUrl: "https://filterplus.example" };

  const failedRaise = await withPlatform(pool, SYSTEM, (tx) =>
    raiseAlert(tx, broken, {
      deviceId,
      kind: "device.lockout",
      detail: "המחשב ננעל. הגלישה בו חסומה.",
      now: localAt("2026-09-12", 12),
    }),
  );

  check(failedRaise.delivery === "deferred", "שליחה שנכשלה מסומנת כממתינה", failedRaise.delivery);

  run = await deliverPending(pool, notify, localAt("2026-09-12", 12));
  const retried = fresh();

  check(
    run.sent === 1 && retried.length === 1 && (retried[0]?.body ?? "").includes("ננעל"),
    "וכשהספק חוזר, היא יוצאת",
    "כשל בשליחה דוחה את הידיעה. הוא אינו מוחק אותה",
  );

  // ─────────────────────────────────────── מחשב ששתק, פעמיים
  section("10 · מחשב ששתק, חזר, ושתק שוב");

  await withPlatform(pool, SYSTEM, async (tx) => {
    await tx.query("DELETE FROM alerts WHERE device_id = $1", [deviceId]);
    await tx.query(
      "UPDATE device_state SET last_seen_at = now() - interval '45 minutes', health = 'healthy' WHERE device_id = $1",
      [deviceId],
    );
  });

  await scanOnce(pool, new Date(), notify);

  const silent = fresh();

  check(
    silent.length === 1 && silent[0]!.subject.includes("הפסיק לדווח"),
    "שתיקה ראשונה שולחת מייל",
    silent[0]?.subject ?? "לא יצא דבר",
  );

  await beat({});
  check(
    !(await openAlerts()).some((a) => a.kind === "device.silent"),
    "פעימה סוגרת את ההתראה",
    "זה מה שהיה חסר: ההתראה הראשונה הייתה גם האחרונה",
  );

  await withPlatform(pool, SYSTEM, async (tx) => {
    await tx.query(
      "UPDATE alerts SET last_notified_at = now() - interval '2 hours' WHERE device_id = $1",
      [deviceId],
    );
    await tx.query(
      "UPDATE device_state SET last_seen_at = now() - interval '45 minutes', health = 'healthy' WHERE device_id = $1",
      [deviceId],
    );
  });

  await scanOnce(pool, new Date(), notify);

  check(
    fresh().length === 1,
    "שתיקה שנייה שולחת שוב",
    "לפני התיקון: 'alerted: 0' בכל סריקה, לנצח",
  );

  await app.close();
  await pool.end();

  console.log(`\n${"═".repeat(64)}`);
  console.log(`עברו ${passed} · נכשלו ${failed}`);
  console.log("═".repeat(64));

  process.exit(failed === 0 ? 0 : 1);
}

await main();
