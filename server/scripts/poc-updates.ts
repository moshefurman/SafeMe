/**
 * עדכוני סוכן.
 *
 * עדכון הוא הרצת קוד שרירותי בהרשאות SYSTEM על מחשב מוגן — הסמכות
 * החזקה במערכת. כל בדיקה כאן היא כלל בטיחות, לא התנהגות.
 */

import { randomUUID } from "node:crypto";
import pg from "pg";
import { createPool, sslFor, withPlatform } from "../src/db/client.ts";
import { LocalSigner, verifyEnvelope } from "../src/crypto/signing.ts";
import { buildUpdateOffer } from "../src/updates/offer.ts";
import {
  compareVersions,
  decideUpdate,
  parseVersion,
  type Release,
} from "../src/updates/decide.ts";
import { loadConfig } from "../src/config.ts";

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

function release(version: string, over: Partial<Release> = {}): Release {
  return {
    version,
    parsed: parseVersion(version)!,
    downloadUrl: `https://cdn.safeme.test/${version}.exe`,
    sha256: "a".repeat(64),
    sizeBytes: 8_000_000,
    minFrom: { major: 0, minor: 0, patch: 0 },
    rolloutPercent: 100,
    ...over,
  };
}

const always = () => 0;

async function main(): Promise<void> {
  // ─────────────────────────────────────────── השוואת גרסאות
  section("1 · השוואת גרסאות");

  check(parseVersion("1.2.3")?.minor === 2, "פענוח semver");
  check(parseVersion("1.2") === null, "גרסה חלקית נדחית");
  check(parseVersion("v1.2.3") === null, "קידומת v נדחית");

  // הטעות הקלאסית: השוואה כטקסט
  check(
    compareVersions(parseVersion("1.10.0")!, parseVersion("1.9.0")!) > 0,
    "1.10.0 גדול מ-1.9.0",
    "השוואה לקסיקוגרפית הייתה הופכת את הסדר",
  );

  // ───────────────────────────────── הגנה מפני שדרוג לאחור
  section("2 · שדרוג לאחור");

  check(
    decideUpdate("1.5.0", [release("1.4.0")], always).offer === null,
    "גרסה ישנה יותר לא מוצעת",
    'זו דרך תקיפה מלאה: "עדכון" לגרסה עם פרצה ידועה',
  );

  check(
    decideUpdate("1.5.0", [release("1.5.0")], always).offer === null,
    "אותה גרסה לא מוצעת",
  );

  check(
    decideUpdate("1.5.0", [release("1.5.1")], always).offer?.version === "1.5.1",
    "גרסה חדשה יותר כן מוצעת",
  );

  // ───────────────────────────────────────── קפיצה גדולה מדי
  section("3 · קפיצה מעל שינויי מבנה");

  const bigJump = decideUpdate(
    "1.0.0",
    [release("3.0.0", { minFrom: { major: 2, minor: 0, patch: 0 } })],
    always,
  );
  check(
    bigJump.offer === null && bigJump.reason === "too_old_to_jump",
    "סוכן ישן מדי אינו קופץ ישירות",
    "שדרוג שמדלג על שינויי מבנה הוא מה שהופך מחשב ללבנה",
  );

  check(
    decideUpdate(
      "2.1.0",
      [release("3.0.0", { minFrom: { major: 2, minor: 0, patch: 0 } })],
      always,
    ).offer?.version === "3.0.0",
    "סוכן חדש מספיק כן קופץ",
  );

  // ─────────────────────────────────────────── הפצה מדורגת
  section("4 · הפצה מדורגת");

  const staged = [release("2.0.0", { rolloutPercent: 10 })];

  check(decideUpdate("1.0.0", staged, () => 5).offer !== null, "דלי 5 בהפצה של 10 אחוז — מקבל");
  check(decideUpdate("1.0.0", staged, () => 10).offer === null, "דלי 10 — לא מקבל");
  check(decideUpdate("1.0.0", staged, () => 99).offer === null, "דלי 99 — לא מקבל");

  check(
    decideUpdate("1.0.0", [release("2.0.0", { rolloutPercent: 0 })], () => 0).offer === null,
    "הפצה של אפס אחוז לא מגיעה לאיש",
    "כך נכנסת גרסה למערכת בלי להתפרסם",
  );

  // ─────────────────────────────────────── בחירה מבין כמה
  section("5 · בחירה מבין כמה גרסאות");

  const many = [release("3.0.0"), release("2.5.0"), release("2.0.0")];
  check(decideUpdate("1.0.0", many, always).offer?.version === "3.0.0", "נבחרת החדשה ביותר");

  // כשהחדשה חסומה, יורדים לזו שאחריה ולא נעצרים
  const blocked = [
    release("3.0.0", { minFrom: { major: 2, minor: 5, patch: 0 } }),
    release("2.5.0"),
  ];
  check(
    decideUpdate("2.0.0", blocked, always).offer?.version === "2.5.0",
    "כשהחדשה חסומה, מוצעת הבאה בתור",
    "אחרת מחשב ישן היה נתקע לנצח בגרסה שלו",
  );

  check(
    decideUpdate("1.0.0", [], always).offer === null,
    "בלי גרסאות אין הצעה",
  );
  check(
    decideUpdate("לא-גרסה", [release("2.0.0")], always).offer === null,
    "גרסה נוכחית משובשת — לא מציעים כלום",
  );

  // ─────────────────────────── חתימה, קשירה, והפרדת המפתח
  section("6 · החתימה, מול בסיס נתונים אמיתי");

  const config = loadConfig({ ...process.env, NODE_ENV: "test" });
  const pool = createPool({ connectionString: config.DATABASE_URL_APP });

  const updateSigner = LocalSigner.ephemeral(`poc-update-${randomUUID().slice(0, 8)}`);
  const policySigner = LocalSigner.ephemeral(`poc-policy-${randomUUID().slice(0, 8)}`);

  const deviceId = randomUUID();
  const hwidHash = "68DA741869148613";

  // פרסום גרסה הוא פעולת פלטפורמה, ולכן נעשה כבעל הסכמה.
  // ל-safeme_app יש הרשאת קריאה בלבד על agent_releases — וזה מכוון:
  // בקשת HTTP לעולם לא אמורה להיות מסוגלת לפרסם קוד להרצה.
  const adminUrl = process.env["DATABASE_URL"];

  if (!adminUrl) {
    console.error("חסר DATABASE_URL. פרסום גרסה דורש את בעל הסכמה.");
    process.exit(1);
  }

  const admin = new pg.Client({ connectionString: adminUrl, ssl: sslFor(adminUrl) });
  await admin.connect();

  await admin.query("DELETE FROM agent_releases");
  await admin.query(
    `INSERT INTO agent_releases
       (version, v_major, v_minor, v_patch, download_url, sha256, size_bytes,
        rollout_percent)
     VALUES ('9.9.9', 9, 9, 9, 'https://cdn.safeme.test/9.9.9.exe',
             decode(repeat('ab', 32), 'hex'), 9000000, 100)`,
  );

  const envelope = await withPlatform(pool, SYSTEM, (tx) =>
    buildUpdateOffer(tx, updateSigner, { deviceId, hwidHash }, "1.0.0", new Date(),
      "https://api.safeme.test"),
  );

  check(envelope !== null, "הצעה נבנתה");

  const updatePem = await updateSigner.publicKeyPem();
  const policyPem = await policySigner.publicKeyPem();

  check(verifyEnvelope(envelope!, updatePem), "ההצעה מאומתת במפתח העדכונים");

  check(
    !verifyEnvelope(envelope!, policyPem),
    "ההצעה **אינה** מאומתת במפתח המדיניות",
    "זו כל ההפרדה: מי שחותם מדיניות אינו יכול להריץ קוד",
  );

  const payload = JSON.parse(
    Buffer.from(envelope!.payload, "base64url").toString("utf8"),
  ) as Record<string, unknown>;

  check(payload["version"] === "9.9.9", "הגרסה נכונה", String(payload["version"]));
  check(
    payload["downloadUrl"] === "https://api.safeme.test/api/v1/update/9.9.9",
    "ההורדה עוברת דרך מארח SafeMe, לא ישירות מ-GitHub",
    "מחשב מסונן מגיע לשרת אך לא בהכרח ל-github.com",
  );
  check(
    payload["hwidHash"] === hwidHash,
    "ההצעה קשורה למחשב",
    "בלי זה, הצעה שנלכדה משמשת כהיתר עצירה לכל מחשב אחר",
  );

  const issued = new Date(payload["issuedUtc"] as string);
  const expires = new Date(payload["expiresUtc"] as string);
  const minutes = (expires.getTime() - issued.getTime()) / 60_000;

  check(minutes === 30, "תוקף קצר", `${minutes} דקות`);

  // בלי baseUrl (סוכן ישן, או Host פסול) ההצעה נופלת חזרה לכתובת
  // המאגר, כדי שלא תישבר.
  const fallback = await withPlatform(pool, SYSTEM, (tx) =>
    buildUpdateOffer(tx, updateSigner, { deviceId, hwidHash }, "1.0.0", new Date(), null),
  );
  const fallbackPayload = JSON.parse(
    Buffer.from(fallback!.payload, "base64url").toString("utf8"),
  ) as Record<string, unknown>;
  check(
    fallbackPayload["downloadUrl"] === "https://cdn.safeme.test/9.9.9.exe",
    "בלי baseUrl נשמרת כתובת המאגר",
  );

  // ההרשאה עצמה היא חלק מההגנה, ולכן נבדקת
  let writeDenied = false;

  try {
    await withPlatform(pool, SYSTEM, (tx) =>
      tx.query("UPDATE agent_releases SET rollout_percent = 100"),
    );
  } catch {
    writeDenied = true;
  }

  check(
    writeDenied,
    "משתמש האפליקציה אינו יכול לפרסם או לשנות גרסה",
    "בקשת HTTP לעולם לא אמורה להיות מסוגלת לפרסם קוד להרצה",
  );

  // גרסה שנפסלה יורדת מהמדף מיד
  await admin.query(
    "UPDATE agent_releases SET revoked_at = now(), revoked_reason = 'נמצאה פגומה'",
  );

  const afterRevoke = await withPlatform(pool, SYSTEM, (tx) =>
    buildUpdateOffer(tx, updateSigner, { deviceId, hwidHash }, "1.0.0", new Date(),
      "https://api.safeme.test"),
  );

  check(afterRevoke === null, "גרסה שנפסלה אינה מוצעת יותר");

  await admin.end();
  await pool.end();

  console.log(`\n${"═".repeat(64)}`);
  console.log(`עברו ${passed} · נכשלו ${failed}`);
  console.log("═".repeat(64));

  process.exit(failed === 0 ? 0 : 1);
}

await main();
