/**
 * הורדת המתקין.
 *
 * הכתובת נושאת את שם הקובץ, ושם הקובץ נושא את אסימון ההתקנה. שתי
 * הדרישות נבדקות כאן: שהשם יוצא נכון מהשרת, ושאסימון פסול לא מוריד
 * קובץ.
 *
 * הקובץ ה"מרוחק" מוגש מכתובת data, ולכן הבדיקה אינה נוגעת ברשת.
 */

import { randomBytes, randomUUID } from "node:crypto";
import pg from "pg";

import { buildApp } from "../src/app.ts";
import { createPool, sslFor, withPlatform } from "../src/db/client.ts";
import { LocalSigner } from "../src/crypto/signing.ts";
import { hashEnrollToken } from "../src/auth/device-token.ts";
import { fileNameForToken } from "../src/installer/filename.ts";
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

/** תוכן המתקין המדומה. עברית כדי לוודא שהבתים עוברים כמו שהם. */
const PAYLOAD = Buffer.from("SafeMe · מתקין מדומה · לא קובץ אמיתי", "utf8");
const DATA_URL =
  "data:application/octet-stream;base64," + PAYLOAD.toString("base64");

const FLOOR = { mode: "enforce", onRedAction: "lockout", minScoreForGreen: 85 };

async function main(): Promise<void> {
  const config = loadConfig({
    ...process.env,
    NODE_ENV: "test",
    DEVICE_TOKEN_SECRET: process.env["DEVICE_TOKEN_SECRET"] ?? randomBytes(32).toString("hex"),
  });

  const pool = createPool({ connectionString: config.DATABASE_URL_APP });
  const u = () => randomUUID().slice(0, 8);

  const app = await buildApp({
    config,
    pool,
    signer: LocalSigner.ephemeral(`poc-policy-${u()}`),
    looseningSigner: LocalSigner.ephemeral(`poc-loosening-${u()}`),
    uninstallSigner: LocalSigner.ephemeral(`poc-uninstall-${u()}`),
    updateSigner: LocalSigner.ephemeral(`poc-update-${u()}`),
    logger: false,
  });

  // פרסום גרסה הוא פעולת פלטפורמה ולכן נעשה כבעל הסכמה
  const adminUrl = process.env["DATABASE_URL"];

  if (!adminUrl) {
    console.error("חסר DATABASE_URL. פרסום גרסה דורש את בעל הסכמה.");
    process.exit(1);
  }

  const admin = new pg.Client({ connectionString: adminUrl, ssl: sslFor(adminUrl) });
  await admin.connect();
  await admin.query("DELETE FROM agent_releases");

  const tenantId = await withPlatform(pool, SYSTEM, async (tx) => {
    const t = await tx.query<{ id: string }>(
      `INSERT INTO tenants (type, name, trial_started_at, trial_ends_at)
       VALUES ('family', 'משפחת הורדה', now(), now() + interval '30 days')
       RETURNING id`,
    );
    return t.rows[0]!.id;
  });

  /** מנפיק אסימון עם מצב נתון, ומחזיר את הגולמי. */
  async function issue(options: {
    expiresInDays?: number;
    revoked?: boolean;
    maxUses?: number;
    uses?: number;
  } = {}): Promise<string> {
    const raw = `ENR-${randomBytes(12).toString("hex").toUpperCase()}`;

    await withPlatform(pool, SYSTEM, async (tx) => {
      await tx.query(
        `INSERT INTO enroll_tokens
           (tenant_id, token_hash, install_profile, enforcement_mode, policy_floor,
            max_uses, uses, expires_at, revoked_at)
         VALUES ($1, $2, 'family_child', 'enforce', $3, $4, $5,
                 now() + make_interval(days => $6), $7)`,
        [
          tenantId,
          hashEnrollToken(raw),
          JSON.stringify(FLOOR),
          options.maxUses ?? 1,
          options.uses ?? 0,
          options.expiresInDays ?? 14,
          options.revoked ? new Date() : null,
        ],
      );
    });

    return raw;
  }

  const get = (fileName: string) =>
    app.fastify.inject({ method: "GET", url: `/d/${fileName}` });

  // ───────────────────────────────────── בלי גרסה מפורסמת
  section("1 · כשאין גרסה מפורסמת");

  const early = await get(fileNameForToken(await issue()));

  check(early.statusCode === 503, "מוחזרת שגיאה ברורה ולא קובץ ריק", `סטטוס ${early.statusCode}`);
  check(
    (early.json() as { error: string }).error.includes("גרסה זמינה"),
    "ההודעה מסבירה מה חסר",
    (early.json() as { error: string }).error,
  );

  // ───────────────────────────────────── הורדה תקינה
  section("2 · הורדה תקינה");

  await admin.query(
    `INSERT INTO agent_releases
       (version, v_major, v_minor, v_patch, download_url, sha256, size_bytes, rollout_percent)
     VALUES ('1.0.0', 1, 0, 0, $1, decode(repeat('ab', 32), 'hex'), $2, 100)`,
    [DATA_URL, PAYLOAD.length],
  );

  const token = await issue();
  const fileName = fileNameForToken(token);
  const ok = await get(fileName);

  check(ok.statusCode === 200, "הקובץ הוגש", `סטטוס ${ok.statusCode}`);

  check(
    ok.headers["content-disposition"] === `attachment; filename="${fileName}"`,
    "שם הקובץ נקבע על ידי השרת",
    String(ok.headers["content-disposition"]),
  );

  check(
    String(ok.headers["content-disposition"]).includes(token),
    "והוא נושא את אסימון ההתקנה",
    "זה מה שמאפשר למתקין לדעת לאיזה חשבון להתחבר",
  );

  check(ok.rawPayload.equals(PAYLOAD), "התוכן עבר בלי שינוי", `${ok.rawPayload.length} בתים`);
  check(ok.headers["x-safeme-version"] === "1.0.0", "הגרסה מדווחת בכותרת");

  check(
    String(ok.headers["cache-control"]).includes("no-store"),
    "התשובה אינה נשמרת במטמון",
    "כל לקוח מקבל שם קובץ משלו",
  );

  // ───────────────────────────────────── אסימונים פסולים
  section("3 · אסימונים שאין להוריד איתם");

  const expired = await get(fileNameForToken(await issue({ expiresInDays: -1 })));
  check(expired.statusCode === 410, "אסימון שפג נדחה", `סטטוס ${expired.statusCode}`);
  check(
    (expired.json() as { error: string }).error.includes("פג"),
    "וההודעה מסבירה מה לעשות",
    (expired.json() as { error: string }).error,
  );

  const revoked = await get(fileNameForToken(await issue({ revoked: true })));
  check(revoked.statusCode === 410, "אסימון שבוטל נדחה");

  const used = await get(fileNameForToken(await issue({ maxUses: 2, uses: 2 })));
  check(used.statusCode === 410, "אסימון שנוצל במלואו נדחה");

  const stillGood = await get(fileNameForToken(await issue({ maxUses: 3, uses: 1 })));
  check(stillGood.statusCode === 200, "אסימון עם שימושים שנותרו עדיין עובד");

  // ───────────────────────────────────── קישורים פגומים
  section("4 · קישורים שאינם תקינים");

  const unknown = await get(fileNameForToken(`ENR-${randomBytes(12).toString("hex").toUpperCase()}`));
  check(unknown.statusCode === 404, "אסימון שלא הונפק מעולם — 404");

  check(
    JSON.stringify(unknown.json()) === JSON.stringify({ error: "קישור הורדה אינו תקין" }),
    "אותה תשובה בדיוק כמו לקישור פגום",
    "הבחנה ביניהם הייתה מאפשרת לבדוק אילו אסימונים הונפקו",
  );

  for (const bad of ["SafeMe-Setup.exe", "SafeMe-Setup-ENR-A1B2.exe", "x.exe"]) {
    const r = await get(bad);
    check(r.statusCode === 404, `שם ללא אסימון תקין נדחה — ${bad}`);
  }

  // ───────────────────────────────────── סובלנות לשם שהדפדפן שינה
  section("5 · שם שהדפדפן שינה");

  const dup = await get(fileName.replace(".exe", " (1).exe"));
  check(dup.statusCode === 200, "סיומת כפילות עדיין עובדת", "הורדה חוזרת באותו דפדפן");

  const lower = await get(fileName.toLowerCase());
  check(lower.statusCode === 200, "אותיות קטנות עדיין עובדות");

  check(
    String(dup.headers["content-disposition"]) === `attachment; filename="${fileName}"`,
    "והשם המוחזר מנורמל בחזרה",
    "כדי שהקובץ הנשמר יהיה תקין גם אם הקישור לא היה",
  );

  await admin.end();
  await app.close();
  await pool.end();

  console.log(`\n${"═".repeat(64)}`);
  console.log(`עברו ${passed} · נכשלו ${failed}`);
  console.log("═".repeat(64));

  process.exit(failed === 0 ? 0 : 1);
}

await main();
