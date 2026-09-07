/**
 * רושם גרסת סוכן בטבלת agent_releases.
 *
 * זו פעולת פלטפורמה ולכן היא רצה כבעל הסכמה, ולא דרך ה-API.
 * ל-safeme_app יש הרשאת קריאה בלבד על הטבלה, במכוון: בקשת HTTP
 * לעולם לא אמורה להיות מסוגלת לפרסם קוד להרצה על מחשבי לקוחות.
 *
 *   node scripts/publish-release.ts \
 *     --version 1.0.0 \
 *     --url https://github.com/.../SafeMe-Setup.exe \
 *     --sha256 <hex> \
 *     --size 38150767
 *
 * אחוז ההפצה מתחיל ב-0 כברירת מחדל.
 *
 * זה מכוון: גרסה נכנסת למערכת ואפשר להוריד אותה מהאתר, אך היא אינה
 * נדחפת לאיש. העלאת האחוז היא החלטה נפרדת, ובה מתחילה ההפצה.
 */

import { createHash } from "node:crypto";
import pg from "pg";

import { sslFor } from "../src/db/client.ts";
import { parseVersion } from "../src/updates/decide.ts";

function arg(name: string): string | null {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1]! : null;
}

function fail(message: string): never {
  console.error(`\n  ${message}\n`);
  process.exit(1);
}

async function main(): Promise<void> {
  const url = process.env["DATABASE_URL"];

  if (!url) fail("חסר DATABASE_URL. פרסום גרסה דורש את בעל הסכמה.");

  const version = arg("version") ?? fail("חסר --version");
  const downloadUrl = arg("url") ?? fail("חסר --url");
  const sha256 = (arg("sha256") ?? fail("חסר --sha256")).trim().toLowerCase();
  const size = Number(arg("size") ?? fail("חסר --size"));

  const parsed = parseVersion(version);

  if (parsed === null) fail(`גרסה חייבת להיות בפורמט x.y.z — התקבל: ${version}`);
  if (!/^[0-9a-f]{64}$/.test(sha256)) fail("sha256 חייב להיות 64 תווים הקסדצימליים");
  if (!Number.isFinite(size) || size <= 0) fail("size חייב להיות מספר חיובי");

  // מאיזו גרסה מותר לקפוץ. ברירת המחדל היא מאפס — לגרסה ראשונה
  // אין ממה לדלג, ואין שינויי מבנה שנעשו בדרך.
  const minFrom = parseVersion(arg("min-from") ?? "0.0.0")
    ?? fail("min-from חייב להיות בפורמט x.y.z");

  const rollout = Number(arg("rollout") ?? "0");

  if (!Number.isInteger(rollout) || rollout < 0 || rollout > 100) {
    fail("rollout חייב להיות מספר שלם בין 0 ל-100");
  }

  const client = new pg.Client({ connectionString: url, ssl: sslFor(url) });
  await client.connect();

  try {
    const who = await client.query<{ user: string }>("SELECT current_user AS user");

    const existing = await client.query<{ version: string }>(
      "SELECT version FROM agent_releases WHERE version = $1",
      [version],
    );

    if (existing.rowCount! > 0) {
      fail(
        `גרסה ${version} כבר רשומה. גרסה שפורסמה אינה משתנה — ` +
          "יש לפרסם גרסה חדשה, או לפסול את הקיימת.",
      );
    }

    await client.query(
      `INSERT INTO agent_releases
         (version, v_major, v_minor, v_patch, channel,
          download_url, sha256, size_bytes,
          min_from_major, min_from_minor, min_from_patch,
          rollout_percent, notes)
       VALUES ($1, $2, $3, $4, 'stable', $5, decode($6, 'hex'), $7, $8, $9, $10, $11, $12)`,
      [
        version,
        parsed.major,
        parsed.minor,
        parsed.patch,
        downloadUrl,
        sha256,
        size,
        minFrom.major,
        minFrom.minor,
        minFrom.patch,
        rollout,
        arg("notes"),
      ],
    );

    console.log("");
    console.log(`  גרסה ${version} פורסמה, כמשתמש ${who.rows[0]!.user}.`);
    console.log("");
    console.log(`    כתובת       : ${downloadUrl}`);
    console.log(`    גודל        : ${(size / 1024 / 1024).toFixed(1)} מגה`);
    console.log(`    אחוז הפצה   : ${rollout}`);
    console.log("");

    if (rollout === 0) {
      console.log("  אחוז ההפצה הוא אפס: הגרסה זמינה להורדה מהאתר,");
      console.log("  אך אינה נדחפת לאף מחשב קיים.");
      console.log("");
      console.log("  להתחלת הפצה מדורגת:");
      /*
       * הנתיב יחסית ל-server, כי שם הפקודה הזו רצה בפועל: ה-Shell
       * של Render עולה ב-/app שהוא שורש ה-server, ואותו דבר מקומית.
       * רמז שהניח שורש-ריפו (node server\scripts\…) נתן MODULE_NOT_FOUND
       * למי שהריץ מ-server. לוכסן קדימה עובד גם ב-Windows וגם ב-Render.
       */
      console.log(`    node scripts/set-rollout.ts --version ${version} --rollout 100`);
      console.log("");
    }
  } finally {
    await client.end();
  }
}

/** מוודא שהתוכן במקום תואם למה שנרשם. משמש בבדיקה ידנית. */
export function sha256Of(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

await main();
