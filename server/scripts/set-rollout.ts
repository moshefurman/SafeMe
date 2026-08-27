/**
 * משנה את אחוז ההפצה של גרסה, או פוסל אותה.
 *
 * שתי הפעולות היחידות שמבצעים על גרסה שכבר פורסמה. תוכן הגרסה
 * עצמו אינו משתנה לעולם — מכשיר שהוריד קובץ ואימת את סכום הביקורת
 * שלו לא אמור לגלות מאוחר יותר שהקובץ באותה כתובת הוא אחר.
 *
 *   node scripts/set-rollout.ts --version 1.0.0 --rollout 10
 *   node scripts/set-rollout.ts --version 1.0.0 --revoke "נמצא פגם"
 */

import pg from "pg";
import { sslFor } from "../src/db/client.ts";

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

  if (!url) fail("חסר DATABASE_URL. שינוי גרסה דורש את בעל הסכמה.");

  const version = arg("version") ?? fail("חסר --version");
  const revoke = arg("revoke");
  const rolloutArg = arg("rollout");

  if (revoke === null && rolloutArg === null) {
    fail("יש לציין --rollout או --revoke");
  }

  const client = new pg.Client({ connectionString: url, ssl: sslFor(url) });
  await client.connect();

  try {
    if (revoke !== null) {
      const r = await client.query(
        `UPDATE agent_releases
            SET revoked_at = now(), revoked_reason = $2, rollout_percent = 0
          WHERE version = $1 AND revoked_at IS NULL`,
        [version, revoke],
      );

      if (r.rowCount === 0) fail(`גרסה ${version} אינה קיימת או כבר נפסלה.`);

      console.log(`\n  גרסה ${version} נפסלה: ${revoke}`);
      console.log("  היא לא תוצע יותר לאיש, ולא תהיה זמינה להורדה.\n");

      return;
    }

    const rollout = Number(rolloutArg);

    if (!Number.isInteger(rollout) || rollout < 0 || rollout > 100) {
      fail("rollout חייב להיות מספר שלם בין 0 ל-100");
    }

    const r = await client.query<{ rollout_percent: number }>(
      `UPDATE agent_releases
          SET rollout_percent = $2
        WHERE version = $1 AND revoked_at IS NULL
      RETURNING rollout_percent`,
      [version, rollout],
    );

    if (r.rowCount === 0) fail(`גרסה ${version} אינה קיימת או שנפסלה.`);

    console.log(`\n  גרסה ${version}: אחוז ההפצה הוא עכשיו ${rollout}.`);

    if (rollout > 0) {
      console.log("");
      console.log("  הדלי נגזר ממזהה המכשיר ומהגרסה ולכן יציב: אותם מכשירים");
      console.log("  שנכללו יישארו כלולים גם כשתעלה את האחוז, ולא יוחלפו");
      console.log("  באחרים באמצע הורדה.");
    }

    console.log("");
  } finally {
    await client.end();
  }
}

await main();
