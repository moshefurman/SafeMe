/**
 * מייצא את המפתח הציבורי לאימות קודי הסרה.
 *
 * למה זה נחוץ: במסלול הרגיל המפתח מגיע למכשיר מהשרת, בתשובת
 * הרישום. בהתקנה ללא חשבון אין רישום — ולכן המפתח חייב להיות מוטבע
 * במתקין עצמו, כבר בשלב האריזה.
 *
 * בלעדיו, מחשב שנחסם לחלוטין היה נשאר בלי שום דרך לאמת קוד הסרה.
 * לא מהמוקד, לא בתשלום, ולא בכלל. הסקריפט הזה הוא מה שמונע את זה.
 *
 * המפתח ציבורי, ולכן הפצתו אינה חושפת דבר. מה שחותם הוא המפתח
 * הפרטי, והוא נשאר ב-KMS ולעולם אינו יוצא ממנו.
 *
 * שימוש:
 *   node scripts/export-uninstall-key.ts > uninstall.pem
 *   .\build\pack.ps1 -UninstallKeyPem uninstall.pem
 */

import { writeFileSync } from "node:fs";

import pg from "pg";

import { sslFor } from "../src/db/client.ts";

function fail(message: string): never {
  console.error(message);
  process.exit(1);
}

async function main(): Promise<void> {
  /*
   * מתחבר כבעל הסכמה, כמו שאר סקריפטי התפעול.
   *
   * createPool מיועד לאפליקציה ומחייב את התפקיד safeme_app, כי שם
   * RLS הוא מה שמבודד בין דיירים. signing_keys היא טבלה גלובלית
   * בלי tenant_id, והקריאה כאן היא פעולת תפעול חד-פעמית — אותו
   * מסלול שבו רצים migrate ו-publish-release.
   */
  const url = process.env["DATABASE_URL"];

  if (!url) fail("חסר DATABASE_URL. ייצוא המפתח דורש את בעל הסכמה.");

  const client = new pg.Client({ connectionString: url, ssl: sslFor(url) });

  await client.connect();

  try {
    /*
     * המפתח הפעיל בלבד.
     *
     * מפתח שהוצא משימוש עדיין מאמת חתימות ישנות, אבל הטבעתו
     * במתקין חדש הייתה קושרת כל מחשב שיותקן מעכשיו למפתח שכבר
     * אינו בשימוש — ואת קוד ההסרה המוקד ייצר בחדש.
     */
    const r = await client.query<{ kid: string; public_pem: string }>(
      `SELECT kid, public_pem
         FROM signing_keys
        WHERE purpose = 'uninstall' AND retired_at IS NULL
        ORDER BY created_at DESC
        LIMIT 1`,
    );

    const key = r.rows[0];

    if (!key) {
      console.error("לא נמצא מפתח הסרה פעיל.");

      fail(
        "המפתח נרשם בעליית השרת. יש לוודא שהשרת עלה לפחות פעם אחת " +
          "מול בסיס הנתונים הזה.",
      );
    }

    const pem = `${key.public_pem.trim()}
`;
    const index = process.argv.indexOf("--out");
    const out = index >= 0 && index + 1 < process.argv.length
      ? process.argv[index + 1]!
      : null;

    if (out === null) {
      // בלי --out: ה-PEM ל-stdout וההודעות ל-stderr, כדי שהפניית
      // פלט תעבוד בקליפות שכן כותבות UTF-8.
      console.error(`מפתח ${key.kid}`);
      console.error("להפניה בטוחה בכל קליפה: --out <קובץ>");
      process.stdout.write(pem);

      return;
    }

    writeFileSync(out, pem, { encoding: "utf8" });

    console.error(`מפתח ${key.kid} נכתב ל-${out}`);
  } finally {
    await client.end();
  }
}

main().catch((error: unknown) => {
  fail(error instanceof Error ? error.message : String(error));
});
