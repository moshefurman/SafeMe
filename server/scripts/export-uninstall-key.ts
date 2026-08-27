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

import pg from "pg";

import { createPool, withPlatform } from "../src/db/client.ts";

const SYSTEM = { userId: "system", reason: "ייצוא מפתח ציבורי" };

function fail(message: string): never {
  console.error(message);
  process.exit(1);
}

async function main(): Promise<void> {
  const url = process.env["DATABASE_URL"];

  if (!url) fail("חסר DATABASE_URL.");

  const pool: pg.Pool = createPool({ connectionString: url });

  try {
    const key = await withPlatform(pool, SYSTEM, async (tx) => {
      /*
       * המפתח הפעיל בלבד.
       *
       * מפתח שהוצא משימוש עדיין מאמת חתימות ישנות, אבל הטבעתו
       * במתקין חדש הייתה קושרת כל מחשב שיותקן מעכשיו למפתח
       * שכבר אינו בשימוש — ואת קוד ההסרה המוקד ייצר בחדש.
       */
      const r = await tx.query<{ kid: string; public_pem: string }>(
        `SELECT kid, public_pem
           FROM signing_keys
          WHERE purpose = 'uninstall' AND retired_at IS NULL
          ORDER BY created_at DESC
          LIMIT 1`,
      );

      return r.rows[0] ?? null;
    });

    if (key === null) {
      fail(
        "לא נמצא מפתח הסרה פעיל.\n" +
          "המפתח נרשם בעליית השרת. יש לוודא שהשרת עלה לפחות פעם אחת " +
          "מול בסיס הנתונים הזה.",
      );
    }

    // ה-PEM ל-stdout, וכל השאר ל-stderr. כך אפשר להפנות את הפלט
    // לקובץ בלי שההודעות ייכנסו לתוכו.
    console.error(`מפתח ${key.kid}`);
    console.log(key.public_pem.trim());
  } finally {
    await pool.end();
  }
}

main().catch((error: unknown) => {
  fail(error instanceof Error ? error.message : String(error));
});
