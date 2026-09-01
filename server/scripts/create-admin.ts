/**
 * יוצר מנהל פלטפורמה.
 *
 * חשבון של דייר אינו יכול לנהל ספקי סינון, ובצדק: מי שמגדיר מה
 * נחשב "ספק מאושר" מגדיר בפועל מה נחשב חיבור מסונן, ודייר שיכול
 * לעשות זאת יכול לאשר לעצמו כל חיבור.
 *
 * שני אילוצים בסכימה מונעים קיצור דרך, ושניהם נכונים:
 *
 *   users_role_scope           תפקיד פלטפורמה חייב tenant_id ריק
 *   users_platform_requires_mfa  חשבון פעיל חייב אימות דו-שלבי
 *
 * ולכן אי אפשר פשוט לקדם חשבון קיים שיש לו דייר. הסקריפט יוצר
 * חשבון נפרד, במצב invited — שהוא המצב היחיד שמותר לפני שנרשם
 * אימות דו-שלבי. הרישום עצמו קורה בכניסה הראשונה בפורטל.
 *
 * שימוש:
 *   node scripts/create-admin.ts --email you@example.com
 *   node scripts/create-admin.ts --email you@example.com --reset-password
 *
 * ---
 *
 * למה יש כאן איפוס סיסמה בכלל.
 *
 * אין בפורטל מסלול "שכחתי סיסמה", ובניית אחד דורשת דואר יוצא
 * שעדיין אינו מוגדר. עד אז מנהל פלטפורמה ששכח את הסיסמה נעול
 * מחוץ למסכים שרק הוא רואה, בלי שום דרך חזרה — והסקריפט הזה,
 * שרץ ממילא כבעל הסכמה, הוא המקום הנכון לפתוח אותה.
 *
 * גם אחרי שיהיה מסלול איפוס במייל, זה יישאר הגיבוי היחיד למצב
 * שבו הדואר עצמו שבור.
 *
 * מה שהוא **אינו** נוגע בו: אימות דו-שלבי. סיסמה חדשה בלי הקוד
 * אינה מספיקה, וזה בדיוק העניין — מי שמשיג גישה למסד לא מקבל
 * בכך את החשבון.
 */

import { randomBytes } from "node:crypto";

import pg from "pg";

import { sslFor } from "../src/db/client.ts";
import { hashPassword } from "../src/auth/password.ts";

function arg(name: string): string | null {
  const i = process.argv.indexOf(`--${name}`);

  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1]! : null;
}

function fail(message: string): never {
  console.error(message);
  process.exit(1);
}

async function main(): Promise<void> {
  const url = process.env["DATABASE_URL"];

  if (!url) fail("חסר DATABASE_URL. יצירת מנהל דורשת את בעל הסכמה.");

  const email = (arg("email") ?? fail("חסר --email")).trim().toLowerCase();

  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) fail(`כתובת לא תקינה: ${email}`);

  /*
   * הסיסמה נוצרת כאן ולא מתקבלת כפרמטר.
   *
   * סיסמה בשורת פקודה נשמרת בהיסטוריית הקליפה, ובמקרה הזה היא
   * סיסמה של החשבון החזק ביותר במערכת.
   */
  const password = randomBytes(15).toString("base64url");

  const client = new pg.Client({ connectionString: url, ssl: sslFor(url) });

  await client.connect();

  try {
    const existing = await client.query<{ role: string; tenant_id: string | null }>(
      "SELECT role, tenant_id FROM users WHERE email = $1",
      [email],
    );

    if (existing.rows[0]) {
      const row = existing.rows[0];

      if (row.role === "platform_admin") {
        if (!process.argv.includes("--reset-password")) {
          fail(
            `${email} כבר מנהל פלטפורמה.
` +
              "לאיפוס סיסמה: הוסף --reset-password",
          );
        }

        /*
         * בלי updated_at: אין עמודה כזו ב-users.
         *
         * היא קיימת ברוב הטבלאות האחרות, וזה בדיוק סוג ההנחה
         * שנופלת בזמן ריצה ולא בהידור — pg מקבל SQL כמחרוזת.
         */
        const reset = await client.query(
          "UPDATE users SET password_hash = $2 WHERE email = $1",
          [email, await hashPassword(password)],
        );

        if (reset.rowCount !== 1) fail(`עדכון הסיסמה לא תפס עבור ${email}.`);

        console.log("");
        console.log("  הסיסמה אופסה.");
        console.log("");
        console.log(`    אימייל : ${email}`);
        console.log(`    סיסמה  : ${password}`);
        console.log("");
        console.log("  הסיסמה מוצגת פעם אחת בלבד ואינה נשמרת בשום מקום.");
        console.log("  האימות הדו-שלבי לא שונה. אם הוא רשום, יידרש גם קוד.");
        console.log("");

        return;
      }

      fail(
        `${email} כבר קיים כ-${row.role}${row.tenant_id ? " של דייר" : ""}.\n` +
          "תפקיד פלטפורמה מחייב חשבון בלי דייר, ולכן יש להשתמש בכתובת אחרת.",
      );
    }

    /*
     * status = 'invited' ולא 'active'.
     *
     * האילוץ בסכימה מתיר תפקיד פלטפורמה בלי אימות דו-שלבי רק
     * כשהחשבון אינו פעיל. הוא נעשה פעיל מעצמו ברישום ה-MFA
     * בכניסה הראשונה — וזה הסדר הנכון: אין רגע שבו קיים חשבון
     * פלטפורמה פעיל בלי אימות שני.
     */
    await client.query(
      `INSERT INTO users (tenant_id, email, password_hash, display_name, role, status)
       VALUES (NULL, $1, $2, $3, 'platform_admin', 'invited')`,
      [email, await hashPassword(password), arg("name") ?? "מנהל פלטפורמה"],
    );

    console.log("");
    console.log("  נוצר מנהל פלטפורמה.");
    console.log("");
    console.log(`    אימייל : ${email}`);
    console.log(`    סיסמה  : ${password}`);
    console.log("");
    console.log("  הסיסמה מוצגת פעם אחת בלבד ואינה נשמרת בשום מקום.");
    console.log("  בכניסה הראשונה תתבקש לרשום אימות דו-שלבי — עד שתעשה זאת");
    console.log("  החשבון אינו פעיל, וזה מכוון.");
    console.log("");
  } finally {
    await client.end();
  }
}

main().catch((error: unknown) => {
  fail(error instanceof Error ? error.message : String(error));
});
