/**
 * קובע סיסמה ל-safeme_app ומרכיב את מחרוזת החיבור של האפליקציה.
 *
 * קיים כדי לא לדרוש psql. הפעולה עצמה היא שורת SQL אחת, אבל היא
 * נופלת בדיוק בנקודה שקל לטעות בה: להרכיב ביד מחרוזת חיבור, עם
 * סיסמה בתוך URL, ולהחליף בה את המשתמש הנכון.
 *
 *   node scripts/set-app-password.ts
 *   node scripts/set-app-password.ts --password <סיסמה קיימת>
 */

import { randomBytes } from "node:crypto";
import pg from "pg";
import { APP_ROLE, sslFor } from "../src/db/client.ts";

function argValue(name: string): string | null {
  const index = process.argv.indexOf(name);
  return index === -1 ? null : process.argv[index + 1] ?? null;
}

/**
 * הקסדצימלי ולא base64, במכוון: הסיסמה נכנסת לתוך URL, ו-base64
 * מכיל + / ו-= שהם תווים בעלי משמעות שם.
 */
function generatePassword(): string {
  return randomBytes(24).toString("hex");
}

async function main(): Promise<void> {
  const url = process.env["DATABASE_URL"];

  if (!url) {
    console.error("חסר DATABASE_URL. זו מחרוזת החיבור של בעל הסכמה.");
    process.exitCode = 1;
    return;
  }

  const password = argValue("--password") ?? generatePassword();
  const client = new pg.Client({ connectionString: url, ssl: sslFor(url) });

  await client.connect();

  try {
    const who = await client.query<{ user: string }>("SELECT current_user AS user");
    const current = who.rows[0]!.user;

    if (current === APP_ROLE) {
      throw new Error(
        `מחובר כ-${APP_ROLE}. יש להריץ עם מחרוזת החיבור של בעל הסכמה, ` +
          "אותה מחרוזת שמשמשת למיגרציות.",
      );
    }

    const exists = await client.query("SELECT 1 FROM pg_roles WHERE rolname = $1", [APP_ROLE]);

    if (exists.rowCount === 0) {
      throw new Error(
        `התפקיד ${APP_ROLE} אינו קיים. יש להריץ קודם: node scripts/migrate.ts`,
      );
    }

    // ALTER ROLE היא פקודת שירות ואי אפשר לפרמטר אותה — לא ב-$1 ולא
    // בתוך DO, שאינו מקבל פרמטרים כלל. לכן הסיסמה עוברת בריחה
    // מפורשת דרך הדרייבר, ולא בשרשור מחרוזות.
    await client.query(
      `ALTER ROLE ${APP_ROLE} WITH LOGIN PASSWORD ${client.escapeLiteral(password)}`,
    );

    const appUrl = new URL(url);
    appUrl.username = APP_ROLE;

    // encodeURIComponent ולא השמה ישירה: מגדיר ה-URL אינו מקודד את
    // סימן האחוז עצמו, ולכן סיסמה שמכילה "%20" כטקסט הייתה מתפענחת
    // לרווח, והחיבור היה נכשל באימות בלי שום רמז לסיבה.
    appUrl.password = encodeURIComponent(password);

    const connectionString = appUrl.toString();

    // אימות הלוך-ושוב. מחרוזת חיבור שגויה מתגלה אחרת רק כשגיאת
    // אימות סיסמה — ההודעה שהכי קל לחפש בגללה במקום הלא נכון.
    if (decodeURIComponent(new URL(connectionString).password) !== password) {
      throw new Error(
        "מחרוזת החיבור אינה משחזרת את הסיסמה. מומלץ להריץ בלי --password " +
          "ולתת לסקריפט לייצר אותה.",
      );
    }

    console.log("");
    console.log(`הסיסמה נקבעה עבור ${APP_ROLE}, כמשתמש ${current}.`);
    console.log("");
    console.log("── DATABASE_URL_APP ──");
    console.log("");
    console.log(connectionString);
    console.log("");
    console.log("──────────────────────");
    console.log("");
    console.log("שמור את הסיסמה במנהל סיסמאות. היא אינה ניתנת לשחזור.");
    console.log("");
    console.log("אם הרצת עם המחרוזת החיצונית, החלף את המארח בזה של");
    console.log("המחרוזת הפנימית לפני שתגדיר ב-Render. השירות רץ באותה");
    console.log("רשת, ואין סיבה שהתעבורה תצא לאינטרנט.");
    console.log("");
  } finally {
    await client.end();
  }
}

await main();
