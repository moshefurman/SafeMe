import pg from "pg";

/**
 * חיבור למסד הנתונים והקשר הבקשה.
 *
 * כל שאילתה של האפליקציה חייבת לרוץ בתוך withTenant או withPlatform.
 * שתיהן פותחות טרנזקציה ומגדירות SET LOCAL, כך שההקשר פג בסיום ואינו
 * נגרר לבקשה הבאה שתקבל את אותו חיבור מה-pool.
 */

const { Pool } = pg;

export type TenantId = string;

export interface DbConfig {
  connectionString: string;
  max?: number;
  applicationName?: string;
}

/**
 * מוודא שהאפליקציה אינה מתחברת כבעל הסכמה.
 *
 * RLS אינו חל על בעל הטבלה. חיבור כ-safeme_owner מבטל בשקט את כל
 * מדיניות הבידוד, וזו תקלה שלא תתגלה עד שדייר יראה נתונים של אחר.
 * לכן נכשלים כאן, בעליית התהליך.
 */
/** המשתמש היחיד שהאפליקציה רשאית להתחבר בו. נוצר במיגרציה 0001. */
export const APP_ROLE = "safeme_app";

export function assertAppRole(connectionString: string): void {
  let user: string;

  try {
    user = decodeURIComponent(new URL(connectionString).username);
  } catch {
    throw new Error("DATABASE_URL_APP אינו מחרוזת חיבור תקינה");
  }

  // רשימת היתר ולא רשימת חסימה, ובמכוון.
  //
  // הגרסה הקודמת חסמה את safeme_owner ואת postgres בלבד — והחמיצה
  // את המקרה השכיח ביותר בפועל: ספק מנוהל שמייצר בעל סכמה בשם
  // משלו, כמו safeme_user ב-Render. חיבור כזה היה עובר, RLS לא היה
  // חל עליו, וכל דייר היה רואה את הנתונים של כולם — בלי שום שגיאה
  // שתסגיר את זה.
  //
  // אין דרך לדעת מראש איך ייקרא בעל הסכמה אצל כל ספק. כן אפשר לדעת
  // איך נקרא המשתמש הנכון.
  // Supabase pooler מוסיף את מזהה הפרויקט לשם המשתמש: safeme_app.vpbhh...
  // חותכים את הסיומת כדי שהבדיקה תעבוד גם בחיבור ישיר וגם דרך pooler.
  const baseUser = user.includes(".") ? user.split(".")[0] : user;

  if (baseUser !== APP_ROLE) {
    throw new Error(
      `האפליקציה מנסה להתחבר כ-${user}, ונדרש ${APP_ROLE}. ` +
        "RLS אינו חל על בעל הסכמה, ולכן בידוד הדיירים היה מבוטל בשקט. " +
        `יש ליצור את ${APP_ROLE} ולהתחבר בו — ראה deploy/render.md.`,
    );
  }
}

/**
 * הגדרת TLS לפי יעד החיבור.
 *
 * Postgres מקומי ב-Docker אינו דורש הצפנה, וכל ספק מנוהל כן דורש.
 * ברירת מחדל אחת לא מתאימה לשניהם, ולכן ההחלטה נגזרת מהמארח:
 * לולאה מקומית — בלי TLS, כל השאר — עם TLS ועם אימות תעודה.
 *
 * האימות דלוק כברירת מחדל ובמכוון. חיבור מוצפן בלי אימות תעודה
 * מגן מפני האזנה אך לא מפני התחזות, וזו בדיוק המחצית שחשובה כאן:
 * מחרוזת החיבור נושאת את סיסמת בסיס הנתונים.
 */
export function sslFor(
  connectionString: string,
  env: NodeJS.ProcessEnv = process.env,
): { ca?: string; rejectUnauthorized: boolean } | undefined {
  let host: string;
  let mode: string | null;

  try {
    const url = new URL(connectionString);
    host = url.hostname;
    mode = url.searchParams.get("sslmode");
  } catch {
    return undefined;
  }

  mode ??= env["PGSSLMODE"] ?? null;

  if (mode === "disable") return undefined;

  const isLoopback = host === "localhost" || host === "127.0.0.1" || host === "::1";

  if (isLoopback && mode === null) return undefined;

  // ספק שמנפיק תעודה מרשות שאינה במאגר של Node
  const ca = env["DATABASE_CA_CERT"];
  if (ca && ca.trim() !== "") return { ca, rejectUnauthorized: true };

  // מוצא אחרון, למי שמנפיק תעודה חתומה עצמית. פותח פתח להתחזות,
  // ולכן דורש הצהרה מפורשת ולא נבחר לבד.
  if (env["DATABASE_SSL_INSECURE"] === "true") return { rejectUnauthorized: false };

  return { rejectUnauthorized: true };
}

export function createPool(config: DbConfig): pg.Pool {
  assertAppRole(config.connectionString);

  return new Pool({
    connectionString: config.connectionString,
    ssl: sslFor(config.connectionString),
    max: config.max ?? 10,
    application_name: config.applicationName ?? "safeme-server",
    idle_in_transaction_session_timeout: 10_000,
  });
}

export interface TxClient {
  query: pg.ClientBase["query"];
}

/**
 * מריץ פעולה בהקשר של דייר מסוים. כל שאילתה בתוך fn רואה רק את
 * השורות של אותו דייר, גם אם הקוד שכח לסנן לפי tenant_id.
 */
export async function withTenant<T>(
  pool: pg.Pool,
  tenantId: TenantId,
  fn: (tx: TxClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    // set_config עם פרמטר, ולא אינטרפולציה של מחרוזת לתוך SET
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
    await client.query("SELECT set_config('app.platform', 'off', true)");

    const result = await fn(client);

    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

/**
 * מריץ פעולה בהקשר של צוות החברה, מעל בידוד הדיירים.
 *
 * זו הדלת האחורית היחידה במערכת, ולכן היא מקבלת פרמטרים שמאלצים
 * את הקורא לתעד מי ביקש ולמה. כל שימוש נרשם ביומן הביקורת.
 */
export async function withPlatform<T>(
  pool: pg.Pool,
  actor: { userId: string; reason: string },
  fn: (tx: TxClient) => Promise<T>,
): Promise<T> {
  if (!actor.userId || !actor.reason) {
    throw new Error("גישת פלטפורמה מחייבת מזהה משתמש וסיבה, לצורך תיעוד");
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    await client.query("SELECT set_config('app.platform', 'on', true)");

    const result = await fn(client);

    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

/** בדיקת זמינות. אינה נוגעת בנתוני דיירים ולכן אינה דורשת הקשר. */
export async function ping(pool: pg.Pool): Promise<boolean> {
  const result = await pool.query("SELECT 1 AS ok");
  return result.rows.length === 1;
}
