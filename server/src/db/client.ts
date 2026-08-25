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
export function assertAppRole(connectionString: string): void {
  let user: string;

  try {
    user = decodeURIComponent(new URL(connectionString).username);
  } catch {
    throw new Error("DATABASE_URL_APP אינו מחרוזת חיבור תקינה");
  }

  if (user === "safeme_owner" || user === "postgres") {
    throw new Error(
      `האפליקציה מנסה להתחבר כ-${user}. RLS אינו חל על בעל הסכמה, ` +
        "ולכן בידוד הדיירים היה מבוטל. יש להתחבר כ-safeme_app.",
    );
  }
}

export function createPool(config: DbConfig): pg.Pool {
  assertAppRole(config.connectionString);

  return new Pool({
    connectionString: config.connectionString,
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
