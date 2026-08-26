import { readdir, readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { sslFor } from "../src/db/client.ts";

/**
 * מריץ מיגרציות SQL לפי סדר שמות הקבצים.
 *
 * המיגרציות כתובות ידנית ולא נוצרות מכלי, כי הן מכילות RLS, חלוקה
 * לפי זמן, טריגרים והרשאות — דברים שאף מחולל סכמה לא מייצר נכון.
 *
 * הרצה: node scripts/migrate.ts
 * מצב:  node scripts/migrate.ts --status
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = join(HERE, "..", "migrations");

interface Migration {
  name: string;
  sql: string;
  checksum: string;
}

async function loadMigrations(): Promise<Migration[]> {
  const entries = await readdir(MIGRATIONS_DIR);
  const files = entries.filter((f) => f.endsWith(".sql")).sort();

  const migrations: Migration[] = [];

  for (const name of files) {
    const sql = await readFile(join(MIGRATIONS_DIR, name), "utf8");
    migrations.push({
      name,
      sql,
      checksum: createHash("sha256").update(sql).digest("hex").slice(0, 16),
    });
  }

  return migrations;
}

async function ensureLedger(client: pg.Client): Promise<void> {
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      name       text PRIMARY KEY,
      checksum   text NOT NULL,
      applied_at timestamptz NOT NULL DEFAULT now()
    )
  `);
}

async function appliedMap(client: pg.Client): Promise<Map<string, string>> {
  const result = await client.query<{ name: string; checksum: string }>(
    "SELECT name, checksum FROM schema_migrations",
  );

  return new Map(result.rows.map((r) => [r.name, r.checksum]));
}

async function main(): Promise<void> {
  const url = process.env["DATABASE_URL"];

  if (!url) {
    console.error("חסר DATABASE_URL. יש להריץ מיגרציות כ-safeme_owner.");
    process.exitCode = 1;
    return;
  }

  const statusOnly = process.argv.includes("--status");
  const client = new pg.Client({ connectionString: url, ssl: sslFor(url) });

  await client.connect();

  try {
    await ensureLedger(client);

    const migrations = await loadMigrations();
    const applied = await appliedMap(client);

    if (statusOnly) {
      for (const m of migrations) {
        const previous = applied.get(m.name);
        const mark = previous === undefined
          ? "ממתין"
          : previous === m.checksum
            ? "הוחל"
            : "שונה לאחר החלה";

        console.log(`${mark.padEnd(18)} ${m.name}`);
      }

      return;
    }

    for (const m of migrations) {
      const previous = applied.get(m.name);

      if (previous !== undefined) {
        // מיגרציה שהוחלה וקובץ המקור שלה השתנה מאז היא סכנה שקטה:
        // בסביבה אחת הסכמה תיראה אחרת. עוצרים במקום להמשיך.
        if (previous !== m.checksum) {
          throw new Error(
            `המיגרציה ${m.name} הוחלה בעבר אך תוכנה שונה מאז. ` +
              "יש ליצור מיגרציה חדשה במקום לערוך קיימת.",
          );
        }

        continue;
      }

      console.log(`מחיל ${m.name} ...`);

      await client.query("BEGIN");

      try {
        await client.query(m.sql);
        await client.query(
          "INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)",
          [m.name, m.checksum],
        );
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        throw new Error(
          `המיגרציה ${m.name} נכשלה: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }

    console.log("כל המיגרציות הוחלו.");
  } finally {
    await client.end();
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
