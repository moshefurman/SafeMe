import { readdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * בדיקה סטטית של קובצי המיגרציה, בלי מסד נתונים.
 *
 * אינה מחליפה הרצה אמיתית, אבל תופסת את הטעויות שקל לעשות בכתיבה ידנית:
 * מרכאות דולר לא מאוזנות, סוגריים לא סגורים, וקבצים שנחתכו באמצע.
 *
 * הרצה: node scripts/check-sql.ts
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = join(HERE, "..", "migrations");

interface Problem {
  file: string;
  message: string;
}

/** מסיר הערות ומחרוזות, כדי שספירת הסוגריים תתייחס רק לקוד. */
function stripNoise(sql: string): { code: string; dollarTags: string[] } {
  const dollarTags: string[] = [];
  let out = "";
  let i = 0;

  while (i < sql.length) {
    const rest = sql.slice(i);

    // הערת שורה
    if (rest.startsWith("--")) {
      const end = sql.indexOf("\n", i);
      i = end === -1 ? sql.length : end;
      continue;
    }

    // הערת בלוק
    if (rest.startsWith("/*")) {
      const end = sql.indexOf("*/", i + 2);
      i = end === -1 ? sql.length : end + 2;
      continue;
    }

    // מחרוזת רגילה
    if (rest.startsWith("'")) {
      let j = i + 1;
      while (j < sql.length) {
        if (sql[j] === "'" && sql[j + 1] === "'") { j += 2; continue; }
        if (sql[j] === "'") { j += 1; break; }
        j += 1;
      }
      i = j;
      continue;
    }

    // מרכאות דולר: $$ או $tag$
    const dollar = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(rest);
    if (dollar) {
      const tag = dollar[0];
      dollarTags.push(tag);

      const close = sql.indexOf(tag, i + tag.length);
      if (close === -1) {
        // לא נסגר: משאירים כדי שהספירה תדווח על כך
        i = sql.length;
        continue;
      }

      dollarTags.push(tag);
      i = close + tag.length;
      continue;
    }

    out += sql[i];
    i += 1;
  }

  return { code: out, dollarTags };
}

async function main(): Promise<void> {
  const entries = await readdir(MIGRATIONS_DIR);
  const files = entries.filter((f) => f.endsWith(".sql")).sort();

  if (files.length === 0) {
    console.error("לא נמצאו קובצי מיגרציה.");
    process.exitCode = 1;
    return;
  }

  const problems: Problem[] = [];

  for (const file of files) {
    const sql = await readFile(join(MIGRATIONS_DIR, file), "utf8");
    const { code, dollarTags } = stripNoise(sql);

    // כל תג דולר חייב להופיע מספר זוגי של פעמים
    const counts = new Map<string, number>();
    for (const tag of dollarTags) counts.set(tag, (counts.get(tag) ?? 0) + 1);

    for (const [tag, n] of counts) {
      if (n % 2 !== 0) {
        problems.push({ file, message: `מרכאות דולר לא מאוזנות עבור ${tag}` });
      }
    }

    let depth = 0;
    for (const ch of code) {
      if (ch === "(") depth += 1;
      if (ch === ")") depth -= 1;
      if (depth < 0) break;
    }

    if (depth !== 0) {
      problems.push({ file, message: `סוגריים לא מאוזנים (הפרש ${depth})` });
    }

    if (!code.trimEnd().endsWith(";")) {
      problems.push({ file, message: "הקובץ אינו מסתיים בנקודה-פסיק" });
    }

    const statements = code.split(";").filter((s) => s.trim().length > 0).length;
    console.log(`${file.padEnd(36)} ${String(statements).padStart(3)} פקודות`);
  }

  if (problems.length > 0) {
    console.error("");
    for (const p of problems) console.error(`  ${p.file}: ${p.message}`);
    process.exitCode = 1;
    return;
  }

  console.log("\nכל קובצי המיגרציה עברו את הבדיקה הסטטית.");
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
