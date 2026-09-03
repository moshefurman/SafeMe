/**
 * בדיקת הזריעה והתיקון של רימון מול מסד אמיתי.
 *
 * מריץ את seedProviders על מסד נקי ובודק שרימון קיבלה את טווחי
 * AS42925, את ה-ASN, ואת דף החסימה ב-HTTP רגיל; ואז מדמה שורה
 * שאדם ערך — הצורה הישנה, עם updated_by מלא — ומוודא שהתיקון ממזג
 * בלי לדרוס, נספר פעם אחת, ואינו חוזר.
 *
 * הרצה: node --env-file=.env scripts/check-provider-repair.ts
 * מול מסד הפיתוח בלבד. יוצר משתמש בדיקה ומוחק אותו בסוף.
 */

import pg from "pg";

import { listProviders, RIMON_PREFIXES, seedProviders } from "../src/policy/providers.ts";

const url = process.env["DATABASE_URL"];

if (!url) {
  console.error("חסר DATABASE_URL");
  process.exit(1);
}

if (!/localhost|127\.0\.0\.1/.test(url)) {
  console.error("הבדיקה משנה שורות. מסד פיתוח בלבד.");
  process.exit(1);
}

const pool = new pg.Pool({ connectionString: url });

let failures = 0;

function check(label: string, ok: boolean, detail = ""): void {
  console.log(`${ok ? "✓" : "✗"} ${label}${detail ? ` — ${detail}` : ""}`);

  if (!ok) failures++;
}

async function rimon() {
  const rows = await listProviders(pool);
  const r = rows.find((p) => p.key === "rimon");

  if (!r) throw new Error("רימון לא נמצאה");

  return r.detection as {
    network?: { cidrs?: string[]; asns?: number[] };
    httpMarkers?: { url?: string; bodyContains?: string[] };
    tlsIssuer?: { patterns?: string[] };
    repairVersion?: number;
  };
}

try {
  // ---- זריעה על שורה שלא נערכה ----
  await seedProviders(pool);
  const seeded = await rimon();

  check("זריעה: כל טווחי AS42925", RIMON_PREFIXES.every((c) => seeded.network?.cidrs?.includes(c)),
    `${seeded.network?.cidrs?.length ?? 0} טווחים`);
  check("זריעה: ASN 42925", (seeded.network?.asns ?? []).includes(42925));
  check("זריעה: דף חסימה ב-HTTP רגיל", seeded.httpMarkers?.url === "http://xvideo.com/",
    seeded.httpMarkers?.url ?? "ריק");

  const again = await seedProviders(pool);
  check("זריעה חוזרת אינה נוגעת בדבר", again === 0, `נגעה ב-${again}`);

  // ---- שורה שאדם ערך, בצורה הישנה ----
  const user = await pool.query<{ id: string }>(
    `INSERT INTO users (tenant_id, email, password_hash, role, status, mfa_secret, mfa_enrolled_at)
     VALUES (NULL, 'repair-check@localhost', 'x', 'platform_admin', 'active', 'x', now())
     RETURNING id`,
  );
  const userId = user.rows[0]!.id;

  const old = {
    ...seeded,
    repairVersion: undefined,
    network: { cidrs: ["213.151.48.0/20"], reverseDnsPatterns: ["*rimon*"] },
    httpMarkers: { ...seeded.httpMarkers, url: "https://www.bet365.com", bodyContains: ["cause=url_level"] },
    tlsIssuer: { patterns: ["*netspark*", "*edited-by-a-person*"], probes: ["www.bet365.com"] },
  };

  await pool.query(
    "UPDATE providers SET detection = $1::jsonb, updated_by = $2 WHERE key = 'rimon'",
    [JSON.stringify(old), userId],
  );

  const touched = await seedProviders(pool);
  const repaired = await rimon();

  check("תיקון נספר פעם אחת", touched === 1, `נגע ב-${touched}`);
  check("תיקון: הטווח הישן נשאר", repaired.network?.cidrs?.includes("213.151.48.0/20") === true);
  check("תיקון: טווחי AS42925 נוספו", RIMON_PREFIXES.every((c) => repaired.network?.cidrs?.includes(c)),
    `${repaired.network?.cidrs?.length ?? 0} טווחים`);
  check("תיקון: ASN נוסף", (repaired.network?.asns ?? []).includes(42925));
  check("תיקון: הכתובת הוחלפה", repaired.httpMarkers?.url === "http://xvideo.com/");
  check("תיקון: סימן הגוף נוסף, הישן נשאר",
    repaired.httpMarkers?.bodyContains?.includes("safepage.neto.net.il") === true
    && repaired.httpMarkers?.bodyContains?.includes("cause=url_level") === true);
  check("תיקון: עריכת האדם נשמרה",
    repaired.tlsIssuer?.patterns?.includes("*edited-by-a-person*") === true);
  check("תיקון: גרסת תיקון נרשמה", repaired.repairVersion === 1);

  const third = await seedProviders(pool);
  check("תיקון אינו חוזר", third === 0, `נגע ב-${third}`);

  // ---- ניקוי ----
  await pool.query("UPDATE providers SET updated_by = NULL WHERE key = 'rimon'");
  await pool.query("DELETE FROM users WHERE id = $1", [userId]);
  await seedProviders(pool);
} finally {
  await pool.end();
}

console.log(failures === 0 ? "\nהכול עבר." : `\n${failures} כשלים.`);
process.exit(failures === 0 ? 0 : 1);
