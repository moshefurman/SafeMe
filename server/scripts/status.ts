/**
 * מצב הפריסה, במבט אחד.
 *
 * נכתב אחרי שהתברר שכמה תקלות היו בלתי נראות מבחוץ: מדיניות שנדחתה
 * בכל פעימה, כללי זיהוי שלא הגיעו, וגרסה שלא נרשמה. כולן החזירו
 * 200 בכל מסלול שנבדק, ורק המסד ידע.
 *
 * אינו משנה דבר. קריאה בלבד.
 *
 *   node scripts/status.ts
 */

import pg from "pg";

import { sslFor } from "../src/db/client.ts";

function fail(message: string): never {
  console.error(message);
  process.exit(1);
}

const ok = (t: string, d = "") => console.log(`  ✓ ${t}${d ? ` — ${d}` : ""}`);
const bad = (t: string, d = "") => console.log(`  ✗ ${t}${d ? ` — ${d}` : ""}`);
const note = (t: string) => console.log(`    ${t}`);

function section(title: string): void {
  console.log(`\n${title}`);
  console.log("─".repeat(64));
}

interface PolicyRow {
  version: number;
  body: {
    baselineVersion?: number;
    enforcement?: {
      mode?: string;
      onRedAction?: string;
      alwaysAllow?: { hosts?: string[] };
      egress?: { enabled?: boolean };
    };
    providers?: Array<{
      id: string;
      rootCa?: { thumbprints?: string[] };
      network?: { cidrs?: string[] };
      tlsIssuer?: { patterns?: string[] };
      httpMarkers?: { headers?: Record<string, string> };
    }>;
  };
}

async function main(): Promise<void> {
  const url = process.env["DATABASE_URL"];

  if (!url) fail("חסר DATABASE_URL.");

  const client = new pg.Client({ connectionString: url, ssl: sslFor(url) });

  await client.connect();

  try {
    console.log("═".repeat(64));
    console.log("  SafeMe · מצב הפריסה");
    console.log("═".repeat(64));

    // ─────────────────────────────────────────── מדיניות

    section("מדיניות הבסיס");

    const policy = await client.query<PolicyRow>(
      "SELECT version, body FROM policies WHERE tenant_id IS NULL ORDER BY version DESC LIMIT 1",
    );

    const row = policy.rows[0];

    if (!row) {
      bad("אין תבנית גלובלית");
      note("מכשיר בחשבון חדש יקבל 404 וירוץ בלי הגדרות.");
    } else {
      const e = row.body.enforcement ?? {};

      ok("קיימת", `גרסה ${row.version} · סימון תוכן ${row.body.baselineVersion ?? "חסר"}`);

      if (row.body.baselineVersion === undefined) {
        bad("בלי סימון תוכן");
        note("שינויים עתידיים בתבנית לא יגיעו למכשירים. יש לפרוס גרסה חדשה.");
      }

      const observing = e.mode === "monitor" && e.onRedAction === "warn";

      console.log(
        `  ${observing ? "✓" : "!"} מצב: ${e.mode} · פעולה באדום: ${e.onRedAction}`,
      );

      note(
        observing
          ? "מצב תצפית: מודד ומדווח, אינו חוסם על סמך מסקנה עצמית."
          : "מצב אכיפה. ודא שהזיהוי עובד לפני שמשאירים כך.",
      );

      const hosts = e.alwaysAllow?.hosts ?? [];

      if (hosts.length > 0) {
        ok("מארחים פתוחים גם בחסימה", hosts.join(", "));
      } else {
        bad("אין מארח פתוח בחסימה");
        note("מחשב שנחסם לא יוכל להגיע לפורטל כדי להשתחרר.");
      }

      console.log(`  · default-deny: ${e.egress?.enabled ? "פעיל" : "כבוי"}`);
    }

    // ─────────────────────────────────────────── ספקים

    section("זיהוי ספקים");

    for (const p of row?.body.providers ?? []) {
      const vectors: string[] = [];

      if ((p.rootCa?.thumbprints?.length ?? 0) > 0) {
        vectors.push(`${p.rootCa!.thumbprints!.length} תעודות`);
      }

      if ((p.network?.cidrs?.length ?? 0) > 0) {
        vectors.push(`${p.network!.cidrs!.length} טווחים`);
      }

      if ((p.tlsIssuer?.patterns?.length ?? 0) > 0) vectors.push("מנפיק תעודה");
      if (Object.keys(p.httpMarkers?.headers ?? {}).length > 0) vectors.push("כותרת HTTP");

      if (vectors.length > 0) {
        ok(p.id, vectors.join(" · "));
      } else {
        bad(p.id, "אין כללי זיהוי — לא יזוהה על אף מכשיר");
      }
    }

    // ─────────────────────────────────────────── גרסאות

    section("גרסאות");

    const releases = await client.query<{
      version: string;
      rollout_percent: number;
      revoked: boolean;
    }>(
      `SELECT version, rollout_percent, revoked_at IS NOT NULL AS revoked
         FROM agent_releases
        ORDER BY v_major DESC, v_minor DESC, v_patch DESC
        LIMIT 5`,
    );

    if (releases.rows.length === 0) {
      bad("אין גרסה רשומה");
      note("הורדת המתקין תחזיר 503.");
    } else {
      for (const r of releases.rows) {
        const state = r.revoked ? "נפסלה" : `${r.rollout_percent}% הפצה`;

        console.log(`  · ${r.version.padEnd(10)} ${state}`);
      }
    }

    // ─────────────────────────────────────────── מכשירים

    section("מכשירים");

    const devices = await client.query<{
      total: string;
      reporting: string;
      silent: string;
    }>(
      `SELECT count(*) AS total,
              count(*) FILTER (WHERE s.last_seen_at > now() - interval '10 minutes') AS reporting,
              count(*) FILTER (WHERE s.health IN ('missing', 'offline')) AS silent
         FROM devices d LEFT JOIN device_state s ON s.device_id = d.id
        WHERE d.status = 'active'`,
    );

    const d = devices.rows[0]!;

    console.log(`  · רשומים: ${d.total} · דיווחו בעשר הדקות: ${d.reporting} · שותקים: ${d.silent}`);

    // מה המכשירים מדווחים בפועל. זו התשובה לשאלה "האם הזיהוי עובד".
    const detected = await client.query<{ detected_provider: string | null; n: string }>(
      `SELECT detected_provider, count(*) AS n
         FROM device_state
        WHERE last_seen_at > now() - interval '1 day'
        GROUP BY detected_provider`,
    );

    if (detected.rows.length > 0) {
      section("מה המכשירים מזהים");

      for (const r of detected.rows) {
        const name = r.detected_provider ?? "לא זוהה ספק";

        console.log(`  · ${name.padEnd(18)} ${r.n} מכשירים`);
      }
    }

    // ─────────────────────────────────────────── מנהלים

    section("חשבונות");

    const admins = await client.query<{ n: string; enrolled: string }>(
      `SELECT count(*) AS n,
              count(*) FILTER (WHERE mfa_enrolled_at IS NOT NULL) AS enrolled
         FROM users WHERE role = 'platform_admin'`,
    );

    const a = admins.rows[0]!;

    if (Number(a.n) === 0) {
      bad("אין מנהל פלטפורמה");
      note("מסך ניהול הספקים אינו נגיש. ראה scripts/create-admin.ts");
    } else {
      ok(`${a.n} מנהלי פלטפורמה`, `${a.enrolled} עם אימות דו-שלבי`);
    }

    console.log("\n" + "═".repeat(64));
  } finally {
    await client.end();
  }
}

main().catch((error: unknown) => {
  fail(error instanceof Error ? error.message : String(error));
});
