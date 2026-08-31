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
      httpMarkers?: {
        url?: string;
        headers?: Record<string, string>;
        probes?: unknown[];
        levelHosts?: string[];
        levelNames?: string[];
      };
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
      note("מחשב בחשבון חדש יקבל 404 וירוץ בלי הגדרות.");
    } else {
      const e = row.body.enforcement ?? {};

      ok("קיימת", `גרסה ${row.version} · סימון תוכן ${row.body.baselineVersion ?? "חסר"}`);

      if (row.body.baselineVersion === undefined) {
        bad("בלי סימון תוכן");
        note("שינויים עתידיים בתבנית לא יגיעו למחשבים. יש לפרוס גרסה חדשה.");
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

      /*
       * סמני HTTP, בשלוש הצורות שלהם.
       *
       * נבדקו עד כאן לפי headers בלבד, ולכן ספק שהזיהוי
       * שלו יושב ב-url או ב-probes הוצג כאילו אין לו כלום.
       * בדיוק מה שקרה עם נטפרי, ושלח אותנו לחפש את התקלה
       * במקום אחר לגמרי.
       */
      if (Object.keys(p.httpMarkers?.headers ?? {}).length > 0) vectors.push("כותרת HTTP");

      if (p.httpMarkers?.url) vectors.push(`בדיקה מ-${new URL(p.httpMarkers.url).host}`);

      const probeCount = p.httpMarkers?.probes?.length ?? 0;

      if (probeCount > 0) vectors.push(`${probeCount} גששים`);

      /*
       * מארחי קריאת הרמה.
       *
       * הם מגיעים דרך אותו זרע כמו שאר כללי הזיהוי, והזרע נעצר
       * ברגע שמישהו ערך את הספק במסך הניהול — updated_by מפסיק
       * להיות ריק, וכל עדכון עתידי בקוד אינו מגיע. זה קרה כבר
       * פעם אחת עם התעודות, ולכן הוא מוצג כאן במפורש.
       */
      const levelHosts = p.httpMarkers?.levelHosts ?? [];

      if (levelHosts.length > 0) vectors.push(`רמה מ-${levelHosts.join(", ")}`);

      if (vectors.length > 0) {
        ok(p.id, vectors.join(" · "));

        if (levelHosts.length === 0 && (p.httpMarkers?.headers ?? {})) {
          note("אין מארח לקריאת רמת ההגנה. השדה יציג 'לא נקראה'.");
        }
      } else {
        bad(p.id, "אין כללי זיהוי — לא יזוהה על אף מחשב");
      }
    }

    // ───────────────────────────────── מדיניות שנדחתה
    // ─────────────────────── מה כל מחשב באמת מקבל

    /*
     * כל מה שלמעלה מתאר את מדיניות הבסיס, והיא אינה
     * בהכרח מה שהמחשב מקבל. השרת בוחר לפי קדימות:
     * שיוך ישיר למחשב, אחריו מדיניות הדייר, ורק אז הבסיס.
     *
     * זה הפער שעלול להטעות בדיוק כשמחפשים אותו: כלל חדש
     * נכנס לבסיס, הכלי מציג אותו, והמחשב ממשיך לקבל שורה
     * אחרת שאיש לא חידש.
     */
    section("מה כל מחשב באמת מקבל");

    const served = await client.query<{
      name: string;
      version: number;
      source: string;
      has_netfree_probe: boolean;
      detail: string;
    }>(
      `SELECT d.machine_name AS name,
              chosen.version,
              CASE
                WHEN chosen.assigned THEN 'שיוך ישיר'
                WHEN chosen.tenant_id IS NOT NULL THEN 'מדיניות הדייר'
                ELSE 'בסיס'
              END AS source,
              EXISTS (
                SELECT 1 FROM jsonb_array_elements(chosen.body -> 'providers') pr
                 WHERE pr ->> 'id' = 'netfree'
                   AND pr -> 'httpMarkers' ->> 'url' IS NOT NULL
              ) AS has_netfree_probe,
              (
                SELECT CASE
                  WHEN chosen.body -> 'providers' IS NULL THEN 'אין רשימת ספקים בכלל'
                  WHEN NOT EXISTS (
                    SELECT 1 FROM jsonb_array_elements(chosen.body -> 'providers') q
                     WHERE q ->> 'id' = 'netfree'
                  ) THEN format('%s ספקים, ונטפרי איננה ביניהם',
                                 jsonb_array_length(chosen.body -> 'providers'))
                  ELSE (
                    SELECT format('נטפרי קיימת, httpMarkers=%s',
                                  COALESCE((q -> 'httpMarkers')::text, 'חסר'))
                      FROM jsonb_array_elements(chosen.body -> 'providers') q
                     WHERE q ->> 'id' = 'netfree'
                     LIMIT 1
                  )
                END
              ) AS detail
         FROM devices d
         CROSS JOIN LATERAL (
           SELECT pol.version,
                  pol.tenant_id,
                  pol.body,
                  (asg.device_id IS NOT NULL) AS assigned
             FROM policies pol
             LEFT JOIN device_policy_assignments asg
                    ON asg.policy_id = pol.id AND asg.device_id = d.id
            WHERE asg.device_id IS NOT NULL
               OR ((pol.tenant_id = d.tenant_id OR pol.tenant_id IS NULL)
                   AND NOT EXISTS (
                     SELECT 1 FROM device_policy_assignments x WHERE x.policy_id = pol.id
                   ))
            ORDER BY (asg.device_id IS NOT NULL) DESC,
                     (pol.tenant_id IS NOT NULL) DESC,
                     pol.version DESC
            LIMIT 1
         ) chosen
        ORDER BY d.machine_name
        LIMIT 20`,
    );

    for (const r of served.rows) {
      const label = `גרסה ${r.version} · ${r.source}`;

      if (r.has_netfree_probe) ok(r.name, label);
      else {
        bad(r.name, `${label} — בלי הכללים החדשים`);

        /*
         * מה יש שם בפועל.
         *
         * "בלי הכללים" אינו אומר אם הספק חסר, אם רשימת
         * הספקים כולה חסרה, או שהספק קיים בלי השדה.
         * שלוש תקלות שונות לגמרי מאחורי אותה שורה.
         */
        note(`בגוף שהמחשב מקבל: ${r.detail}`);
      }
    }

    if (served.rows.some((r) => r.source !== "בסיס")) {
      note("מחשב שאינו על הבסיס אינו מקבל שינויים שנעשו בו.");
    }


    /*
     * הסיבה שהייתה קיימת ולא נראתה.
     *
     * סוכן שדוחה מדיניות שולח אירוע חבלה ואינו רושם דבר אצלו.
     * מי שעמד מול מחשב תקוע על גרסת מדיניות ישנה ראה שתיקה:
     * הפעימה עובדת, המספר בשרת עולה, המספר במחשב עומד.
     *
     * הרישום המקומי תוקן בסוכן, אבל הוא מגיע רק בגרסה הבאה —
     * ומה שכבר נשלח יושב כאן מזמן.
     */
    section("מדיניות שנדחתה");

    const rejected = await client.query<{
      name: string;
      detail: string | null;
      occurred_at: Date;
      times: string;
    }>(
      `SELECT d.machine_name AS name,
              e.detail,
              max(e.occurred_at) AS occurred_at,
              count(*)::text     AS times
         FROM events e
         JOIN devices d ON d.id = e.device_id
        WHERE e.kind = 'policySignatureInvalid'
          AND e.occurred_at > now() - interval '24 hours'
        GROUP BY d.machine_name, e.detail
        ORDER BY max(e.occurred_at) DESC
        LIMIT 10`,
    );

    if (rejected.rowCount === 0) {
      ok("אף מחשב לא דחה מדיניות ב-24 השעות האחרונות");
    } else {
      for (const r of rejected.rows) {
        bad(r.name, `${r.times} פעמים · אחרון ${r.occurred_at.toLocaleString("he-IL")}`);
        note(r.detail ?? "בלי פירוט");
      }

      note("מחשב שדוחה מדיניות נשאר על הגרסה הישנה, וכל כלל חדש אינו מגיע אליו.");
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

    // ─────────────────────────────────────────── אסימונים

    section("אסימוני רישום");

    /*
     * הרצפה נקבעת ברגע יצירת האסימון ונחתמת איתו.
     *
     * אסימון שנוצר לפני שהמדיניות רוככה נושא רצפה מחמירה יותר
     * ממנה — ומחשב שנרשם דרכו ידחה כל חבילה, לנצח. הכשל הזה
     * שקוף לגמרי: השרת מגיש מדיניות תקינה, המחשב מקבל אותה,
     * דוחה אותה בשקט, וממשיך לפי מה שיש לו.
     *
     * זה קרה בפועל, ורק יומן האירועים במחשב ידע.
     */
    const tokens = await client.query<{
      floor: { mode?: string; onRedAction?: string };
      uses: number;
      max_uses: number;
      expired: boolean;
      created_at: Date;
    }>(
      `SELECT policy_floor AS floor, uses, max_uses,
              expires_at <= now() AS expired, created_at
         FROM enroll_tokens
        WHERE revoked_at IS NULL
        ORDER BY created_at DESC
        LIMIT 10`,
    );

    const MODES = ["monitor", "warn", "enforce"];
    const ACTIONS = ["none", "warn", "lockout"];

    const baselineMode = row?.body.enforcement?.mode ?? "monitor";
    const baselineAction = row?.body.enforcement?.onRedAction ?? "warn";

    const usable = tokens.rows.filter((t) => !t.expired && t.uses < t.max_uses);

    if (usable.length === 0) {
      console.log("  · אין אסימון פעיל. יש ליצור קישור התקנה בפורטל.");
    }

    for (const t of usable) {
      const mode = t.floor?.mode ?? "monitor";
      const action = t.floor?.onRedAction ?? "warn";

      const tooStrict =
        MODES.indexOf(mode) > MODES.indexOf(baselineMode)
        || ACTIONS.indexOf(action) > ACTIONS.indexOf(baselineAction);

      const when = t.created_at.toLocaleDateString("he-IL");

      if (tooStrict) {
        bad(`אסימון מ-${when}`, `רצפה ${mode}/${action} מחמירה מהמדיניות`);
        note("מחשב שנרשם דרכו ידחה את המדיניות בכל פעימה. יש ליצור קישור חדש.");
      } else {
        ok(`אסימון מ-${when}`, `רצפה ${mode}/${action} · ${t.uses}/${t.max_uses} שימושים`);
      }
    }

    // ─────────────────────────────────────────── מחשבים

    section("מחשבים");

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

    /*
     * מי יקבל קוד קצר ומי ארוך.
     *
     * לא מדד סקרנות: מחשב במצב rsa מקבל חתימה בת שש מאות תווים,
     * ואי אפשר להכתיב אותה בטלפון. כלומר כל מחשב כזה הוא שיחת
     * מוקד שאי אפשר לסיים.
     *
     * המצב נקבע ברישום ומחייב שגזירת הסוד תהיה פעילה באותו רגע.
     * מחשב שנרשם לפני שהוגדר המפתח יישאר rsa עד שיירשם מחדש —
     * וזה בדיוק המצב שבלבל אותנו: קוד ארוך למרות שהכול "מוגדר".
     */
    const modes = await client.query<{ mode: string; count: string; names: string[] }>(
      `SELECT uninstall_key_mode AS mode,
              count(*)::text AS count,
              array_agg(COALESCE(display_name, machine_name, 'ללא שם') ORDER BY created_at) AS names
         FROM devices WHERE status = 'active'
        GROUP BY uninstall_key_mode`,
    );

    for (const row of modes.rows) {
      const label = row.mode === "hmac"
        ? `${row.count} מחשבים · קוד הסרה קצר`
        : `${row.count} מחשבים · קוד הסרה ארוך, לא ניתן להכתבה בטלפון`;

      if (row.mode === "hmac") ok("קודי הסרה", label);
      else {
        bad("קודי הסרה", label);
        note(`נדרש רישום מחדש: ${row.names.slice(0, 5).join(", ")}`);
      }
    }

    /*
     * הרצפה שכל מחשב נושא בפועל.
     *
     * זו התשובה לשאלה "למה המחשב לא מקבל את המדיניות", והיא לא
     * הייתה נראית בשום מקום מחוץ ליומן האירועים במחשב עצמו.
     */
    const floors = await client.query<{ mode: string; action: string; n: string }>(
      `SELECT policy_floor ->> 'mode' AS mode,
              policy_floor ->> 'onRedAction' AS action,
              count(*) AS n
         FROM devices WHERE status = 'active'
        GROUP BY 1, 2`,
    );

    for (const f of floors.rows) {
      const mode = f.mode ?? "monitor";
      const action = f.action ?? "warn";

      const rejects =
        MODES.indexOf(mode) > MODES.indexOf(baselineMode)
        || ACTIONS.indexOf(action) > ACTIONS.indexOf(baselineAction);

      if (rejects) {
        bad(`${f.n} מחשבים ברצפה ${mode}/${action}`, "דוחים את המדיניות הנוכחית");
        note("הרצפה נחתמה ברישום ואינה משתנה. יש להסיר ולהתקין מחדש עם קישור חדש.");
      } else {
        ok(`${f.n} מחשבים ברצפה ${mode}/${action}`);
      }
    }

    // מה המחשבים מדווחים בפועל. זו התשובה לשאלה "האם הזיהוי עובד".
    const detected = await client.query<{ detected_provider: string | null; n: string }>(
      `SELECT detected_provider, count(*) AS n
         FROM device_state
        WHERE last_seen_at > now() - interval '1 day'
        GROUP BY detected_provider`,
    );

    if (detected.rows.length > 0) {
      section("מה המחשבים מזהים");

      for (const r of detected.rows) {
        const name = r.detected_provider ?? "לא זוהה ספק";

        console.log(`  · ${name.padEnd(18)} ${r.n} מחשבים`);
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
