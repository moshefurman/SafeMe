import pg from "pg";
import { createPool, withPlatform, withTenant } from "../src/db/client.ts";

/**
 * POC: מוכיח שהמאפיינים הביטחוניים שבאפיון אכן נאכפים על ידי בסיס הנתונים,
 * ולא רק מתוארים בתיעוד.
 *
 * כל בדיקה כאן מנסה לעשות משהו אסור ומצפה להיכשל. בדיקה שעוברת בשקט
 * היא בדיקה חסרת ערך, ולכן כל אחת מדווחת מה בדיוק היא ניסתה.
 *
 * הרצה:
 *   DATABASE_URL_APP=postgres://safeme_app:...@localhost:55432/safeme \
 *   DATABASE_URL=postgres://postgres:...@localhost:55432/safeme \
 *   node scripts/poc.ts
 */

const APP_URL = process.env["DATABASE_URL_APP"];
const SUPER_URL = process.env["DATABASE_URL"];

if (!APP_URL || !SUPER_URL) {
  console.error("חסר DATABASE_URL_APP או DATABASE_URL");
  process.exit(1);
}

let passed = 0;
let failed = 0;

function ok(title: string, detail: string): void {
  passed += 1;
  console.log(`  ✓ ${title}`);
  if (detail) console.log(`      ${detail}`);
}

function bad(title: string, detail: string): void {
  failed += 1;
  console.log(`  ✗ ${title}`);
  console.log(`      ${detail}`);
}

function section(title: string): void {
  console.log(`\n${title}`);
  console.log("─".repeat(64));
}

/** מריץ פעולה שאמורה להיכשל, ומחזיר את הודעת השגיאה. */
async function expectFailure(fn: () => Promise<unknown>): Promise<string | null> {
  try {
    await fn();
    return null;
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}

const PLATFORM_ACTOR = { userId: "00000000-0000-0000-0000-000000000001", reason: "הרצת POC" };

async function main(): Promise<void> {
  const pool = createPool({ connectionString: APP_URL!, applicationName: "safeme-poc" });
  const superClient = new pg.Client({ connectionString: SUPER_URL! });
  await superClient.connect();

  // ─────────────────────────────────────────────── הכנת נתוני בדיקה
  section("הכנה: שתי משפחות, מחשב לכל אחת");

  const seed = await withPlatform(pool, PLATFORM_ACTOR, async (tx) => {
    await tx.query("DELETE FROM devices");
    await tx.query("DELETE FROM tenants");

    const floor = JSON.stringify({ mode: "enforce", onRedAction: "lockout", minScoreForGreen: 85 });

    const a = await tx.query<{ id: string }>(
      `INSERT INTO tenants (type, name, trial_started_at, trial_ends_at)
       VALUES ('family', 'משפחת א', now(), now() + interval '30 days')
       RETURNING id`,
    );
    const b = await tx.query<{ id: string }>(
      `INSERT INTO tenants (type, name, trial_started_at, trial_ends_at)
       VALUES ('family', 'משפחת ב', now(), now() + interval '30 days')
       RETURNING id`,
    );

    const tenantA = a.rows[0]!.id;
    const tenantB = b.rows[0]!.id;

    const da = await tx.query<{ id: string }>(
      `INSERT INTO devices (tenant_id, hwid, display_name, install_profile, enforcement_mode, policy_floor)
       VALUES ($1, 'HWID-AAA', 'המחשב של יוסי', 'family_child', 'enforce', $2) RETURNING id`,
      [tenantA, floor],
    );
    const db = await tx.query<{ id: string }>(
      `INSERT INTO devices (tenant_id, hwid, display_name, install_profile, enforcement_mode, policy_floor)
       VALUES ($1, 'HWID-BBB', 'המחשב של דוד', 'family_child', 'enforce', $2) RETURNING id`,
      [tenantB, floor],
    );

    return { tenantA, tenantB, deviceA: da.rows[0]!.id, deviceB: db.rows[0]!.id };
  });

  ok("נוצרו שני דיירים ושני מחשבים", `דייר א ${seed.tenantA.slice(0, 8)} · דייר ב ${seed.tenantB.slice(0, 8)}`);

  // ─────────────────────────────────────────────── בידוד דיירים
  section("1 · בידוד דיירים (RLS)");

  const seenByA = await withTenant(pool, seed.tenantA, async (tx) => {
    const r = await tx.query<{ hwid: string }>("SELECT hwid FROM devices");
    return r.rows.map((x) => x.hwid);
  });

  if (seenByA.length === 1 && seenByA[0] === "HWID-AAA") {
    ok("דייר א רואה רק את המחשב שלו", `SELECT * FROM devices החזיר: ${seenByA.join(", ")}`);
  } else {
    bad("דייר א ראה מחשבים שאינם שלו", `הוחזר: ${seenByA.join(", ")}`);
  }

  // שאילתה ללא WHERE, כדי להראות שהבידוד אינו תלוי בזכירת המפתח בקוד
  const seenByB = await withTenant(pool, seed.tenantB, async (tx) => {
    const r = await tx.query<{ hwid: string }>("SELECT hwid FROM devices WHERE 1 = 1");
    return r.rows.map((x) => x.hwid);
  });

  if (seenByB.length === 1 && seenByB[0] === "HWID-BBB") {
    ok("דייר ב רואה רק את המחשב שלו", "גם בשאילתה ללא סינון לפי tenant_id");
  } else {
    bad("דייר ב ראה מחשבים שאינם שלו", `הוחזר: ${seenByB.join(", ")}`);
  }

  // ניסיון גישה ישירה למחשב של דייר אחר לפי מזהה מדויק
  const crossRead = await withTenant(pool, seed.tenantA, async (tx) => {
    const r = await tx.query("SELECT hwid FROM devices WHERE id = $1", [seed.deviceB]);
    return r.rows.length;
  });

  if (crossRead === 0) {
    ok("גישה ישירה למזהה של דייר אחר מחזירה ריק", `SELECT ... WHERE id = '${seed.deviceB.slice(0, 8)}...' → 0 שורות`);
  } else {
    bad("דלף מחשב של דייר אחר", `הוחזרו ${crossRead} שורות`);
  }

  // ניסיון לשתול שורה עבור דייר אחר
  const injectError = await expectFailure(() =>
    withTenant(pool, seed.tenantA, async (tx) =>
      tx.query(
        `INSERT INTO devices (tenant_id, hwid, install_profile, enforcement_mode, policy_floor)
         VALUES ($1, 'HWID-EVIL', 'family_child', 'enforce', '{}'::jsonb)`,
        [seed.tenantB],
      ),
    ),
  );

  if (injectError) {
    ok("כתיבה בשם דייר אחר נדחתה", injectError.split("\n")[0]!);
  } else {
    bad("הצליחה כתיבה בשם דייר אחר", "WITH CHECK לא נאכף");
  }

  // ─────────────────────────────────────────────── ברירת מחדל בטוחה
  section("2 · הקשר חסר משמעו דחייה");

  const noContext = await (async () => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const r = await client.query("SELECT count(*)::int AS n FROM devices");
      await client.query("ROLLBACK");
      return (r.rows[0] as { n: number }).n;
    } finally {
      client.release();
    }
  })();

  if (noContext === 0) {
    ok("שאילתה ללא app.tenant_id מחזירה אפס שורות", "current_tenant() מחזירה NULL, וכל השוואה מולה נכשלת");
  } else {
    bad("שאילתה ללא הקשר החזירה נתונים", `${noContext} שורות`);
  }

  // ─────────────────────────────────────────────── גישת פלטפורמה
  section("3 · גישת צוות החברה");

  const platformView = await withPlatform(pool, PLATFORM_ACTOR, async (tx) => {
    const r = await tx.query<{ hwid: string }>("SELECT hwid FROM devices ORDER BY hwid");
    return r.rows.map((x) => x.hwid);
  });

  if (platformView.length === 2) {
    ok("צוות החברה רואה את כל הדיירים", platformView.join(", "));
  } else {
    bad("צוות החברה לא רואה הכול", `הוחזר: ${platformView.join(", ")}`);
  }

  // ─────────────────────────────────────────────── מחיצות
  section("4 · בידוד גם בשאילתה ישירה למחיצה");

  const partition = await withPlatform(pool, PLATFORM_ACTOR, async (tx) => {
    await tx.query(
      `INSERT INTO heartbeats (device_id, tenant_id, sequence, status, score, payload)
       VALUES ($1, $2, 1, 'safe', 95, '{}'::jsonb)`,
      [seed.deviceA, seed.tenantA],
    );

    const r = await tx.query<{ name: string }>(
      "SELECT app.ensure_heartbeat_partition(CURRENT_DATE) AS name",
    );
    return r.rows[0]!.name;
  });

  const partitionLeak = await withTenant(pool, seed.tenantB, async (tx) => {
    const r = await tx.query(`SELECT count(*)::int AS n FROM ${partition}`);
    return (r.rows[0] as { n: number }).n;
  });

  if (partitionLeak === 0) {
    ok("דייר ב אינו רואה פעימות של דייר א", `שאילתה ישירה ל-${partition} → 0 שורות`);
  } else {
    bad("שאילתה ישירה למחיצה עקפה את הבידוד", `${partitionLeak} שורות דלפו`);
  }

  // ─────────────────────────────────────────────── יומן ביקורת
  section("5 · יומן ביקורת בלתי ניתן לשינוי");

  await withPlatform(pool, PLATFORM_ACTOR, async (tx) =>
    tx.query(
      `INSERT INTO audit_log (actor_type, action, tenant_id, payload)
       VALUES ('platform_user', 'uninstall.code.issued', $1, '{"operator":"op-17"}'::jsonb)`,
      [seed.tenantA],
    ),
  );

  const appUpdate = await expectFailure(() =>
    withPlatform(pool, PLATFORM_ACTOR, async (tx) =>
      tx.query("UPDATE audit_log SET action = 'nothing.happened'"),
    ),
  );

  if (appUpdate) {
    ok("האפליקציה אינה יכולה לערוך את היומן", appUpdate.split("\n")[0]!);
  } else {
    bad("האפליקציה ערכה את יומן הביקורת", "REVOKE לא נאכף");
  }

  // שכבה שנייה: גם מי שיש לו הרשאות מלאות נחסם על ידי הטריגר
  const superDelete = await expectFailure(() =>
    superClient.query("DELETE FROM audit_log"),
  );

  if (superDelete) {
    ok("גם superuser אינו יכול למחוק מהיומן", superDelete.split("\n")[0]!);
  } else {
    bad("superuser מחק מיומן הביקורת", "הטריגר לא פעל");
  }

  // ─────────────────────────────────────────────── כללי ההסרה
  section("6 · כללי ההסרה נאכפים בסכמה");

  const shortCooldown = await expectFailure(() =>
    withPlatform(pool, PLATFORM_ACTOR, async (tx) =>
      tx.query(
        `INSERT INTO uninstall_requests
           (device_id, tenant_id, challenge, challenge_nonce, challenge_issued_at,
            id_verified, card_verified, response_issued_at, effective_at)
         VALUES ($1, $2, 'ABC', '\\x00'::bytea, now(), true, true, now(), now() + interval '5 minutes')`,
        [seed.deviceA, seed.tenantA],
      ),
    ),
  );

  if (shortCooldown) {
    ok("חלון צינון קצר מ-30 דקות נדחה", "CHECK uninstall_cooldown_30m");
  } else {
    bad("התקבל חלון צינון קצר מ-30 דקות", "הכלל מ-7.5 אינו נאכף");
  }

  const noVerification = await expectFailure(() =>
    withPlatform(pool, PLATFORM_ACTOR, async (tx) =>
      tx.query(
        `INSERT INTO uninstall_requests
           (device_id, tenant_id, challenge, challenge_nonce, challenge_issued_at,
            id_verified, card_verified, response_issued_at, effective_at)
         VALUES ($1, $2, 'ABC', '\\x01'::bytea, now(), false, false, now(), now() + interval '31 minutes')`,
        [seed.deviceA, seed.tenantA],
      ),
    ),
  );

  if (noVerification) {
    ok("הנפקת קוד ללא אימות ת\"ז ואשראי נדחתה", "CHECK uninstall_requires_verification");
  } else {
    bad("הונפק קוד בלי אימות זהות", "הכלל מ-7.1 אינו נאכף");
  }

  const validRequest = await expectFailure(() =>
    withPlatform(pool, PLATFORM_ACTOR, async (tx) =>
      tx.query(
        `INSERT INTO uninstall_requests
           (device_id, tenant_id, challenge, challenge_nonce, challenge_issued_at,
            id_verified, card_verified, response_issued_at, effective_at)
         VALUES ($1, $2, 'ABC', '\\x02'::bytea, now(), true, true, now(), now() + interval '30 minutes')`,
        [seed.deviceA, seed.tenantA],
      ),
    ),
  );

  if (!validRequest) {
    ok("בקשה תקינה מתקבלת", "אימות מלא + חלון צינון של 30 דקות");
  } else {
    bad("בקשה תקינה נדחתה", validRequest.split("\n")[0]!);
  }

  // ─────────────────────────────────────────────── מגבלות מבניות
  section("7 · מה שהמבנה עצמו אוסר");

  const panColumn = await superClient.query<{ n: string }>(
    `SELECT count(*) AS n FROM information_schema.columns
     WHERE table_name = 'verification_profiles'
       AND column_name ~* '(pan|cvv|card_number|full_id|id_number)'`,
  );

  if (panColumn.rows[0]!.n === "0") {
    ok("אין עמודה למספר אשראי מלא, ל-CVV או לת\"ז מלאה", "verification_profiles מכיל טוקן, 4 ספרות ו-hash בלבד");
  } else {
    bad("קיימת עמודה אסורה", "ראה 7.2 באפיון");
  }

  const rlsGaps = await superClient.query<{ missing: string | null }>(
    `SELECT string_agg(c.relname, ', ') AS missing
     FROM pg_class c
     JOIN pg_namespace n ON n.oid = c.relnamespace
     JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id'
     WHERE n.nspname = 'public' AND c.relkind IN ('r','p') AND NOT c.relrowsecurity`,
  );

  if (!rlsGaps.rows[0]!.missing) {
    ok("כל טבלה עם tenant_id מוגנת ב-RLS", "כולל מחיצות שנוצרות דינמית");
  } else {
    bad("טבלאות ללא RLS", rlsGaps.rows[0]!.missing!);
  }

  // ─────────────────────────────────────────────── ספקים
  section("8 · קטלוג ספקי הסינון");

  const providers = await withTenant(pool, seed.tenantA, async (tx) => {
    const r = await tx.query<{ key: string; display_name: string }>(
      "SELECT key, display_name FROM providers ORDER BY sort_order",
    );
    return r.rows;
  });

  if (providers.length === 4) {
    ok("ארבעת הספקים נזרעו", providers.map((p) => p.display_name).join(" · "));
  } else {
    bad("מספר ספקים לא צפוי", `${providers.length}`);
  }

  // ─────────────────────────────────────────────── סיכום
  console.log("\n" + "═".repeat(64));
  console.log(`עברו ${passed} · נכשלו ${failed}`);
  console.log("═".repeat(64));

  await superClient.end();
  await pool.end();

  if (failed > 0) process.exitCode = 1;
}

main().catch((error: unknown) => {
  console.error("\nה-POC נכשל:", error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
