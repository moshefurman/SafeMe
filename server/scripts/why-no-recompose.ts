/**
 * למה ההרכבה לא פרסמה.
 *
 * מריץ בדיוק את אותם צעדים כמו rebuildTenantPolicies, ומדפיס מה
 * הוא רואה בכל אחד — בלי לפרסם דבר.
 *
 * נכתב אחרי שההרכבה רצה בשרת, לא עשתה כלום, ולא הייתה דרך לדעת
 * למה בלי לקרוא את יומן הפריסה. זו אותה תקלה שחזרה כל הלילה
 * בצורות שונות: מנגנון שפועל ואין לו איך לומר מה החליט.
 *
 * אינו משנה דבר. קריאה בלבד.
 *
 *   node scripts/why-no-recompose.ts
 */

import pg from "pg";

import { sslFor } from "../src/db/client.ts";

function fail(message: string): never {
  console.error(`\n  ${message}\n`);
  process.exit(1);
}

/** אותה השוואה כמו בהרכבה: בלי חותמת הזמן, ובסדר מפתחות יציב. */
function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;

  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([k]) => k !== "issuedUtc")
    .sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0));

  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(",")}}`;
}

function netfreeMarkers(body: Record<string, unknown>): string {
  const providers = body["providers"];

  if (!Array.isArray(providers)) return "אין רשימת ספקים";

  const nf = providers.find(
    (p) => (p as Record<string, unknown>)["id"] === "netfree",
  ) as Record<string, unknown> | undefined;

  if (!nf) return `${providers.length} ספקים, נטפרי איננה ביניהם`;

  const markers = nf["httpMarkers"] as Record<string, unknown> | undefined;

  if (!markers) return "נטפרי קיימת, httpMarkers חסר";

  const probes = Array.isArray(markers["probes"]) ? markers["probes"].length : 0;

  return `url=${markers["url"] ?? "חסר"} · ${probes} גששים`;
}

async function main(): Promise<void> {
  const url = process.env["DATABASE_URL"];

  if (!url) fail("חסר DATABASE_URL.");

  const client = new pg.Client({ connectionString: url, ssl: sslFor(url) });
  await client.connect();

  try {
    console.log("=".repeat(64));
    console.log("  למה ההרכבה לא פרסמה");
    console.log("=".repeat(64));

    // ---- 1. הבסיס ----

    const base = await client.query<{ version: number; body: Record<string, unknown> }>(
      `SELECT version, body FROM policies
        WHERE tenant_id IS NULL
        ORDER BY version DESC LIMIT 1`,
    );

    const baseRow = base.rows[0];

    console.log("");
    console.log("1. הבסיס שההרכבה קוראת");
    console.log("-".repeat(64));

    if (!baseRow) {
      console.log("  ✗ אין מדיניות בסיס. ההרכבה יוצאת מיד ומחזירה 0.");
      return;
    }

    console.log(`  גרסה ${baseRow.version}`);
    console.log(`  נטפרי: ${netfreeMarkers(baseRow.body)}`);

    // ---- 2. הדיירים ----

    const tenants = await client.query<{ tenant_id: string }>(
      "SELECT DISTINCT tenant_id FROM policies WHERE tenant_id IS NOT NULL",
    );

    console.log("");
    console.log(`2. דיירים עם מדיניות משלהם: ${tenants.rowCount}`);
    console.log("-".repeat(64));

    for (const { tenant_id: tenantId } of tenants.rows) {
      const own = await client.query<{ version: number; body: Record<string, unknown> }>(
        `SELECT p.version, p.body FROM policies p
          WHERE p.tenant_id = $1
            AND NOT EXISTS (
              SELECT 1 FROM device_policy_assignments a WHERE a.policy_id = p.id
            )
          ORDER BY p.version DESC LIMIT 1`,
        [tenantId],
      );

      const ownRow = own.rows[0];

      console.log("");
      console.log(`  דייר ${tenantId}`);

      if (!ownRow) {
        console.log("    אין לו שורה שאינה משויכת למחשב. ההרכבה מדלגת עליו.");
        continue;
      }

      console.log(`    השורה שנבחרת : גרסה ${ownRow.version}`);
      console.log(`    נטפרי בה     : ${netfreeMarkers(ownRow.body)}`);

      const ownEnforcement = (ownRow.body["enforcement"] ?? {}) as Record<string, unknown>;
      const baseEnforcement = (baseRow.body["enforcement"] ?? {}) as Record<string, unknown>;

      const overlay = ownEnforcement["egress"] === undefined
        ? {}
        : { egress: ownEnforcement["egress"] };

      console.log(`    שכבת egress  : ${Object.keys(overlay).length > 0 ? "קיימת" : "אין"}`);

      const composed = {
        ...baseRow.body,
        enforcement: { ...baseEnforcement, ...overlay },
      };

      console.log(`    נטפרי במורכב : ${netfreeMarkers(composed)}`);

      const same = canonical(ownRow.body) === canonical(composed);

      if (same) {
        console.log("    ✗ ההשוואה אומרת שהם זהים, ולכן אין פרסום.");
        console.log("      וזו התשובה: אם התוכן שונה בעליל, הבאג בהשוואה.");
      } else {
        console.log("    ✓ שונים — ההרכבה אמורה לפרסם גרסה חדשה.");
        console.log("      אם היא לא פרסמה, החריגה נבלעה. ראה יומן הפריסה.");
      }
    }

    console.log("");
    console.log("=".repeat(64));
  } finally {
    await client.end();
  }
}

main().catch((error: unknown) => {
  fail(error instanceof Error ? error.message : String(error));
});
