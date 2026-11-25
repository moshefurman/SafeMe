/**
 * מצב העדכון האוטומטי, למחשב.
 *
 * נכתב אחרי שהתברר שהמנגנון בנוי ומעולם לא נצפה עובד — ושכל ניסיון
 * לבדוק אותו דרש לנחש איפה הוא נעצר. יש שישה מקומות שבהם עדכון
 * אינו יוצא לדרך, וכולם מחזירים בשקט "אין מה להציע":
 *
 *   אין גרסה רשומה · ההפצה על אפס · הגרסה אינה חדשה יותר ·
 *   הקפיצה גדולה מדי · המחשב מחוץ לדלי · הגרסה שהמחשב מדווח משובשת
 *
 * הכלי הזה אומר איזה מהם.
 *
 * אינו משנה דבר. קריאה בלבד.
 *
 *   node scripts/update-status.ts
 */

import pg from "pg";

import { sslFor } from "../src/db/client.ts";
import { decideUpdate, parseVersion, type Release } from "../src/updates/decide.ts";

function fail(message: string): never {
  console.error(message);
  process.exit(1);
}

const REASON: Record<string, string> = {
  no_releases: "אין גרסה רשומה שההפצה שלה מעל אפס",
  unparsable_current: "הגרסה שהמחשב מדווח אינה בפורמט x.y.z",
  not_newer: "אין גרסה חדשה יותר מזו שמותקנת",
  too_old_to_jump: "הגרסה המותקנת ישנה מכדי לקפוץ ישירות",
  not_in_rollout: "המחשב מחוץ לאחוז ההפצה הנוכחי",
};

async function main(): Promise<void> {
  const url = process.env["DATABASE_URL"];

  if (!url) fail("חסר DATABASE_URL.");

  const client = new pg.Client({ connectionString: url, ssl: sslFor(url) });

  await client.connect();

  try {
    console.log("=".repeat(64));
    console.log("  FilterPlus · מצב העדכון האוטומטי");
    console.log("=".repeat(64));

    // ---------------------------------------------------------- גרסאות

    console.log("");
    console.log("גרסאות רשומות");
    console.log("-".repeat(64));

    const releases = await client.query<{
      version: string;
      rollout_percent: number;
      revoked: boolean;
      channel: string;
      size_bytes: string;
      download_url: string;
      min_from: string;
    }>(
      `SELECT version, rollout_percent, revoked_at IS NOT NULL AS revoked,
              channel, size_bytes, download_url,
              min_from_major || '.' || min_from_minor || '.' || min_from_patch AS min_from
         FROM agent_releases
        ORDER BY v_major DESC, v_minor DESC, v_patch DESC`,
    );

    if (releases.rows.length === 0) {
      console.log("  אין אף גרסה. הרץ scripts/publish-release.ts");
      console.log("  בלי זה שום מחשב לא יתעדכן, וגם הורדת המתקין תחזיר 503.");
    }

    for (const r of releases.rows) {
      const live = !r.revoked && r.rollout_percent > 0 && r.channel === "stable";
      const state = r.revoked
        ? "נפסלה"
        : r.rollout_percent === 0
          ? "רשומה, אך ההפצה על אפס — לא תוצע לאיש"
          : `${r.rollout_percent}% הפצה`;

      console.log(`  ${live ? "*" : " "} ${r.version.padEnd(9)} ${state}`);
      console.log(`      מ-${r.min_from} ומעלה · ${Math.round(Number(r.size_bytes) / 1048576)} מגה`);
      console.log(`      ${r.download_url}`);
    }

    // ---------------------------------------------------------- מחשבים

    console.log("");
    console.log("מה יוצע לכל מחשב");
    console.log("-".repeat(64));

    const devices = await client.query<{
      id: string;
      name: string;
      agent_version: string | null;
      last_seen_at: Date | null;
    }>(
      `SELECT d.id,
              COALESCE(d.display_name, d.machine_name, 'מחשב ללא שם') AS name,
              d.agent_version, s.last_seen_at
         FROM devices d
         LEFT JOIN device_state s ON s.device_id = d.id
        WHERE d.status = 'active'
        ORDER BY s.last_seen_at DESC NULLS LAST`,
    );

    if (devices.rows.length === 0) console.log("  אין מחשבים פעילים.");

    for (const device of devices.rows) {
      const candidates = await client.query<{
        version: string;
        v_major: number;
        v_minor: number;
        v_patch: number;
        download_url: string;
        sha256: string;
        size_bytes: string;
        min_from_major: number;
        min_from_minor: number;
        min_from_patch: number;
        rollout_percent: number;
        bucket: string;
      }>(
        `SELECT version, v_major, v_minor, v_patch, download_url,
                encode(sha256, 'hex') AS sha256, size_bytes,
                min_from_major, min_from_minor, min_from_patch, rollout_percent,
                app.rollout_bucket($1, version) AS bucket
           FROM agent_releases
          WHERE revoked_at IS NULL AND channel = 'stable' AND rollout_percent > 0
          ORDER BY v_major DESC, v_minor DESC, v_patch DESC
          LIMIT 20`,
        [device.id],
      );

      const buckets = new Map<string, number>();

      const list: Release[] = candidates.rows.map((r) => {
        buckets.set(r.version, Number(r.bucket));

        return {
          version: r.version,
          parsed: { major: r.v_major, minor: r.v_minor, patch: r.v_patch },
          downloadUrl: r.download_url,
          sha256: r.sha256,
          sizeBytes: Number(r.size_bytes),
          minFrom: {
            major: r.min_from_major,
            minor: r.min_from_minor,
            patch: r.min_from_patch,
          },
          rolloutPercent: r.rollout_percent,
        };
      });

      const current = device.agent_version ?? "לא ידועה";
      const seen = device.last_seen_at
        ? device.last_seen_at.toLocaleString("he-IL")
        : "מעולם";

      console.log("");
      console.log(`  ${device.name}`);
      console.log(`     מותקן: ${current} · דיווח אחרון: ${seen}`);

      if (device.agent_version === null) {
        console.log("     -> לא יוצע דבר: המחשב לא דיווח גרסה");
        continue;
      }

      const decision = decideUpdate(
        device.agent_version,
        list,
        (v) => buckets.get(v) ?? 100,
      );

      if (decision.offer === null) {
        console.log(`     -> לא יוצע דבר: ${REASON[decision.reason] ?? decision.reason}`);

        // הדלי הוא הסיבה היחידה שאפשר לתקן בלי לפרסם גרסה
        if (decision.reason === "not_in_rollout") {
          for (const [version, bucket] of buckets) {
            const percent = list.find((r) => r.version === version)?.rolloutPercent ?? 0;

            console.log(`        ${version}: המחשב בדלי ${bucket}, ההפצה על ${percent}`);
          }

          console.log("        הרץ scripts/set-rollout.ts --rollout 100");
        }

        continue;
      }

      console.log(`     -> יוצע ${decision.offer.version}`);
      console.log(`        ${decision.offer.downloadUrl}`);
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
