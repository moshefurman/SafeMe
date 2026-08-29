import { randomBytes } from "node:crypto";
import { createPool, withPlatform } from "../src/db/client.ts";
import { loadConfig } from "../src/config.ts";
import { createUser } from "../src/routes/portal-auth.ts";

/**
 * נתוני הדגמה לפיתוח הפורטל.
 *
 * מייצר מצב שדומה למה שרואים בשטח: רוב המחשבים תקינים, אחד לא
 * מסונן, אחד בנעילה, ואחד שנותק. בלי מגוון כזה קל לבנות מסך שנראה
 * מצוין רק כשהכול ירוק.
 *
 * הרצה: npm run seed:demo
 */

const SYSTEM = { userId: "system", reason: "זריעת נתוני הדגמה" };

const DEMO_PASSWORD = "Demo-SafeMe-2026!";

interface DemoDevice {
  hwid: string;
  name: string;
  status: "safe" | "low_filter" | "unfiltered" | "blocked" | "unknown";
  score: number;
  provider: string | null;
  ssid: string | null;
  minutesAgo: number;
  health: "healthy" | "late" | "missing" | "offline";
  lockout?: boolean;
  events?: Array<{ kind: string; detail: string; hoursAgo: number }>;
}

const DEVICES: DemoDevice[] = [
  {
    hwid: "DEMO7K2M4P8R1T5V9X3Z6B0C4E",
    name: "המחשב של יוסי",
    status: "safe",
    score: 96,
    provider: "netfree",
    ssid: "COHEN-HOME",
    minutesAgo: 2,
    health: "healthy",
  },
  {
    hwid: "DEMO9F3H7J1L5N8Q2S6U0W4Y8A",
    name: "המחשב של שרה",
    status: "safe",
    score: 92,
    provider: "rimon",
    ssid: "COHEN-HOME",
    minutesAgo: 4,
    health: "healthy",
  },
  {
    hwid: "DEMO2D6G0K4M8P2R6T0V4X8Z2B",
    name: "המחשב של אבי",
    status: "low_filter",
    score: 71,
    provider: "etrog",
    ssid: "COHEN-HOME",
    minutesAgo: 3,
    health: "healthy",
    events: [
      { kind: "AiAccess", detail: "claude.ai נגיש למרות שאמור להיות חסום", hoursAgo: 1 },
      { kind: "ImageBlur", detail: "התמונה לא טושטשה", hoursAgo: 5 },
    ],
  },
  {
    hwid: "DEMO5J9L3N7Q1S5U9W3Y7A1C5E",
    name: "הנייד של מרים",
    status: "unfiltered",
    score: 24,
    provider: null,
    ssid: "COFFEE-SHOP-FREE",
    minutesAgo: 1,
    health: "healthy",
    events: [
      { kind: "ProviderIdentity", detail: "לא זוהה ספק סינון מאושר", hoursAgo: 0.2 },
      { kind: "WfpFiltersMissing", detail: "חוקי WFP נמחקו מחוץ לסוכן", hoursAgo: 0.5 },
    ],
  },
  {
    hwid: "DEMO8M2P6R0T4V8X2Z6B0D4F8H",
    name: "המחשב של דוד",
    status: "blocked",
    score: 18,
    provider: null,
    ssid: null,
    minutesAgo: 6,
    health: "healthy",
    lockout: true,
    events: [{ kind: "ClockRolledBack", detail: "שעון המערכת הוזז שעתיים אחורה", hoursAgo: 2 }],
  },
  {
    hwid: "DEMO1B5D9F3H7K1M5P9R3T7V1X",
    name: "המחשב במשרד",
    status: "unknown",
    score: 0,
    provider: null,
    ssid: null,
    minutesAgo: 260,
    health: "offline",
    events: [{ kind: "ServiceStopAttempt", detail: "נותק מהשרת מעל 4 שעות", hoursAgo: 4 }],
  },
];

async function main(): Promise<void> {
  const config = loadConfig({
    ...process.env,
    DEVICE_TOKEN_SECRET: process.env["DEVICE_TOKEN_SECRET"] ?? randomBytes(32).toString("hex"),
  });

  const pool = createPool({ connectionString: config.DATABASE_URL_APP });

  const tenantId = await withPlatform(pool, SYSTEM, async (tx) => {
    await tx.query("DELETE FROM devices WHERE hwid LIKE 'DEMO%'");
    await tx.query("DELETE FROM users  WHERE email LIKE '%@demo.safeme.test'");
    await tx.query("DELETE FROM tenants WHERE name = 'משפחת כהן'");

    const r = await tx.query<{ id: string }>(
      "INSERT INTO tenants (type, name, contact_email) VALUES ('family', 'משפחת כהן', $1) RETURNING id",
      ["parent@demo.safeme.test"],
    );

    return r.rows[0]!.id;
  });

  await createUser(pool, {
    email: "parent@demo.safeme.test",
    password: DEMO_PASSWORD,
    role: "tenant_owner",
    tenantId,
    displayName: "יעקב כהן",
  });

  await createUser(pool, {
    email: "operator@demo.safeme.test",
    password: DEMO_PASSWORD,
    role: "support_operator",
    tenantId: null,
    displayName: "נציגת מוקד",
  });

  await withPlatform(pool, SYSTEM, async (tx) => {
    const floor = JSON.stringify({
      mode: "enforce",
      onRedAction: "lockout",
      minScoreForGreen: 85,
      minScoreForYellow: 60,
      requireProvider: ["netfree", "rimon", "etrog", "nativ"],
    });

    for (const device of DEVICES) {
      const inserted = await tx.query<{ id: string }>(
        `INSERT INTO devices
           (tenant_id, hwid, display_name, machine_name, os_version, agent_version,
            install_profile, enforcement_mode, policy_floor, enrolled_at)
         VALUES ($1, $2, $3, $4, '10.0.26100', '1.0.0', 'family_child', 'enforce', $5,
                 now() - interval '40 days')
         RETURNING id`,
        [tenantId, device.hwid, device.name, device.name.replace(/\s/g, "-"), floor],
      );

      const deviceId = inserted.rows[0]!.id;

      await tx.query(
        `INSERT INTO device_state
           (device_id, tenant_id, last_seen_at, last_status, last_score, detected_provider,
            wifi_ssid, lockout_active, lockout_until, health, wfp_filter_count, policy_version,
            heartbeat_seq)
         VALUES ($1, $2, now() - ($3 || ' minutes')::interval, $4::security_status, $5, $6, $7,
                 $8, $9, $10::dead_man_state, $11, 42, 1200)`,
        [
          deviceId,
          tenantId,
          String(device.minutesAgo),
          device.status,
          device.score,
          device.provider,
          device.ssid,
          device.lockout ?? false,
          device.lockout ? new Date(Date.now() + 40 * 60_000) : null,
          device.health,
          device.lockout ? 27 : 0,
        ],
      );

      // כמה פעימות אחרונות, כדי שציר הזמן לא יהיה ריק
      for (let i = 0; i < 8; i += 1) {
        await tx.query(
          `INSERT INTO heartbeats
             (device_id, tenant_id, received_at, sequence, status, score, policy_version,
              lockout_active, payload)
           VALUES ($1, $2, now() - ($3 || ' minutes')::interval, $4, $5::security_status, $6, 42, $7, '{}'::jsonb)`,
          [
            deviceId,
            tenantId,
            String(device.minutesAgo + i * 3),
            1200 - i,
            device.status,
            Math.max(0, device.score - (i % 3)),
            device.lockout ?? false,
          ],
        );
      }

      for (const event of device.events ?? []) {
        await tx.query(
          `INSERT INTO events (device_id, tenant_id, kind, severity, detail, occurred_at)
           VALUES ($1, $2, $3, 'warning', $4, now() - ($5 || ' hours')::interval)`,
          [deviceId, tenantId, event.kind, event.detail, String(event.hoursAgo)],
        );
      }

      if (device.lockout) {
        await tx.query(
          `INSERT INTO device_commands
             (device_id, tenant_id, type, args, reason, status, delivered_at)
           VALUES ($1, $2, 'lockout', '{"minutes":"60"}', 'החיבור אינו מסונן', 'delivered', now() - interval '20 minutes')`,
          [deviceId, tenantId],
        );
      }
    }
  });

  console.log("נתוני ההדגמה נוצרו.");
  console.log(`  דייר    : משפחת כהן`);
  console.log(`  מחשבים : ${DEVICES.length}`);
  console.log();
  console.log("כניסה לפורטל:");
  console.log(`  הורה   parent@demo.safeme.test   / ${DEMO_PASSWORD}`);
  console.log(`  מוקד   operator@demo.safeme.test / ${DEMO_PASSWORD}  (ידרוש הגדרת MFA)`);

  await pool.end();
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack : error);
  process.exitCode = 1;
});
