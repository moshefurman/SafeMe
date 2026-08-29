import type pg from "pg";
import type { FastifyBaseLogger } from "fastify";

import { withPlatform } from "../db/client.ts";
import { silentDeviceMessage, type Mailer } from "../notify/mailer.ts";
import {
  computeTransitions,
  describeSilence,
  type DeadManState,
  type DeviceSilence,
} from "../telemetry/deadman.ts";

/**
 * הסורק שמזהה מחשבים ששתקו.
 *
 * רץ בתוך תהליך ה-API ולא בתור נפרד. בהיקף של אלפי מחשבים סריקה
 * כזו היא שאילתה אחת קצרה, ותור הודעות היה תשתית נוספת בלי תמורה.
 *
 * נעילת ייעוץ של Postgres מבטיחה שרק מופע אחד סורק בכל רגע, גם
 * כשרצים כמה מופעים של השרת. בלעדיה כל מופע היה יוצר התראות משלו
 * לאותם מחשבים.
 */

/** מזהה שרירותי וקבוע לנעילה. חייב להיות ייחודי בתוך בסיס הנתונים. */
const LOCK_KEY = 0x5a_fe_11_0e;

/** כל כמה זמן לסרוק. תדיר מספיק כדי שהדשבורד יהיה עדכני. */
const SCAN_INTERVAL_MS = 2 * 60_000;

const SYSTEM = {
  userId: "00000000-0000-0000-0000-000000000000",
  reason: "סריקת מחשבים ששתקו",
};

interface Row {
  device_id: string;
  last_seen_at: Date | null;
  health: DeadManState;
}

export interface DeadManScan {
  scanned: number;
  changed: number;
  alerted: number;
}

/**
 * סריקה אחת. מיוצאת בנפרד כדי שאפשר יהיה להריץ אותה בבדיקה בלי
 * להמתין לתזמון.
 */
export async function scanOnce(
  pool: pg.Pool,
  now: Date = new Date(),
  notify?: { mailer: Mailer; portalUrl: string },
): Promise<DeadManScan> {
  return withPlatform(pool, SYSTEM, async (tx) => {
    // נעילת ייעוץ ברמת הטרנזקציה: משוחררת מעצמה בסיום, גם אם
    // הסריקה נכשלה באמצע. נעילה ברמת סשן הייתה נתקעת.
    const lock = await tx.query<{ acquired: boolean }>(
      "SELECT pg_try_advisory_xact_lock($1) AS acquired",
      [LOCK_KEY],
    );

    if (!lock.rows[0]?.acquired) {
      return { scanned: 0, changed: 0, alerted: 0 };
    }

    // רק מחשבים מותקנים, ורק כאלה שיכולים להשתנות. מחשב שכבר
    // מסומן offline לא יידרדר יותר, ואין טעם לסרוק אותו בכל מחזור.
    const rows = await tx.query<Row>(
      `SELECT s.device_id, s.last_seen_at, s.health
         FROM device_state s
         JOIN devices d ON d.id = s.device_id
        WHERE d.status = 'active'
          AND s.last_seen_at IS NOT NULL
          AND (s.health <> 'offline' OR s.last_seen_at > now() - interval '48 hours')`,
    );

    const devices: DeviceSilence[] = rows.rows.map((r) => ({
      deviceId: r.device_id,
      lastSeenAt: r.last_seen_at,
      currentHealth: r.health,
    }));

    const transitions = computeTransitions(devices, now);

    if (transitions.length === 0) {
      return { scanned: devices.length, changed: 0, alerted: 0 };
    }

    let alerted = 0;

    for (const t of transitions) {
      await tx.query(
        "UPDATE device_state SET health = $2::dead_man_state WHERE device_id = $1",
        [t.deviceId, t.to],
      );

      if (!t.raisesAlert) continue;

      // ON CONFLICT: אינדקס ייחודי מונע התראה פתוחה כפולה לאותו
      // מחשב ואותו סוג. מחשב שנעלם, חזר ונעלם שוב מקבל התראה
      // אחת שנפתחת מחדש, ולא ערימה.
      const inserted = await tx.query(
        `INSERT INTO alerts (device_id, tenant_id, kind, state, first_seen_at)
         SELECT $1, d.tenant_id, 'device.silent', 'open', now()
           FROM devices d WHERE d.id = $1
         ON CONFLICT (device_id, kind) WHERE state <> 'resolved'
         DO NOTHING`,
        [t.deviceId],
      );

      if (inserted.rowCount && inserted.rowCount > 0) {
        alerted++;

        // הודעה נשלחת רק על התראה שנפתחה עכשיו. ההתראה עצמה כבר
        // רשומה, ולכן כשל בשליחה אינו מאבד את המידע — הוא רק דוחה
        // את הידיעה עד שההורה ייכנס לפורטל.
        if (notify) await notifyOwner(tx, notify, t.deviceId, t.silentMinutes);
      }

      await tx.query(
        `INSERT INTO events (device_id, tenant_id, kind, severity, detail, occurred_at)
         SELECT $1, d.tenant_id, 'device.silent', 'critical', $2, now()
           FROM devices d WHERE d.id = $1`,
        [t.deviceId, describeSilence(t.silentMinutes)],
      );
    }

    return { scanned: devices.length, changed: transitions.length, alerted };
  });
}

/**
 * שולח הודעה לבעל החשבון.
 *
 * נכשל בשקט ובמכוון: ההתראה כבר נרשמה, וכשל בשליחה אינו סיבה
 * להפיל את הסריקה ולהשאיר את שאר המחשבים בלי בדיקה.
 */
async function notifyOwner(
  tx: { query: pg.ClientBase["query"] },
  notify: { mailer: Mailer; portalUrl: string },
  deviceId: string,
  silentMinutes: number,
): Promise<void> {
  try {
    const r = await tx.query<{ email: string; name: string }>(
      `SELECT u.email,
              COALESCE(d.display_name, d.machine_name, 'מחשב ללא שם') AS name
         FROM devices d
         JOIN users u ON u.tenant_id = d.tenant_id AND u.role = 'tenant_owner'
        WHERE d.id = $1
        LIMIT 1`,
      [deviceId],
    );

    const owner = r.rows[0];

    if (!owner) return;

    await notify.mailer.send(
      silentDeviceMessage({
        to: owner.email,
        deviceName: owner.name,
        silenceText: describeSilence(silentMinutes),
        portalUrl: notify.portalUrl,
      }),
    );
  } catch {
    // נבלע. ההתראה קיימת בפורטל בכל מקרה.
  }
}

/**
 * מפעיל את הסורק על תזמון. מחזיר פונקציית עצירה.
 */
export function startDeadManWorker(
  pool: pg.Pool,
  log: FastifyBaseLogger,
  notify?: { mailer: Mailer; portalUrl: string },
): () => void {
  let stopped = false;

  const tick = async (): Promise<void> => {
    if (stopped) return;

    try {
      const result = await scanOnce(pool, new Date(), notify);

      if (result.changed > 0) {
        log.warn(result, "מחשבים ששתקו");
      }
    } catch (error) {
      // סריקה שנכשלה לא תפיל את השרת. היא תרוץ שוב במחזור הבא.
      log.error({ err: error }, "סריקת מחשבים ששתקו נכשלה");
    }
  };

  const timer = setInterval(() => void tick(), SCAN_INTERVAL_MS);

  // unref כדי שהתזמון לא ימנע מהתהליך להיסגר בבדיקות ובכיבוי מסודר
  timer.unref();

  void tick();

  return () => {
    stopped = true;
    clearInterval(timer);
  };
}
