import type pg from "pg";
import type { FastifyBaseLogger } from "fastify";

import { withPlatform, type TxClient } from "../db/client.ts";
import { KINDS, loadContext, markNotified, sendToAll, type AlertKind, type Notify } from "../notify/alerts.ts";
import { digestMessage, type DigestItem } from "../notify/mailer.ts";
import { decideDelivery, digestDue, localHour } from "../notify/settings.ts";

/**
 * העובד שמוסר את מה שהמתין.
 *
 * שלושה דברים מגיעים לכאן, ולכולם אותו טיפול:
 *
 *   סיכום יומי   ההורה בחר "יומי" לסוג הזה. יוצא פעם ביום, בבוקר.
 *   שעות שקט     ההורה ביקש מיד, אבל זה קרה בלילה. יוצא כשהשקט נגמר.
 *   כשל בשליחה   הספק דחה. מנסים שוב בסבב הבא, עד שיצליח.
 *
 * מה שמאחד אותם: ההתראה כבר נרשמה, ואיחור עדיף על אובדן. מה שמפריד:
 * מתי. ההחלטה כאן נעשית לפי אותם כללים שהמסלול המיידי משתמש בהם,
 * כדי ששינוי הגדרה באמצע ההמתנה יכובד — הורה שכיבה סוג התראה לא
 * אמור לקבל אותו בבוקר בגלל שהוא נפתח אתמול.
 */

const LOCK_KEY = 0x5a_fe_d1_6e;

/** כל כמה זמן. מספיק תדיר כדי ששעות שקט ייגמרו בזמן. */
const TICK_MS = 5 * 60_000;

const SYSTEM = {
  userId: "00000000-0000-0000-0000-000000000000",
  reason: "מסירת התראות שהמתינו",
};

interface PendingRow {
  id: string;
  tenant_id: string;
  kind: AlertKind;
  detail: string | null;
  first_seen_at: Date;
  resolved_at: Date | null;
  device_name: string;
}

export interface DigestRun {
  tenants: number;
  sent: number;
  /** התראות שההורה כיבה בינתיים. נמחקות מההמתנה בלי לשלוח. */
  dropped: number;
  failed: number;
}

/**
 * סבב אחד. מיוצא כדי שאפשר יהיה להריץ אותו בבדיקה בלי להמתין.
 */
export async function deliverPending(
  pool: pg.Pool,
  notify: Notify,
  now: Date = new Date(),
): Promise<DigestRun> {
  return withPlatform(pool, SYSTEM, async (tx) => {
    const lock = await tx.query<{ acquired: boolean }>(
      "SELECT pg_try_advisory_xact_lock($1) AS acquired",
      [LOCK_KEY],
    );

    if (!lock.rows[0]?.acquired) {
      return { tenants: 0, sent: 0, dropped: 0, failed: 0 };
    }

    const pending = await tx.query<PendingRow>(
      `SELECT a.id, a.tenant_id, a.kind, a.detail, a.first_seen_at, a.resolved_at,
              COALESCE(d.display_name, d.machine_name, 'מחשב ללא שם') AS device_name
         FROM alerts a
         JOIN devices d ON d.id = a.device_id
        WHERE a.deferred
        ORDER BY a.tenant_id, a.first_seen_at`,
    );

    const byTenant = new Map<string, PendingRow[]>();

    for (const row of pending.rows) {
      const list = byTenant.get(row.tenant_id) ?? [];
      list.push(row);
      byTenant.set(row.tenant_id, list);
    }

    const run: DigestRun = { tenants: byTenant.size, sent: 0, dropped: 0, failed: 0 };

    for (const [tenantId, rows] of byTenant) {
      const outcome = await deliverForTenant(tx, notify, tenantId, rows, now);

      run.sent += outcome.sent;
      run.dropped += outcome.dropped;
      run.failed += outcome.failed;
    }

    return run;
  });
}

async function deliverForTenant(
  tx: TxClient,
  notify: Notify,
  tenantId: string,
  rows: readonly PendingRow[],
  now: Date,
): Promise<{ sent: number; dropped: number; failed: number }> {
  const context = await loadContext(tx, tenantId);

  // בלי כתובת אין למי. ההתראות נשארות ממתינות עד שתהיה.
  if (context === null) return { sent: 0, dropped: 0, failed: 0 };

  const hour = localHour(now);
  const dailyDue = digestDue(now, context.lastDigestAt);

  const due: PendingRow[] = [];
  const dropped: string[] = [];
  let includesDaily = false;

  for (const row of rows) {
    const info = KINDS[row.kind];

    // סוג לא מוכר — נשאר משורה ישנה או מקוד עתידי. לא נוגעים.
    if (!info) continue;

    const decision = decideDelivery(context.settings, info.setting, hour);

    if (decision.send === "never") {
      dropped.push(row.id);
      continue;
    }

    if (decision.send === "digest" && decision.reason === "channel") {
      if (dailyDue) {
        due.push(row);
        includesDaily = true;
      }
      continue;
    }

    // "מיד" שנדחה בגלל שקט, או שנכשל: יוצא ברגע שהשקט נגמר
    if (decision.send === "now") due.push(row);
  }

  if (dropped.length > 0) {
    await tx.query(
      "UPDATE alerts SET deferred = false WHERE id = ANY($1::uuid[])",
      [dropped],
    );
  }

  if (due.length === 0) return { sent: 0, dropped: dropped.length, failed: 0 };

  const items: DigestItem[] = due.map((row) => ({
    deviceName: row.device_name,
    headline: KINDS[row.kind].headline,
    detail: row.detail ?? "",
    openedAt: row.first_seen_at,
    resolvedAt: row.resolved_at,
  }));

  const ok = await sendToAll(
    notify.mailer,
    digestMessage({ to: "", items, portalUrl: notify.portalUrl }),
    context.recipients,
  );

  // כשל משאיר הכול ממתין. הסבב הבא ינסה שוב.
  if (!ok) return { sent: 0, dropped: dropped.length, failed: due.length };

  await markNotified(tx, due.map((row) => row.id), now);

  if (includesDaily) {
    await tx.query(
      "UPDATE notification_settings SET last_digest_at = $2 WHERE tenant_id = $1",
      [tenantId, now],
    );
  }

  return { sent: due.length, dropped: dropped.length, failed: 0 };
}

/**
 * מפעיל את העובד על תזמון. מחזיר פונקציית עצירה.
 */
export function startDigestWorker(
  pool: pg.Pool,
  log: FastifyBaseLogger,
  notify: Notify,
): () => void {
  let stopped = false;

  const tick = async (): Promise<void> => {
    if (stopped) return;

    try {
      const result = await deliverPending(pool, notify);

      if (result.sent > 0 || result.failed > 0 || result.dropped > 0) {
        log.info(result, "התראות שהמתינו");
      }
    } catch (error) {
      log.error({ err: error }, "מסירת התראות שהמתינו נכשלה");
    }
  };

  const timer = setInterval(() => void tick(), TICK_MS);

  timer.unref();

  void tick();

  return () => {
    stopped = true;
    clearInterval(timer);
  };
}
