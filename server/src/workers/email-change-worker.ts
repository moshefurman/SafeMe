import type pg from "pg";
import type { FastifyBaseLogger } from "fastify";

import { withPlatform } from "../db/client.ts";

/**
 * מחיל בקשות להחלפת כתובת שהחלון שלהן נגמר.
 *
 * הבקשה נשמרת ואינה מבוצעת מיד, ולכן מישהו חייב להחיל אותה כשהזמן
 * מגיע. בלי העובד הזה ההשהיה לא הייתה השהיה אלא ביטול שקט — הבקשה
 * הייתה יושבת במסד לנצח וההורה היה בטוח ששינה כתובת.
 *
 * רץ בתדירות נמוכה בכוונה: החלון הוא 24 שעות, ואיחור של דקות אינו
 * משנה דבר.
 */

const SYSTEM = {
  userId: "00000000-0000-0000-0000-000000000000",
  reason: "החלת החלפת כתובת התראות",
};

export interface ApplyResult {
  applied: number;
}

/**
 * מחיל את כל מה שהבשיל.
 *
 * ההחלה והסימון קורים באותה עסקה: בקשה שהוחלה בלי שסומנה הייתה
 * מוחלת שוב בסבב הבא, ובקשה שסומנה בלי שהוחלה הייתה נעלמת בלי
 * לשנות דבר.
 */
export async function applyDueEmailChanges(pool: pg.Pool): Promise<ApplyResult> {
  return withPlatform(pool, SYSTEM, async (tx) => {
    const due = await tx.query<{ id: string; tenant_id: string; new_email: string }>(
      `SELECT id, tenant_id, new_email
         FROM email_change_requests
        WHERE applied_at IS NULL AND cancelled_at IS NULL AND effective_at <= now()
        ORDER BY effective_at
        LIMIT 100
        FOR UPDATE SKIP LOCKED`,
    );

    for (const row of due.rows) {
      await tx.query(
        "UPDATE notification_settings SET primary_email = $2, updated_at = now() WHERE tenant_id = $1",
        [row.tenant_id, row.new_email],
      );

      await tx.query(
        "UPDATE email_change_requests SET applied_at = now() WHERE id = $1",
        [row.id],
      );

      await tx.query(
        `INSERT INTO audit_log
           (actor_type, actor_id, action, target_type, target_id, tenant_id, payload)
         VALUES ('system', NULL, 'notifications.primaryEmail.applied',
                 'notification', $1, $2, $3)`,
        [row.id, row.tenant_id, JSON.stringify({ to: row.new_email })],
      );
    }

    return { applied: due.rows.length };
  });
}

/** מפעיל על תזמון. מחזיר פונקציית עצירה. */
export function startEmailChangeWorker(
  pool: pg.Pool,
  log: FastifyBaseLogger,
  everyMs = 5 * 60 * 1000,
): () => void {
  let stopped = false;

  const tick = async (): Promise<void> => {
    if (stopped) return;

    try {
      const result = await applyDueEmailChanges(pool);

      if (result.applied > 0) {
        log.info({ applied: result.applied }, "הוחלפו כתובות התראות שהמתינו");
      }
    } catch (error) {
      // נבלע. בקשה שלא הוחלה עכשיו תוחל בסבב הבא, והחמצת סבב
      // אינה סיבה להפיל את השרת.
      log.warn({ err: error }, "החלת החלפות כתובת נכשלה");
    }
  };

  const timer = setInterval(() => void tick(), everyMs);

  timer.unref?.();
  void tick();

  return () => {
    stopped = true;
    clearInterval(timer);
  };
}
