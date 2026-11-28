import type { FastifyInstance } from "fastify";
import { targetLabel, trusteeGate } from "../auth/trustee.ts";
import type pg from "pg";
import { z } from "zod";

import { withTenant, withPlatform } from "../db/client.ts";
import { createGuards } from "../auth/guards.ts";
import { isPlatformRole } from "../auth/rbac.ts";
import type { ActiveSession } from "../auth/session.ts";
import type { Config } from "../config.ts";
import type { Signer } from "../crypto/signing.ts";
import { composeDeviceOverlay } from "../policy/device-overlay.ts";
import { loadSchedules, describeSchedule } from "../policy/schedules.ts";

/**
 * חלונות זמן שבהם המחשב חסום.
 *
 * ההורה מגדיר "אין אינטרנט בין 22:00 ל-07:00", והסוכן אוכף. המנגנון
 * בסוכן היה קיים מזמן ומעולם לא היה אפשר להגדיר אותו.
 *
 * החלונות נשמרים בטבלה, והמדיניות החתומה נגזרת מהם ומתפרסמת מחדש
 * בכל שינוי — ומשויכת למחשב הזה בלבד. שני מחשבים באותו חשבון יכולים
 * לשאת חלונות שונים לגמרי, וזו כל הנקודה: מה שנכון לילד בן שבע אינו
 * מה שנכון לבן שבע־עשרה.
 */

/** שעה בפורמט HH:mm. בלי מחלקות תו מקוצרות, כדי שהתבנית תישאר קריאה. */
const HHMM = /^([01][0-9]|2[0-3]):[0-5][0-9]$/;

const scheduleBody = z.object({
  /*
   * ימי השבוע, 0 ראשון עד 6 שבת. ריק פירושו כל יום.
   *
   * המספור הוא של DayOfWeek ב-.NET, כי זה מה שהסוכן משווה מולו.
   * מספור משלנו היה מחייב תרגום בשני צדדים, ותרגום כזה נשבר בשקט.
   */
  days: z.array(z.number().int().min(0).max(6)).max(7).default([]),

  from: z.string().regex(HHMM, "שעה בפורמט HH:mm"),
  to: z.string().regex(HHMM, "שעה בפורמט HH:mm"),

  label: z.string().trim().max(60).optional(),
});

const SYSTEM = {
  userId: "00000000-0000-0000-0000-000000000000",
  reason: "רישום ביומן ביקורת",
};

async function audit(
  pool: pg.Pool,
  session: ActiveSession,
  entry: { action: string; targetId?: string; tenantId?: string | null; payload?: unknown },
): Promise<void> {
  await withPlatform(pool, SYSTEM, async (tx) => {
    await tx.query(
      `INSERT INTO audit_log
         (actor_type, actor_id, action, target_type, target_id, tenant_id, payload)
       VALUES ($1, $2, $3, 'device', $4, $5, $6)`,
      [
        isPlatformRole(session.user.role) ? "platform_user" : "tenant_user",
        session.user.userId,
        entry.action,
        entry.targetId ?? null,
        entry.tenantId ?? session.user.tenantId,
        JSON.stringify(entry.payload ?? {}),
      ],
    );
  });
}

interface Deps {
  pool: pg.Pool;
  config: Config;
  signer: Signer;
}

export async function registerScheduleRoutes(
  app: FastifyInstance,
  deps: Deps,
): Promise<void> {
  const { pool, config, signer } = deps;
  const guards = createGuards(pool, config);
  const base = [guards.requireSession, guards.requirePlatformMfa];

  /**
   * מפרסם מדיניות למחשב אחד, ובה החלונות הנוכחיים שלו.
   *
   * ההרכבה עצמה משותפת לכל מה שחל על מחשב בודד — שעות חסימה
   * ורשימה לבנה — ויושבת ב-device-overlay.ts. היא הייתה כתובה כאן
   * פעם, בנפרד מזו שרצה בעליית השרת, ושתיהן נפרדו בשקט: זו בחרה
   * מספר גרסה חלש יותר ולא נשאה את דגל חסימת הרשתות, וההיא מחקה
   * את השיוך כשלא נשארו שעות. שמירה ואחריה אתחול הפיקו שתי
   * מדיניות שונות לאותו מחשב.
   *
   * מחזיר את הגרסה שהמחשב יחזיק. null כשאינה ידועה.
   */
  async function republish(
    tenantId: string,
    deviceId: string,
    publishedBy: string,
  ): Promise<number | null> {
    const result = await composeDeviceOverlay(pool, signer, { tenantId, deviceId, publishedBy });

    return result.version;
  }

  /** בעלות: מחשב שאינו של הדייר אינו קיים מבחינתו. */
  async function ownsDevice(tenantId: string, deviceId: string): Promise<boolean> {
    return withTenant(pool, tenantId, async (tx) => {
      const r = await tx.query(
        "SELECT 1 FROM devices WHERE id = $1 AND tenant_id = $2",
        [deviceId, tenantId],
      );

      return (r.rowCount ?? 0) > 0;
    });
  }

  app.get<{ Params: { id: string } }>(
    "/api/portal/v1/devices/:id/schedules",
    { preHandler: [...base, guards.requirePermission("devices.viewOwn")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;

      if (!tenantId) return reply.send({ schedules: [] });

      const rows = await withTenant(pool, tenantId, (tx) =>
        loadSchedules(tx, request.params.id));

      return reply.send({
        schedules: rows.map((row) => ({
          id: row.id,
          days: row.days,
          from: row.from_time.slice(0, 5),
          to: row.to_time.slice(0, 5),
          label: row.label,
          enabled: row.enabled,
          description: describeSchedule(row),
        })),
      });
    },
  );

  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/devices/:id/schedules",
    { preHandler: [...base, guards.requirePermission("devices.lockout")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;

      if (!tenantId) return reply.code(400).send({ error: "החשבון אינו משויך לדייר" });

      const parsed = scheduleBody.safeParse(request.body);

      if (!parsed.success) {
        return reply.code(400).send({
          error: parsed.error.issues[0]?.message ?? "בקשה לא תקינה",
        });
      }

      /*
       * חלון באורך אפס.
       *
       * אפשר לפרש אותו כ"לא חוסם" או כ"חוסם תמיד", ושני פירושים
       * לאותה שורה הם שורה שלא נבדקה. נדחה כאן, עם הסבר, במקום
       * להיתפס באילוץ במסד בלי הודעה מובנת.
       */
      if (parsed.data.from === parsed.data.to) {
        return reply.code(400).send({
          error: "שעת ההתחלה והסיום זהות, ולכן לא ייחסם דבר.",
        });
      }

      if (!await ownsDevice(tenantId, request.params.id)) {
        return reply.code(404).send({ error: "המחשב אינו קיים" });
      }

      const id = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query<{ id: string }>(
          `INSERT INTO device_schedules
             (device_id, tenant_id, days, from_time, to_time, label, created_by)
           VALUES ($1, $2, $3::smallint[], $4::time, $5::time, $6, $7)
           RETURNING id`,
          [
            request.params.id,
            tenantId,
            parsed.data.days,
            parsed.data.from,
            parsed.data.to,
            parsed.data.label ?? null,
            session.user.userId,
          ],
        );

        return r.rows[0]!.id;
      });

      const version = await republish(tenantId, request.params.id, session.user.userId);

      await audit(pool, session, {
        action: "device.schedule.added",
        targetId: request.params.id,
        tenantId,
        payload: { from: parsed.data.from, to: parsed.data.to, days: parsed.data.days, version },
      });

      return reply.send({
        ok: true,
        id,
        version,
        note: "המחשב יקבל את השינוי בפעימה הבאה, בדרך כלל תוך שלוש דקות.",
      });
    },
  );

  app.delete<{ Params: { id: string; scheduleId: string } }>(
    "/api/portal/v1/devices/:id/schedules/:scheduleId",
    { preHandler: [...base, guards.requirePermission("devices.lockout")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;

      if (!tenantId) return reply.code(400).send({ error: "החשבון אינו משויך לדייר" });

      {
        const where = await targetLabel(tenantId, { deviceId: request.params.id });

        if (await trusteeGate(request, reply, `למחוק שעות חסימה ${where}`)) return reply;
      }

      const removed = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query(
          `DELETE FROM device_schedules
            WHERE id = $1 AND device_id = $2 AND tenant_id = $3`,
          [request.params.scheduleId, request.params.id, tenantId],
        );

        return (r.rowCount ?? 0) > 0;
      });

      if (!removed) return reply.code(404).send({ error: "שעות החסימה אינן קיימות" });

      const version = await republish(tenantId, request.params.id, session.user.userId);

      await audit(pool, session, {
        action: "device.schedule.removed",
        targetId: request.params.id,
        tenantId,
        payload: { scheduleId: request.params.scheduleId, version },
      });

      return reply.send({ ok: true, version });
    },
  );
}
