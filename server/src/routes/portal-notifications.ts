import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

import type { FastifyInstance } from "fastify";
import type pg from "pg";
import { z } from "zod";

import { withTenant, withPlatform } from "../db/client.ts";
import { createGuards } from "../auth/guards.ts";
import { isPlatformRole } from "../auth/rbac.ts";
import type { ActiveSession } from "../auth/session.ts";
import type { Config } from "../config.ts";
import { effectiveAt } from "../notify/settings.ts";
import { emailChangeMessage, verifyRecipientMessage, type Mailer, type Message }
  from "../notify/mailer.ts";

/**
 * הגדרות ההתראות.
 *
 * שלוש רמות של שינוי, ולא אחת — כי לא כל שינוי כאן שווה בסיכונו:
 *
 *   מתי לקבל       מיידי. טעות ניתנת לתיקון בקליק.
 *   כתובת נוספת    אחרי אימות בכתובת עצמה.
 *   הכתובת הראשית  מושהה 24 שעות, ומודיע לשתי הכתובות.
 *
 * ההבחנה הזו היא כל הנקודה. מי שמשיג גישה לחשבון ההורה אינו צריך
 * לגעת בסינון: די שיפנה את ההתראות אליו, וההגנה נשארת פעילה בזמן
 * שאיש אינו רואה דבר. זו העקיפה הזולה במוצר, והיחידה שאינה
 * משאירה סימן.
 *
 * ההשהיה אינה בירוקרטיה אלא החלון שבו ההורה רואה ועוצר — ולכן
 * הביטול אינו דורש כניסה לחשבון. מי שהגיע לחשבון יכול לבטל את
 * הביטול; הקישור בתיבה הוא מה שאינו בשליטתו.
 */

const CHANNEL = z.enum(["off", "immediate", "daily"]);

const settingsBody = z.object({
  onDeviceSilent: CHANNEL.optional(),
  onUnfiltered: CHANNEL.optional(),
  onNewNetwork: CHANNEL.optional(),
  onTamper: CHANNEL.optional(),
  onLockout: CHANNEL.optional(),
  weeklyDigest: z.boolean().optional(),
  quietFrom: z.number().int().min(0).max(23).nullable().optional(),
  quietTo: z.number().int().min(0).max(23).nullable().optional(),
});

const emailBody = z.object({
  email: z.string().trim().toLowerCase().email().max(200),
});

/** camelCase בבקשה, snake_case בעמודות. המיפוי מפורש כדי שלא ינחשו. */
const COLUMN: Record<string, string> = {
  onDeviceSilent: "on_device_silent",
  onUnfiltered: "on_unfiltered",
  onNewNetwork: "on_new_network",
  onTamper: "on_tamper",
  onLockout: "on_lockout",
  weeklyDigest: "weekly_digest",
  quietFrom: "quiet_from",
  quietTo: "quiet_to",
};

const SYSTEM_ACTOR = {
  userId: "00000000-0000-0000-0000-000000000000",
  reason: "רישום ביומן ביקורת",
};

const tokenHash = (raw: string): Buffer =>
  createHash("sha256").update(raw, "utf8").digest();

/**
 * השוואה בזמן קבוע.
 *
 * אסימון הביטול מגיע מקישור פומבי, ולכן הוא בדיוק המקום שבו השוואה
 * רגילה מדליפה מידע לפי זמן התגובה.
 */
function hashMatches(candidate: Buffer, stored: Buffer): boolean {
  return candidate.length === stored.length && timingSafeEqual(candidate, stored);
}

async function audit(
  pool: pg.Pool,
  session: ActiveSession | null,
  entry: { action: string; targetId?: string; tenantId?: string | null; payload?: unknown },
): Promise<void> {
  await withPlatform(pool, SYSTEM_ACTOR, async (tx) => {
    await tx.query(
      `INSERT INTO audit_log
         (actor_type, actor_id, action, target_type, target_id, tenant_id, payload)
       VALUES ($1, $2, $3, 'notification', $4, $5, $6)`,
      [
        session === null
          ? "system"
          : isPlatformRole(session.user.role) ? "platform_user" : "tenant_user",
        session?.user.userId ?? null,
        entry.action,
        entry.targetId ?? null,
        entry.tenantId ?? session?.user.tenantId ?? null,
        JSON.stringify(entry.payload ?? {}),
      ],
    );
  });
}

interface Deps {
  pool: pg.Pool;
  config: Config;
  mailer: Mailer;
}

export async function registerNotificationRoutes(
  app: FastifyInstance,
  deps: Deps,
): Promise<void> {
  const { pool, config, mailer } = deps;
  const guards = createGuards(pool, config);
  const base = [guards.requireSession, guards.requirePlatformMfa];

  /**
   * שולח בשקט.
   *
   * כשל בשליחה אינו מפיל את הפעולה: ההגדרה כבר נשמרה, והתשובה
   * למשתמש אומרת מה קרה. הודעה שלא יצאה גרועה מפעולה שלא בוצעה,
   * ושתיהן גרועות משגיאה שמסתירה איזו מהן קרתה.
   */
  const trySend = async (message: Message): Promise<boolean> => {
    try {
      await mailer.send(message);
      return true;
    } catch (error) {
      app.log.warn({ err: error, to: message.to }, "שליחת הודעת התראות נכשלה");
      return false;
    }
  };

  // ---------------------------------------------------------------- קריאה

  app.get(
    "/api/portal/v1/notifications",
    { preHandler: [...base, guards.requirePermission("devices.viewOwn")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;

      if (!tenantId) return reply.code(400).send({ error: "החשבון אינו משויך לדייר" });

      const data = await withTenant(pool, tenantId, async (tx) => {
        const settings = await tx.query(
          `SELECT primary_email, on_device_silent, on_unfiltered, on_new_network,
                  on_tamper, on_lockout, weekly_digest, quiet_from, quiet_to, updated_at
             FROM notification_settings WHERE tenant_id = $1`,
          [tenantId],
        );

        const recipients = await tx.query(
          `SELECT id, email, verified_at, created_at
             FROM notification_recipients
            WHERE tenant_id = $1
            ORDER BY created_at`,
          [tenantId],
        );

        const pending = await tx.query(
          `SELECT id, from_email, new_email, requested_at, effective_at
             FROM email_change_requests
            WHERE tenant_id = $1 AND applied_at IS NULL AND cancelled_at IS NULL`,
          [tenantId],
        );

        return {
          settings: settings.rows[0] ?? null,
          recipients: recipients.rows,
          pendingChange: pending.rows[0] ?? null,
        };
      });

      return reply.send(data);
    },
  );

  // ---------------------------------------------------------------- מתי לקבל

  /**
   * שינוי מיידי, ובמכוון.
   *
   * כיבוי התראה אינו מסתיר דבר: כל מה שקורה נשאר בפורטל ובהיסטוריה,
   * וההגדרה נוגעת רק למה שנדחף לתיבה. הסיכון קטן מספיק שהשהיה הייתה
   * רק מרגילה את ההורה שההגדרות לא מגיבות.
   */
  app.put(
    "/api/portal/v1/notifications",
    { preHandler: [...base, guards.requirePermission("enrollTokens.create")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;

      if (!tenantId) return reply.code(400).send({ error: "החשבון אינו משויך לדייר" });

      const parsed = settingsBody.safeParse(request.body ?? {});

      if (!parsed.success) return reply.code(400).send({ error: "בקשה לא תקינה" });

      /*
       * שעות שקט הן זוג. חצי זוג היה משאיר חלון פתוח בקצה אחד,
       * והאילוץ במסד היה דוחה את השורה — כאן ההודעה ברורה יותר.
       */
      if (("quietFrom" in parsed.data) !== ("quietTo" in parsed.data)) {
        return reply.code(400).send({
          error: "שעות שקט נקבעות כזוג: שעת התחלה ושעת סיום",
        });
      }

      const entries = Object.entries(parsed.data).filter(([, v]) => v !== undefined);

      if (entries.length === 0) return reply.code(400).send({ error: "אין מה לעדכן" });

      const sets = entries.map(([k], i) => `${COLUMN[k]} = $${i + 2}`);
      const values = entries.map(([, v]) => v);

      const updated = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query(
          `UPDATE notification_settings
              SET ${sets.join(", ")}, updated_at = now(), updated_by = $${entries.length + 2}
            WHERE tenant_id = $1`,
          [tenantId, ...values, session.user.userId],
        );

        return r.rowCount ?? 0;
      });

      if (updated === 0) return reply.code(404).send({ error: "לא נמצאו הגדרות לחשבון" });

      await audit(pool, session, {
        action: "notifications.updated",
        tenantId,
        payload: { fields: entries.map(([k]) => k) },
      });

      return reply.send({ ok: true });
    },
  );

  // ---------------------------------------------------------------- כתובות נוספות

  app.post(
    "/api/portal/v1/notifications/recipients",
    { preHandler: [...base, guards.requirePermission("enrollTokens.create")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;

      if (!tenantId) return reply.code(400).send({ error: "החשבון אינו משויך לדייר" });

      const parsed = emailBody.safeParse(request.body);

      if (!parsed.success) return reply.code(400).send({ error: "כתובת לא תקינה" });

      const raw = randomBytes(24).toString("base64url");
      const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

      const created = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query<{ id: string }>(
          `INSERT INTO notification_recipients
             (tenant_id, email, verify_hash, verify_expires_at, created_by)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (tenant_id, email) DO UPDATE
             SET verify_hash = EXCLUDED.verify_hash,
                 verify_expires_at = EXCLUDED.verify_expires_at
           WHERE notification_recipients.verified_at IS NULL
           RETURNING id`,
          [tenantId, parsed.data.email, tokenHash(raw), expires, session.user.userId],
        );

        const tenant = await tx.query<{ name: string }>(
          "SELECT name FROM tenants WHERE id = $1",
          [tenantId],
        );

        return { id: r.rows[0]?.id ?? null, name: tenant.rows[0]?.name ?? "החשבון שלך" };
      });

      if (created.id === null) {
        return reply.code(409).send({ error: "הכתובת כבר מאושרת ומקבלת התראות" });
      }

      const sent = await trySend(
        verifyRecipientMessage({
          to: parsed.data.email,
          tenantName: created.name,
          verifyUrl: `${config.PORTAL_URL}/notifications/verify?token=${raw}`,
        }),
      );

      await audit(pool, session, {
        action: "notifications.recipient.invited",
        targetId: created.id,
        tenantId,
        payload: { email: parsed.data.email, sent },
      });

      return reply.send({
        ok: true,
        id: created.id,
        sent,
        note: sent
          ? "נשלח אישור לכתובת. היא תתחיל לקבל התראות אחרי שבעליה יאשר."
          : "הכתובת נוספה, אך שליחת האישור נכשלה. אפשר לנסות שוב.",
      });
    },
  );

  /** אישור הכתובת. פומבי במכוון — בעל הכתובת אינו בהכרח בעל החשבון. */
  app.get<{ Querystring: { token?: string } }>(
    "/api/portal/v1/notifications/verify",
    async (request, reply) => {
      const raw = request.query.token;

      if (typeof raw !== "string" || raw.length < 16) {
        return reply.code(400).send({ error: "קישור אישור לא תקין" });
      }

      const confirmed = await withPlatform(pool, SYSTEM_ACTOR, async (tx) => {
        const r = await tx.query<{ id: string; tenant_id: string; email: string }>(
          `UPDATE notification_recipients
              SET verified_at = now(), verify_hash = NULL, verify_expires_at = NULL
            WHERE verify_hash = $1
              AND verified_at IS NULL
              AND verify_expires_at > now()
        RETURNING id, tenant_id, email`,
          [tokenHash(raw)],
        );

        return r.rows[0] ?? null;
      });

      if (confirmed === null) {
        return reply.code(410).send({ error: "הקישור אינו תקף או שכבר נוצל" });
      }

      await audit(pool, null, {
        action: "notifications.recipient.verified",
        targetId: confirmed.id,
        tenantId: confirmed.tenant_id,
        payload: { email: confirmed.email },
      });

      return reply.send({ ok: true, email: confirmed.email });
    },
  );

  app.delete<{ Params: { id: string } }>(
    "/api/portal/v1/notifications/recipients/:id",
    { preHandler: [...base, guards.requirePermission("enrollTokens.create")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;

      if (!tenantId) return reply.code(400).send({ error: "החשבון אינו משויך לדייר" });

      const removed = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query<{ email: string }>(
          "DELETE FROM notification_recipients WHERE id = $1 AND tenant_id = $2 RETURNING email",
          [request.params.id, tenantId],
        );

        return r.rows[0] ?? null;
      });

      if (removed === null) return reply.code(404).send({ error: "הכתובת אינה קיימת" });

      await audit(pool, session, {
        action: "notifications.recipient.removed",
        targetId: request.params.id,
        tenantId,
        payload: { email: removed.email },
      });

      return reply.send({ ok: true });
    },
  );

  // ---------------------------------------------------------------- הכתובת הראשית

  /**
   * בקשה להחליף את כתובת ההתראות.
   *
   * לא משנה דבר עכשיו. פותחת בקשה, מודיעה לשתי הכתובות, ומחכה.
   *
   * ההודעה לכתובת הישנה היא ההגנה כולה: מי שהשיג גישה לחשבון שולט
   * במה שמוצג בפורטל, אך לא בתיבה של ההורה — ולכן הוא אינו יכול
   * להסתיר את הבקשה ואינו יכול לעצור את ההודעה.
   */
  app.post(
    "/api/portal/v1/notifications/primary-email",
    { preHandler: [...base, guards.requirePermission("enrollTokens.create")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;

      if (!tenantId) return reply.code(400).send({ error: "החשבון אינו משויך לדייר" });

      const parsed = emailBody.safeParse(request.body);

      if (!parsed.success) return reply.code(400).send({ error: "כתובת לא תקינה" });

      const raw = randomBytes(24).toString("base64url");
      const due = effectiveAt(new Date());

      const opened = await withTenant(pool, tenantId, async (tx) => {
        const current = await tx.query<{ primary_email: string }>(
          "SELECT primary_email FROM notification_settings WHERE tenant_id = $1",
          [tenantId],
        );

        const from = current.rows[0]?.primary_email;

        if (from === undefined) return { error: "missing" as const };
        if (from.toLowerCase() === parsed.data.email) return { error: "same" as const };

        const r = await tx.query<{ id: string }>(
          `INSERT INTO email_change_requests
             (tenant_id, from_email, new_email, requested_by, requested_ip,
              effective_at, cancel_hash)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT DO NOTHING
           RETURNING id`,
          [tenantId, from, parsed.data.email, session.user.userId,
            request.ip, due, tokenHash(raw)],
        );

        return r.rows[0] === undefined
          ? { error: "open" as const }
          : { id: r.rows[0].id, from };
      });

      if ("error" in opened) {
        const message = {
          missing: "לא נמצאו הגדרות לחשבון",
          same: "זו כבר כתובת ההתראות",
          open: "כבר יש בקשת החלפה פתוחה. יש לבטל אותה קודם.",
        }[opened.error];

        return reply.code(opened.error === "missing" ? 404 : 409).send({ error: message });
      }

      const cancelUrl = `${config.PORTAL_URL}/notifications/cancel?token=${raw}`;

      /*
       * שתי ההודעות יוצאות במקביל, ושתיהן נספרות.
       *
       * אם ההודעה לכתובת הישנה לא יצאה, ההשהיה איבדה את משמעותה —
       * ולכן הבקשה מבוטלת ולא ממשיכה בשקט. זה נראה כמו החמרה מיותרת
       * עד שחושבים מה קורה כשזה בדיוק המקרה שבו מישהו כן ניסה.
       */
      const [toldOld, toldNew] = await Promise.all([
        trySend(emailChangeMessage({
          to: opened.from,
          audience: "current",
          fromEmail: opened.from,
          newEmail: parsed.data.email,
          effectiveAt: due,
          cancelUrl,
          portalUrl: config.PORTAL_URL,
        })),
        trySend(emailChangeMessage({
          to: parsed.data.email,
          audience: "new",
          fromEmail: opened.from,
          newEmail: parsed.data.email,
          effectiveAt: due,
          cancelUrl,
          portalUrl: config.PORTAL_URL,
        })),
      ]);

      if (!toldOld) {
        await withTenant(pool, tenantId, async (tx) => {
          await tx.query(
            "UPDATE email_change_requests SET cancelled_at = now() WHERE id = $1",
            [opened.id],
          );
        });

        await audit(pool, session, {
          action: "notifications.primaryEmail.aborted",
          targetId: opened.id,
          tenantId,
          payload: { reason: "ההודעה לכתובת הנוכחית לא נשלחה" },
        });

        return reply.code(502).send({
          error: "לא הצלחנו להודיע לכתובת הנוכחית, ולכן הבקשה בוטלה. "
            + "בלי ההודעה הזו אין מי שיעצור החלפה שלא ביקשת.",
        });
      }

      await audit(pool, session, {
        action: "notifications.primaryEmail.requested",
        targetId: opened.id,
        tenantId,
        payload: { from: opened.from, to: parsed.data.email, effectiveAt: due, toldNew },
      });

      return reply.send({
        ok: true,
        effectiveAt: due.toISOString(),
        note: "נשלחה הודעה לשתי הכתובות. ההחלפה תיכנס לתוקף בעוד 24 שעות, "
          + "ואפשר לעצור אותה עד אז.",
      });
    },
  );

  /**
   * ביטול מתוך הפורטל.
   *
   * לנוחות בלבד. הביטול שחשוב הוא זה שבקישור, כי הוא היחיד שעובד
   * גם כשהחשבון עצמו בידיים אחרות.
   */
  app.post(
    "/api/portal/v1/notifications/primary-email/cancel",
    { preHandler: [...base, guards.requirePermission("enrollTokens.create")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;

      if (!tenantId) return reply.code(400).send({ error: "החשבון אינו משויך לדייר" });

      const cancelled = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query<{ id: string }>(
          `UPDATE email_change_requests
              SET cancelled_at = now(), cancelled_by = $2
            WHERE tenant_id = $1 AND applied_at IS NULL AND cancelled_at IS NULL
        RETURNING id`,
          [tenantId, session.user.userId],
        );

        return r.rows[0] ?? null;
      });

      if (cancelled === null) return reply.code(404).send({ error: "אין בקשה פתוחה" });

      await audit(pool, session, {
        action: "notifications.primaryEmail.cancelled",
        targetId: cancelled.id,
        tenantId,
        payload: { via: "portal" },
      });

      return reply.send({ ok: true });
    },
  );

  /**
   * ביטול דרך הקישור שבהודעה.
   *
   * פומבי במכוון, וזה העיקר: מי שהשיג גישה לחשבון יכול לבטל כל
   * ביטול שנעשה מתוך הפורטל. הקישור בתיבה הוא הדבר היחיד שאינו
   * בשליטתו, ודרישת כניסה כאן הייתה מבטלת את ההגנה.
   */
  app.get<{ Querystring: { token?: string } }>(
    "/api/portal/v1/notifications/cancel",
    async (request, reply) => {
      const raw = request.query.token;

      if (typeof raw !== "string" || raw.length < 16) {
        return reply.code(400).send({ error: "קישור ביטול לא תקין" });
      }

      const cancelled = await withPlatform(pool, SYSTEM_ACTOR, async (tx) => {
        const open = await tx.query<{ id: string; tenant_id: string; cancel_hash: Buffer }>(
          `SELECT id, tenant_id, cancel_hash FROM email_change_requests
            WHERE applied_at IS NULL AND cancelled_at IS NULL`,
        );

        // השוואה בזמן קבוע על הבקשות הפתוחות, ולא WHERE על הגיבוב
        const match = open.rows.find((row) => hashMatches(tokenHash(raw), row.cancel_hash));

        if (match === undefined) return null;

        await tx.query(
          "UPDATE email_change_requests SET cancelled_at = now() WHERE id = $1",
          [match.id],
        );

        return match;
      });

      if (cancelled === null) {
        return reply.code(410).send({ error: "הקישור אינו תקף, או שהבקשה כבר טופלה" });
      }

      await audit(pool, null, {
        action: "notifications.primaryEmail.cancelled",
        targetId: cancelled.id,
        tenantId: cancelled.tenant_id,
        payload: { via: "email" },
      });

      return reply.send({ ok: true, note: "ההחלפה בוטלה. כתובת ההתראות לא השתנתה." });
    },
  );
}
