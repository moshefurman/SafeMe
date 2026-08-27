import type { FastifyInstance } from "fastify";
import type pg from "pg";
import { z } from "zod";

import { withTenant, withPlatform } from "../db/client.ts";
import { createGuards } from "../auth/guards.ts";
import { isPlatformRole } from "../auth/rbac.ts";
import type { ActiveSession } from "../auth/session.ts";
import type { Config } from "../config.ts";
import { CATEGORY_LABELS, validateRule } from "../network/blocklist.ts";

/**
 * ניהול רשתות: אישור, חסימה, והגדרת המדיניות.
 *
 * הפעולה המרכזית כאן היא אישור — והיא היחידה שמתירה. לכן היא מקבלת
 * הרשאה משלה ולא נסמכת על devices.lockout, שהיא הרשאה שמחמירה.
 */

const decideBody = z.object({
  approval: z.enum(["approved", "blocked"]),
  note: z.string().max(500).optional(),
});

const ruleBody = z.object({
  kind: z.enum(["ssid", "gateway", "category"]),
  pattern: z.string().trim().min(1).max(128),
  note: z.string().trim().max(200).optional(),
});

const policyBody = z.object({
  networkPolicy: z.enum(["strict", "balanced", "lenient"]),
});

const SYSTEM_ACTOR = {
  userId: "00000000-0000-0000-0000-000000000000",
  reason: "רישום ביומן ביקורת",
};

/**
 * רישום ביומן הביקורת.
 *
 * זהה במבנה לזה שב-portal-devices: אותן עמודות, אותו סוג פועל.
 * יומן שכל מסלול כותב אליו אחרת אינו יומן.
 */
async function audit(
  pool: pg.Pool,
  session: ActiveSession,
  entry: { action: string; targetId?: string; tenantId?: string | null; payload?: unknown },
): Promise<void> {
  await withPlatform(pool, SYSTEM_ACTOR, async (tx) => {
    await tx.query(
      `INSERT INTO audit_log
         (actor_type, actor_id, action, target_type, target_id, tenant_id, payload)
       VALUES ($1, $2, $3, 'network', $4, $5, $6)`,
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
}

export async function registerNetworkRoutes(
  app: FastifyInstance,
  deps: Deps,
): Promise<void> {
  const { pool, config } = deps;
  const guards = createGuards(pool, config);
  const base = [guards.requireSession, guards.requirePlatformMfa];

  /** רשימת הרשתות. ממתינות ראשונות — הן מה שדורש פעולה. */
  app.get(
    "/api/portal/v1/networks",
    { preHandler: [...base, guards.requirePermission("devices.viewOwn")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;

      if (!tenantId) return reply.send({ networks: [], policy: "balanced" });

      const result = await withTenant(pool, tenantId, async (tx) => {
        const networks = await tx.query(
          `SELECT n.id, n.ssid, n.gateway_ip, n.approval, n.detected_provider,
                  n.hotspot_confidence, n.hotspot_reasons,
                  n.first_seen_at, n.last_seen_at, n.note,
                  (SELECT count(*) FROM network_sessions s WHERE s.network_id = n.id)
                    AS session_count,
                  (SELECT coalesce(sum(
                     extract(epoch from (coalesce(s.ended_at, now()) - s.started_at))
                   ), 0)::bigint FROM network_sessions s WHERE s.network_id = n.id)
                    AS total_seconds
             FROM known_networks n
            WHERE n.tenant_id = $1
            ORDER BY (n.approval = 'pending') DESC, n.last_seen_at DESC
            LIMIT 200`,
          [tenantId],
        );

        const tenant = await tx.query<{ network_policy: string }>(
          "SELECT network_policy FROM tenants WHERE id = $1",
          [tenantId],
        );

        return {
          networks: networks.rows,
          policy: tenant.rows[0]?.network_policy ?? "balanced",
        };
      });

      return reply.send(result);
    },
  );

  /** היסטוריית החיבורים של מכשיר. */
  app.get<{ Params: { id: string } }>(
    "/api/portal/v1/devices/:id/networks",
    { preHandler: [...base, guards.requirePermission("devices.viewOwn")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;

      if (!tenantId) return reply.send({ sessions: [] });

      const sessions = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query(
          `SELECT s.id, s.started_at, s.ended_at, s.outcome,
                  n.ssid, n.approval, n.hotspot_confidence
             FROM network_sessions s
             JOIN known_networks n ON n.id = s.network_id
            WHERE s.device_id = $1
            ORDER BY s.started_at DESC
            LIMIT 100`,
          [request.params.id],
        );

        return r.rows;
      });

      return reply.send({ sessions });
    },
  );

  /**
   * אישור או חסימה של רשת.
   *
   * שתי הפעולות נכתבות לאותה עמודה, אך אינן שקולות: חסימה מחמירה
   * ואישור מתיר. הרישום ביומן הביקורת מבחין ביניהן.
   */
  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/networks/:id/decide",
    { preHandler: [...base, guards.requirePermission("networks.approve")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;
      const parsed = decideBody.safeParse(request.body);

      if (!parsed.success) return reply.code(400).send({ error: "בקשה לא תקינה" });
      if (!tenantId) return reply.code(400).send({ error: "אין דייר משויך" });

      const updated = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query<{
          ssid: string | null;
          hotspot_confidence: string | null;
          blocked_by_rule: string | null;
        }>(
          `UPDATE known_networks
              SET approval = $3::network_approval,
                  decided_by = $4,
                  decided_at = now(),
                  note = $5,
                  -- אישור ידני מנתק את הרשת מהכלל שחסם אותה.
                  -- בלי זה הפעימה הבאה הייתה חוסמת אותה מחדש,
                  -- וההורה היה רואה כפתור שלוחצים עליו ולא קורה כלום.
                  blocked_by_rule = CASE
                    WHEN $3 = 'approved' THEN NULL
                    ELSE known_networks.blocked_by_rule
                  END
            WHERE id = $1 AND tenant_id = $2
        RETURNING ssid, hotspot_confidence, blocked_by_rule`,
          [
            request.params.id,
            tenantId,
            parsed.data.approval,
            session.user.userId,
            parsed.data.note ?? null,
          ],
        );

        return r.rows[0] ?? null;
      });

      if (updated === null) return reply.code(404).send({ error: "הרשת אינה קיימת" });

      // אישור רשת שזוהתה כנקודה חמה ודאית אינו חוסם את הפעולה, אבל
      // כן נרשם במפורש: הסוכן יחסום אותה בכל מקרה, וההורה צריך לדעת
      // שהאישור לא ישנה דבר.
      const futile =
        parsed.data.approval === "approved" && updated.hotspot_confidence === "certain";

      // אישור של רשת שכלל חסם הוא חריג מכוון, ולא טעות — אבל
      // ההורה צריך לדעת שהוא יצר חריג ולא ביטל את הכלל.
      const overrodeRule =
        parsed.data.approval === "approved" && updated.blocked_by_rule !== null;

      await audit(pool, session, {
        action: parsed.data.approval === "approved" ? "network.approved" : "network.blocked",
        targetId: request.params.id,
        tenantId,
        payload: { ssid: updated.ssid, futile, overrodeRule },
      });

      return reply.send({
        ok: true,
        ssid: updated.ssid,
        warning: futile
          ? "הרשת זוהתה בוודאות כשיתוף אינטרנט מטלפון, ותיחסם למרות האישור."
          : overrodeRule
            ? "הרשת הזו נחסמה על ידי כלל ברשימה השחורה. האישור יוצר לה חריג, והכלל נשאר בתוקף לשאר הרשתות."
            : null,
      });
    },
  );

  /**
   * שינוי מדיניות הרשתות.
   *
   * מעבר לרמה מקלה הוא הרפיה, ולכן דורש את אותה הרשאה שמתירה רשת.
   * ההגדרה משפיעה רק על רשתות חדשות — מה שכבר אושר או נחסם נשאר.
   */
  app.post(
    "/api/portal/v1/settings/network-policy",
    { preHandler: [...base, guards.requirePermission("networks.approve")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;
      const parsed = policyBody.safeParse(request.body);

      if (!parsed.success) return reply.code(400).send({ error: "בקשה לא תקינה" });
      if (!tenantId) return reply.code(400).send({ error: "אין דייר משויך" });

      /*
       * הכתיבה הזו רצה בהרשאת הפלטפורמה ולא בהרשאת הדייר.
       *
       * ל-tenants יש WITH CHECK (app.is_platform()), כלומר סשן
       * של דייר אינו יכול לכתוב לשורה של עצמו — וזה נכון: הדייר
       * לא אמור לשנות את סוג הרישיון או את מועדי הניסיון שלו.
       * מדיניות הרשתות היא היוצא מן הכלל היחיד, ולכן היא נכתבת
       * כאן במפורש: עמודה אחת, שורה אחת, לפי מזהה שכבר נלקח
       * מהסשן המאומת ולא מגוף הבקשה.
       */
      const changed = await withPlatform(
        pool,
        { userId: session.user.userId, reason: "שינוי מדיניות רשתות" },
        async (tx) => {
          const r = await tx.query(
            "UPDATE tenants SET network_policy = $2::network_policy WHERE id = $1",
            [tenantId, parsed.data.networkPolicy],
          );

          return r.rowCount ?? 0;
        },
      );

      // עדכון שלא נגע בשום שורה אינו הצלחה. בלי הבדיקה הזו המסך
      // היה מציג את הערך החדש עד לרענון, והמשתמש היה חושב שהגדיר.
      if (changed === 0) return reply.code(404).send({ error: "הדייר אינו קיים" });

      await audit(pool, session, {
        action: "settings.networkPolicy",
        tenantId,
        payload: { to: parsed.data.networkPolicy },
      });

      return reply.send({ ok: true, networkPolicy: parsed.data.networkPolicy });
    },
  );


  /**
   * שכחת רשת.
   *
   * מוחקת את הרשת ואת היסטוריית החיבורים שלה. בפעם הבאה שהמכשיר
   * יתחבר אליה היא תיראה חדשה לגמרי ותישפט לפי המדיניות.
   *
   * מחיקה ולא סימון: רשת שנשכחה ונשארת בטבלה היא בדיוק מה שגורם
   * לרשימה לגדול עד שאיש אינו קורא אותה. ההיסטוריה שלה הולכת איתה,
   * וזה מכוון — מי ששוכח רשת מבקש להתחיל איתה מחדש.
   *
   * שים לב: רשת שנשכחה אינה חסומה. אם היא נחסמה בטעות ורוצים
   * לחסום שוב, יש לחסום אותה מפורשות או להוסיף כלל.
   */
  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/networks/:id/forget",
    { preHandler: [...base, guards.requirePermission("networks.approve")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;

      if (!tenantId) return reply.code(400).send({ error: "אין דייר משויך" });

      const removed = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query<{ ssid: string | null }>(
          "DELETE FROM known_networks WHERE id = $1 AND tenant_id = $2 RETURNING ssid",
          [request.params.id, tenantId],
        );

        return r.rows[0] ?? null;
      });

      if (removed === null) return reply.code(404).send({ error: "הרשת אינה קיימת" });

      await audit(pool, session, {
        action: "network.forgotten",
        targetId: request.params.id,
        tenantId,
        payload: { ssid: removed.ssid },
      });

      return reply.send({ ok: true, ssid: removed.ssid });
    },
  );

  // ─────────────────────────────────────────────── רשימה שחורה

  /** כללי החסימה של הדייר. */
  app.get(
    "/api/portal/v1/networks/rules",
    { preHandler: [...base, guards.requirePermission("devices.viewOwn")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;

      if (!tenantId) return reply.send({ rules: [], categories: CATEGORY_LABELS });

      const rules = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query(
          `SELECT id, kind, pattern, note, enabled, hit_count, last_hit_at, created_at
             FROM network_block_rules
            WHERE tenant_id = $1
            ORDER BY created_at DESC`,
          [tenantId],
        );

        return r.rows;
      });

      return reply.send({ rules, categories: CATEGORY_LABELS });
    },
  );

  /**
   * הוספת כלל.
   *
   * זו פעולה שמחמירה, ולכן היא נגישה גם למי שרשאי לאשר רשתות —
   * אבל התקינות נבדקת כאן ולא רק בטופס. תבנית של כוכבית בודדת
   * חוסמת גם את הרשת הביתית, והמשפחה נשארת בלי אינטרנט עד שמישהו
   * יבין מה קרה.
   */
  app.post(
    "/api/portal/v1/networks/rules",
    { preHandler: [...base, guards.requirePermission("networks.approve")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;
      const parsed = ruleBody.safeParse(request.body);

      if (!parsed.success) return reply.code(400).send({ error: "בקשה לא תקינה" });
      if (!tenantId) return reply.code(400).send({ error: "אין דייר משויך" });

      const { kind, pattern, note } = parsed.data;
      const problem = validateRule(kind, pattern);

      if (problem !== null) return reply.code(400).send({ error: problem });

      const created = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query<{ id: string }>(
          `INSERT INTO network_block_rules (tenant_id, kind, pattern, note, created_by)
           VALUES ($1, $2::block_rule_kind, $3, $4, $5)
           ON CONFLICT (tenant_id, kind, pattern) DO NOTHING
           RETURNING id`,
          [tenantId, kind, pattern.trim(), note ?? null, session.user.userId],
        );

        return r.rows[0] ?? null;
      });

      if (created === null) {
        return reply.code(409).send({ error: "הכלל הזה כבר קיים." });
      }

      await audit(pool, session, {
        action: "network.rule.added",
        targetId: created.id,
        tenantId,
        payload: { kind, pattern },
      });

      return reply.send({ ok: true, id: created.id });
    },
  );

  /**
   * ביטול כלל.
   *
   * מחיקה ולא כיבוי: רשימה שרק גדלה נהיית בלתי קריאה, וכלל מבוטל
   * שנשאר בתצוגה הוא בדיוק מה שגורם להורה להפסיק לקרוא אותה.
   *
   * הרשתות שנחסמו בגללו חוזרות להמתין לאישור, ולא נפתחות מאליהן.
   * הן נחסמו פעם אחת מסיבה כלשהי, וההחלטה מה לעשות איתן עכשיו היא
   * של ההורה.
   */
  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/networks/rules/:id/delete",
    { preHandler: [...base, guards.requirePermission("networks.approve")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;

      if (!tenantId) return reply.code(400).send({ error: "אין דייר משויך" });

      const result = await withTenant(pool, tenantId, async (tx) => {
        const freed = await tx.query(
          `UPDATE known_networks
              SET approval = 'pending', decided_at = NULL, blocked_by_rule = NULL
            WHERE tenant_id = $1 AND blocked_by_rule = $2`,
          [tenantId, request.params.id],
        );

        const deleted = await tx.query(
          "DELETE FROM network_block_rules WHERE id = $1 AND tenant_id = $2",
          [request.params.id, tenantId],
        );

        return { freed: freed.rowCount ?? 0, deleted: deleted.rowCount ?? 0 };
      });

      if (result.deleted === 0) return reply.code(404).send({ error: "הכלל אינו קיים" });

      await audit(pool, session, {
        action: "network.rule.removed",
        targetId: request.params.id,
        tenantId,
        payload: { freed: result.freed },
      });

      return reply.send({
        ok: true,
        freed: result.freed,
        note: result.freed > 0
          ? `${result.freed} רשתות חזרו להמתין לאישורך.`
          : null,
      });
    },
  );
}
