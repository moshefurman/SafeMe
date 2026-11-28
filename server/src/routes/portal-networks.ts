import type { FastifyInstance } from "fastify";
import { targetLabel, trusteeGate } from "../auth/trustee.ts";
import type pg from "pg";
import { z } from "zod";

import { withTenant, withPlatform } from "../db/client.ts";
import { createGuards } from "../auth/guards.ts";
import { rebuildAssignedPolicies, rebuildTenantPolicies } from "../policy/recompose.ts";
import { hasFeature } from "../billing/entitlements.ts";
import { isPlatformRole } from "../auth/rbac.ts";
import type { ActiveSession } from "../auth/session.ts";
import type { Config } from "../config.ts";
import type { Signer } from "../crypto/signing.ts";
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

  /*
   * החותם נדרש כאן מאז שמדיניות הרשתות נכנסת למדיניות החתומה.
   *
   * הסוכן אוכף רק מה שנחתם, ולכן שינוי הגדרה שאינו מפורסם הוא
   * שינוי שאינו קיים בשום מחשב.
   */
  signer: Signer;
}

const deviceDecideBody = z.object({
  deviceId: z.string().uuid(),
  approval: z.enum(["approved", "blocked"]),
  note: z.string().trim().max(200).optional(),
});

export async function registerNetworkRoutes(
  app: FastifyInstance,
  deps: Deps,
): Promise<void> {
  const { pool, config, signer } = deps;
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
                  ,
                  /*
                   * למי ההכרעה שייכת.
                   *
                   * בלי זה ההורה רואה את אותה רשת פעמיים ואינו יודע
                   * מה גובר על מה — וזו בדיוק ההפתעה שהמנגנון הזה
                   * אמור למנוע, לא ליצור.
                   */
                  n.device_id,
                  d.display_name AS device_name,
                  d.machine_name AS device_machine
             FROM known_networks n
             LEFT JOIN devices d ON d.id = n.device_id
            WHERE n.tenant_id = $1

            /*
             * הכרעות החשבון קודם, ותחתן אלה של מחשבים.
             *
             * הכלל הוא ברירת המחדל, והחריגים נקראים ביחס אליו.
             */
            ORDER BY (n.approval = 'pending') DESC,
                     (n.device_id IS NOT NULL),
                     n.last_seen_at DESC
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

  /** היסטוריית החיבורים של מחשב. */
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
  /**
   * הכרעה על רשת, למחשב אחד בלבד.
   *
   * ההכרעה הרגילה חלה על כל החשבון: הורה שמאשר את הרשת אצל סבתא
   * מאשר אותה גם לילד השני. במשפחה אחת זה נוח; במשפחה שרוצה כלל
   * שונה לכל ילד, או בארגון, זה בדיוק ההפך.
   *
   * השורה שנוצרת כאן גוברת על הכללית עבור המחשב הזה בלבד, ושאר
   * המחשבים ממשיכים לפי מה שהוחלט לחשבון.
   *
   * ---
   *
   * ביכולת per_device_policy בלבד, וההודעה אומרת זאת במפורש.
   *
   * "אין הרשאה" היה שולח את ההורה לחפש בעיה בחשבון שלו. מה שהוא
   * צריך לדעת הוא שזו יכולת שנקנית, ומה היא נותנת.
   */
  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/networks/:id/decide-for-device",
    { preHandler: [...base, guards.requirePermission("networks.approve")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;
      const parsed = deviceDecideBody.safeParse(request.body);

      if (!parsed.success) return reply.code(400).send({ error: "בקשה לא תקינה" });
      if (!tenantId) return reply.code(400).send({ error: "אין דייר משויך" });

      if (!(await hasFeature(pool, tenantId, "per_device_policy"))) {
        return reply.code(403).send({
          error: "הגדרה נפרדת לכל מחשב אינה כלולה במנוי הנוכחי. "
            + "היא מאפשרת לאשר רשת למחשב אחד בלי לאשר אותה לשאר.",
        });
      }

      if (parsed.data.approval === "approved") {
        const network = await targetLabel(tenantId, { networkId: request.params.id });
        const where = await targetLabel(tenantId, { deviceId: parsed.data.deviceId });

        if (await trusteeGate(request, reply, `לאשר את הרשת ${network} ${where}`)) return reply;
      }

      const outcome = await withTenant(pool, tenantId, async (tx) => {
        /*
         * הרשת הכללית היא המקור לטביעה ולשם.
         *
         * השורה למחשב אינה נוצרת יש מאין: היא עותק של רשת שכבר
         * נצפתה, עם הכרעה משלה. בלי זה אפשר היה ליצור הכרעה לרשת
         * שאיש מעולם לא היה מחובר אליה.
         */
        const source = await tx.query<{
          fingerprint: string;
          ssid: string | null;
          gateway_ip: string | null;
          gateway_mac: string | null;
        }>(
          `SELECT fingerprint, ssid, gateway_ip, gateway_mac
             FROM known_networks WHERE id = $1 AND tenant_id = $2`,
          [request.params.id, tenantId],
        );

        const net = source.rows[0];

        if (!net) return "missing" as const;

        const owned = await tx.query(
          "SELECT 1 FROM devices WHERE id = $1 AND status <> 'uninstalled'",
          [parsed.data.deviceId],
        );

        if (owned.rowCount === 0) return "no-device" as const;

        await tx.query(
          `INSERT INTO known_networks
             (tenant_id, device_id, fingerprint, ssid, gateway_ip, gateway_mac,
              approval, decided_by, decided_at, note)
           VALUES ($1, $2, $3, $4, $5, $6, $7::network_approval, $8, now(), $9)
           ON CONFLICT (tenant_id, fingerprint,
                        COALESCE(device_id, '00000000-0000-0000-0000-000000000000'::uuid))
           DO UPDATE SET
             approval   = EXCLUDED.approval,
             decided_by = EXCLUDED.decided_by,
             decided_at = now(),
             note       = EXCLUDED.note,

             /*
              * אישור ידני מנתק גם כאן מהכלל שחסם.
              *
              * בלי זה הפעימה הבאה הייתה חוסמת מחדש, וההורה היה
              * רואה כפתור שלוחצים עליו ולא קורה כלום.
              */
             blocked_by_rule = CASE
               WHEN EXCLUDED.approval = 'approved' THEN NULL
               ELSE known_networks.blocked_by_rule
             END`,
          [
            tenantId,
            parsed.data.deviceId,
            net.fingerprint,
            net.ssid,
            net.gateway_ip,
            net.gateway_mac,
            parsed.data.approval,
            session.user.userId,
            parsed.data.note ?? null,
          ],
        );

        return net.ssid ?? "הרשת";
      });

      if (outcome === "missing") return reply.code(404).send({ error: "הרשת אינה קיימת" });

      if (outcome === "no-device") {
        return reply.code(404).send({ error: "המחשב אינו קיים או שהוסר" });
      }

      await audit(pool, session, {
        action: "network.decidedForDevice",
        tenantId,
        payload: {
          network: request.params.id,
          device: parsed.data.deviceId,
          approval: parsed.data.approval,
        },
      });

      return reply.send({
        ok: true,
        note: parsed.data.approval === "approved"
          ? `${outcome} אושרה למחשב הזה בלבד. שאר המחשבים ממשיכים לפי הגדרת החשבון.`
          : `${outcome} נחסמה למחשב הזה בלבד. שאר המחשבים ממשיכים לפי הגדרת החשבון.`,
      });
    },
  );

  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/networks/:id/decide",
    { preHandler: [...base, guards.requirePermission("networks.approve")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;
      const parsed = decideBody.safeParse(request.body);

      if (!parsed.success) return reply.code(400).send({ error: "בקשה לא תקינה" });
      if (!tenantId) return reply.code(400).send({ error: "אין דייר משויך" });

      if (parsed.data.approval === "approved") {
        const network = await targetLabel(tenantId, { networkId: request.params.id });

        if (await trusteeGate(request, reply, `לאשר את הרשת ${network} לכל המחשבים בחשבון`)) return reply;
      }

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

      {
        // מחמיר 1, מאוזן 2, מקל 3. עלייה במספר היא הקלה.
        const rank: Record<string, number> = { strict: 1, balanced: 2, lenient: 3 };
        const label: Record<string, string> = { strict: "מחמיר", balanced: "מאוזן", lenient: "מקל" };

        const now = await withPlatform(
          pool,
          { userId: session.user.userId, reason: "קריאת מדיניות רשתות" },
          async (tx) => {
            const r = await tx.query<{ policy: string }>(
              "SELECT network_policy::text AS policy FROM tenants WHERE id = $1",
              [tenantId],
            );

            return r.rows[0]?.policy ?? "strict";
          },
        );

        if ((rank[parsed.data.networkPolicy] ?? 3) > (rank[now] ?? 1)) {
          if (await trusteeGate(request, reply,
            `להקל את היחס לרשתות חדשות מ"${label[now] ?? now}" ל"${label[parsed.data.networkPolicy]}"`)) return reply;
        }
      }

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
      /*
       * הרצפה חוסמת הקלה, לא החמרה.
       *
       * ההורה קבע בהתקנה מה המצב המתירני ביותר שהוא מרשה לעצמו,
       * וזו כל הנקודה: ההחלטה נלקחה כשהוא צלול, ולא ברגע שההגבלה
       * מפריעה לו. להחמיר הוא רשאי תמיד.
       *
       * התנאי בשאילתה ולא לפניה: בדיקה נפרדת פותחת חלון שבו הרצפה
       * משתנה בין הקריאה לכתיבה. rowCount אפס אומר או שהדייר אינו
       * קיים או שהבקשה מקלה מהרצפה, והשאילתה שאחריה מבדילה.
       */
      const RANK = "CASE %s WHEN 'strict' THEN 1 WHEN 'balanced' THEN 2 ELSE 3 END";

      const changed = await withPlatform(
        pool,
        { userId: session.user.userId, reason: "שינוי מדיניות רשתות" },
        async (tx) => {
          const r = await tx.query(
            `UPDATE tenants SET network_policy = $2::network_policy
              WHERE id = $1
                AND ${RANK.replace("%s", "$2::network_policy")}
                 <= ${RANK.replace("%s", "network_policy_floor")}`,
            [tenantId, parsed.data.networkPolicy],
          );

          return r.rowCount ?? 0;
        },
      );

      if (changed === 0) {
        const floor = await withPlatform(
          pool,
          { userId: session.user.userId, reason: "קריאת רצפת רשתות" },
          async (tx) => {
            const r = await tx.query<{ floor: string }>(
              "SELECT network_policy_floor::text AS floor FROM tenants WHERE id = $1",
              [tenantId],
            );

            return r.rows[0]?.floor ?? null;
          },
        );

        if (floor !== null && floor !== parsed.data.networkPolicy) {
          const label: Record<string, string> = {
            strict: "חוסם כל רשת חדשה",
            balanced: "מאשר רשת מסוננת",
            lenient: "מקל",
          };

          return reply.code(403).send({
            error: `בהתקנה נקבע שהחשבון לא יֵקל מעבר ל"${label[floor] ?? floor}". `
              + "שינוי הרף נעשה דרך המוקד.",
          });
        }
      }

      // עדכון שלא נגע בשום שורה אינו הצלחה. בלי הבדיקה הזו המסך
      // היה מציג את הערך החדש עד לרענון, והמשתמש היה חושב שהגדיר.
      if (changed === 0) return reply.code(404).send({ error: "הדייר אינו קיים" });

      await audit(pool, session, {
        action: "settings.networkPolicy",
        tenantId,
        payload: { to: parsed.data.networkPolicy },
      });

      /*
       * ההגדרה נכנסת למדיניות החתומה, ולא רק לטבלה.
       *
       * הסוכן אוכף אך ורק מה שנחתם. השדה blockUntilApproved הוא מה
       * שאומר לו לחסום רשת חדשה במקום לאשר אותה עד שתגיע הכרעה,
       * ובלי פרסום כאן הוא היה מגיע רק בעליית השרת הבאה — כלומר
       * ההורה היה משנה את ההגדרה, רואה אותה במסך, והמחשב היה
       * ממשיך להתנהג כמקודם.
       *
       * זה בדיוק מה שקרה בשטח: לקוח הגדיר שאף רשת לא תאושר עד
       * אישור, והמחשב התחבר לרשת חדשה וגלש.
       *
       * ההרכבה אינה חוסמת את התשובה: ההגדרה כבר נשמרה, וכישלון
       * בפרסום אינו סיבה להחזיר שגיאה על פעולה שהצליחה.
       */
      try {
        await rebuildTenantPolicies(pool, signer, session.user.userId);
        await rebuildAssignedPolicies(pool, signer, session.user.userId);
      } catch (error) {
        request.log.error(
          { err: error, tenant: tenantId },
          "פרסום המדיניות אחרי שינוי מדיניות הרשתות נכשל.",
        );
      }

      return reply.send({ ok: true, networkPolicy: parsed.data.networkPolicy });
    },
  );


  /**
   * שכחת רשת.
   *
   * מוחקת את הרשת ואת היסטוריית החיבורים שלה. בפעם הבאה שהמחשב
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

      if (await trusteeGate(request, reply, "לבטל כלל ברשימה השחורה של הרשתות")) return reply;

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
