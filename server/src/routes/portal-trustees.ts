import type { FastifyInstance } from "fastify";
import type pg from "pg";
import { z } from "zod";

import { createGuards } from "../auth/guards.ts";
import {
  hashToken,
  loadTrusteeState,
  newToken,
  notifyTrustees,
  requestMessage,
  trusteeGate,
} from "../auth/trustee.ts";
import type { Config } from "../config.ts";
import { withPlatform, withTenant } from "../db/client.ts";
import type { Mailer, Message } from "../notify/mailer.ts";

/**
 * נאמנים: ניהול מצד בעל החשבון, וקישורי האישור מצד הנאמן.
 *
 * שני קהלים, ושתי קבוצות מסלולים. בעל החשבון מחובר ועובר את שומרי
 * הסף הרגילים. הנאמן אינו משתמש במערכת ואין לו סיסמה: הוא מזוהה
 * באסימון שבקישור שקיבל בדוא"ל, והמסלולים שלו פומביים במכוון.
 *
 * מה מיידי ומה לא. להוסיף נאמן ולעבור למצב "מאשר" הם החמרה, ולכן
 * מיידיים. להסיר נאמן ולרדת למצב "מיודע" הם הקלה: הראשון ממתין
 * לאישור הנאמן או שבעה ימים, והשני עובר דרך שער הנאמן כמו כל הקלה.
 */

const MAX_TRUSTEES = 3;
const REMOVAL_DAYS = 7;

const SYSTEM = { userId: "system", reason: "קישור נאמן" };

interface Deps {
  pool: pg.Pool;
  config: Config;
  mailer: Mailer;
}

interface TrusteeRow {
  id: string;
  name: string;
  email: string;
  verified_at: Date | null;
  removal_effective_at: Date | null;
  created_at: Date;
}

interface RequestRow {
  id: string;
  summary: string;
  method: string;
  path: string;
  body: unknown;
  status: string;
  created_at: Date;
  decided_at: Date | null;
  decided_by_name: string | null;
}

const inviteBody = z.object({
  name: z.string().trim().min(1, "חסר שם").max(80),
  email: z.string().trim().toLowerCase().email("כתובת לא תקינה").max(200),
});

const modeBody = z.object({ mode: z.enum(["inform", "approve"]) });

const linkBody = z.object({
  token: z.string().min(16).max(200),
  action: z.enum(["accept", "decline", "approve", "deny", "approve_removal", "stop_removal"]),
  by: z.string().uuid().optional(),
});

function missingTable(error: unknown): boolean {
  return (error as { code?: string }).code === "42P01";
}

export async function registerTrusteeRoutes(app: FastifyInstance, deps: Deps): Promise<void> {
  const { pool, config, mailer } = deps;
  const guards = createGuards(pool, config);
  const base = [guards.requireSession, guards.requirePlatformMfa];

  const trySend = async (message: Message): Promise<boolean> => {
    try {
      await mailer.send(message);

      return true;
    } catch (error) {
      app.log.warn({ err: error, to: message.to }, "שליחת הודעה לנאמן נכשלה");

      return false;
    }
  };

  /** רק בעל חשבון מנהל נאמנים. */
  function ownerTenant(request: { portal?: { session: { user: { role: string; tenantId: string | null } } } }): string | null {
    const user = request.portal?.session.user;

    return user && user.role === "tenant_owner" && user.tenantId ? user.tenantId : null;
  }

  // ---------------------------------------------------------------- תמונת מצב

  app.get("/api/portal/v1/trustees", { preHandler: base }, async (request, reply) => {
    const tenantId = request.portal!.session.user.tenantId;

    if (!tenantId) return reply.send({ available: false, mode: "approve", trustees: [], requests: [] });

    try {
      // גם מנקה נאמנים שהסרתם נכנסה לתוקף
      const state = await loadTrusteeState(pool, tenantId);

      const data = await withTenant(pool, tenantId, async (tx) => {
        const trustees = await tx.query<TrusteeRow>(
          `SELECT id, name, email, verified_at, removal_effective_at, created_at
             FROM trustees WHERE tenant_id = $1 ORDER BY created_at`,
          [tenantId],
        );

        const requests = await tx.query<RequestRow>(
          `SELECT r.id, r.summary, r.method, r.path, r.body, r.status,
                  r.created_at, r.decided_at, t.name AS decided_by_name
             FROM trustee_requests r
             LEFT JOIN trustees t ON t.id = r.decided_by
            WHERE r.tenant_id = $1
            ORDER BY r.created_at DESC LIMIT 40`,
          [tenantId],
        );

        return { trustees: trustees.rows, requests: requests.rows };
      });

      return reply.send({
        available: true,
        mode: state.mode,
        max: MAX_TRUSTEES,
        trustees: data.trustees.map((t) => ({
          id: t.id,
          name: t.name,
          email: t.email,
          verified: t.verified_at !== null,
          removalEffectiveAt: t.removal_effective_at?.toISOString() ?? null,
        })),
        requests: data.requests.map((r) => ({
          id: r.id,
          summary: r.summary,
          method: r.method,
          path: r.path,
          body: r.body,
          status: r.status,
          createdAt: r.created_at.toISOString(),
          decidedAt: r.decided_at?.toISOString() ?? null,
          decidedBy: r.decided_by_name,
        })),
      });
    } catch (error) {
      // הקוד עלה לפני שהמיגרציה רצה. המסך מציג שהיכולת עוד לא זמינה.
      if (missingTable(error)) {
        return reply.send({ available: false, mode: "approve", trustees: [], requests: [] });
      }

      throw error;
    }
  });

  // ---------------------------------------------------------------- הוספת נאמן

  app.post("/api/portal/v1/trustees", { preHandler: base }, async (request, reply) => {
    const session = request.portal!.session;
    const tenantId = ownerTenant(request);

    if (!tenantId) return reply.code(403).send({ error: "רק בעל החשבון יכול למנות נאמן" });

    const parsed = inviteBody.safeParse(request.body);

    if (!parsed.success) {
      return reply.code(400).send({ error: parsed.error.issues[0]?.message ?? "פרטים לא תקינים" });
    }

    /*
     * בעל החשבון אינו יכול למנות את עצמו.
     *
     * נאמן שהוא אותה כתובת של בעל החשבון הוא אישור עצמי בשם אחר.
     * מי שרוצה שבעל החשבון יהיה הנאמן פשוט אינו ממנה נאמן.
     */
    if (parsed.data.email === session.user.email.toLowerCase()) {
      return reply.code(400).send({
        error: "הנאמן צריך להיות אדם אחר, עם כתובת דוא\"ל אחרת משלך.",
      });
    }

    const token = newToken();

    const created = await withTenant(pool, tenantId, async (tx) => {
      const count = await tx.query<{ n: string }>(
        "SELECT count(*) AS n FROM trustees WHERE tenant_id = $1",
        [tenantId],
      );

      if (Number(count.rows[0]?.n ?? 0) >= MAX_TRUSTEES) return { kind: "full" as const };

      const r = await tx.query<{ id: string }>(
        `INSERT INTO trustees (tenant_id, name, email, verify_hash, created_by)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (tenant_id, email) DO UPDATE
           SET name = EXCLUDED.name, verify_hash = EXCLUDED.verify_hash
         WHERE trustees.verified_at IS NULL
         RETURNING id`,
        [tenantId, parsed.data.name, parsed.data.email, hashToken(token), session.user.userId],
      );

      if (!r.rows[0]) return { kind: "exists" as const };

      const tenant = await tx.query<{ name: string }>(
        "SELECT name FROM tenants WHERE id = $1", [tenantId]);

      return { kind: "ok" as const, id: r.rows[0].id, tenantName: tenant.rows[0]?.name ?? "החשבון" };
    });

    if (created.kind === "full") {
      return reply.code(409).send({ error: `אפשר למנות עד ${MAX_TRUSTEES} נאמנים.` });
    }

    if (created.kind === "exists") {
      return reply.code(409).send({ error: "האדם הזה כבר נאמן פעיל בחשבון." });
    }

    const sent = await trySend({
      to: parsed.data.email,
      subject: "Filter+‎ · ביקשו ממך להיות נאמן",
      body: [
        `שלום ${parsed.data.name},`,
        "",
        `${session.user.displayName ?? session.user.email} מבקש שתהיה הנאמן של ${created.tenantName} ב-Filter+‎.`,
        "",
        "Filter+‎ הוא סינון אינטרנט למחשבים. נאמן הוא אדם שסומכים עליו: כשבעל",
        "החשבון ירצה להקל על הסינון או להסיר אותו, תקבל על כך הודעה בדוא\"ל,",
        "ואם כך הוגדר, השינוי לא יתבצע בלי אישורך.",
        "",
        "אין צורך בחשבון או בסיסמה. לקבלת התפקיד או לסירוב:",
        `${config.PORTAL_URL}/trustee?token=${token}`,
        "",
        "אם אינך מכיר את הבקשה, התעלם מההודעה. בלי אישורך לא תהיה נאמן.",
        "",
        "— Filter+‎",
      ].join("\n"),
    });

    await audit(pool, session.user.userId, tenantId, "trustee.invited", { email: parsed.data.email, sent });

    return reply.send({
      ok: true,
      note: sent
        ? `נשלחה הזמנה אל ${parsed.data.email}. הוא יהיה נאמן אחרי שיאשר בקישור.`
        : "הנאמן נוסף, אך שליחת ההזמנה נכשלה. אפשר להוסיף אותו שוב כדי לשלוח מחדש.",
    });
  });

  // ---------------------------------------------------------------- הסרת נאמן

  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/trustees/:id/remove",
    { preHandler: base },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = ownerTenant(request);

      if (!tenantId) return reply.code(403).send({ error: "רק בעל החשבון יכול להסיר נאמן" });

      const token = newToken();

      const result = await withTenant(pool, tenantId, async (tx) => {
        const row = await tx.query<TrusteeRow>(
          `SELECT id, name, email, verified_at, removal_effective_at, created_at
             FROM trustees WHERE id = $1 AND tenant_id = $2`,
          [request.params.id, tenantId],
        );

        const trustee = row.rows[0];

        if (!trustee) return { kind: "missing" as const };

        // מי שעוד לא אישר את התפקיד אינו נאמן, ואין ממה להגן
        if (trustee.verified_at === null) {
          await tx.query("DELETE FROM trustees WHERE id = $1", [trustee.id]);

          return { kind: "deleted" as const };
        }

        if (trustee.removal_effective_at !== null) {
          return { kind: "already" as const, at: trustee.removal_effective_at };
        }

        const r = await tx.query<{ removal_effective_at: Date }>(
          `UPDATE trustees
              SET removal_requested_at = now(),
                  removal_effective_at = now() + make_interval(days => $2),
                  removal_hash = $3
            WHERE id = $1
        RETURNING removal_effective_at`,
          [trustee.id, REMOVAL_DAYS, hashToken(token)],
        );

        const tenant = await tx.query<{ name: string }>(
          "SELECT name FROM tenants WHERE id = $1", [tenantId]);

        return {
          kind: "scheduled" as const,
          trustee,
          at: r.rows[0]!.removal_effective_at,
          tenantName: tenant.rows[0]?.name ?? "החשבון",
        };
      });

      if (result.kind === "missing") return reply.code(404).send({ error: "הנאמן אינו קיים" });
      if (result.kind === "deleted") return reply.send({ ok: true, note: "ההזמנה בוטלה." });

      if (result.kind === "already") {
        return reply.code(409).send({ error: "הסרת הנאמן כבר ממתינה." });
      }

      const sent = await trySend({
        to: result.trustee.email,
        subject: "Filter+‎ · מבקשים להסיר אותך מתפקיד הנאמן",
        body: [
          `שלום ${result.trustee.name},`,
          "",
          `${session.user.displayName ?? session.user.email} מבקש להסיר אותך מתפקיד הנאמן של ${result.tenantName}.`,
          "",
          `אם לא תעשה דבר, ההסרה תיכנס לתוקף בעוד ${REMOVAL_DAYS} ימים.`,
          "אפשר לאשר אותה עכשיו, או לעצור אותה:",
          `${config.PORTAL_URL}/trustee?token=${token}`,
          "",
          "אחרי ההסרה לא תקבל עוד בקשות, ובעל החשבון יוכל להקל על הסינון בלי אישורך.",
          "",
          "— Filter+‎",
        ].join("\n"),
      });

      await audit(pool, session.user.userId, tenantId, "trustee.removal_requested", {
        trustee: result.trustee.email, sent,
      });

      return reply.send({
        ok: true,
        note: `נשלחה אל ${result.trustee.name} בקשה לאשר את ההסרה. אם לא יענה, היא תיכנס לתוקף בעוד ${REMOVAL_DAYS} ימים, והוא יכול לעצור אותה עד אז.`,
      });
    },
  );

  /** בעל החשבון מתחרט על ההסרה. החמרה, ולכן מיידית. */
  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/trustees/:id/keep",
    { preHandler: base },
    async (request, reply) => {
      const tenantId = ownerTenant(request);

      if (!tenantId) return reply.code(403).send({ error: "רק בעל החשבון יכול לשנות נאמנים" });

      await withTenant(pool, tenantId, async (tx) => {
        await tx.query(
          `UPDATE trustees
              SET removal_requested_at = NULL, removal_effective_at = NULL, removal_hash = NULL
            WHERE id = $1 AND tenant_id = $2`,
          [request.params.id, tenantId],
        );
      });

      return reply.send({ ok: true, note: "ההסרה בוטלה. הנאמן נשאר." });
    },
  );

  // ---------------------------------------------------------------- מצב הנאמנות

  app.post("/api/portal/v1/trustees/mode", { preHandler: base }, async (request, reply) => {
    const session = request.portal!.session;
    const tenantId = ownerTenant(request);

    if (!tenantId) return reply.code(403).send({ error: "רק בעל החשבון יכול לשנות את המצב" });

    const parsed = modeBody.safeParse(request.body);

    if (!parsed.success) return reply.code(400).send({ error: "מצב לא מוכר" });

    const state = await loadTrusteeState(pool, tenantId);

    // ירידה מ"מאשר" ל"מיודע" היא הקלה, והיא עצמה דורשת את הנאמן
    if (state.mode === "approve" && parsed.data.mode === "inform") {
      if (await trusteeGate(request, reply, "לשנות את תפקיד הנאמן: רק לקבל הודעות, בלי לאשר")) return;
    }

    await withTenant(pool, tenantId, async (tx) => {
      await tx.query(
        `INSERT INTO trustee_settings (tenant_id, mode, updated_by)
         VALUES ($1, $2, $3)
         ON CONFLICT (tenant_id) DO UPDATE
           SET mode = EXCLUDED.mode, updated_at = now(), updated_by = EXCLUDED.updated_by`,
        [tenantId, parsed.data.mode, session.user.userId],
      );
    });

    await audit(pool, session.user.userId, tenantId, "trustee.mode_changed", { mode: parsed.data.mode });

    return reply.send({ ok: true, mode: parsed.data.mode, note: "נשמר." });
  });

  // ---------------------------------------------------------------- בקשות

  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/trustees/requests/:id/cancel",
    { preHandler: base },
    async (request, reply) => {
      const tenantId = ownerTenant(request);

      if (!tenantId) return reply.code(403).send({ error: "רק בעל החשבון יכול לבטל בקשה" });

      await withTenant(pool, tenantId, async (tx) => {
        await tx.query(
          `UPDATE trustee_requests
              SET status = 'cancelled', decide_hash = NULL
            WHERE id = $1 AND tenant_id = $2 AND status IN ('pending', 'approved')`,
          [request.params.id, tenantId],
        );
      });

      return reply.send({ ok: true, note: "הבקשה בוטלה." });
    },
  );

  /** תזכורת. הקישור הקודם מתבטל ונשלח חדש, כי האסימון נשמר מגובב בלבד. */
  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/trustees/requests/:id/remind",
    { preHandler: base },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = ownerTenant(request);

      if (!tenantId) return reply.code(403).send({ error: "רק בעל החשבון יכול לשלוח תזכורת" });

      const token = newToken();

      const row = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query<{ summary: string }>(
          `UPDATE trustee_requests SET decide_hash = $3
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
        RETURNING summary`,
          [request.params.id, tenantId, hashToken(token)],
        );

        return r.rows[0] ?? null;
      });

      if (row === null) return reply.code(404).send({ error: "אין בקשה ממתינה כזו" });

      const state = await loadTrusteeState(pool, tenantId);

      const sent = await notifyTrustees(state, (t) => requestMessage({
        to: t.email,
        trusteeName: t.name,
        tenantName: state.tenantName,
        requesterName: session.user.displayName ?? session.user.email,
        summary: row.summary,
        link: `${config.PORTAL_URL}/trustee?token=${token}&by=${t.id}`,
      }));

      return reply.send({
        ok: true,
        note: sent > 0 ? "נשלחה תזכורת לנאמן." : "שליחת התזכורת נכשלה.",
      });
    },
  );

  // ================================================================ צד הנאמן

  /**
   * מה הקישור הזה.
   *
   * קריאה בלבד: פתיחת הקישור אינה מאשרת דבר. תוכנות דוא"ל וסורקי
   * אבטחה פותחים קישורים לבד, ואישור ב-GET היה מאשר בקשות בלי
   * שאיש קרא אותן. ההחלטה נעשית בלחיצה, ב-POST.
   */
  app.get<{ Querystring: { token?: string } }>(
    "/api/portal/v1/trustee/link",
    async (request, reply) => {
      const raw = request.query.token;

      if (typeof raw !== "string" || raw.length < 16) {
        return reply.code(400).send({ error: "קישור לא תקין" });
      }

      const found = await describeLink(pool, hashToken(raw));

      if (found === null) {
        return reply.code(410).send({ error: "הקישור אינו תקף, או שכבר נעשה בו שימוש." });
      }

      return reply.send(found);
    },
  );

  app.post("/api/portal/v1/trustee/link", async (request, reply) => {
    const parsed = linkBody.safeParse(request.body);

    if (!parsed.success) return reply.code(400).send({ error: "בקשה לא תקינה" });

    const hash = hashToken(parsed.data.token);
    const { action, by } = parsed.data;

    try {
      const note = await withPlatform(pool, SYSTEM, async (tx) => {
        // ---- הזמנה לתפקיד
        if (action === "accept" || action === "decline") {
          const r = action === "accept"
            ? await tx.query<{ tenant_id: string; email: string }>(
              `UPDATE trustees SET verified_at = now(), verify_hash = NULL
                WHERE verify_hash = $1 AND verified_at IS NULL
            RETURNING tenant_id, email`, [hash])
            : await tx.query<{ tenant_id: string; email: string }>(
              `DELETE FROM trustees WHERE verify_hash = $1 AND verified_at IS NULL
            RETURNING tenant_id, email`, [hash]);

          if (!r.rows[0]) return null;

          await insertAudit(tx, r.rows[0].tenant_id,
            action === "accept" ? "trustee.accepted" : "trustee.declined", { email: r.rows[0].email });

          return action === "accept"
            ? "קיבלת את התפקיד. מעכשיו תקבל בדוא\"ל בקשות והודעות על שינויים בהגנה."
            : "סירבת לתפקיד. לא תקבל הודעות נוספות.";
        }

        // ---- בקשה להקלה או להסרה
        if (action === "approve" || action === "deny") {
          const r = await tx.query<{ id: string; tenant_id: string; summary: string }>(
            `UPDATE trustee_requests r
                SET status = $2, decided_at = now(), decide_hash = NULL,
                    decided_by = (SELECT t.id FROM trustees t
                                   WHERE t.id = $3 AND t.tenant_id = r.tenant_id)
              WHERE r.decide_hash = $1 AND r.status = 'pending'
          RETURNING r.id, r.tenant_id, r.summary`,
            [hash, action === "approve" ? "approved" : "denied", by ?? null],
          );

          if (!r.rows[0]) return null;

          await insertAudit(tx, r.rows[0].tenant_id,
            action === "approve" ? "trustee.request.approved" : "trustee.request.denied",
            { request: r.rows[0].id, summary: r.rows[0].summary });

          return action === "approve"
            ? "אישרת. בעל החשבון יכול עכשיו לבצע את הפעולה הזו, פעם אחת."
            : "דחית. הפעולה לא תתבצע.";
        }

        // ---- הסרת הנאמן עצמו
        const r = action === "approve_removal"
          ? await tx.query<{ tenant_id: string; email: string }>(
            "DELETE FROM trustees WHERE removal_hash = $1 RETURNING tenant_id, email", [hash])
          : await tx.query<{ tenant_id: string; email: string }>(
            `UPDATE trustees
                SET removal_requested_at = NULL, removal_effective_at = NULL, removal_hash = NULL
              WHERE removal_hash = $1
          RETURNING tenant_id, email`, [hash]);

        if (!r.rows[0]) return null;

        await insertAudit(tx, r.rows[0].tenant_id,
          action === "approve_removal" ? "trustee.removal_approved" : "trustee.removal_stopped",
          { email: r.rows[0].email });

        return action === "approve_removal"
          ? "אישרת את ההסרה. אינך עוד נאמן של החשבון."
          : "עצרת את ההסרה. אתה נשאר הנאמן של החשבון.";
      });

      if (note === null) {
        return reply.code(410).send({ error: "הקישור אינו תקף, או שכבר נעשה בו שימוש." });
      }

      return reply.send({ ok: true, note });
    } catch (error) {
      if (missingTable(error)) return reply.code(410).send({ error: "הקישור אינו תקף." });

      throw error;
    }
  });
}

/** מה מסתתר מאחורי אסימון: הזמנה, בקשה, או הסרה. */
async function describeLink(pool: pg.Pool, hash: string): Promise<Record<string, unknown> | null> {
  try {
    return await withPlatform(pool, SYSTEM, async (tx) => {
      const invite = await tx.query<{ name: string; tenant: string }>(
        `SELECT t.name, n.name AS tenant
           FROM trustees t JOIN tenants n ON n.id = t.tenant_id
          WHERE t.verify_hash = $1 AND t.verified_at IS NULL`,
        [hash],
      );

      if (invite.rows[0]) {
        return { kind: "invite", trusteeName: invite.rows[0].name, tenantName: invite.rows[0].tenant };
      }

      const req = await tx.query<{ summary: string; created_at: Date; tenant: string; requester: string | null }>(
        `SELECT r.summary, r.created_at, n.name AS tenant,
                COALESCE(u.display_name, u.email) AS requester
           FROM trustee_requests r
           JOIN tenants n ON n.id = r.tenant_id
           LEFT JOIN users u ON u.id = r.requested_by
          WHERE r.decide_hash = $1 AND r.status = 'pending'`,
        [hash],
      );

      if (req.rows[0]) {
        return {
          kind: "request",
          summary: req.rows[0].summary,
          tenantName: req.rows[0].tenant,
          requesterName: req.rows[0].requester ?? "בעל החשבון",
          createdAt: req.rows[0].created_at.toISOString(),
        };
      }

      const removal = await tx.query<{ name: string; tenant: string; removal_effective_at: Date }>(
        `SELECT t.name, n.name AS tenant, t.removal_effective_at
           FROM trustees t JOIN tenants n ON n.id = t.tenant_id
          WHERE t.removal_hash = $1 AND t.removal_effective_at > now()`,
        [hash],
      );

      if (removal.rows[0]) {
        return {
          kind: "removal",
          trusteeName: removal.rows[0].name,
          tenantName: removal.rows[0].tenant,
          effectiveAt: removal.rows[0].removal_effective_at.toISOString(),
        };
      }

      return null;
    });
  } catch (error) {
    if (missingTable(error)) return null;

    throw error;
  }
}

async function insertAudit(
  tx: { query: (sql: string, params?: unknown[]) => Promise<unknown> },
  tenantId: string,
  action: string,
  payload: unknown,
): Promise<void> {
  await tx.query(
    `INSERT INTO audit_log (actor_type, action, tenant_id, payload)
     VALUES ('system', $1, $2, $3)`,
    [action, tenantId, JSON.stringify(payload ?? {})],
  );
}

async function audit(
  pool: pg.Pool,
  userId: string,
  tenantId: string,
  action: string,
  payload: unknown,
): Promise<void> {
  await withPlatform(pool, { userId: "system", reason: "תיעוד נאמנים" }, async (tx) => {
    await tx.query(
      `INSERT INTO audit_log (actor_type, actor_id, action, tenant_id, payload)
       VALUES ('tenant_user', $1, $2, $3, $4)`,
      [userId, action, tenantId, JSON.stringify(payload ?? {})],
    );
  });
}
