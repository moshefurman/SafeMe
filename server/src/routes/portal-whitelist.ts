import type { FastifyInstance, FastifyReply } from "fastify";
import type pg from "pg";
import { z } from "zod";

import { withTenant, withPlatform } from "../db/client.ts";
import { createGuards } from "../auth/guards.ts";
import { can, isPlatformRole } from "../auth/rbac.ts";
import type { ActiveSession } from "../auth/session.ts";
import type { Config } from "../config.ts";
import type { Signer } from "../crypto/signing.ts";
import { composeDeviceOverlay } from "../policy/device-overlay.ts";
import {
  MAX_APPROVED_DOMAINS,
  checkDomainsAllowed,
  learningActive,
  loadWhitelist,
  looksAdult,
  normalizeDomain,
  registrableDomain,
  REASON_BLOCKED,
  whitelistSystemDomains,
} from "../policy/whitelist.ts";

/**
 * רשימה לבנה למחשב: גלישה רק לאתרים שאושרו.
 *
 * ההורה מדליק את המצב, והמחשב מפסיק לפתוח כל אתר שאינו ברשימה.
 * זו ההגדרה המחמירה ביותר במוצר, והיא מתאימה למחשב של ילד קטן או
 * למחשב שנועד לשימוש אחד.
 *
 * הקושי הוא לבנות את הרשימה. אתר אחד נטען מעשרות שמות, והורה אינו
 * יודע אותם. לכן יש למידה: חלון זמן שבו המחשב רושם כל שם שביקש,
 * וההורה בוחר מתוך מה שנצפה. הלמידה אינה מאשרת דבר בעצמה.
 *
 * כמו בשעות החסימה, הטבלאות הן הכוונה, והמדיניות החתומה נגזרת
 * מהן ומתפרסמת מחדש בכל שינוי — למחשב הזה בלבד.
 *
 * ---
 *
 * ההרשאות נחלקות לפי הכיוון, כמו בשאר המערכת: מה שמחמיר דורש
 * policy.tighten, ומה שמתיר דורש networks.approve — "כל מה שמתיר
 * מקבל שער משלו" (rbac.ts).
 *
 *   מחמיר: הפעלה, הסרת אתר, עצירת למידה, ניקוי הנצפים.
 *   מתיר:  כיבוי, הוספת אתר, התחלת למידה.
 *
 * למידה היא הקלה: בזמן החלון המחשב פתוח לכל אתר שאינו מסווג
 * כתוכן למבוגרים.
 *
 * מנגנון היתרי ההקלה (loosening.ts) אינו מעורב כאן. הוא שומר על
 * רצפת המדיניות — מצב האכיפה, הפעולה באדום, ספי הציון, הספק
 * הנדרש — שנקבעת בהתקנה ונאכפת בסוכן. הרשימה הלבנה אינה חלק
 * מהרצפה, והסוכן אינו משווה אותה.
 */

const NOTE = "המחשב יקבל את השינוי בפעימה הבאה, בדרך כלל תוך שלוש דקות.";

const LEARNING_NOTE =
  "הלמידה תתחיל במחשב בפעימה הבאה, בדרך כלל תוך שלוש דקות. " +
  "כדי להתחיל מיד, לחצו \"רענן מהשרת\" ב-SafeMe שליד השעון, במחשב עצמו.";

const enabledBody = z.object({ enabled: z.boolean() });

const domainsBody = z.object({
  domains: z.array(z.string().max(2048)).min(1).max(100),
  source: z.enum(["manual", "learned"]).default("manual"),
});

const learningBody = z.object({ minutes: z.number().int().min(5).max(120) });

const dismissBody = z.object({
  domains: z.array(z.string().max(253)).min(1).max(500),
});

const SYSTEM = {
  userId: "00000000-0000-0000-0000-000000000000",
  reason: "רישום ביומן ביקורת",
};

async function audit(
  pool: pg.Pool,
  session: ActiveSession,
  entry: { action: string; targetId: string; tenantId: string; payload?: unknown },
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
        entry.targetId,
        entry.tenantId,
        JSON.stringify(entry.payload ?? {}),
      ],
    );
  });
}

interface Deps {
  pool: pg.Pool;
  config: Config;
  signer: Signer;

  /**
   * מוחלף בבדיקות, כדי שבדיקת התוכן לא תצא לרשת.
   * בריצה רגילה חסר, ואז נעשה שימוש ב-fetch של Node.
   */
  fetch?: typeof fetch | undefined;
}

/** האם שם מכוסה על ידי רשומה מאושרת: היא עצמה, או אב שלה. */
function coveredBy(domain: string, approved: ReadonlySet<string>): boolean {
  const labels = domain.split(".");

  for (let i = 0; i < labels.length - 1; i++) {
    if (approved.has(labels.slice(i).join("."))) return true;
  }

  return false;
}

export async function registerWhitelistRoutes(
  app: FastifyInstance,
  deps: Deps,
): Promise<void> {
  const { pool, config, signer } = deps;
  const guards = createGuards(pool, config);
  const base = [guards.requireSession, guards.requirePlatformMfa];
  const checkOptions = deps.fetch === undefined ? {} : { fetch: deps.fetch };

  const tighten = [...base, guards.requirePermission("policy.tighten")];
  const loosen = [...base, guards.requirePermission("networks.approve")];

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

  /**
   * הדייר והמחשב של הבקשה, או תשובת שגיאה שכבר נשלחה.
   *
   * מזהה שאינו uuid נענה ב-404 ולא מגיע למסד: שם הוא היה נופל על
   * המרת טיפוס ומחזיר 500, ו"שגיאה פנימית" על כתובת שגויה מלמדת
   * את מי ששואל משהו על המבנה.
   */
  async function scope(
    session: ActiveSession,
    deviceId: string,
    reply: FastifyReply,
  ): Promise<string | null> {
    const tenantId = session.user.tenantId;

    if (!tenantId) {
      await reply.code(400).send({ error: "החשבון אינו משויך לדייר" });
      return null;
    }

    if (!z.string().uuid().safeParse(deviceId).success || !await ownsDevice(tenantId, deviceId)) {
      await reply.code(404).send({ error: "המחשב אינו קיים" });
      return null;
    }

    return tenantId;
  }

  /** מרכיב ומפרסם את המדיניות של המחשב אחרי שינוי. */
  async function republish(
    tenantId: string,
    deviceId: string,
    publishedBy: string,
  ): Promise<number | null> {
    const result = await composeDeviceOverlay(pool, signer, { tenantId, deviceId, publishedBy });

    return result.version;
  }

  // ---------------------------------------------------------------- תצוגה

  app.get<{ Params: { id: string } }>(
    "/api/portal/v1/devices/:id/whitelist",
    { preHandler: [...base, guards.requirePermission("devices.viewOwn")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;

      const empty = {
        enabled: false,
        learningUntil: null,
        serverTime: new Date().toISOString(),
        domains: [],
        observed: [],
        systemDomains: whitelistSystemDomains(),
        maxDomains: MAX_APPROVED_DOMAINS,
      };

      if (!tenantId || !z.string().uuid().safeParse(request.params.id).success) {
        return reply.send(empty);
      }

      const { state, observed } = await withTenant(pool, tenantId, async (tx) => {
        const state = await loadWhitelist(tx, request.params.id);

        /*
         * לפי כמות הבקשות, והרבה לפני המעט.
         *
         * מה שנטען מאות פעמים הוא האתר שהילד באמת השתמש בו; מה
         * שנטען פעם אחת הוא בדרך כלל פרסומת או מעקב. הסדר הזה
         * שם את מה שההורה מחפש בראש.
         */
        const rows = await tx.query<{
          domain: string;
          hits: string;
          last_seen_at: Date;
          verdict: string | null;
        }>(
          `SELECT domain, hits, last_seen_at, verdict
             FROM device_whitelist_observed
            WHERE device_id = $1 AND NOT dismissed
            ORDER BY hits DESC, domain
            LIMIT 2000`,
          [request.params.id],
        );

        return { state, observed: rows.rows };
      });

      const now = new Date();
      const approved = new Set(state.domains.map((d) => d.domain));

      return reply.send({
        enabled: state.enabled,

        // חלון שעבר מוצג כ"אין למידה", בדיוק כפי שהמדיניות אומרת לסוכן.
        learningUntil: learningActive(state, now) ? state.learningUntil!.toISOString() : null,

        /*
         * השעה של השרת, לספירה לאחור.
         *
         * הדפדפן של ההורה והשרת אינם חייבים להסכים על השעה, וספירה
         * שנשענת על שעון הדפדפן הייתה מציגה "נותרו 17 דקות" כשנותרו
         * 12 — או מסיימת כשהלמידה עוד רצה.
         */
        serverTime: now.toISOString(),

        domains: state.domains.map((d) => ({
          id: d.id,
          domain: d.domain,
          source: d.source,
          createdAt: d.created_at,
        })),

        observed: observed.map((o) => {
          const registrable = registrableDomain(o.domain);

          /*
           * חסום לפי השם, או לפי בדיקה חיה שכבר נעשתה ונשמרה.
           *
           * הבדיקה החיה אינה רצה כאן: מאות שאילתות החוצה בכל פתיחת
           * מסך אינן סבירות. היא רצה ברגע האישור, על כל שם, ואין
           * דרך לעקוף אותה — מה שמוצג כאן כ"אפשר לאשר" עוד ייבדק.
           */
          const blocked = o.verdict === "blocked" || looksAdult(o.domain) || looksAdult(registrable);

          return {
            domain: o.domain,
            registrable,
            hits: Number(o.hits),
            lastSeenAt: o.last_seen_at,
            blocked,
            ...(blocked ? { reason: REASON_BLOCKED } : {}),
            approved: coveredBy(o.domain, approved),
          };
        }),

        systemDomains: whitelistSystemDomains(),
        maxDomains: MAX_APPROVED_DOMAINS,
      });
    },
  );

  // ---------------------------------------------------------------- הפעלה וכיבוי

  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/devices/:id/whitelist",
    { preHandler: tighten },
    async (request, reply) => {
      const session = request.portal!.session;
      const parsed = enabledBody.safeParse(request.body);

      if (!parsed.success) return reply.code(400).send({ error: "בקשה לא תקינה" });

      /*
       * כיבוי הוא הקלה, ולכן נבדק מול השער של מה שמתיר.
       *
       * השער שבמסלול הוא של ההחמרה, כי זה הכיוון הנפוץ. הכיוון
       * נודע רק מגוף הבקשה, ולכן הבדיקה השנייה נעשית כאן.
       */
      if (!parsed.data.enabled && !can(session.user.role, "networks.approve")) {
        return reply.code(403).send({ error: "אין הרשאה לפעולה זו.", mfaRequired: false });
      }

      const tenantId = await scope(session, request.params.id, reply);

      if (tenantId === null) return reply;

      const count = await withTenant(pool, tenantId, async (tx) => {
        await tx.query(
          `INSERT INTO device_whitelist (device_id, tenant_id, enabled, updated_by)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (device_id) DO UPDATE
              SET enabled = EXCLUDED.enabled, updated_at = now(), updated_by = EXCLUDED.updated_by`,
          [request.params.id, tenantId, parsed.data.enabled, session.user.userId],
        );

        const r = await tx.query<{ n: string }>(
          "SELECT count(*) AS n FROM device_whitelist_domains WHERE device_id = $1",
          [request.params.id],
        );

        return Number(r.rows[0]?.n ?? 0);
      });

      const version = await republish(tenantId, request.params.id, session.user.userId);

      await audit(pool, session, {
        action: parsed.data.enabled ? "device.whitelist.enabled" : "device.whitelist.disabled",
        targetId: request.params.id,
        tenantId,
        payload: { domains: count, version },
      });

      /*
       * הפעלה עם רשימה ריקה מותרת, ונאמרת.
       *
       * היא אינה טעות בהכרח — הורה רשאי לנעול קודם ולאשר אחר כך —
       * אבל התוצאה היא מחשב שאינו פותח שום אתר, והורה שלא ציפה
       * לזה יחשוב שהמוצר שבר את האינטרנט.
       */
      const warning = parsed.data.enabled && count === 0
        ? "הרשימה ריקה: עד שיאושרו אתרים, המחשב לא יפתח שום אתר מלבד מרכז הניהול של SafeMe. "
        : "";

      return reply.send({ ok: true, enabled: parsed.data.enabled, version, note: warning + NOTE });
    },
  );

  // ---------------------------------------------------------------- אתרים מאושרים

  /**
   * הוספת אתרים: מהקלדה, או מסימון של מה שנצפה בלמידה.
   *
   * שני הנתיבים עוברים כאן, ובכוונה אין נתיב שלישי. בדיקת התוכן
   * היא מה שמונע אישור של אתר למבוגרים, ושער אחד הוא שער שאי
   * אפשר לשכוח לסגור.
   *
   * התשובה מפרטת כל שם בנפרד. בקשה של עשרים שמות שאחד מהם נדחה
   * אינה נכשלת: התשעה־עשר נוספים, וההורה רואה מי נדחה ולמה.
   */
  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/devices/:id/whitelist/domains",
    { preHandler: loosen },
    async (request, reply) => {
      const session = request.portal!.session;
      const parsed = domainsBody.safeParse(request.body);

      if (!parsed.success) {
        return reply.code(400).send({ error: "יש לשלוח בין אתר אחד למאה אתרים בכל פעם." });
      }

      const tenantId = await scope(session, request.params.id, reply);

      if (tenantId === null) return reply;

      const deviceId = request.params.id;
      const source = parsed.data.source;

      interface Result { input: string; domain: string; ok: boolean; reason?: string; already?: boolean }

      const results: Result[] = [];
      const candidates: string[] = [];
      const seen = new Set<string>();

      const existing = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query<{ domain: string }>(
          "SELECT domain FROM device_whitelist_domains WHERE device_id = $1",
          [deviceId],
        );

        return new Set(r.rows.map((x) => x.domain));
      });

      for (const input of parsed.data.domains) {
        // www מוסר רק ממה שהוקלד. ראה NormalizeOptions.
        const domain = normalizeDomain(input, { stripWww: source === "manual" });

        if (domain === null) {
          results.push({
            input,
            domain: input.trim(),
            ok: false,
            reason: "זה אינו שם של אתר. יש לכתוב שם כמו example.co.il, או להדביק קישור.",
          });
          continue;
        }

        if (seen.has(domain)) continue;
        seen.add(domain);

        if (existing.has(domain)) {
          results.push({ input, domain, ok: true, already: true });
          continue;
        }

        candidates.push(domain);
        results.push({ input, domain, ok: false });
      }

      /*
       * התקרה נבדקת לפני הבדיקות החיות, ועל הכול יחד.
       *
       * אישור חלקי עד התקרה היה משאיר את ההורה לנחש אילו נכנסו.
       */
      if (existing.size + candidates.length > MAX_APPROVED_DOMAINS) {
        return reply.code(400).send({
          error:
            `אפשר לאשר עד ${MAX_APPROVED_DOMAINS} אתרים למחשב. ` +
            `כרגע מאושרים ${existing.size}, והבקשה מוסיפה ${candidates.length}.`,
        });
      }

      const verdicts = await checkDomainsAllowed(candidates, checkOptions);
      const allowed: string[] = [];
      const refused: string[] = [];

      for (const result of results) {
        const verdict = verdicts.get(result.domain);

        if (verdict === undefined) continue;

        if (verdict.ok) {
          result.ok = true;
          allowed.push(result.domain);
          continue;
        }

        result.reason = verdict.reason;

        if (verdict.kind === "blocked") refused.push(result.domain);
      }

      await withTenant(pool, tenantId, async (tx) => {
        if (allowed.length > 0) {
          await tx.query(
            `INSERT INTO device_whitelist_domains (device_id, tenant_id, domain, source, created_by)
             SELECT $1, $2, d, $4, $5 FROM unnest($3::text[]) AS d
             ON CONFLICT (device_id, domain) DO NOTHING`,
            [deviceId, tenantId, allowed, source, session.user.userId],
          );
        }

        /*
         * ההכרעה נשמרת על השורה שנצפתה, אם יש כזו.
         *
         * אתר שנפסל יוצג מעתה כחסום במקום לחזור ולהיראות כמו משהו
         * שאפשר לאשר. כשל בבדיקה אינו נשמר: תקלת רשת של רגע לא
         * אמורה לסמן אתר תמים לתמיד.
         */
        for (const [verdict, names] of [["ok", allowed], ["blocked", refused]] as const) {
          if (names.length === 0) continue;

          await tx.query(
            `UPDATE device_whitelist_observed
                SET verdict = $3, checked_at = now()
              WHERE device_id = $1 AND domain = ANY($2::text[])`,
            [deviceId, names, verdict],
          );
        }
      });

      const version = allowed.length > 0
        ? await republish(tenantId, deviceId, session.user.userId)
        : null;

      /*
       * גם ניסיון שנדחה כולו נרשם.
       *
       * מי שניסה לאשר אתר למבוגרים ונדחה הוא בדיוק מה שהורה שני,
       * או בעל החשבון, ירצה לדעת עליו.
       */
      await audit(pool, session, {
        action: "device.whitelist.domains_added",
        targetId: deviceId,
        tenantId,
        payload: {
          source,
          added: allowed,
          rejected: results.filter((r) => !r.ok).map((r) => ({ domain: r.domain, reason: r.reason })),
          version,
        },
      });

      return reply.send({
        ok: true,
        added: allowed.length,
        results,
        version,
        ...(allowed.length > 0 ? { note: NOTE } : {}),
      });
    },
  );

  app.delete<{ Params: { id: string; domainId: string } }>(
    "/api/portal/v1/devices/:id/whitelist/domains/:domainId",
    { preHandler: tighten },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = await scope(session, request.params.id, reply);

      if (tenantId === null) return reply;

      if (!z.string().uuid().safeParse(request.params.domainId).success) {
        return reply.code(404).send({ error: "האתר אינו ברשימה" });
      }

      const removed = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query<{ domain: string }>(
          `DELETE FROM device_whitelist_domains
            WHERE id = $1 AND device_id = $2 AND tenant_id = $3
        RETURNING domain`,
          [request.params.domainId, request.params.id, tenantId],
        );

        return r.rows[0]?.domain ?? null;
      });

      if (removed === null) return reply.code(404).send({ error: "האתר אינו ברשימה" });

      const version = await republish(tenantId, request.params.id, session.user.userId);

      await audit(pool, session, {
        action: "device.whitelist.domain_removed",
        targetId: request.params.id,
        tenantId,
        payload: { domain: removed, version },
      });

      return reply.send({ ok: true, version, note: NOTE });
    },
  );

  // ---------------------------------------------------------------- למידה

  /**
   * פותח חלון למידה, או מאריך חלון פתוח.
   *
   * החלון נמדד מעכשיו: "30 דקות" פירושו שלושים דקות מהלחיצה, גם
   * אם כבר רצה למידה. כך לחיצה נוספת היא הארכה, והמספר שעל הכפתור
   * הוא תמיד מה שיקרה.
   *
   * הסוכן אינו מקבל דחיפה. הוא ילמד על החלון בפעימה הבאה שלו, ולכן
   * הלמידה מתחילה במחשב עד שלוש דקות אחרי הלחיצה — והתשובה אומרת
   * זאת, כדי שההורה לא יגלוש שתי דקות לשווא.
   */
  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/devices/:id/whitelist/learning",
    { preHandler: loosen },
    async (request, reply) => {
      const session = request.portal!.session;
      const parsed = learningBody.safeParse(request.body);

      if (!parsed.success) {
        return reply.code(400).send({ error: "משך הלמידה הוא בין 5 ל-120 דקות." });
      }

      const tenantId = await scope(session, request.params.id, reply);

      if (tenantId === null) return reply;

      const until = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query<{ learning_until: Date }>(
          `INSERT INTO device_whitelist
             (device_id, tenant_id, learning_until, learning_started_at, updated_by)
           VALUES ($1, $2, now() + ($3::int * interval '1 minute'), now(), $4)
           ON CONFLICT (device_id) DO UPDATE
              SET learning_until = EXCLUDED.learning_until,
                  -- חלון שעדיין פתוח שומר על שעת ההתחלה שלו: זו הארכה, לא התחלה.
                  learning_started_at = CASE
                    WHEN device_whitelist.learning_until > now()
                    THEN device_whitelist.learning_started_at
                    ELSE now() END,
                  updated_at = now(),
                  updated_by = EXCLUDED.updated_by
        RETURNING learning_until`,
          [request.params.id, tenantId, parsed.data.minutes, session.user.userId],
        );

        return r.rows[0]!.learning_until;
      });

      const version = await republish(tenantId, request.params.id, session.user.userId);

      await audit(pool, session, {
        action: "device.whitelist.learning_started",
        targetId: request.params.id,
        tenantId,
        payload: { minutes: parsed.data.minutes, until: until.toISOString(), version },
      });

      return reply.send({
        ok: true,
        learningUntil: until.toISOString(),
        serverTime: new Date().toISOString(),
        version,
        note: LEARNING_NOTE,
      });
    },
  );

  app.delete<{ Params: { id: string } }>(
    "/api/portal/v1/devices/:id/whitelist/learning",
    { preHandler: tighten },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = await scope(session, request.params.id, reply);

      if (tenantId === null) return reply;

      /*
       * "עכשיו" ולא NULL.
       *
       * הסוכן עוד מחזיק שמות שצבר ולא שלח, ונקודת הקליטה מקבלת
       * אותם עד עשר דקות אחרי סוף החלון. NULL היה אומר "מעולם לא
       * הייתה למידה", והמנה האחרונה — לעיתים העיקרית — הייתה נזרקת.
       */
      await withTenant(pool, tenantId, (tx) =>
        tx.query(
          `UPDATE device_whitelist
              SET learning_until = now(), updated_at = now(), updated_by = $2
            WHERE device_id = $1 AND learning_until > now()`,
          [request.params.id, session.user.userId],
        ));

      const version = await republish(tenantId, request.params.id, session.user.userId);

      await audit(pool, session, {
        action: "device.whitelist.learning_stopped",
        targetId: request.params.id,
        tenantId,
        payload: { version },
      });

      return reply.send({ ok: true, learningUntil: null, version, note: NOTE });
    },
  );

  // ---------------------------------------------------------------- מה שנצפה

  /**
   * מסיר שמות מרשימת הנצפים, בלי לאשר אותם.
   *
   * השורה מסומנת ולא נמחקת: שם שנמחק היה חוזר בדיווח הבא של
   * הסוכן, וההורה היה מסיר את אותן פרסומות שוב ושוב.
   *
   * אינו נוגע במדיניות — הנצפים אינם חלק ממנה — ולכן דבר אינו
   * מתפרסם.
   */
  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/devices/:id/whitelist/observed/dismiss",
    { preHandler: tighten },
    async (request, reply) => {
      const session = request.portal!.session;
      const parsed = dismissBody.safeParse(request.body);

      if (!parsed.success) return reply.code(400).send({ error: "בקשה לא תקינה" });

      const tenantId = await scope(session, request.params.id, reply);

      if (tenantId === null) return reply;

      const names = parsed.data.domains.map((d) => d.trim().toLowerCase());

      const dismissed = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query(
          `UPDATE device_whitelist_observed SET dismissed = true
            WHERE device_id = $1 AND domain = ANY($2::text[]) AND NOT dismissed`,
          [request.params.id, names],
        );

        return r.rowCount ?? 0;
      });

      await audit(pool, session, {
        action: "device.whitelist.observed_dismissed",
        targetId: request.params.id,
        tenantId,
        payload: { count: dismissed },
      });

      return reply.send({ ok: true, dismissed });
    },
  );

  /** מוחק את כל מה שנצפה, כולל מה שהוסר. התחלה נקייה ללמידה חדשה. */
  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/devices/:id/whitelist/observed/clear",
    { preHandler: tighten },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = await scope(session, request.params.id, reply);

      if (tenantId === null) return reply;

      const cleared = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query(
          "DELETE FROM device_whitelist_observed WHERE device_id = $1",
          [request.params.id],
        );

        return r.rowCount ?? 0;
      });

      await audit(pool, session, {
        action: "device.whitelist.observed_cleared",
        targetId: request.params.id,
        tenantId,
        payload: { count: cleared },
      });

      return reply.send({ ok: true, cleared });
    },
  );
}
