import type { FastifyInstance } from "fastify";
import type pg from "pg";
import { z } from "zod";

import { withPlatform } from "../db/client.ts";
import { createGuards } from "../auth/guards.ts";
import type { Config } from "../config.ts";
import type { Signer } from "../crypto/signing.ts";
import { republishBaseline } from "../policy/baseline.ts";
import {
  hasAnyRule,
  listProviders,
  validateDetection,
  type Detection,
} from "../policy/providers.ts";

/**
 * ניהול ספקי הסינון.
 *
 * הרשאת פלטפורמה בלבד, ולא של דייר. מי שמגדיר מה נחשב "ספק מאושר"
 * מגדיר בפועל מה נחשב חיבור מסונן — ודייר שיכול לעשות זאת יכול
 * לאשר לעצמו כל חיבור שהוא, ובכך לבטל את המוצר מבפנים.
 *
 * וכמו במסך ה-default-deny: שינוי כאן **מפרסם מדיניות חתומה חדשה**.
 * הסוכן אוכף רק מה שנחתם, וכלל ששמור במאגר ולא נחתם אינו משנה דבר
 * על אף מחשב.
 */

const detectionSchema = z.object({
  rootCa: z
    .object({
      thumbprints: z.array(z.string().trim().min(1)).max(50).default([]),
      subjectPatterns: z.array(z.string().trim().min(1)).max(20).default([]),
      required: z.boolean().default(false),
    })
    .optional(),
  network: z
    .object({
      cidrs: z.array(z.string().trim().min(1)).max(100).default([]),
      asns: z.array(z.number().int()).max(50).default([]),
      reverseDnsPatterns: z.array(z.string().trim().min(1)).max(20).default([]),
    })
    .optional(),
  /*
   * מנפיק התעודה.
   *
   * הווקטור החזק ביותר לספק שמסנן דרך פרוקסי — והוא לא היה בסכימה
   * כלל. zod משמיט מה שאינו בה, ולכן כל עריכה בממשק מחקה אותו:
   * לחיצה אחת על "שמור" ברימון הייתה מוחקת את *netspark*, הווקטור
   * היחיד שמזהה אותה, בלי אזהרה.
   *
   * זו הפעם השנייה שאותו כשל קורה בסכימה הזו. הראשונה הייתה
   * ב-httpMarkers, וההערה שמתחת מתעדת אותה. שדה שנוסף למודל ולא
   * לסכימה אינו נכשל — הוא נמחק בשקט.
   */
  tlsIssuer: z
    .object({
      patterns: z.array(z.string().trim().min(1)).max(20).default([]),
      probes: z.array(z.string().trim().min(1)).max(10).default([]),
    })
    .optional(),

  /*
   * סמני HTTP.
   *
   * הסכימה קיבלה url ו-bodyContains בלבד, ו-zod משמיט מה שאינו
   * בסכימה. עריכה אחת של רימון בממשק היתה מוחקת את כותרת
   * הזיהוי ואת קריאת רמת ההגנה — בלי אזהרה, ובלי דרך חזרה:
   * אותה עריכה ממלאת גם את updated_by, ומשם ואילך הזריעה
   * מדלגת על השורה לנצח.
   *
   * כל השדות מופיעים עכשיו, גם אלה שהממשק אינו עורך.
   */
  httpMarkers: z
    .object({
      url: z.string().trim().url().optional(),
      headers: z.record(z.string(), z.string()).optional(),
      bodyContains: z.array(z.string().trim().min(1)).max(20).default([]),

      probes: z
        .array(
          z.object({
            url: z.string().trim().url(),
            status: z.number().int().min(100).max(599).optional(),
            bodyContains: z.array(z.string().trim().min(1)).max(10).default([]),
            bodyNotContains: z.array(z.string().trim().min(1)).max(10).default([]),
          }),
        )
        .max(5)
        .optional(),

      levelHosts: z.array(z.string().trim().min(1)).max(10).optional(),
      levelNames: z.array(z.string().trim().min(1)).max(20).optional(),
    })
    .optional(),
});

const updateBody = z.object({
  displayName: z.string().trim().min(1).max(80).optional(),
  trustLevel: z.enum(["low", "medium", "high"]).optional(),
  enabled: z.boolean().optional(),
  detection: detectionSchema.optional(),
});

const createBody = updateBody.extend({
  key: z
    .string()
    .trim()
    .min(2)
    .max(40)
    // מזהה יציב שנכנס לחבילת המדיניות ומושווה בסוכן. אותיות
    // קטנות בלבד, כדי שלא יהיו שני ספקים שנבדלים ברישיות.
    .regex(/^[a-z][a-z0-9_-]*$/, "מזהה באותיות קטנות, מתחיל באות"),
  displayName: z.string().trim().min(1).max(80),
});

interface Deps {
  pool: pg.Pool;
  config: Config;
  signer: Signer;
}

const SYSTEM = { userId: "system", reason: "ניהול ספקי סינון" };

export async function registerProviderRoutes(
  app: FastifyInstance,
  deps: Deps,
): Promise<void> {
  const { pool, config, signer } = deps;
  const guards = createGuards(pool, config);

  const base = [
    guards.requireSession,
    guards.requirePlatformMfa,
    guards.requirePermission("providers.manage"),
  ];

  /** הספקים, עם סימון מי מהם חסר כללים. */
  app.get("/api/portal/v1/providers", { preHandler: base }, async (_request, reply) => {
    const providers = await listProviders(pool);

    return reply.send({
      providers: providers.map((p) => ({
        ...p,

        // ספק בלי כלל אינו שגיאה, אבל הוא גם לא יזוהה לעולם.
        hasRules: hasAnyRule(p.detection),

        /*
         * ושלד גרוע מחוסר: "CN=Etrog*" נראה ברשימה בדיוק כמו
         * טביעת אצבע אמיתית, ולא יתאים לעולם. בלי הסימון הזה
         * הפער נראה כמו כלל שעובד.
         */
        verified: p.detection.dataStatus === "verified",
      })),
    });
  });

  /** הוספת ספק. */
  app.post("/api/portal/v1/providers", { preHandler: base }, async (request, reply) => {
    const parsed = createBody.safeParse(request.body);

    if (!parsed.success) {
      return reply.code(400).send({ error: parsed.error.issues[0]?.message ?? "בקשה לא תקינה" });
    }

    const detection = (parsed.data.detection ?? {}) as Detection;
    const problem = validateDetection(detection);

    if (problem !== null) return reply.code(400).send({ error: problem });

    const created = await withPlatform(pool, SYSTEM, async (tx) => {
      const r = await tx.query<{ id: string }>(
        `INSERT INTO providers (key, display_name, trust_level, enabled, detection, updated_by)
         VALUES ($1, $2, $3::trust_level, $4, $5::jsonb, $6)
         ON CONFLICT (key) DO NOTHING
         RETURNING id`,
        [
          parsed.data.key,
          parsed.data.displayName,
          parsed.data.trustLevel ?? "medium",
          parsed.data.enabled ?? true,
          JSON.stringify(detection),
          request.portal!.session.user.userId,
        ],
      );

      return r.rows[0] ?? null;
    });

    if (created === null) return reply.code(409).send({ error: "מזהה הספק כבר קיים." });

    const version = await republishBaseline(pool, signer, config.PORTAL_URL);

    return reply.send({ ok: true, policyVersion: version, ...noteFor(detection) });
  });

  /**
   * עדכון ספק.
   *
   * כל שינוי נשמר קודם בהיסטוריה. כלל זיהוי שגוי מנתק משפחות
   * מהאינטרנט או מזהה כמסונן מה שאינו — ובשני המקרים צריך לדעת
   * מה היה קודם ומי שינה.
   */
  app.patch<{ Params: { key: string } }>(
    "/api/portal/v1/providers/:key",
    { preHandler: base },
    async (request, reply) => {
      const parsed = updateBody.safeParse(request.body);

      if (!parsed.success) {
        return reply.code(400).send({ error: parsed.error.issues[0]?.message ?? "בקשה לא תקינה" });
      }

      if (parsed.data.detection !== undefined) {
        const problem = validateDetection(parsed.data.detection as Detection);

        if (problem !== null) return reply.code(400).send({ error: problem });
      }

      const updated = await withPlatform(pool, SYSTEM, async (tx) => {
        const current = await tx.query<{
          id: string;
          detection: Detection;
          trust_level: string;
          enabled: boolean;
        }>(
          "SELECT id, detection, trust_level, enabled FROM providers WHERE key = $1",
          [request.params.key],
        );

        const row = current.rows[0];

        if (!row) return null;

        // ההיסטוריה נכתבת לפני השינוי, ובאותה טרנזקציה. אחריו היא
        // הייתה יכולה ללכת לאיבוד בדיוק כשהיא הכי נחוצה.
        await tx.query(
          `INSERT INTO provider_history (provider_id, detection, trust_level, enabled, changed_by)
           VALUES ($1, $2::jsonb, $3::trust_level, $4, $5)`,
          [
            row.id,
            JSON.stringify(row.detection),
            row.trust_level,
            row.enabled,
            request.portal!.session.user.userId,
          ],
        );

        /*
         * מיזוג לפי מקטע, ולא דריסה של הכול.
         *
         * הוספת שדה לסכימה מתקנת את המקרה הידוע; היא אינה מונעת את
         * הבא. ממשק ששולח מקטע אחד לא אמור למחוק מקטעים שהוא כלל
         * אינו מכיר — וזה בדיוק מה שקרה פעמיים כאן, פעם ב-httpMarkers
         * ופעם ב-tlsIssuer.
         *
         * מקטע שנשלח מחליף את קודמו במלואו: זה מה שמאפשר למחוק
         * טביעה או טווח. מקטע שלא נשלח נשאר כפי שהיה.
         */
        const merged = parsed.data.detection === undefined
          ? null
          : { ...(row.detection ?? {}), ...(parsed.data.detection as object) };

        const next = {
          displayName: parsed.data.displayName ?? null,
          trustLevel: parsed.data.trustLevel ?? null,
          enabled: parsed.data.enabled ?? null,
          detection: merged === null ? null : JSON.stringify(merged),
        };

        await tx.query(
          `UPDATE providers SET
             display_name = COALESCE($2, display_name),
             trust_level  = COALESCE($3::trust_level, trust_level),
             enabled      = COALESCE($4, enabled),
             detection    = COALESCE($5::jsonb, detection),
             updated_by   = $6,
             updated_at   = now()
           WHERE id = $1`,
          [
            row.id,
            next.displayName,
            next.trustLevel,
            next.enabled,
            next.detection,
            request.portal!.session.user.userId,
          ],
        );

        return row.id;
      });

      if (updated === null) return reply.code(404).send({ error: "הספק אינו קיים" });

      const version = await republishBaseline(pool, signer, config.PORTAL_URL);

      return reply.send({
        ok: true,
        policyVersion: version,
        ...noteFor(parsed.data.detection as Detection | undefined),
      });
    },
  );

  /** היסטוריית השינויים של ספק. */
  app.get<{ Params: { key: string } }>(
    "/api/portal/v1/providers/:key/history",
    { preHandler: base },
    async (request, reply) => {
      const history = await withPlatform(pool, SYSTEM, async (tx) => {
        const r = await tx.query(
          `SELECT h.changed_at, h.trust_level, h.enabled, h.detection, u.email AS changed_by
             FROM provider_history h
             JOIN providers p ON p.id = h.provider_id
             LEFT JOIN users u ON u.id = h.changed_by
            WHERE p.key = $1
            ORDER BY h.changed_at DESC
            LIMIT 50`,
          [request.params.key],
        );

        return r.rows;
      });

      return reply.send({ history });
    },
  );
}

/**
 * הערה למי ששמר ספק בלי כללים.
 *
 * לא שגיאה — זה מצב לגיטימי — אבל בלי אמירה מפורשת הוא ייראה
 * כאילו הוא עובד, והמחשבים ידווחו "לא זוהה ספק" בלי שאיש יקשר
 * בין הדברים.
 */
function noteFor(detection: Detection | undefined): { note: string | null } {
  if (detection === undefined) return { note: null };

  return {
    note: hasAnyRule(detection)
      ? null
      : "לספק אין כללי זיהוי, ולכן הוא לא יזוהה על אף מחשב.",
  };
}
