import type { FastifyInstance } from "fastify";
import type pg from "pg";
import { z } from "zod";

import { withTenant, withPlatform } from "../db/client.ts";
import { createGuards } from "../auth/guards.ts";
import { isPlatformRole } from "../auth/rbac.ts";
import type { ActiveSession } from "../auth/session.ts";
import type { Config } from "../config.ts";
import type { Signer } from "../crypto/signing.ts";
import { publishPolicy } from "../policy/publish.ts";
import { buildEgressRule, describeEgress, type EgressRule } from "../policy/egress.ts";

/**
 * הגדרת ה-default-deny.
 *
 * מה שמייחד את המסלול הזה משאר ההגדרות: הוא אינו כותב שורה בטבלה
 * אלא **מפרסם מדיניות חדשה וחתומה**.
 *
 * הסוכן אוכף רק מה שנחתם. הגדרה ששמורה במאגר ולא נחתמה אינה משנה
 * דבר על אף מחשב — היא רק נראית כאילו. לכן כל שינוי כאן הוא גרסת
 * מדיניות חדשה, והמחשבים מושכים אותה בפעימה הבאה.
 */

const bodySchema = z.object({
  enabled: z.boolean(),
  mode: z.enum(["ispLevel", "proxyEndpoint"]).default("ispLevel"),
  allowQuic: z.boolean().default(false),

  /** שרתי ה-DNS של הספק. ריק פותח את הפורט לכל שרת שמות. */
  resolvers: z.array(z.string().trim().min(1)).max(20).default([]),

  /** היעדים המותרים במצב שרתי ספק. */
  providerCidrs: z.array(z.string().trim().min(1)).max(50).default([]),

  youtubeAudioOnly: z.boolean().optional(),
});

interface Deps {
  pool: pg.Pool;
  config: Config;
  signer: Signer;
}

const SYSTEM_ACTOR = {
  userId: "00000000-0000-0000-0000-000000000000",
  reason: "רישום ביומן ביקורת",
};

/**
 * צורת CIDR.
 *
 * נבדקת כאן ולא רק בסוכן, כי טווח שגוי במצב שרתי-ספק אינו תקלה
 * קוסמטית: הוא מוריד את המחשב לנעילה מלאה. מוטב לדחות בטופס.
 */
const CIDR = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}|[0-9a-fA-F:]+\/\d{1,3})$/;

function invalidCidrs(values: readonly string[]): string[] {
  return values.filter((v) => !CIDR.test(v.trim()));
}

export async function registerEgressRoutes(
  app: FastifyInstance,
  deps: Deps,
): Promise<void> {
  const { pool, config, signer } = deps;
  const guards = createGuards(pool, config);
  const base = [guards.requireSession, guards.requirePlatformMfa];

  /** ההגדרה הנוכחית, כפי שהיא במדיניות שפורסמה. */
  app.get(
    "/api/portal/v1/settings/egress",
    { preHandler: [...base, guards.requirePermission("devices.viewOwn")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;

      if (!tenantId) return reply.send({ rule: buildEgressRule(), browser: { youtubeAudioOnly: false }, version: null });

      const current = await loadCurrent(pool, tenantId);

      return reply.send({
        rule: current.rule,
        browser: current.browser,
        version: current.version,
        description: describeEgress(current.rule),
      });
    },
  );

  /**
   * שינוי ההגדרה.
   *
   * ההרשאה היא networks.approve ולא policy.tighten: המסלול הזה
   * יכול גם להקל — לכבות את המצב, או לפתוח QUIC — ומה שמתיר מקבל
   * שער משלו.
   */
  app.post(
    "/api/portal/v1/settings/egress",
    { preHandler: [...base, guards.requirePermission("networks.approve")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;
      const parsed = bodySchema.safeParse(request.body);

      if (!parsed.success) return reply.code(400).send({ error: "בקשה לא תקינה" });
      if (!tenantId) return reply.code(400).send({ error: "אין דייר משויך" });

      const input = parsed.data;

      // ---- בדיקות שמונעות נעילה בשוגג ----

      const bad = invalidCidrs([...input.resolvers, ...input.providerCidrs]);

      if (bad.length > 0) {
        return reply.code(400).send({
          error: `טווח כתובות לא תקין: ${bad.join(", ")}. הצורה היא 1.2.3.4/32.`,
        });
      }

      /*
       * מצב שרתי-ספק בלי כתובות נועל את כל המחשבים.
       *
       * הסוכן מטפל בזה נכון — הוא נועל ולא פותח — אבל התוצאה
       * זהה: משפחה בלי אינטרנט בגלל טופס שנשלח חצי. נדחה כאן.
       */
      if (input.enabled && input.mode === "proxyEndpoint" && input.providerCidrs.length === 0) {
        return reply.code(400).send({
          error:
            "מצב שרתי ספק מחייב לפחות טווח כתובות אחד. " +
            "בלעדיו כל המחשבים יינעלו לחלוטין.",
        });
      }

      const rule = buildEgressRule({
        enabled: input.enabled,
        mode: input.mode,
        allowQuic: input.allowQuic,
        resolvers: input.resolvers,
        providerCidrs: input.providerCidrs,
      });

      // ---- פרסום ----

      const current = await loadCurrent(pool, tenantId);

      /*
       * הבסיס להרכבה הוא הבסיס, ולא העותק של הדייר.
       *
       * כאן נולד הפיצול. הגוף נבנה מ-current.body, שהוא המדיניות
       * שהדייר כבר מקבל — כלומר העותק שלו עצמו מהפעם הקודמת. כל
       * שמירה יצרה עותק של עותק, והדייר נותק מהבסיס לצמיתות: ספק
       * חדש, כלל זיהוי חדש, מארח פתוח חדש — שום דבר לא הגיע.
       *
       * נצפה בשטח בגרסה 17, בזמן שהבסיס עמד על 13 עם שני גששים
       * חדשים לנטפרי. השכבה של הדייר היא כלל היציאה בלבד, וכל
       * השאר צריך להתרענן איתו.
       */
      const base = await loadBaselineBody(pool, tenantId);

      const prevEnforcement = ((base ?? current.body ?? {})["enforcement"] ?? {}) as Record<string, unknown>;
      const prevBrowser = (prevEnforcement["browser"] ?? {}) as Record<string, unknown>;
      const browserPatch = input.youtubeAudioOnly !== undefined
        ? { ...prevBrowser, youtubeAudioOnly: input.youtubeAudioOnly }
        : prevBrowser;

      const version = await nextVersion(pool, tenantId);

      const body = {
        ...(base ?? current.body ?? {}),
        version,
        issuedUtc: new Date().toISOString(),
        enforcement: {
          ...prevEnforcement,
          egress: rule,
          browser: browserPatch,
        },
      };

      const published = await publishPolicy(pool, signer, {
        tenantId,
        version,
        body,
        publishedBy: session.user.userId,
      });

      await audit(pool, session, {
        action: input.enabled ? "settings.egress.enabled" : "settings.egress.disabled",
        tenantId,
        payload: { mode: rule.mode, allowQuic: rule.allowQuic, version },
      });

      return reply.send({
        ok: true,
        rule,
        browser: { youtubeAudioOnly: (browserPatch as { youtubeAudioOnly?: boolean }).youtubeAudioOnly ?? false },
        version: published.version,
        description: describeEgress(rule),
        note:
          "המחשבים יקבלו את השינוי בפעימה הבאה, בדרך כלל תוך שלוש דקות.",
      });
    },
  );
}

interface BrowserSettings {
  youtubeAudioOnly: boolean;
}

interface Current {
  rule: EgressRule;
  browser: BrowserSettings;
  version: number | null;
  body: Record<string, unknown> | null;
  enforcement: Record<string, unknown> | null;
}

/**
 * המדיניות הפעילה של הדייר.
 *
 * נטענת מהגוף המפורש ולא מהבתים החתומים: הבתים הם מה שנשלח למחשב
 * ואין לשנותם, והגוף הוא אותו תוכן בצורה שאפשר לקרוא ולערוך.
 *
 * דייר בלי מדיניות משלו מקבל את התבנית הגלובלית כבסיס, כדי שההגדרה
 * הראשונה לא תמחק את מה שכבר חל עליו.
 */
async function loadCurrent(pool: pg.Pool, tenantId: string): Promise<Current> {
  const row = await withTenant(pool, tenantId, async (tx) => {
    /*
     * שורות ששייכות למחשב מסוים אינן מדיניות הדייר.
     *
     * שתיהן נושאות tenant_id, ולכן בחירה לפי הגרסה הגבוהה בלבד
     * נוחתת על שכבה של מחשב אחד ומציגה אותה כהגדרה של כולם.
     */
    const own = await tx.query<{ version: number; body: Record<string, unknown> }>(
      `SELECT p.version, p.body FROM policies p
        WHERE p.tenant_id = $1
          AND NOT EXISTS (
            SELECT 1 FROM device_policy_assignments a WHERE a.policy_id = p.id
          )
        ORDER BY p.version DESC LIMIT 1`,
      [tenantId],
    );

    if (own.rows[0]) return { ...own.rows[0], inherited: false };

    const global = await tx.query<{ body: Record<string, unknown> }>(
      "SELECT body FROM policies WHERE tenant_id IS NULL ORDER BY version DESC LIMIT 1",
    );

    return global.rows[0] ? { version: 0, body: global.rows[0].body, inherited: true } : null;
  });

  if (row === null) {
    return { rule: buildEgressRule(), browser: { youtubeAudioOnly: false }, version: null, body: null, enforcement: null };
  }

  const enforcement = (row.body["enforcement"] ?? null) as Record<string, unknown> | null;
  const stored = enforcement?.["egress"];
  const storedBrowser = (enforcement?.["browser"] ?? {}) as Record<string, unknown>;

  return {
    // הגדרה שאינה קיימת עדיין מוצגת ככבויה, ולא כשגיאה: זה המצב
    // של כל דייר לפני השינוי הראשון.
    rule: isEgressRule(stored) ? stored : buildEgressRule(),
    browser: { youtubeAudioOnly: storedBrowser["youtubeAudioOnly"] === true },
    version: row.inherited ? null : row.version,
    body: row.body,
    enforcement,
  };
}

function isEgressRule(value: unknown): value is EgressRule {
  return typeof value === "object"
    && value !== null
    && typeof (value as { enabled?: unknown }).enabled === "boolean";
}

async function audit(
  pool: pg.Pool,
  session: ActiveSession,
  entry: { action: string; tenantId?: string | null; payload?: unknown },
): Promise<void> {
  await withPlatform(pool, SYSTEM_ACTOR, async (tx) => {
    await tx.query(
      `INSERT INTO audit_log
         (actor_type, actor_id, action, target_type, target_id, tenant_id, payload)
       VALUES ($1, $2, $3, 'settings', $4, $4, $5)`,
      [
        isPlatformRole(session.user.role) ? "platform_user" : "tenant_user",
        session.user.userId,
        entry.action,
        entry.tenantId ?? session.user.tenantId,
        JSON.stringify(entry.payload ?? {}),
      ],
    );
  });
}

/** גוף מדיניות הבסיס, שהוא המקור לכל מה שאינו שכבת הדייר. */
async function loadBaselineBody(
  pool: pg.Pool,
  tenantId: string,
): Promise<Record<string, unknown> | null> {
  return withTenant(pool, tenantId, async (tx) => {
    const r = await tx.query<{ body: Record<string, unknown> }>(
      "SELECT body FROM policies WHERE tenant_id IS NULL ORDER BY version DESC LIMIT 1",
    );

    return r.rows[0]?.body ?? null;
  });
}

/**
 * המספר הבא, מעל כל השרשראות — כולל גרסאות שנמחקו.
 *
 * הרכבה מחדש עלולה למחוק שורות עם גרסאות גבוהות, ואז max(version)
 * יורד אחורה. הסוכן דוחה מדיניות שגרסתה נמוכה מזו שבידיו, ולכן
 * הגרסה החדשה חייבת לעבור גם את מה שהמחשב מחזיק מקומית.
 *
 * שלוש נקודות מדידה:
 *   1. version (עמודה) — הגרסה הגבוהה בשורות שנותרו
 *   2. body->'version' — הגרסה שנחתמה בגוף (עשויה להיות גבוהה מהעמודה)
 *   3. device_state.policy_version — מה שהסוכנים דיווחו בפעימה האחרונה
 */
async function nextVersion(pool: pg.Pool, tenantId: string): Promise<number> {
  return withTenant(pool, tenantId, async (tx) => {
    const r = await tx.query<{ version: number }>(
      `SELECT GREATEST(
         COALESCE((SELECT max(version) FROM policies WHERE tenant_id = $1 OR tenant_id IS NULL), 0),
         COALESCE((SELECT max((body->>'version')::int) FROM policies WHERE tenant_id = $1 OR tenant_id IS NULL), 0),
         COALESCE((SELECT max(ds.policy_version) FROM device_state ds JOIN devices d ON d.id = ds.device_id WHERE d.tenant_id = $1), 0)
       ) AS version`,
      [tenantId],
    );

    return (r.rows[0]?.version ?? 0) + 1;
  });
}
