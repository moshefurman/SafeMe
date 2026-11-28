import type { FastifyInstance } from "fastify";
import { trusteeGate } from "../auth/trustee.ts";
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
import { nextPolicyVersion } from "../policy/compose.ts";
import { rebuildAssignedPolicies } from "../policy/recompose.ts";

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
  youtubeHideThumbnails: z.boolean().optional(),

  /** ערוצים שבהם הסרטון מוצג במלואו. קישור, ‎@handle או מזהה UC. */
  youtubeAllowedChannels: z.array(z.string().trim().min(1).max(200)).max(100).optional(),

  aiSafeMode: z.boolean().optional(),

  /** ביטויים חסומים. תשובת AI שמכילה אחד מהם מטושטשת. */
  aiBlockedKeywords: z.array(z.string().trim().min(1).max(200)).max(1000).optional(),
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

/**
 * ערוץ יוטיוב בצורה אחידה: "@handle" באותיות קטנות, או מזהה UC.
 *
 * מתקבל קישור מלא, ‎@handle או מזהה. קישורי ‎/c/ ו-‎/user/ הישנים
 * נדחים: אין להם צורה יציבה שהתוסף יכול להשוות אליה.
 */
export function normalizeChannel(raw: string): string | null {
  let s = raw.trim();
  try { s = decodeURIComponent(s); } catch { /* נשאר כמו שהוא */ }

  const id = s.match(/(?:^|\/channel\/)(UC[\w-]{22})(?=$|[/?#])/);
  if (id) return id[1]!;

  const handle = s.match(/(?:^|youtube\.com\/)@([^/?#\s]{3,100})(?=$|[/?#])/i);
  if (handle) return `@${handle[1]!.toLowerCase()}`;

  // שם בלי ‎@, כמו "NatGeo". רק כשזו כל המחרוזת, כדי ש-"youtube.com/watch" לא ייקרא כערוץ.
  if (/^[^\s/?#@.:]{3,100}$/.test(s)) return `@${s.toLowerCase()}`;

  return null;
}

function readChannels(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

const EMPTY_BROWSER: BrowserSettings = {
  youtubeAudioOnly: false,
  youtubeHideThumbnails: false,
  youtubeAllowedChannels: [],
  aiSafeMode: false,
  aiBlockedKeywords: [],
};

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

      if (!tenantId) return reply.send({ rule: buildEgressRule(), browser: EMPTY_BROWSER, version: null });

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

      let channels: string[] | undefined;

      if (input.youtubeAllowedChannels !== undefined) {
        const normalized = input.youtubeAllowedChannels.map((c) => [c, normalizeChannel(c)] as const);
        const wrong = normalized.filter(([, n]) => n === null).map(([c]) => c);

        if (wrong.length > 0) {
          return reply.code(400).send({
            error:
              `ערוץ לא מזוהה: ${wrong.join(", ")}. ` +
              "יש להדביק קישור לערוץ (youtube.com/@שם) או לכתוב ‎@שם.",
          });
        }

        channels = [...new Set(normalized.map(([, n]) => n!))];
      }

      // ---- פרסום ----

      const current = await loadCurrent(pool, tenantId);

      /*
       * מה בשמירה הזו מקל, ביחס למה שיש עכשיו.
       *
       * הטופס שולח את כל השדות בכל שמירה, ולכן אי אפשר לשפוט לפי
       * הגוף לבדו: "כבוי" יכול להיות מצב שלא השתנה. רק מה שהיה
       * פעיל ועכשיו נכבה, או היה חסום ועכשיו מותר, נחשב הקלה.
       */
      {
        const eased: string[] = [];
        const was = current.rule;
        const wasBrowser = current.browser;

        if (was.enabled && !rule.enabled) eased.push("לכבות את חסימת ה-VPN ותוכנות העקיפה");
        if (rule.enabled && was.mode === "proxyEndpoint" && rule.mode !== "proxyEndpoint") eased.push("לרדת מחסימה מחמירה לרגילה");
        if (rule.enabled && !was.allowQuic && rule.allowQuic) eased.push("להתיר גלישה מהירה (QUIC), שחלק מהסינון אינו חל עליה");
        if (wasBrowser.youtubeAudioOnly && input.youtubeAudioOnly === false) eased.push("לבטל את \"יוטיוב בשמע בלבד\"");
        if (wasBrowser.youtubeHideThumbnails && input.youtubeHideThumbnails === false) eased.push("לבטל את הסתרת התמונות ביוטיוב");
        if (wasBrowser.aiSafeMode && input.aiSafeMode === false) eased.push("לבטל את הסינון במנועי AI");

        if (channels !== undefined) {
          const added = channels.filter((c) => !wasBrowser.youtubeAllowedChannels.includes(c));

          if (added.length > 0) eased.push(`להתיר צפייה בערוצי יוטיוב: ${added.slice(0, 6).join(", ")}`);
        }

        if (input.aiBlockedKeywords !== undefined && wasBrowser.aiSafeMode) {
          const kept = new Set(input.aiBlockedKeywords.map((k) => k.toLowerCase()));
          const removed = wasBrowser.aiBlockedKeywords.filter((k) => !kept.has(k.toLowerCase()));

          if (removed.length > 0) eased.push(`להסיר ${removed.length} מילים מרשימת המילים החסומות`);
        }

        if (eased.length > 0 && await trusteeGate(request, reply, eased.join("; "))) return reply;
      }

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

      /*
       * הגדרות הדפדפן הקודמות נלקחות מהדייר, לא מהבסיס.
       *
       * הן שכבה של הדייר בדיוק כמו כלל היציאה, והבסיס אינו מכיל
       * אותן כלל. קריאה מהבסיס החזירה תמיד ריק — ושמירה שלא שלחה
       * את שלושת שדות היוטיוב הייתה מוחקת את מה שהוגדר קודם.
       */
      const prevBrowser = (current.enforcement?.["browser"] ?? {}) as Record<string, unknown>;
      const hasBrowserChange =
        input.youtubeAudioOnly !== undefined || input.youtubeHideThumbnails !== undefined || channels !== undefined
        || input.aiSafeMode !== undefined || input.aiBlockedKeywords !== undefined;
      const browserPatch = hasBrowserChange
        ? {
            ...prevBrowser,
            ...(input.youtubeAudioOnly !== undefined && { youtubeAudioOnly: input.youtubeAudioOnly }),
            ...(input.youtubeHideThumbnails !== undefined && { youtubeHideThumbnails: input.youtubeHideThumbnails }),
            ...(channels !== undefined && { youtubeAllowedChannels: channels }),
            ...(input.aiSafeMode !== undefined && { aiSafeMode: input.aiSafeMode }),
            ...(input.aiBlockedKeywords !== undefined && { aiBlockedKeywords: input.aiBlockedKeywords }),
          }
        : prevBrowser;

      const version = await nextPolicyVersion(pool, tenantId);

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

      try {
        await rebuildAssignedPolicies(pool, signer, session.user.userId);
      } catch (error) {
        request.log.error(
          { err: error, tenant: tenantId },
          "הרכבת מדיניות מחשב אחרי שמירת הגדרות דפדפן נכשלה.",
        );
      }

      return reply.send({
        ok: true,
        rule,
        browser: {
          youtubeAudioOnly: (browserPatch as Record<string, unknown>).youtubeAudioOnly === true,
          youtubeHideThumbnails: (browserPatch as Record<string, unknown>).youtubeHideThumbnails === true,
          youtubeAllowedChannels: readChannels((browserPatch as Record<string, unknown>).youtubeAllowedChannels),
          aiSafeMode: (browserPatch as Record<string, unknown>).aiSafeMode === true,
          aiBlockedKeywords: readChannels((browserPatch as Record<string, unknown>).aiBlockedKeywords),
        },
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
  youtubeHideThumbnails: boolean;
  youtubeAllowedChannels: string[];
  aiSafeMode: boolean;
  aiBlockedKeywords: string[];
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
    return { rule: buildEgressRule(), browser: EMPTY_BROWSER, version: null, body: null, enforcement: null };
  }

  const enforcement = (row.body["enforcement"] ?? null) as Record<string, unknown> | null;
  const stored = enforcement?.["egress"];
  const storedBrowser = (enforcement?.["browser"] ?? {}) as Record<string, unknown>;

  return {
    // הגדרה שאינה קיימת עדיין מוצגת ככבויה, ולא כשגיאה: זה המצב
    // של כל דייר לפני השינוי הראשון.
    rule: isEgressRule(stored) ? stored : buildEgressRule(),
    browser: {
      youtubeAudioOnly: storedBrowser["youtubeAudioOnly"] === true,
      youtubeHideThumbnails: storedBrowser["youtubeHideThumbnails"] === true,
      youtubeAllowedChannels: readChannels(storedBrowser["youtubeAllowedChannels"]),
      aiSafeMode: storedBrowser["aiSafeMode"] === true,
      aiBlockedKeywords: readChannels(storedBrowser["aiBlockedKeywords"]),
    },
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
