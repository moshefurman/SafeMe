import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type pg from "pg";
import { z } from "zod";
import { withPlatform } from "../db/client.ts";
import { hashPassword, verifyPassword } from "../auth/password.ts";
import { buildOtpAuthUri, generateSecret, verifyTotp } from "../auth/totp.ts";
import {
  SESSION_COOKIE,
  createSession,
  csrfMatches,
  markMfaVerified,
  rotateCsrf,
  resolveSession,
  revokeAllForUser,
  revokeSession,
  type ActiveSession,
} from "../auth/session.ts";
import { authorize, isPlatformRole, type Permission } from "../auth/rbac.ts";
import { createGuards } from "../auth/guards.ts";
import { evaluateTrial, type BillingPlan } from "../billing/trial.ts";
import type { Config } from "../config.ts";

/**
 * אימות הפורטל: כניסה, אימות דו-שלבי, וניהול הפעלה.
 *
 * שלושה כללים שמעצבים את הקובץ הזה:
 *   1. משתמשי פלטפורמה חייבים MFA. בלי אימות שני ההפעלה שלהם
 *      חסרת ערך — היא לא תעבור אף בדיקת הרשאה.
 *   2. הודעות הכישלון אחידות. "אימייל או סיסמה שגויים" נאמר גם כשהאימייל
 *      לא קיים, כדי לא לאפשר מיפוי חשבונות.
 *   3. כל אירוע אימות נרשם ביומן הביקורת, כולל כשלונות.
 */

const SYSTEM_ACTOR = { userId: "system", reason: "אימות פורטל" };

/** חלון ההגבלה וספי הנעילה. */
const RATE_WINDOW = "15 minutes";
const MAX_FAILURES_PER_EMAIL = 5;
const MAX_FAILURES_PER_IP = 20;

const loginBody = z.object({
  email: z.string().email().max(254),
  password: z.string().min(1).max(256),
});

const codeBody = z.object({
  code: z.string().regex(/^\d{6}$/, "קוד בן שש ספרות"),
});

// ---------------------------------------------------------------- הקשר בקשה

export interface PortalContext {
  session: ActiveSession;
}

declare module "fastify" {
  interface FastifyRequest {
    portal?: PortalContext;
  }
}

export interface PortalAuthDeps {
  pool: pg.Pool;
  config: Config;
}

// ---------------------------------------------------------------- עזר

function setSessionCookie(reply: FastifyReply, token: string, expiresAt: Date, secure: boolean): void {
  const attributes = [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    "HttpOnly",
    "SameSite=Strict",
    "Path=/",
    `Expires=${expiresAt.toUTCString()}`,
  ];

  // Secure מושמט בפיתוח מקומי מעל HTTP, ונדרש בכל סביבה אחרת
  if (secure) attributes.push("Secure");

  void reply.header("Set-Cookie", attributes.join("; "));
}

function clearSessionCookie(reply: FastifyReply): void {
  void reply.header(
    "Set-Cookie",
    `${SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`,
  );
}

async function audit(
  pool: pg.Pool,
  entry: {
    action: string;
    actorId?: string | null;
    tenantId?: string | null;
    ip?: string | null;
    payload?: Record<string, unknown>;
  },
): Promise<void> {
  await withPlatform(pool, SYSTEM_ACTOR, async (tx) => {
    await tx.query(
      `INSERT INTO audit_log (actor_type, actor_id, actor_ip, action, tenant_id, payload)
       VALUES ($1, $2, NULLIF($3, '')::inet, $4, $5, $6)`,
      [
        entry.actorId ? "platform_user" : "system",
        entry.actorId ?? null,
        entry.ip ?? "",
        entry.action,
        entry.tenantId ?? null,
        JSON.stringify(entry.payload ?? {}),
      ],
    );
  });
}

async function recordAttempt(
  pool: pg.Pool,
  email: string,
  ip: string | null,
  success: boolean,
  stage: string,
): Promise<void> {
  await withPlatform(pool, SYSTEM_ACTOR, async (tx) => {
    await tx.query(
      `INSERT INTO login_attempts (email, ip, success, stage)
       VALUES ($1, NULLIF($2, '')::inet, $3, $4)`,
      [email, ip ?? "", success, stage],
    );
  });
}

// ---------------------------------------------------------------- מסלולים

export async function registerPortalAuthRoutes(
  app: FastifyInstance,
  deps: PortalAuthDeps,
): Promise<void> {
  const { pool, config } = deps;
  const secureCookie = config.NODE_ENV === "production";

  // שומרי הסף משותפים עם מסלולי הפורטל, כדי שלא יתפצלו שני העתקים
  const { requireSession, requirePlatformMfa } = createGuards(pool, config);

  // ---------------------------------------------------------------- כניסה

  app.post("/api/portal/v1/auth/login", async (request, reply) => {
    const parsed = loginBody.safeParse(request.body);
    const ip = request.ip || null;

    if (!parsed.success) {
      return reply.code(400).send({ error: "בקשה לא תקינה" });
    }

    const { email, password } = parsed.data;

    // הגבלת קצב לפני כל עבודה יקרה, ולפני חשיפת מידע כלשהו
    const failures = await withPlatform(pool, SYSTEM_ACTOR, async (tx) => {
      const r = await tx.query<{ by_email: string; by_ip: string }>(
        "SELECT * FROM app.recent_login_failures($1, NULLIF($2, '')::inet, $3::interval)",
        [email, ip ?? "", RATE_WINDOW],
      );

      return r.rows[0]!;
    });

    if (Number(failures.by_email) >= MAX_FAILURES_PER_EMAIL ||
        Number(failures.by_ip) >= MAX_FAILURES_PER_IP) {
      await audit(pool, { action: "auth.login.rate_limited", ip, payload: { email } });

      return reply.code(429).send({
        error: "יותר מדי ניסיונות. נסה שוב בעוד רבע שעה.",
      });
    }

    const user = await withPlatform(pool, SYSTEM_ACTOR, async (tx) => {
      const r = await tx.query<{
        id: string;
        tenant_id: string | null;
        password_hash: string;
        role: string;
        status: string;
        mfa_secret: string | null;
        mfa_enrolled_at: Date | null;
      }>(
        `SELECT id, tenant_id, password_hash, role, status, mfa_secret, mfa_enrolled_at
         FROM users WHERE email = $1`,
        [email],
      );

      return r.rows[0] ?? null;
    });

    // גיבוב מדומה כשהמשתמש אינו קיים, כדי שזמן התשובה לא יסגיר זאת
    const stored = user?.password_hash ??
      "scrypt$16384$8$1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    const passwordOk = await verifyPassword(password, stored);

    const usable = user !== null && (user.status === "active" || user.status === "invited");

    if (!user || !passwordOk || !usable) {
      await recordAttempt(pool, email, ip, false, "password");
      await audit(pool, { action: "auth.login.failed", ip, payload: { email } });

      return reply.code(401).send({ error: "אימייל או סיסמה שגויים" });
    }

    await recordAttempt(pool, email, ip, true, "password");

    const session = await createSession(
      pool,
      { id: user.id, tenantId: user.tenant_id },
      {
        ip,
        userAgent: request.headers["user-agent"] ?? null,
        // אימות שני מסומן רק אחרי הקלדת קוד, לעולם לא בכניסה עצמה
        mfaVerified: false,
      },
    );

    setSessionCookie(reply, session.token, session.expiresAt, secureCookie);

    await audit(pool, {
      action: "auth.login.success",
      actorId: user.id,
      tenantId: user.tenant_id,
      ip,
    });

    const platform = isPlatformRole(user.role as never);

    return reply.send({
      csrfToken: session.csrfToken,
      role: user.role,
      // משתמש פלטפורמה שטרם רשם MFA חייב לרשום עכשיו, לפני כל פעולה
      mfaRequired: platform,
      mfaEnrolled: user.mfa_enrolled_at !== null,
      expiresAt: session.expiresAt.toISOString(),
    });
  });

  // ---------------------------------------------------------------- רישום MFA

  app.post(
    "/api/portal/v1/auth/mfa/enroll",
    { preHandler: requireSession },
    async (request, reply) => {
      const session = request.portal!.session;

      if (session.user.mfaEnrolled) {
        return reply.code(409).send({ error: "אימות דו-שלבי כבר מוגדר" });
      }

      const secret = generateSecret();

      await withPlatform(pool, SYSTEM_ACTOR, async (tx) => {
        // נשמר בלי mfa_enrolled_at: הרישום נחשב מוגמר רק אחרי
        // שהמשתמש הוכיח שהוא מצליח לייצר קוד תקף
        await tx.query("UPDATE users SET mfa_secret = $1 WHERE id = $2", [
          secret,
          session.user.userId,
        ]);
      });

      await audit(pool, {
        action: "auth.mfa.enroll_started",
        actorId: session.user.userId,
        tenantId: session.user.tenantId,
        ip: request.ip,
      });

      return reply.send({
        secret,
        otpauthUri: buildOtpAuthUri(secret, session.user.email),
      });
    },
  );

  app.post(
    "/api/portal/v1/auth/mfa/confirm",
    { preHandler: requireSession },
    async (request, reply) => {
      const parsed = codeBody.safeParse(request.body);
      const session = request.portal!.session;

      if (!parsed.success) return reply.code(400).send({ error: "קוד לא תקין" });

      const secret = await withPlatform(pool, SYSTEM_ACTOR, async (tx) => {
        const r = await tx.query<{ mfa_secret: string | null }>(
          "SELECT mfa_secret FROM users WHERE id = $1",
          [session.user.userId],
        );

        return r.rows[0]?.mfa_secret ?? null;
      });

      if (!secret || !verifyTotp(secret, parsed.data.code)) {
        await recordAttempt(pool, session.user.email, request.ip, false, "mfa");

        return reply.code(401).send({ error: "הקוד שגוי" });
      }

      await withPlatform(pool, SYSTEM_ACTOR, async (tx) => {
        await tx.query(
          "UPDATE users SET mfa_enrolled_at = now(), status = 'active' WHERE id = $1",
          [session.user.userId],
        );
      });

      await markMfaVerified(pool, session.sessionId);

      await audit(pool, {
        action: "auth.mfa.enrolled",
        actorId: session.user.userId,
        tenantId: session.user.tenantId,
        ip: request.ip,
      });

      return reply.send({ ok: true });
    },
  );

  // ---------------------------------------------------------------- אימות MFA

  app.post(
    "/api/portal/v1/auth/mfa/verify",
    { preHandler: requireSession },
    async (request, reply) => {
      const parsed = codeBody.safeParse(request.body);
      const session = request.portal!.session;

      if (!parsed.success) return reply.code(400).send({ error: "קוד לא תקין" });

      const secret = await withPlatform(pool, SYSTEM_ACTOR, async (tx) => {
        const r = await tx.query<{ mfa_secret: string | null }>(
          "SELECT mfa_secret FROM users WHERE id = $1 AND mfa_enrolled_at IS NOT NULL",
          [session.user.userId],
        );

        return r.rows[0]?.mfa_secret ?? null;
      });

      if (!secret || !verifyTotp(secret, parsed.data.code)) {
        await recordAttempt(pool, session.user.email, request.ip, false, "mfa");

        await audit(pool, {
          action: "auth.mfa.failed",
          actorId: session.user.userId,
          tenantId: session.user.tenantId,
          ip: request.ip,
        });

        return reply.code(401).send({ error: "הקוד שגוי" });
      }

      await markMfaVerified(pool, session.sessionId);
      await recordAttempt(pool, session.user.email, request.ip, true, "mfa");

      await audit(pool, {
        action: "auth.mfa.verified",
        actorId: session.user.userId,
        tenantId: session.user.tenantId,
        ip: request.ip,
      });

      return reply.send({ ok: true, verifiedAt: new Date().toISOString() });
    },
  );

  // ---------------------------------------------------------------- מצב ויציאה

  app.get(
    "/api/portal/v1/auth/me",
    { preHandler: [requireSession, requirePlatformMfa] },
    async (request, reply) => {
      const session = request.portal!.session;

      // מצב הניסיון נשלח יחד עם פרטי המשתמש, כדי שהפורטל יציג
      // את הבאנר בלי קריאה נוספת בכל טעינת מסך
      const billing = session.user.tenantId
        ? await withPlatform(pool, SYSTEM_ACTOR, async (tx) => {
            const r = await tx.query<{
              plan: BillingPlan;
              trial_ends_at: Date | null;
              paid_until: Date | null;
              name: string;
              db_now: Date;
            }>(
              // now() נשלף יחד עם התאריכים, כדי שהחישוב יתבצע כולו
              // בשעון אחד ולא יושפע מסטייה בין השרת לבסיס הנתונים
              "SELECT plan, trial_ends_at, paid_until, name, now() AS db_now FROM tenants WHERE id = $1",
              [session.user.tenantId],
            );

            return r.rows[0] ?? null;
          })
        : null;

      const trial = billing
        ? evaluateTrial(
            {
              plan: billing.plan,
              trialEndsAt: billing.trial_ends_at,
              paidUntil: billing.paid_until,
            },
            billing.db_now,
          )
        : null;

      /*
       * אסימון CSRF חדש, אבל רק כשהלקוח אינו מחזיק תקף.
       *
       * הפורטל שולח את שלו בכותרת. כשהוא תואם, אין מה לעשות —
       * וסיבוב בכל קריאה היה פוסל בקשת כתיבה שיצאה במקביל עם
       * האסימון הקודם.
       *
       * כשהוא חסר או שגוי, זה בדרך כלל לשונית שנסגרה ונפתחה:
       * sessionStorage נמחק, והעוגייה שרדה. בלי הסיבוב המשתמש
       * נשאר מחובר וכל פעולה שלו נדחית, בלי דרך להתאושש חוץ
       * מיציאה וכניסה מחדש.
       */
      const suppliedCsrf = request.headers["x-safeme-csrf"];

      const freshCsrf = csrfMatches(
        session,
        typeof suppliedCsrf === "string" ? suppliedCsrf : undefined,
      )
        ? null
        : await rotateCsrf(pool, session.sessionId);

      return reply.send({
        userId: session.user.userId,
        email: session.user.email,
        ...(freshCsrf === null ? {} : { csrfToken: freshCsrf }),
        role: session.user.role,
        tenantId: session.user.tenantId,
        tenantName: billing?.name ?? null,
        displayName: session.user.displayName,
        mfaEnrolled: session.user.mfaEnrolled,
        mfaVerifiedAt: session.mfaVerifiedAt?.toISOString() ?? null,
        expiresAt: session.expiresAt.toISOString(),
        trial: trial
          ? {
              phase: trial.phase,
              daysLeft: trial.daysLeft,
              endsAt: trial.endsAt?.toISOString() ?? null,
              headline: trial.headline,
              needsAttention: trial.needsAttention,
            }
          : null,
      });
    },
  );

  app.post(
    "/api/portal/v1/auth/logout",
    { preHandler: requireSession },
    async (request, reply) => {
      const session = request.portal!.session;

      await revokeSession(pool, session.sessionId);
      clearSessionCookie(reply);

      await audit(pool, {
        action: "auth.logout",
        actorId: session.user.userId,
        tenantId: session.user.tenantId,
        ip: request.ip,
      });

      return reply.send({ ok: true });
    },
  );

  app.post(
    "/api/portal/v1/auth/logout-all",
    { preHandler: [requireSession, requirePlatformMfa] },
    async (request, reply) => {
      const session = request.portal!.session;
      const revoked = await revokeAllForUser(pool, session.user.userId);

      clearSessionCookie(reply);

      await audit(pool, {
        action: "auth.logout_all",
        actorId: session.user.userId,
        tenantId: session.user.tenantId,
        ip: request.ip,
        payload: { revoked },
      });

      return reply.send({ ok: true, revoked });
    },
  );

  // ---------------------------------------------------------------- בדיקת הרשאה

  /**
   * מסלול עזר שמאפשר ל-UI לשאול מראש אם פעולה מותרת, כדי להציג
   * את המסך הנכון. אינו מחליף את האכיפה במסלול עצמו.
   */
  app.get(
    "/api/portal/v1/auth/can/:permission",
    { preHandler: [requireSession, requirePlatformMfa] },
    async (request, reply) => {
      const session = request.portal!.session;
      const { permission } = request.params as { permission: string };

      const outcome = authorize({
        role: session.user.role,
        permission: permission as Permission,
        mfaVerifiedAt: session.mfaVerifiedAt,
        userTenantId: session.user.tenantId,
      });

      return reply.send(outcome);
    },
  );

}

/** יוצר משתמש. משמש בהקמה ראשונית ובבדיקות. */
export async function createUser(
  pool: pg.Pool,
  input: {
    email: string;
    password: string;
    role: string;
    tenantId: string | null;
    displayName?: string;
  },
): Promise<string> {
  const passwordHash = await hashPassword(input.password);

  return withPlatform(pool, SYSTEM_ACTOR, async (tx) => {
    const r = await tx.query<{ id: string }>(
      `INSERT INTO users (email, password_hash, role, tenant_id, display_name, status)
       VALUES ($1, $2, $3::user_role, $4, $5, 'invited')
       RETURNING id`,
      [input.email, passwordHash, input.role, input.tenantId, input.displayName ?? null],
    );

    return r.rows[0]!.id;
  });
}
