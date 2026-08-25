import { createHash, randomBytes } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type pg from "pg";
import { z } from "zod";
import { withPlatform } from "../db/client.ts";
import { hashPassword } from "../auth/password.ts";
import { hashIdLast4 } from "../billing/identity.ts";
import { hashEnrollToken } from "../auth/device-token.ts";
import { createSession } from "../auth/session.ts";
import { TRIAL_DAYS, evaluateTrial } from "../billing/trial.ts";
import type { Config } from "../config.ts";

/**
 * רישום עצמי ותקופת ניסיון.
 *
 * לקוח פותח חשבון בעצמו, בלי אשראי ובלי שיחה עם מוקד, ומקבל 30 יום.
 * בסוף הרישום הוא מקבל אסימון התקנה, כדי שהמסלול מהרשמה עד מכשיר
 * מוגן יהיה רצוף ולא יעבור דרך אימייל שעדיין אין לנו ספק לשלוח בו.
 *
 * זו הדלת היחידה במערכת שפתוחה לאינטרנט בלי אימות מוקדם, ולכן היא
 * מוגבלת בקצב ומתועדת.
 */

const SYSTEM = { userId: "system", reason: "רישום עצמי" };

/** תקרות שמונעות פתיחת חשבונות המונית מאותו מקור. */
const SIGNUP_WINDOW = "1 hour";
const MAX_SIGNUPS_PER_IP = 5;

const signupBody = z.object({
  email: z.string().email().max(254),
  password: z.string().min(12, "סיסמה חייבת להכיל לפחות 12 תווים").max(256),
  displayName: z.string().min(2).max(80),
  accountName: z.string().min(2).max(80),
  accountType: z.enum(["family", "individual", "organization"]).default("family"),

  /*
   * ארבע ספרות אחרונות של תעודת זהות.
   *
   * נאסף כאן ולא בזמן ההסרה, כי בזמן ההסרה אין מול מה להשוות —
   * "אימות" שמבקש להקליד ארבע ספרות כלשהן אינו אימות. ראה 7.1.
   * נשמר כ-hash עם salt ייעודי, לעולם לא כטקסט. ראה 7.2.
   */
  idLast4: z.string().regex(/^\d{4}$/, "ארבע ספרות אחרונות של תעודת הזהות"),
});

export interface SignupDeps {
  pool: pg.Pool;
  config: Config;
}

export async function registerSignupRoutes(
  app: FastifyInstance,
  deps: SignupDeps,
): Promise<void> {
  const { pool, config } = deps;
  const secureCookie = config.NODE_ENV === "production";

  app.post("/api/portal/v1/signup", async (request, reply) => {
    const parsed = signupBody.safeParse(request.body);
    const ip = request.ip || null;

    if (!parsed.success) {
      return reply.code(400).send({
        error: parsed.error.issues[0]?.message ?? "בקשה לא תקינה",
      });
    }

    const { email, password, displayName, accountName, accountType, idLast4 } = parsed.data;

    const tooMany = await withPlatform(pool, SYSTEM, async (tx) => {
      const r = await tx.query<{ n: string }>(
        "SELECT app.recent_signups(NULLIF($1, '')::inet, $2::interval) AS n",
        [ip ?? "", SIGNUP_WINDOW],
      );

      return Number(r.rows[0]!.n) >= MAX_SIGNUPS_PER_IP;
    });

    if (tooMany) {
      return reply.code(429).send({
        error: "נפתחו יותר מדי חשבונות מכתובת זו. נסה שוב מאוחר יותר.",
      });
    }

    const result = await withPlatform(pool, SYSTEM, async (tx) => {
      const taken = await tx.query("SELECT 1 FROM users WHERE email = $1", [email]);

      if (taken.rows.length > 0) return { kind: "taken" as const };

      const tenant = await tx.query<{ id: string; trial_ends_at: Date; db_now: Date }>(
        `INSERT INTO tenants
           (type, name, contact_email, plan, trial_started_at, trial_ends_at, created_via)
         VALUES ($1::tenant_type, $2, $3, 'trial', now(),
                 now() + make_interval(days => $4), 'self_signup')
         -- now() נשלף יחד עם התאריך, כדי שספירת הימים תתבצע כולה
         -- בשעון אחד. סטייה של שניות בין השרת לבסיס הנתונים מספיקה
         -- כדי להציג 31 ימים במקום 30.
         RETURNING id, trial_ends_at, now() AS db_now`,
        [accountType, accountName, email, TRIAL_DAYS],
      );

      const tenantId = tenant.rows[0]!.id;
      const passwordHash = await hashPassword(password);

      // אסימון אימות המייל נוצר עכשיו ונשלח כשיהיה ספק מייל.
      // עד אז החשבון פעיל אך מסומן כלא מאומת.
      const verifyToken = randomBytes(24).toString("base64url");

      const user = await tx.query<{ id: string }>(
        `INSERT INTO users
           (tenant_id, email, password_hash, display_name, role, status, email_verify_hash)
         VALUES ($1, $2, $3, $4, 'tenant_owner', 'active', $5)
         RETURNING id`,
        [
          tenantId,
          email,
          passwordHash,
          displayName,
          createHash("sha256").update(verifyToken, "utf8").digest(),
        ],
      );

      // בניסיון אין אשראי, ולכן העוגן היחיד לאימות הסרה הוא ת"ז.
      // הסימון method='id_only' אומר למסך המוקד מה קיים בפועל.
      const identity = hashIdLast4(idLast4);

      await tx.query(
        `INSERT INTO verification_profiles
           (tenant_id, method, id_last4_hash, id_salt, id_set_at)
         VALUES ($1, 'id_only', $2, $3, now())`,
        [tenantId, identity.hash, identity.salt],
      );

      // אסימון התקנה ראשון, כדי שהמסלול מהרשמה עד מכשיר מוגן יהיה רצוף
      const enrollToken = `ENR-${randomBytes(12).toString("hex").toUpperCase()}`;

      await tx.query(
        `INSERT INTO enroll_tokens
           (tenant_id, token_hash, install_profile, enforcement_mode, policy_floor,
            max_uses, expires_at, created_by)
         VALUES ($1, $2, $3::install_profile, 'enforce', $4, 10,
                 now() + interval '30 days', $5)`,
        [
          tenantId,
          hashEnrollToken(enrollToken),
          accountType === "organization" ? "organization"
            : accountType === "individual" ? "individual"
            : "family_child",
          JSON.stringify({
            mode: "enforce",
            onRedAction: "lockout",
            minScoreForGreen: 85,
            minScoreForYellow: 60,
            requireProvider: [],
          }),
          user.rows[0]!.id,
        ],
      );

      await tx.query(
        `INSERT INTO audit_log (actor_type, actor_id, action, target_type, target_id, tenant_id, payload)
         VALUES ('tenant_user', $1, 'tenant.signup', 'tenant', $2, $2, $3)`,
        [
          user.rows[0]!.id,
          tenantId,
          JSON.stringify({ accountType, via: "self_signup", trialDays: TRIAL_DAYS }),
        ],
      );

      return {
        kind: "ok" as const,
        tenantId,
        userId: user.rows[0]!.id,
        trialEndsAt: tenant.rows[0]!.trial_ends_at,
        dbNow: tenant.rows[0]!.db_now,
        enrollToken,
        verifyToken,
      };
    });

    await withPlatform(pool, SYSTEM, async (tx) => {
      await tx.query(
        "INSERT INTO signup_attempts (ip, email, success) VALUES (NULLIF($1, '')::inet, $2, $3)",
        [ip ?? "", email, result.kind === "ok"],
      );
    });

    if (result.kind === "taken") {
      // מודים שהכתובת תפוסה, במכוון. ההסתרה כאן הייתה עולה למשתמש
      // אמיתי יותר ממה שהיא מונעת מתוקף, שממילא יגלה זאת בניסיון כניסה.
      return reply.code(409).send({ error: "כתובת המייל כבר רשומה במערכת" });
    }

    const session = await createSession(
      pool,
      { id: result.userId, tenantId: result.tenantId },
      {
        ip,
        userAgent: request.headers["user-agent"] ?? null,
        mfaVerified: false,
      },
    );

    void reply.header(
      "Set-Cookie",
      [
        `safeme_session=${encodeURIComponent(session.token)}`,
        "HttpOnly",
        "SameSite=Strict",
        "Path=/",
        `Expires=${session.expiresAt.toUTCString()}`,
        ...(secureCookie ? ["Secure"] : []),
      ].join("; "),
    );

    const trial = evaluateTrial(
      { plan: "trial", trialEndsAt: result.trialEndsAt, paidUntil: null },
      result.dbNow,
    );

    return reply.send({
      csrfToken: session.csrfToken,
      tenantId: result.tenantId,
      trial: {
        phase: trial.phase,
        daysLeft: trial.daysLeft,
        endsAt: result.trialEndsAt.toISOString(),
      },
      // מוצג פעם אחת. המשתמש מזין אותו במתקין.
      enrollToken: result.enrollToken,
      // עד שייבחר ספק מייל, אסימון האימות מוחזר לצורכי פיתוח בלבד
      ...(config.NODE_ENV !== "production" ? { verifyToken: result.verifyToken } : {}),
    });
  });

  /** אימות כתובת המייל. הקישור יישלח כשייבחר ספק מייל. */
  app.post("/api/portal/v1/verify-email", async (request, reply) => {
    const token = (request.body as { token?: string } | undefined)?.token;

    if (!token) return reply.code(400).send({ error: "חסר אסימון אימות" });

    const verified = await withPlatform(pool, SYSTEM, async (tx) => {
      const r = await tx.query(
        `UPDATE users SET email_verified_at = now(), email_verify_hash = NULL
         WHERE email_verify_hash = $1 AND email_verified_at IS NULL
         RETURNING id`,
        [createHash("sha256").update(token, "utf8").digest()],
      );

      return (r.rowCount ?? 0) > 0;
    });

    if (!verified) return reply.code(400).send({ error: "אסימון האימות אינו תקף" });

    return reply.send({ ok: true });
  });
}
