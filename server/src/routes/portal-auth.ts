import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { createHash, randomBytes } from "node:crypto";
import type pg from "pg";
import { z } from "zod";
import { withPlatform } from "../db/client.ts";
import { hashPassword, verifyPassword } from "../auth/password.ts";
import { passwordResetMessage, type Mailer } from "../notify/mailer.ts";
import { buildOtpAuthUri, generateSecret, verifyTotp } from "../auth/totp.ts";
import {
  CSRF_COOKIE,
  SESSION_COOKIE,
  createSession,
  markMfaVerified,
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

/*
 * האסימון נשמר מגובב בלבד.
 *
 * מסד שדלף אינו מקנה יכולת לבנות קישור איפוס — מה ששמור אינו
 * מספיק. אותו דפוס כמו אסימוני הרישום ואסימוני ביטול ההתראות.
 */
const tokenHash = (raw: string): Buffer =>
  createHash("sha256").update(raw, "utf8").digest();

const forgotBody = z.object({
  email: z.string().trim().toLowerCase().email().max(200),
});

const changeBody = z.object({
  current: z.string().min(1).max(200),

  /* אותו מינימום כמו בהרשמה ובאיפוס. מסלול רך יותר הוא הדרך העוקפת. */
  next: z.string().min(10).max(200),
});

const resetBody = z.object({
  token: z.string().trim().min(20).max(200),

  /*
   * עשרה תווים, כמו בהרשמה.
   *
   * מסלול איפוס עם דרישה רכה יותר הופך את עצמו לדרך העוקפת: מי
   * שרוצה סיסמה חלשה פשוט יאפס.
   */
  password: z.string().min(10).max(200),
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

  /*
   * הדוור נדרש מאז שנוסף איפוס סיסמה.
   *
   * הוא היחיד שיכול להוציא את הקישור, ובלעדיו המסלול היה מסך
   * שמבטיח מייל שלא נשלח — גרוע מהיעדר המסך.
   */
  mailer: Mailer;
}

// ---------------------------------------------------------------- עזר

function setSessionCookie(
  reply: FastifyReply,
  token: string,
  csrfToken: string,
  expiresAt: Date,
  secure: boolean,
): void {
  const expires = `Expires=${expiresAt.toUTCString()}`;

  const session = [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    "HttpOnly",
    "SameSite=Strict",
    "Path=/",
    expires,
  ];

  /*
   * אסימון ה-CSRF נכתב בעוגייה קריאה, ובמכוון בלי HttpOnly.
   *
   * הוא נשמר קודם ב-sessionStorage בלבד, שנמחק בסגירת הלשונית בעוד
   * שעוגיית ההפעלה שורדת. המשתמש חזר מחובר ובלי אסימון, וכל פעולה
   * שלו נדחתה — כולל היציאה.
   *
   * גילוי הערך לבעל ההפעלה אינו מחליש דבר: ההגנה נשענת על כך שאתר
   * זר אינו יכול לקרוא את העוגייה ולצרף כותרת מותאמת, ולא על כך
   * שהערך סודי ממי שממילא מחזיק בהפעלה.
   */
  const csrf = [
    `${CSRF_COOKIE}=${encodeURIComponent(csrfToken)}`,
    "SameSite=Strict",
    "Path=/",
    expires,
  ];

  // Secure מושמט בפיתוח מקומי מעל HTTP, ונדרש בכל סביבה אחרת
  if (secure) {
    session.push("Secure");
    csrf.push("Secure");
  }

  void reply.header("Set-Cookie", [session.join("; "), csrf.join("; ")]);
}

function clearSessionCookie(reply: FastifyReply): void {
  void reply.header("Set-Cookie", [
    `${SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`,
    `${CSRF_COOKIE}=; SameSite=Strict; Path=/; Max-Age=0`,
  ]);
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
  const { pool, config, mailer } = deps;
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
        tenant_status: string;
      }>(
        /*
         * מצב הדייר נקרא יחד עם המשתמש.
         *
         * השעיה שאינה חוסמת כניסה אינה השעיה — הלקוח ממשיך לנהל
         * הכול כרגיל ולא מבין שמשהו השתנה. מנהלי פלטפורמה אינם
         * שייכים לדייר (tenant_id ריק), ולכן NULL נחשב פעיל.
         */
        `SELECT u.id, u.tenant_id, u.password_hash, u.role, u.status,
                u.mfa_secret, u.mfa_enrolled_at,
                COALESCE(t.status::text, 'active') AS tenant_status
           FROM users u
           LEFT JOIN tenants t ON t.id = u.tenant_id
          WHERE u.email = $1`,
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

    /*
     * השעיה נאמרת במפורש, ורק אחרי שהסיסמה אומתה.
     *
     * לפני האימות היא הייתה מסגירה אילו חשבונות קיימים. אחריו אין
     * מה להסתיר ממי שכבר הוכיח שהחשבון שלו — ו"אימייל או סיסמה
     * שגויים" היה שולח לקוח מושעה לאפס סיסמה שוב ושוב, בלי שאיש
     * יבין למה זה לא עוזר.
     */
    if (user.tenant_status !== "active") {
      await audit(pool, { action: "auth.login.suspended", ip, payload: { email } });

      return reply.code(403).send({
        error: "החשבון מושעה. המחשבים ממשיכים להיות מוגנים; יש לפנות לתמיכה כדי לחדש את החשבון.",
      });
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

    setSessionCookie(reply, session.token, session.csrfToken, session.expiresAt, secureCookie);

    await audit(pool, {
      action: "auth.login.success",
      actorId: user.id,
      tenantId: user.tenant_id,
      ip,
    });

    const platform = isPlatformRole(user.role as never);

    const enrolled = user.mfa_enrolled_at !== null;

    return reply.send({
      csrfToken: session.csrfToken,
      role: user.role,

      /*
       * שני מקורות לדרישה, ולא אחד.
       *
       * משתמש פלטפורמה חייב לרשום MFA לפני כל פעולה — זו הייתה
       * הדרישה היחידה. אבל משתמש דייר שרשם לעצמו לא נשאל לקוד
       * לעולם, כי הדגל הביט בתפקיד בלבד: הוא היה מקבל מסך שאומר
       * "האימות הדו-שלבי פעיל" בזמן שסיסמה לבדה פותחת את החשבון.
       *
       * 2FA שנרשם ואינו נאכף גרוע מהיעדרו, כי הוא מייצר ביטחון
       * שאינו קיים — ובדיוק אצל מי שטרח להפעיל אותו.
       */
      mfaRequired: platform || enrolled,
      mfaEnrolled: enrolled,
      expiresAt: session.expiresAt.toISOString(),
    });
  });

  // ---------------------------------------------------------------- איפוס סיסמה

  /**
   * בקשת קישור לאיפוס.
   *
   * עונה 200 תמיד, גם על כתובת שאינה קיימת. תשובה שמבדילה הופכת
   * את המסלול לכלי לגילוי מי רשום — ואצל מוצר שכל תכליתו סינון
   * בבית, רשימת לקוחות היא מידע רגיש בפני עצמו.
   *
   * ומאותה סיבה גם השהיה: מסלול שעונה מהר על כתובת לא קיימת ולאט
   * על קיימת מדליף בדיוק את מה שהתשובה האחידה הסתירה.
   */
  app.post("/api/portal/v1/auth/password/forgot", async (request, reply) => {
    const parsed = forgotBody.safeParse(request.body);

    if (!parsed.success) return reply.code(400).send({ error: "כתובת לא תקינה" });

    const email = parsed.data.email;
    const ip = request.ip;

    const user = await withPlatform(pool, SYSTEM_ACTOR, async (tx) => {
      const r = await tx.query<{ id: string; status: string }>(
        "SELECT id, status::text AS status FROM users WHERE email = $1",
        [email],
      );

      return r.rows[0] ?? null;
    });

    /*
     * חשבון מושהה או סגור אינו מקבל קישור.
     *
     * איפוס סיסמה לחשבון שאינו יכול להיכנס הוא מסלול שמסתיים
     * במבוי סתום, ומלמד את המשתמש שהמערכת שבורה במקום שהחשבון
     * מושעה.
     */
    if (user !== null && (user.status === "active" || user.status === "invited")) {
      const raw = randomBytes(32).toString("base64url");

      await withPlatform(pool, SYSTEM_ACTOR, async (tx) => {
        /*
         * בקשות קודמות מבוטלות.
         *
         * בלי זה, מי שלחץ שלוש פעמים מחזיק שלושה מפתחות פתוחים
         * לחשבון — וכל אחד מהם שווה לגמרי לאחרון.
         */
        await tx.query(
          "UPDATE password_resets SET used_at = now() WHERE user_id = $1 AND used_at IS NULL",
          [user.id],
        );

        await tx.query(
          `INSERT INTO password_resets (user_id, token_hash, requested_ip)
           VALUES ($1, $2, $3)`,
          [user.id, tokenHash(raw), ip],
        );
      });

      const url = `${config.PORTAL_URL.replace(/\/+$/, "")}/reset?token=${raw}`;

      try {
        await mailer.send(passwordResetMessage({ to: email, resetUrl: url, minutes: 60 }));
      } catch (error) {
        /*
         * כשל בשליחה נרשם ואינו נחשף.
         *
         * הודעת שגיאה שמופיעה רק כשהכתובת קיימת היא בדיוק ההדלפה
         * שהתשובה האחידה נועדה למנוע.
         */
        request.log.error({ err: error }, "שליחת קישור איפוס נכשלה.");
      }

      await audit(pool, { action: "auth.password.resetRequested", actorId: user.id, ip });
    } else {
      /*
       * השהיה מלאכותית לכתובת שאינה מזכה בקישור.
       *
       * המסלול המוצלח כותב למסד ושולח דואר — מאות אלפיות שנייה.
       * בלי ההשהיה כאן, ההפרש לבדו עונה על השאלה "האם הכתובת
       * רשומה".
       */
      await new Promise((resolve) => setTimeout(resolve, 400 + Math.random() * 300));
    }

    return reply.send({
      ok: true,
      note: "אם הכתובת רשומה, נשלח אליה קישור לאיפוס. הוא תקף לשעה.",
    });
  });

  /**
   * קביעת סיסמה חדשה מול אסימון.
   *
   * האסימון נשמר מגובב, ולכן ההשוואה היא על הגיבוב ולא על הערך —
   * מסד שדלף אינו מקנה יכולת לבנות קישור.
   */
  app.post("/api/portal/v1/auth/password/reset", async (request, reply) => {
    const parsed = resetBody.safeParse(request.body);

    if (!parsed.success) {
      return reply.code(400).send({ error: "הסיסמה חייבת להיות באורך 10 תווים לפחות" });
    }

    const hash = await hashPassword(parsed.data.password);

    const outcome = await withPlatform(pool, SYSTEM_ACTOR, async (tx) => {
      /*
       * הבדיקה והסימון בשאילתה אחת.
       *
       * שתי שאילתות נפרדות פותחות חלון שבו אותו אסימון נפדה
       * פעמיים במקביל. RETURNING על UPDATE מותנה סוגר אותו
       * בשכבה שבה הוא באמת נסגר.
       */
      const r = await tx.query<{ user_id: string }>(
        `UPDATE password_resets SET used_at = now()
          WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
      RETURNING user_id`,
        [tokenHash(parsed.data.token)],
      );

      const row = r.rows[0];

      if (!row) return null;

      await tx.query("UPDATE users SET password_hash = $2 WHERE id = $1", [row.user_id, hash]);

      /*
       * כל הפעילויות הקיימות מבוטלות.
       *
       * מי שאיפס סיסמה עושה זאת לרוב מפני שהוא חושש שמישהו נכנס.
       * פעילות פתוחה ששורדת את האיפוס הופכת אותו לחסר משמעות.
       */
      await tx.query(
        "UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
        [row.user_id],
      );

      return row.user_id;
    });

    if (outcome === null) {
      return reply.code(400).send({ error: "הקישור פג או שכבר נוצל. יש לבקש חדש." });
    }

    await audit(pool, { action: "auth.password.reset", actorId: outcome, ip: request.ip });

    return reply.send({ ok: true, note: "הסיסמה הוחלפה. אפשר להתחבר עכשיו." });
  });

  /**
   * החלפת סיסמה, למי שכבר מחובר.
   *
   * היה איפוס במייל ולא הייתה החלפה. משתמש שזוכר את הסיסמה ורוצה
   * להחליף אותה נאלץ להתנתק, לבקש קישור, ולחכות לדואר — כלומר
   * המסלול הבטוח יותר היה גם המסורבל יותר.
   *
   * ---
   *
   * הסיסמה הנוכחית נדרשת, למרות שהמשתמש מאומת.
   *
   * עוגיית פעילות פתוחה — מחשב שנשאר פתוח, למשל — אינה אמורה
   * להספיק כדי להשתלט על חשבון. הסיסמה היא הדבר שמי שהתיישב מול
   * המסך אינו מחזיק.
   */
  app.post(
    "/api/portal/v1/auth/password/change",
    { preHandler: requireSession },
    async (request, reply) => {
      const parsed = changeBody.safeParse(request.body);
      const session = request.portal!.session;

      if (!parsed.success) {
        return reply.code(400).send({ error: "הסיסמה החדשה חייבת להיות באורך 10 תווים לפחות" });
      }

      const stored = await withPlatform(pool, SYSTEM_ACTOR, async (tx) => {
        const r = await tx.query<{ password_hash: string }>(
          "SELECT password_hash FROM users WHERE id = $1",
          [session.user.userId],
        );

        return r.rows[0]?.password_hash ?? null;
      });

      if (stored === null || !(await verifyPassword(parsed.data.current, stored))) {
        await recordAttempt(pool, session.user.email, request.ip, false, "password");

        return reply.code(401).send({ error: "הסיסמה הנוכחית שגויה" });
      }

      /*
       * אותה סיסמה אינה החלפה.
       *
       * היא הייתה מנתקת את שאר החיבורים בלי לשנות דבר, וזה נראה
       * למשתמש כאילו משהו קרה.
       */
      if (parsed.data.current === parsed.data.next) {
        return reply.code(400).send({ error: "הסיסמה החדשה זהה לנוכחית" });
      }

      const hash = await hashPassword(parsed.data.next);

      await withPlatform(pool, SYSTEM_ACTOR, async (tx) => {
        await tx.query(
          "UPDATE users SET password_hash = $2 WHERE id = $1",
          [session.user.userId, hash],
        );

        /*
         * שאר החיבורים מנותקים, והנוכחי נשאר.
         *
         * מי שמחליף סיסמה עושה זאת לרוב מפני שהוא חושש שמישהו
         * נכנס, וחיבור ששורד את ההחלפה הופך אותה לחסרת משמעות.
         * ניתוק הנוכחי גם הוא היה עונש: הוא היה זורק את מי שרק
         * עשה את הדבר הנכון.
         */
        await tx.query(
          `UPDATE sessions SET revoked_at = now()
            WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL`,
          [session.user.userId, session.sessionId],
        );
      });

      await audit(pool, {
        action: "auth.password.changed",
        actorId: session.user.userId,
        tenantId: session.user.tenantId,
        ip: request.ip,
      });

      return reply.send({
        ok: true,
        note: "הסיסמה הוחלפה. שאר החיבורים לחשבון נותקו.",
      });
    },
  );

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

  /**
   * כיבוי אימות דו-שלבי.
   *
   * דורש קוד תקף, ולא סיסמה. מי שהשיג עוגיית פעילות פתוחה — מחשב
   * שנשאר פתוח, למשל — היה יכול לכבות בלחיצה את ההגנה שנועדה
   * להתמודד בדיוק עם זה. הקוד הוא הדבר היחיד שהתוקף אינו מחזיק.
   *
   * ולצוות החברה זה חסום לגמרי. אילוץ users_platform_requires_mfa
   * היה נכשל ממילא על חשבון פעיל, אבל שגיאת מסד אינה הודעה שאפשר
   * לקרוא — ומדיניות שנאכפת רק במקרה נשברת ברגע שמישהו משנה את
   * האילוץ.
   */
  app.post(
    "/api/portal/v1/auth/mfa/disable",
    { preHandler: requireSession },
    async (request, reply) => {
      const parsed = codeBody.safeParse(request.body);
      const session = request.portal!.session;

      if (!parsed.success) return reply.code(400).send({ error: "קוד לא תקין" });

      if (isPlatformRole(session.user.role as never)) {
        return reply.code(403).send({
          error: "אימות דו-שלבי הוא חובה לחשבונות ניהול ואינו ניתן לכיבוי.",
        });
      }

      const secret = await withPlatform(pool, SYSTEM_ACTOR, async (tx) => {
        const r = await tx.query<{ mfa_secret: string | null }>(
          "SELECT mfa_secret FROM users WHERE id = $1 AND mfa_enrolled_at IS NOT NULL",
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
          "UPDATE users SET mfa_secret = NULL, mfa_enrolled_at = NULL WHERE id = $1",
          [session.user.userId],
        );
      });

      await audit(pool, {
        action: "auth.mfa.disabled",
        actorId: session.user.userId,
        tenantId: session.user.tenantId,
        ip: request.ip,
      });

      return reply.send({ ok: true });
    },
  );

  // ---------------------------------------------------------------- סוג החשבון

  /*
   * שינוי סוג החשבון אחרי ההרשמה.
   *
   * הסוג אינו הרשאה ואינו משנה שום הגדרת סינון במחשבים שכבר
   * רשומים. הוא קובע את הניסוחים במרכז הניהול ואת הפרופיל של
   * מתקינים שיוכנו מעכשיו. לכן הוא נפתח לבעל החשבון בלי אימות
   * נוסף: אין כאן הקלה שצריך להגן עליה.
   */
  app.patch(
    "/api/portal/v1/account/type",
    { preHandler: requireSession },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;

      if (!tenantId || session.user.role !== "tenant_owner") {
        return reply.code(403).send({ error: "רק בעל החשבון יכול לשנות את סוג החשבון" });
      }

      const parsed = z
        .object({ accountType: z.enum(["family", "individual", "organization"]) })
        .safeParse(request.body);

      if (!parsed.success) return reply.code(400).send({ error: "סוג חשבון לא מוכר" });

      await withPlatform(
        pool,
        { userId: session.user.userId, reason: "שינוי סוג חשבון" },
        async (tx) => {
          await tx.query(
            "UPDATE tenants SET type = $2::tenant_type, updated_at = now() WHERE id = $1",
            [tenantId, parsed.data.accountType],
          );

          await tx.query(
            `INSERT INTO audit_log (actor_type, actor_id, actor_ip, action, tenant_id, payload)
             VALUES ('tenant_user', $1, $2::inet, 'account.type_changed', $3, $4)`,
            [session.user.userId, request.ip, tenantId,
              JSON.stringify({ accountType: parsed.data.accountType })],
          );
        },
      );

      return reply.send({ ok: true, accountType: parsed.data.accountType });
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
              type: string;
              db_now: Date;
            }>(
              // now() נשלף יחד עם התאריכים, כדי שהחישוב יתבצע כולו
              // בשעון אחד ולא יושפע מסטייה בין השרת לבסיס הנתונים
              "SELECT plan, trial_ends_at, paid_until, name, type::text AS type, now() AS db_now FROM tenants WHERE id = $1",
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
       * קריאה בלבד. אין כאן סיבוב אסימון CSRF, ובמכוון.
       *
       * קודם המסלול הזה ייצר אסימון חדש כשהלקוח לא שלח תקף — וזה
       * היה באג אמיתי: GET ששינה מצב אבטחה. לשונית שנייה שנטענה
       * גרמה לסיבוב, האסימון של הראשונה מת, וכל פעולה בה נדחתה
       * ב-403 בלי שום סימן — כולל היציאה, שנראתה כמו כפתור מקולקל.
       *
       * לשונית חדשה משיגה אסימון מהעוגייה הקריאה שנכתבה בכניסה,
       * ולכן אין עוד שום סיבה לייצר אחד מכאן.
       */
      return reply.send({
        userId: session.user.userId,
        email: session.user.email,
        role: session.user.role,
        tenantId: session.user.tenantId,
        tenantName: billing?.name ?? null,
        tenantType: billing?.type ?? null,
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
