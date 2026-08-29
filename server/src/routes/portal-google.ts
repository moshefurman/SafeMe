import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type pg from "pg";
import { randomBytes, createHash } from "node:crypto";
import { z } from "zod";

import { withPlatform } from "../db/client.ts";
import { CSRF_COOKIE, createSession } from "../auth/session.ts";
import { hashIdLast4 } from "../billing/identity.ts";
import { TRIAL_DAYS } from "../billing/trial.ts";
import type { Config } from "../config.ts";
import {
  authorizeUrl,
  beginFlow,
  exchangeCode,
  openPending,
  sealPending,
  FLOW_TTL_SECONDS,
  type GoogleIdentity,
} from "../auth/google.ts";

/**
 * כניסה והרשמה דרך Google.
 *
 * Google מאמת מי המשתמש, ולא יותר מזה. סוג החשבון וארבע הספרות של
 * תעודת הזהות — העוגן היחיד לאימות הסרה בתקופת הניסיון — הם דברים
 * שהוא אינו יודע, ולכן משתמש חדש עובר דרך מסך השלמה קצר.
 *
 * שלוש התוצאות האפשריות בחזרה מ-Google:
 *
 *   זהות מוכרת          → סשן, ישר לפורטל
 *   מייל מאומת שכבר קיים → קישור הזהות לחשבון, ואז סשן
 *   חדש לגמרי           → כרטיס חתום, ומסך השלמה
 */

const SESSION_COOKIE = "safeme_session";
const FLOW_COOKIE = "safeme_google_flow";
const PENDING_COOKIE = "safeme_google_pending";

const completeBody = z.object({
  accountType: z.enum(["family", "business"]).default("family"),
  accountName: z.string().trim().min(2).max(120),
  idLast4: z.string().trim().regex(/^\d{4}$/, "נדרשות ארבע ספרות"),
});

interface Deps {
  pool: pg.Pool;
  config: Config;
}

const SYSTEM = { userId: "system", reason: "כניסה דרך Google" };

export async function registerGoogleRoutes(
  app: FastifyInstance,
  deps: Deps,
): Promise<void> {
  const { pool, config } = deps;

  const clientId = (config.GOOGLE_CLIENT_ID ?? "").trim();
  const clientSecret = (config.GOOGLE_CLIENT_SECRET ?? "").trim();
  const secure = config.NODE_ENV === "production";
  const portal = config.PORTAL_URL.replace(/\/+$/, "");
  const redirectUri = `${portal}/api/portal/v1/auth/google/callback`;

  /*
   * הפורטל שואל אם להציג את הכפתור.
   *
   * כפתור שמופיע ונכשל גרוע מכפתור שאינו מופיע: המשתמש מסיק
   * שהמוצר שבור, ולא שהתכונה אינה מוגדרת.
   */
  app.get("/api/portal/v1/auth/google/available", async () =>
    ({ available: clientId !== "" && clientSecret !== "" }));

  if (clientId === "" || clientSecret === "") {
    app.log.warn("GOOGLE_CLIENT_ID או GOOGLE_CLIENT_SECRET חסרים. הכניסה דרך Google מושבתת.");

    return;
  }

  // ---------------------------------------------------------------- פתיחה

  app.get("/api/portal/v1/auth/google/start", async (_request, reply) => {
    const secrets = beginFlow();

    /*
     * SameSite=Lax, ולא Strict כמו עוגיית ההפעלה.
     *
     * החזרה מ-Google היא ניווט חוצה-אתר, ועוגיית Strict אינה
     * נשלחת בו. עם Strict, ה-state לא היה מגיע לצד השני וכל כניסה
     * הייתה נכשלת — בלי שום רמז למה.
     */
    setCookie(reply, FLOW_COOKIE, JSON.stringify(secrets), {
      secure,
      maxAge: FLOW_TTL_SECONDS,
      sameSite: "Lax",
    });

    return reply.redirect(authorizeUrl(clientId, redirectUri, secrets), 302);
  });

  // ---------------------------------------------------------------- חזרה

  app.get<{ Querystring: { code?: string; state?: string; error?: string } }>(
    "/api/portal/v1/auth/google/callback",
    async (request, reply) => {
      const query = request.query;

      // המשתמש ביטל במסך של Google. זו אינה שגיאה.
      if (query.error) return reply.redirect(`${portal}/?google=cancelled`, 302);

      const flow = readFlow(request);

      clearCookie(reply, FLOW_COOKIE, secure);

      if (flow === null || !query.code || !query.state) {
        return reply.redirect(`${portal}/?google=expired`, 302);
      }

      if (query.state !== flow.state) {
        request.log.warn("state שאינו תואם בחזרה מ-Google");

        return reply.redirect(`${portal}/?google=failed`, 302);
      }

      let identity: GoogleIdentity;

      try {
        identity = await exchangeCode({
          code: query.code,
          clientId,
          clientSecret,
          redirectUri,
          codeVerifier: flow.codeVerifier,
          nonce: flow.nonce,
        });
      } catch (error) {
        request.log.error({ err: error }, "החלפת הקוד מול Google נכשלה");

        return reply.redirect(`${portal}/?google=failed`, 302);
      }

      const existing = await findUser(pool, identity);

      // ---- חדש לגמרי: כרטיס חתום ומסך השלמה ----
      if (existing === null) {
        const ticket = sealPending(
          {
            sub: identity.sub,
            email: identity.email,
            name: identity.name,
            issuedAt: Date.now(),
          },
          config.DEVICE_TOKEN_SECRET,
        );

        setCookie(reply, PENDING_COOKIE, ticket, {
          secure,
          maxAge: FLOW_TTL_SECONDS,
          sameSite: "Lax",
        });

        return reply.redirect(`${portal}/?google=complete`, 302);
      }

      // ---- קיים: אולי צריך לקשור, ואז סשן ----
      if (existing.google_sub === null) {
        await withPlatform(pool, SYSTEM, async (tx) => {
          await tx.query(
            "UPDATE users SET google_sub = $2, google_linked_at = now() WHERE id = $1",
            [existing.id, identity.sub],
          );
        });

        await audit(pool, {
          action: "auth.google.linked",
          actorId: existing.id,
          tenantId: existing.tenant_id,
        });
      }

      const session = await createSession(
        pool,
        { id: existing.id, tenantId: existing.tenant_id },
        {
          ip: request.ip || null,
          userAgent: request.headers["user-agent"] ?? null,
          mfaVerified: false,
        },
      );

      setSessionCookie(reply, session.token, session.csrfToken, session.expiresAt, secure);

      await audit(pool, {
        action: "auth.google.login",
        actorId: existing.id,
        tenantId: existing.tenant_id,
      });

      /*
       * ה-CSRF נוסע בכתובת ולא בגוף, כי זו הפניה ולא בקשת AJAX.
       *
       * הוא אינו סוד שדולף כאן: הוא מוגן על ידי עוגיית ההפעלה,
       * שאינה נגישה ל-JavaScript ואינה נשלחת חוצה-אתר. הפורטל
       * קורא אותו ומיד מנקה את הכתובת.
       */
      return reply.redirect(
        `${portal}/?google=ok&csrf=${encodeURIComponent(session.csrfToken)}`,
        302,
      );
    },
  );

  // ---------------------------------------------------------------- השלמה

  /** מה שנשאר לשאול אחרי ש-Google אימת מי זה. */
  app.get("/api/portal/v1/auth/google/pending", async (request, reply) => {
    const pending = readPending(request, config.DEVICE_TOKEN_SECRET);

    if (pending === null) return reply.code(404).send({ error: "אין הרשמה ממתינה" });

    return reply.send({ email: pending.email, name: pending.name });
  });

  app.post("/api/portal/v1/auth/google/complete", async (request, reply) => {
    const pending = readPending(request, config.DEVICE_TOKEN_SECRET);

    if (pending === null) {
      return reply.code(410).send({ error: "ההרשמה פגה. יש להתחיל מחדש." });
    }

    const parsed = completeBody.safeParse(request.body);

    if (!parsed.success) {
      return reply.code(400).send({ error: "בקשה לא תקינה" });
    }

    const { accountType, accountName, idLast4 } = parsed.data;

    const created = await withPlatform(pool, SYSTEM, async (tx) => {
      // מרוץ: אותו אדם לחץ פעמיים, או נרשם בינתיים בדרך אחרת
      const taken = await tx.query(
        "SELECT 1 FROM users WHERE email = $1 OR google_sub = $2",
        [pending.email, pending.sub],
      );

      if (taken.rows.length > 0) return null;

      const tenant = await tx.query<{ id: string }>(
        `INSERT INTO tenants
           (type, name, contact_email, plan, trial_started_at, trial_ends_at, created_via)
         VALUES ($1::tenant_type, $2, $3, 'trial', now(),
                 now() + make_interval(days => $4), 'self_signup')
         RETURNING id`,
        [accountType, accountName, pending.email, TRIAL_DAYS],
      );

      const tenantId = tenant.rows[0]!.id;

      /*
       * בלי password_hash, ובכוונה.
       *
       * סיסמה אקראית שנוצרת כאן היא סוד שאיש אינו יודע ואיש אינו
       * מסובב, וכל תפקידה הוא לספק עמודה שאינה ריקה. המגבלה
       * users_has_a_way_in מוודאת שיש דרך כניסה אחת לפחות.
       */
      const user = await tx.query<{ id: string }>(
        `INSERT INTO users
           (tenant_id, email, display_name, role, status,
            google_sub, google_linked_at, email_verified_at)
         VALUES ($1, $2, $3, 'tenant_owner', 'active', $4, now(), now())
         RETURNING id`,
        [tenantId, pending.email, pending.name ?? pending.email, pending.sub],
      );

      const identity = hashIdLast4(idLast4);

      await tx.query(
        `INSERT INTO verification_profiles
           (tenant_id, method, id_last4_hash, id_salt, id_set_at)
         VALUES ($1, 'id_only', $2, $3, now())`,
        [tenantId, identity.hash, identity.salt],
      );

      const enrollToken = `ENR-${randomBytes(12).toString("hex").toUpperCase()}`;

      await tx.query(
        `INSERT INTO enroll_tokens
           (tenant_id, token_hash, install_profile, enforcement_mode, policy_floor,
            max_uses, expires_at, created_by)
         VALUES ($1, $2, 'family_child', 'enforce', $3, 5, now() + interval '30 days', $4)`,
        [
          tenantId,
          createHash("sha256").update(enrollToken, "utf8").digest(),
          JSON.stringify({ mode: "monitor", onRedAction: "warn" }),
          user.rows[0]!.id,
        ],
      );

      return { userId: user.rows[0]!.id, tenantId };
    });

    clearCookie(reply, PENDING_COOKIE, secure);

    if (created === null) {
      return reply.code(409).send({
        error: "כבר קיים חשבון עם הכתובת הזו. יש להתחבר רגיל.",
      });
    }

    const session = await createSession(
      pool,
      { id: created.userId, tenantId: created.tenantId },
      {
        ip: request.ip || null,
        userAgent: request.headers["user-agent"] ?? null,
        mfaVerified: false,
      },
    );

    setSessionCookie(reply, session.token, session.csrfToken, session.expiresAt, secure);

    await audit(pool, {
      action: "auth.google.signup",
      actorId: created.userId,
      tenantId: created.tenantId,
      payload: { accountType },
    });

    return reply.send({ csrfToken: session.csrfToken, role: "tenant_owner" });
  });
}

// ---------------------------------------------------------------- עזר

interface UserRow {
  id: string;
  tenant_id: string | null;
  google_sub: string | null;
}

/**
 * מאתר משתמש קיים.
 *
 * לפי sub קודם: הוא יציב ואינו משתנה כשהמייל משתנה. נפילה אחורה
 * למייל היא רק כשהוא מאומת אצל Google — אחרת מי שמשיג כתובת שכבר
 * בשימוש היה משתלט על חשבון קיים.
 */
async function findUser(pool: pg.Pool, identity: GoogleIdentity): Promise<UserRow | null> {
  return withPlatform(pool, SYSTEM, async (tx) => {
    const bySub = await tx.query<UserRow>(
      "SELECT id, tenant_id, google_sub FROM users WHERE google_sub = $1",
      [identity.sub],
    );

    if (bySub.rows[0]) return bySub.rows[0];

    if (!identity.emailVerified) return null;

    const byEmail = await tx.query<UserRow>(
      "SELECT id, tenant_id, google_sub FROM users WHERE email = $1",
      [identity.email],
    );

    return byEmail.rows[0] ?? null;
  });
}

function readFlow(request: FastifyRequest): { state: string; codeVerifier: string; nonce: string } | null {
  const raw = readCookie(request, FLOW_COOKIE);

  if (raw === null) return null;

  try {
    const parsed = JSON.parse(raw) as { state?: unknown; codeVerifier?: unknown; nonce?: unknown };

    if (typeof parsed.state !== "string") return null;
    if (typeof parsed.codeVerifier !== "string") return null;
    if (typeof parsed.nonce !== "string") return null;

    return { state: parsed.state, codeVerifier: parsed.codeVerifier, nonce: parsed.nonce };
  } catch {
    return null;
  }
}

function readPending(request: FastifyRequest, secret: string) {
  const raw = readCookie(request, PENDING_COOKIE);

  return raw === null ? null : openPending(raw, secret);
}

function readCookie(request: FastifyRequest, name: string): string | null {
  const header = request.headers.cookie;

  if (!header) return null;

  for (const part of header.split(";")) {
    const [key, ...rest] = part.trim().split("=");

    if (key === name) return decodeURIComponent(rest.join("="));
  }

  return null;
}

function setCookie(
  reply: FastifyReply,
  name: string,
  value: string,
  options: { secure: boolean; maxAge: number; sameSite: "Lax" | "Strict" },
): void {
  const attributes = [
    `${name}=${encodeURIComponent(value)}`,
    "HttpOnly",
    `SameSite=${options.sameSite}`,
    "Path=/",
    `Max-Age=${options.maxAge}`,
  ];

  if (options.secure) attributes.push("Secure");

  appendCookie(reply, attributes.join("; "));
}

function clearCookie(reply: FastifyReply, name: string, secure: boolean): void {
  const attributes = [`${name}=`, "HttpOnly", "SameSite=Lax", "Path=/", "Max-Age=0"];

  if (secure) attributes.push("Secure");

  appendCookie(reply, attributes.join("; "));
}

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

  // קריאה ל-JavaScript במכוון. ההסבר המלא ליד ההגדרה ב-session.ts
  const csrf = [
    `${CSRF_COOKIE}=${encodeURIComponent(csrfToken)}`,
    "SameSite=Strict",
    "Path=/",
    expires,
  ];

  if (secure) {
    session.push("Secure");
    csrf.push("Secure");
  }

  appendCookie(reply, session.join("; "));
  appendCookie(reply, csrf.join("; "));
}

/**
 * מוסיף עוגייה בלי לדרוס קיימת.
 *
 * המסלול הזה כותב שתיים באותה תשובה — ניקוי הכרטיס והגדרת ההפעלה
 * — ו-header עם מחרוזת בודדת היה מוחק את הראשונה.
 */
function appendCookie(reply: FastifyReply, value: string): void {
  const existing = reply.getHeader("Set-Cookie");

  const list = existing === undefined
    ? []
    : Array.isArray(existing)
      ? existing.map(String)
      : [String(existing)];

  void reply.header("Set-Cookie", [...list, value]);
}

async function audit(
  pool: pg.Pool,
  entry: { action: string; actorId?: string | null; tenantId?: string | null; payload?: unknown },
): Promise<void> {
  await withPlatform(pool, SYSTEM, async (tx) => {
    await tx.query(
      `INSERT INTO audit_log (actor_type, actor_id, action, tenant_id, payload)
       VALUES ('tenant_user', $1, $2, $3, $4)`,
      [
        entry.actorId ?? null,
        entry.action,
        entry.tenantId ?? null,
        JSON.stringify(entry.payload ?? {}),
      ],
    );
  });
}
