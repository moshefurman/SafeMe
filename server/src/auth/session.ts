import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type pg from "pg";
import { withPlatform } from "../db/client.ts";
import type { UserRole } from "./rbac.ts";

/**
 * הפעלות משתמש בפורטל.
 *
 * האסימון נשלח בעוגייה ונשמר בשרת כ-hash בלבד. זה נותן שני דברים
 * שעוגייה חתומה לבדה אינה נותנת: שלילה מיידית של הפעלה, ועמידות
 * לדלף מסד נתונים.
 */

const SESSION_TTL_HOURS = 12;
const TOKEN_BYTES = 32;

/**
 * חיפוש הפעלה רץ בהקשר פלטפורמה, כי בשלב הזה עדיין לא ידוע לאיזה
 * דייר הבקשה שייכת. זו נקודת האתחול של כל בקשה, ומיד אחריה נקבע
 * ההקשר האמיתי.
 */
const AUTH_ACTOR = { userId: "system", reason: "אימות הפעלה" };

export const SESSION_COOKIE = "filterplus_session";
export const CSRF_HEADER = "x-filterplus-csrf";

/**
 * העוגייה שנושאת את אסימון ה-CSRF, וקריאה במכוון ל-JavaScript.
 *
 * זו תבנית double-submit: העוגייה נשלחת אוטומטית, והכותרת נשלחת רק
 * בידי קוד שרץ במקור שלנו וקרא אותה. אתר זר יכול לגרום לדפדפן לשלוח
 * את העוגייה, אך לא לקרוא אותה ולא לצרף כותרת מותאמת — ולכן ההגנה
 * עומדת גם כשהערך גלוי לבעל ההפעלה עצמו.
 *
 * הוא היה חסר, ובלעדיו לשונית חדשה לא יכלה להשיג אסימון בשום דרך
 * חוץ מלגרום לשרת לייצר חדש — וכל ייצור כזה פסל את הלשונית האחרת.
 */
export const CSRF_COOKIE = "filterplus_csrf";

export interface SessionUser {
  userId: string;
  tenantId: string | null;
  email: string;
  role: UserRole;
  displayName: string | null;
  mfaEnrolled: boolean;
}

export interface ActiveSession {
  sessionId: string;
  user: SessionUser;
  mfaVerifiedAt: Date | null;
  expiresAt: Date;
  csrfHash: Buffer;
}

function hash(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

export interface IssuedSession {
  sessionId: string;
  token: string;
  csrfToken: string;
  expiresAt: Date;
}

export async function createSession(
  pool: pg.Pool,
  user: { id: string; tenantId: string | null },
  context: { ip?: string | null; userAgent?: string | null; mfaVerified: boolean },
): Promise<IssuedSession> {
  const token = randomBytes(TOKEN_BYTES).toString("base64url");
  const csrfToken = randomBytes(TOKEN_BYTES).toString("base64url");
  const expiresAt = new Date(Date.now() + SESSION_TTL_HOURS * 60 * 60 * 1000);

  const sessionId = await withPlatform(pool, AUTH_ACTOR, async (tx) => {
    const r = await tx.query<{ id: string }>(
      `INSERT INTO sessions
         (user_id, tenant_id, token_hash, csrf_hash, expires_at, mfa_verified_at, ip, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, '')::inet, $8)
       RETURNING id`,
      [
        user.id,
        user.tenantId,
        hash(token),
        hash(csrfToken),
        expiresAt,
        context.mfaVerified ? new Date() : null,
        context.ip ?? "",
        context.userAgent ?? null,
      ],
    );

    return r.rows[0]!.id;
  });

  return { sessionId, token, csrfToken, expiresAt };
}

/**
 * מאתר הפעלה פעילה. מחזיר null לכל תקלה — אסימון שגוי, פג תוקף,
 * נשלל, או משתמש שהושבת — בלי להסגיר במה מדובר.
 */
export async function resolveSession(pool: pg.Pool, token: string): Promise<ActiveSession | null> {
  if (!token) return null;

  return withPlatform(pool, AUTH_ACTOR, async (tx) => {
    const r = await tx.query<{
      id: string;
      csrf_hash: Buffer;
      expires_at: Date;
      mfa_verified_at: Date | null;
      user_id: string;
      tenant_id: string | null;
      email: string;
      role: UserRole;
      display_name: string | null;
      mfa_enrolled_at: Date | null;
      status: string;
    }>(
      `SELECT s.id, s.csrf_hash, s.expires_at, s.mfa_verified_at,
              u.id AS user_id, u.tenant_id, u.email, u.role, u.display_name,
              u.mfa_enrolled_at, u.status
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = $1
         AND s.revoked_at IS NULL
         AND s.expires_at > now()`,
      [hash(token)],
    );

    const row = r.rows[0];

    if (!row || (row.status !== "active" && row.status !== "invited")) return null;

    // עדכון "נראה לאחרונה" בכתיבה נפרדת, כדי שכשל בו לא יפיל אימות
    await tx.query("UPDATE sessions SET last_seen_at = now() WHERE id = $1", [row.id]);

    return {
      sessionId: row.id,
      mfaVerifiedAt: row.mfa_verified_at,
      expiresAt: row.expires_at,
      csrfHash: row.csrf_hash,
      user: {
        userId: row.user_id,
        tenantId: row.tenant_id,
        email: row.email,
        role: row.role,
        displayName: row.display_name,
        mfaEnrolled: row.mfa_enrolled_at !== null,
      },
    };
  });
}

/** משווה אסימון CSRF שהגיע מהלקוח לזה ששמור, בזמן קבוע. */
/**
 * מנפיק אסימון CSRF חדש לסשן קיים.
 *
 * נחוץ כי השרת שומר גיבוב בלבד ואינו יכול להחזיר את המקורי. הפורטל
 * מחזיק את הגולמי ב-sessionStorage, שנמחק עם סגירת הלשונית — בעוד
 * שעוגיית ההפעלה שורדת. התוצאה היא משתמש מחובר שכל פעולת כתיבה
 * שלו נדחית, בלי שום דרך להתאושש חוץ מיציאה וכניסה מחדש.
 *
 * הסיבוב אינו מחליש דבר: הוא מותנה בעוגיית הפעלה תקפה, שהיא
 * HttpOnly ו-SameSite=Strict, ולכן רק הדף האמיתי יכול לבקש אותו.
 * הוא גם מקצר את תוחלת החיים של כל אסימון.
 */
export async function rotateCsrf(pool: pg.Pool, sessionId: string): Promise<string> {
  const csrfToken = randomBytes(TOKEN_BYTES).toString("base64url");

  await withPlatform(pool, AUTH_ACTOR, async (tx) => {
    await tx.query("UPDATE sessions SET csrf_hash = $2 WHERE id = $1", [
      sessionId,
      hash(csrfToken),
    ]);
  });

  return csrfToken;
}

export function csrfMatches(session: ActiveSession, supplied: string | undefined): boolean {
  if (!supplied) return false;

  const candidate = hash(supplied);

  return candidate.length === session.csrfHash.length &&
    timingSafeEqual(candidate, session.csrfHash);
}

/** מסמן אימות שני טרי. נדרש לפני פעולות רגישות. */
export async function markMfaVerified(pool: pg.Pool, sessionId: string): Promise<void> {
  await withPlatform(pool, AUTH_ACTOR, async (tx) => {
    await tx.query("UPDATE sessions SET mfa_verified_at = now() WHERE id = $1", [sessionId]);
  });
}

export async function revokeSession(pool: pg.Pool, sessionId: string): Promise<void> {
  await withPlatform(pool, AUTH_ACTOR, async (tx) => {
    await tx.query(
      "UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
      [sessionId],
    );
  });
}

/** שולל את כל ההפעלות של משתמש. משמש בשינוי סיסמה ובחשד לפריצה. */
export async function revokeAllForUser(pool: pg.Pool, userId: string): Promise<number> {
  return withPlatform(pool, AUTH_ACTOR, async (tx) => {
    const r = await tx.query(
      "UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
      [userId],
    );

    return r.rowCount ?? 0;
  });
}
