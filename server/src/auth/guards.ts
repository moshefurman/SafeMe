import type { FastifyReply, FastifyRequest } from "fastify";
import type pg from "pg";
import { CSRF_HEADER, SESSION_COOKIE, csrfMatches, resolveSession } from "./session.ts";
import { authorize, isPlatformRole, type Permission } from "./rbac.ts";
import type { Config } from "../config.ts";

/**
 * שומרי הסף של הפורטל.
 *
 * שלוש שכבות שמופעלות בסדר קבוע:
 *   1. הפעלה תקפה + CSRF בבקשות משנות-מצב
 *   2. משתמש פלטפורמה אימת גורם שני בהפעלה הזו
 *   3. ההרשאה הספציפית לפעולה, כולל טריות האימות
 *
 * הפרדה למודול משלהן, כדי ששני קובצי המסלולים ישתמשו באותה
 * לוגיקה בדיוק ולא בשני העתקים שמתפצלים עם הזמן.
 */

export function readCookie(request: FastifyRequest, name: string): string | undefined {
  const header = request.headers.cookie;

  if (!header) return undefined;

  for (const part of header.split(";")) {
    const index = part.indexOf("=");

    if (index < 0) continue;
    if (part.slice(0, index).trim() !== name) continue;

    return decodeURIComponent(part.slice(index + 1).trim());
  }

  return undefined;
}

export interface Guards {
  requireSession(request: FastifyRequest, reply: FastifyReply): Promise<void>;
  requirePlatformMfa(request: FastifyRequest, reply: FastifyReply): Promise<void>;
  requirePermission(permission: Permission): (r: FastifyRequest, y: FastifyReply) => Promise<void>;
}

export function createGuards(pool: pg.Pool, _config: Config): Guards {
  async function requireSession(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    const token = readCookie(request, SESSION_COOKIE);
    const session = token ? await resolveSession(pool, token) : null;

    if (!session) {
      await reply.code(401).send({ error: "נדרשת התחברות" });
      return;
    }

    const mutating = !["GET", "HEAD", "OPTIONS"].includes(request.method);

    // העוגייה נשלחת אוטומטית על ידי הדפדפן, ולכן היא לבדה אינה
    // מוכיחה שהבקשה יצאה מהאתר שלנו
    if (mutating && !csrfMatches(session, request.headers[CSRF_HEADER] as string | undefined)) {
      await reply.code(403).send({ error: "אסימון CSRF חסר או שגוי" });
      return;
    }

    request.portal = { session };
  }

  async function requirePlatformMfa(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    const session = request.portal!.session;

    /*
     * שני סוגי משתמשים חייבים לאמת, ומסיבות שונות.
     *
     * צוות החברה — כי כך נדרש. משתמש דייר שרשם לעצמו — כי אחרת
     * ההגדרה שהוא הפעיל אינה עושה דבר, והמסך שאומר לו שהוא מוגן
     * משקר.
     *
     * מי שלא רשם ואינו חייב עובר כאן בלי שינוי.
     */
    if (!isPlatformRole(session.user.role) && !session.user.mfaEnrolled) return;

    if (session.mfaVerifiedAt === null) {
      await reply.code(403).send({
        error: "נדרש אימות דו-שלבי",
        mfaRequired: true,
        mfaEnrolled: session.user.mfaEnrolled,
      });
    }
  }

  /**
   * בודק הרשאה. שיוך המשאב לדייר נבדק בשאילתה עצמה דרך RLS,
   * ולכן כאן נבדקים רק התפקיד וטריות האימות.
   */
  function requirePermission(permission: Permission) {
    return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
      const session = request.portal!.session;

      const outcome = authorize({
        role: session.user.role,
        permission,
        mfaVerifiedAt: session.mfaVerifiedAt,
        userTenantId: session.user.tenantId,
      });

      if (outcome.allowed) return;

      await reply
        .code(outcome.needsMfa ? 403 : 403)
        .send({ error: outcome.reason, mfaRequired: outcome.needsMfa });
    };
  }

  return { requireSession, requirePlatformMfa, requirePermission };
}
