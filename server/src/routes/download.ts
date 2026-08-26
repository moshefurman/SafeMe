import type { FastifyInstance } from "fastify";
import type pg from "pg";

import { withPlatform } from "../db/client.ts";
import { hashEnrollToken } from "../auth/device-token.ts";
import { fileNameForToken, tokenFromFileName } from "../installer/filename.ts";
import type { Config } from "../config.ts";

/**
 * הורדת המתקין.
 *
 * הכתובת נושאת את שם הקובץ, ושם הקובץ נושא את אסימון ההתקנה:
 *
 *   GET /d/SafeMe-Setup-ENR-XXXXXXXXXXXXXXXXXXXXXXXX.exe
 *
 * שני דברים קורים כאן, ושניהם נחוצים.
 *
 * הראשון הוא השם: הדפדפן שומר את הקובץ בשם שהשרת מכתיב, והמתקין
 * קורא אותו בחזרה כדי לדעת לאיזה חשבון להתחבר. הפניה ישירה לאחסון
 * הסטטי הייתה מאבדת את השם — ואיתו את הקשר לחשבון.
 *
 * השני הוא האימות: אסימון שפג, בוטל או מוצה לא יוריד קובץ. אין
 * טעם לתת למישהו מתקין שייכשל ברישום בלי הסבר.
 *
 * העדכונים, לעומת זאת, אינם עוברים כאן. הסוכן מוריד ישירות מהמאגר
 * הציבורי, כי שם הקובץ אינו מעניין אותו והוא מאמת סכום ביקורת
 * וחתימה ממילא. זה מה שמשאיר את רוחב הפס של העדכונים אצל GitHub.
 */

/** תקרת הורדה, כדי שקובץ פגום לא ימשוך זיכרון בלי גבול. */
const MAX_BYTES = 200 * 1024 * 1024;

interface DownloadDeps {
  pool: pg.Pool;
  config: Config;
}

const SYSTEM = {
  userId: "00000000-0000-0000-0000-000000000000",
  reason: "הורדת מתקין",
};

interface TokenRow {
  id: string;
  tenant_id: string;
  expired: boolean;
  revoked: boolean;
  exhausted: boolean;
}

interface ReleaseRow {
  version: string;
  download_url: string;
  size_bytes: string;
}

export async function registerDownloadRoutes(
  app: FastifyInstance,
  deps: DownloadDeps,
): Promise<void> {
  const { pool } = deps;

  app.get<{ Params: { fileName: string } }>(
    "/d/:fileName",
    async (request, reply) => {
      const token = tokenFromFileName(request.params.fileName);

      if (token === null) {
        return reply.code(404).send({ error: "קישור הורדה אינו תקין" });
      }

      const state = await withPlatform(pool, SYSTEM, async (tx) => {
        const r = await tx.query<TokenRow>(
          `SELECT id, tenant_id,
                  expires_at <= now()      AS expired,
                  revoked_at IS NOT NULL   AS revoked,
                  uses >= max_uses         AS exhausted
             FROM enroll_tokens
            WHERE token_hash = $1`,
          [hashEnrollToken(token)],
        );

        return r.rows[0] ?? null;
      });

      // אסימון שאינו קיים ואסימון שפג מקבלים אותה תשובה. הבחנה
      // ביניהן הייתה מאפשרת לבדוק אילו אסימונים הונפקו אי פעם.
      if (state === null) {
        return reply.code(404).send({ error: "קישור הורדה אינו תקין" });
      }

      if (state.revoked) {
        return reply.code(410).send({ error: "קישור ההורדה בוטל" });
      }

      if (state.expired) {
        return reply.code(410).send({
          error: "תוקף קישור ההורדה פג. יש להפיק קישור חדש ממרכז הניהול.",
        });
      }

      if (state.exhausted) {
        return reply.code(410).send({
          error: "קישור ההורדה נוצל במלואו. יש להפיק קישור חדש ממרכז הניהול.",
        });
      }

      const release = await withPlatform(pool, SYSTEM, async (tx) => {
        const r = await tx.query<ReleaseRow>(
          `SELECT version, download_url, size_bytes
             FROM agent_releases
            WHERE revoked_at IS NULL AND channel = 'stable'
            ORDER BY v_major DESC, v_minor DESC, v_patch DESC
            LIMIT 1`,
        );

        return r.rows[0] ?? null;
      });

      if (release === null) {
        request.log.error("התבקשה הורדה אך אין גרסה מפורסמת");

        return reply.code(503).send({
          error: "אין כרגע גרסה זמינה להורדה. נסה שוב מאוחר יותר.",
        });
      }

      if (Number(release.size_bytes) > MAX_BYTES) {
        request.log.error(
          { version: release.version, size: release.size_bytes },
          "גרסה גדולה מהתקרה",
        );

        return reply.code(503).send({ error: "אין כרגע גרסה זמינה להורדה." });
      }

      const upstream = await fetch(release.download_url, {
        headers: { "user-agent": "SafeMe-Server" },
        redirect: "follow",
      });

      if (!upstream.ok || upstream.body === null) {
        request.log.error(
          { status: upstream.status, url: release.download_url },
          "משיכת הגרסה מהמאגר נכשלה",
        );

        return reply.code(502).send({ error: "ההורדה נכשלה. נסה שוב." });
      }

      // השם נקבע כאן ולא במקור. זו כל הסיבה שהבקשה עוברת דרך השרת.
      reply
        .header("content-type", "application/octet-stream")
        .header(
          "content-disposition",
          `attachment; filename="${fileNameForToken(token)}"`,
        )
        .header("x-safeme-version", release.version)
        // הקובץ משתנה בין לקוחות רק בשמו, אך המטמון מפתח לפי כתובת,
        // וכל לקוח מקבל כתובת משלו. אין מה לשתף.
        .header("cache-control", "private, no-store");

      const length = upstream.headers.get("content-length");
      if (length !== null) reply.header("content-length", length);

      return reply.send(upstream.body);
    },
  );
}

/** בונה את כתובת ההורדה המלאה עבור אסימון. */
export function downloadUrlFor(baseUrl: string, token: string): string {
  return `${baseUrl.replace(/\/+$/, "")}/d/${fileNameForToken(token)}`;
}
