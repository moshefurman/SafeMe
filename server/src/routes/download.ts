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
 * העדכונים עוברים במסלול נפרד, GET /api/v1/update/:version שבתחתית
 * הקובץ. הם אינם צריכים אסימון או שם קובץ, אבל כן צריכים לזרום דרך
 * השרת ולא ישירות מ-GitHub — כי מחשב מסונן שאינו פותר את github.com
 * לא הצליח לעדכן. שם הבתים זורמים דרך המארח שהסוכן ממילא מגיע אליו.
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

  /**
   * הורדה ללא אסימון, למי שרוצה לחסום מחשב בלי חשבון.
   *
   * שם הקובץ נקי מכוונה: המתקין מחפש אסימון בשמו, לא מוצא, ופותח
   * את מסך הבחירה — להזין קוד, או לחסום לחלוטין. אותו קובץ בדיוק
   * משמש את שני המסלולים.
   *
   * הפניה ולא הזרמה, בניגוד למסלול עם האסימון.
   *
   * שם ההורדה עם אסימון נקבע על ידינו, ולכן הקובץ **חייב** לעבור
   * דרך השרת. כאן השם כבר נכון במקור, ואין מה להוסיף — הפניה
   * משאירה את רוחב הפס אצל GitHub. זה ההבדל בין קישור ציבורי
   * שאפשר לפרסם לבין חשבון שמשלם על כל הורדה.
   */
  app.get("/d/blocker", async (request, reply) => {
    const release = await latestRelease(pool);

    if (release === null) {
      request.log.error("התבקשה הורדה לחסימה אך אין גרסה מפורסמת");

      return reply.code(503).send({
        error: "אין כרגע גרסה זמינה להורדה. נסה שוב מאוחר יותר.",
      });
    }

    /*
     * רק http ו-https מופנים.
     *
     * ההפניה שולחת את הדפדפן אל מה ששמור בעמודה, וסכימה אחרת שם
     * — data: למשל — הופכת את המסלול הציבורי הזה לכלי להגשת תוכן
     * שרירותי מהדומיין שלנו. רק מנהל יכול לפרסם גרסה, ולכן זו
     * אינה פרצה פתוחה; אבל מסלול שאין בו אימות אינו המקום לסמוך
     * על כך שכל מי שיפרסם בעתיד יזין כתובת שפויה.
     */
    if (!/^https?:\/\//i.test(release.download_url)) {
      request.log.error(
        { version: release.version },
        "כתובת ההורדה אינה http(s) ולכן לא הופנתה",
      );

      return reply.code(503).send({ error: "אין כרגע גרסה זמינה להורדה." });
    }

    return reply
      .header("x-safeme-version", release.version)
      .redirect(release.download_url, 302);
  });

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

      const release = await latestRelease(pool);

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

  /*
   * ---------------------------------------------------------------- עדכון
   *
   * הורדת עדכון דרך השרת, במקום ישירות מ-GitHub.
   *
   * עד כה הסוכן הוריד את גרסת העדכון ישירות מהמאגר הציבורי. אבל כל
   * אוכלוסיית SafeMe יושבת מאחורי סינון, ומחשב שהסינון שלו אינו
   * פותר את github.com ואת release-assets.githubusercontent.com לא
   * הצליח לעדכן — נמדד בשדה על NECHAMI (1.1.45): ההורדה נפלה על
   * "No such host is known. (github.com:443)".
   *
   * כאן הבתים זורמים דרך המארח שהסוכן ממילא מדבר איתו כדי לקבל
   * פעימה. אם הוא מגיע לשרת, הוא מגיע לעדכון. אין צורך ב-GitHub
   * בצד הלקוח.
   *
   * הנתיב פתוח: הבינארי ממילא ציבורי ב-GitHub, ואין כאן סוד. הוא
   * מוגבל לגרסאות שפורסמו בפועל, והסוכן מאמת חתימה וסכום ביקורת
   * ממילא — ולכן כתובת זדונית לא יכולה להזריק בינארי אחר.
   *
   * העלות היא רוחב פס: כל עדכון עובר דרך Render. זה המחיר של הגעה
   * למחשבים מסוננים, וזה בדיוק מה שהתשלום על התוכנית קונה.
   */
  app.get<{ Params: { version: string } }>(
    "/api/v1/update/:version",
    async (request, reply) => {
      const version = request.params.version;

      // צורה בלבד. הגרסה עצמה נבדקת מול הטבלה מיד אחר כך.
      if (!/^\d{1,4}\.\d{1,5}\.\d{1,6}$/.test(version)) {
        return reply.code(404).send({ error: "גרסה אינה תקינה" });
      }

      const release = await releaseByVersion(pool, version);

      if (release === null) {
        return reply.code(404).send({ error: "אין גרסה כזו" });
      }

      if (Number(release.size_bytes) > MAX_BYTES) {
        request.log.error(
          { version, size: release.size_bytes },
          "גרסת עדכון גדולה מהתקרה",
        );

        return reply.code(503).send({ error: "אין כרגע גרסה זמינה להורדה." });
      }

      // הסוכן ממשיך הורדה שנקטעה עם Range. מעבירים אותו הלאה כדי
      // שההמשכיות תישמר, במקום למשוך שישים מגה מאפס בכל ניסיון.
      const range = request.headers.range;

      let upstream: Response;

      try {
        upstream = await fetch(release.download_url, {
          headers: {
            "user-agent": "SafeMe-Server",
            ...(range ? { range } : {}),
          },
          redirect: "follow",
        });
      } catch (error) {
        // תקלת רשת מול המאגר. 502 ולא חריגה שתהפוך ל-500 אקראי:
        // הסוכן רואה 5xx כתקלה חולפת וינסה שוב, וזה בדיוק הנכון.
        request.log.error({ err: error, url: release.download_url }, "החיבור למאגר העדכון נכשל");

        return reply.code(502).send({ error: "ההורדה נכשלה. נסה שוב." });
      }

      // טווח שאינו קיים: מחזירים 416 כמו שהוא, כדי שהסוכן ינקה את
      // השארית ויתחיל מאפס — ולא ינעל על שחרור שנראה פגום.
      if (upstream.status === 416) {
        const contentRange =
          upstream.headers.get("content-range") ?? `bytes */${release.size_bytes}`;

        return reply.code(416).header("content-range", contentRange).send();
      }

      if (!upstream.ok || upstream.body === null) {
        request.log.error(
          { status: upstream.status, url: release.download_url },
          "משיכת העדכון מהמאגר נכשלה",
        );

        // 502 ולא 404: המקור נכשל, לא הבקשה. הסוכן יראה בזה תקלה
        // חולפת וינסה שוב, במקום לנטוש את ההצעה.
        return reply.code(502).send({ error: "ההורדה נכשלה. נסה שוב." });
      }

      reply
        // 200 להורדה מלאה, 206 להמשך. מעבירים כפי שהמקור החזיר.
        .code(upstream.status)
        .header("content-type", "application/octet-stream")
        .header("x-safeme-version", release.version)
        .header("accept-ranges", "bytes")
        .header("cache-control", "private, no-store");

      for (const header of ["content-length", "content-range"]) {
        const value = upstream.headers.get(header);
        if (value !== null) reply.header(header, value);
      }

      return reply.send(upstream.body);
    },
  );
}

/**
 * הגרסה היציבה האחרונה.
 *
 * משותפת לשני המסלולים: מי שמוריד עם אסימון ומי שמוריד לחסימה
 * מקבלים את אותה גרסה. שתי שאילתות נפרדות היו נפרדות ביום שבו
 * מישהו ישנה אחת מהן.
 */
async function latestRelease(pool: pg.Pool): Promise<ReleaseRow | null> {
  return withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<ReleaseRow>(
      `SELECT version, download_url, size_bytes
         FROM agent_releases
        WHERE revoked_at IS NULL AND channel = 'stable'
        ORDER BY v_major DESC, v_minor DESC, v_patch DESC
        LIMIT 1`,
    );

    return r.rows[0] ?? null;
  });
}

/**
 * גרסה מסוימת לפי מספרה.
 *
 * להורדת עדכון: הסוכן מבקש בדיוק את הגרסה שההצעה נקבה בה, ולא את
 * האחרונה — כדי שהבתים יתאימו לסכום הביקורת החתום שבהצעה.
 */
async function releaseByVersion(
  pool: pg.Pool,
  version: string,
): Promise<ReleaseRow | null> {
  return withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<ReleaseRow>(
      `SELECT version, download_url, size_bytes
         FROM agent_releases
        WHERE version = $1 AND revoked_at IS NULL AND channel = 'stable'
        LIMIT 1`,
      [version],
    );

    return r.rows[0] ?? null;
  });
}

/** בונה את כתובת ההורדה המלאה עבור אסימון. */
export function downloadUrlFor(baseUrl: string, token: string): string {
  return `${baseUrl.replace(/\/+$/, "")}/d/${fileNameForToken(token)}`;
}
