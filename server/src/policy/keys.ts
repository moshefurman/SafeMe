import type pg from "pg";
import { withPlatform } from "../db/client.ts";
import type { Signer } from "../crypto/signing.ts";

/**
 * רישום מפתחות חתימה.
 *
 * החלק הציבורי בלבד נשמר במאגר. הוא נדרש לשלושה דברים: אימות חתימות
 * ישנות, הפצה למכשירים ברישום, ומפתח זר מטבלת המדיניות שמונע פרסום
 * מדיניות שנחתמה במפתח שאיש אינו מכיר.
 *
 * הכלל "מפתח פעיל אחד לכל ייעוד" נאכף באינדקס ייחודי חלקי, ולכן
 * רישום מפתח חדש חייב לפרוש את הקודם באותה טרנזקציה.
 */
export async function registerSigningKey(
  pool: pg.Pool,
  signer: Signer,
  options: { purpose: "policy" | "uninstall" | "loosening" | "update"; kmsKeyId?: string },
): Promise<{ registered: boolean; retired: string | null }> {
  const publicPem = await signer.publicKeyPem();

  return withPlatform(
    pool,
    { userId: "system", reason: "רישום מפתח חתימה" },
    async (tx) => {
      const existing = await tx.query<{ kid: string; public_pem: string }>(
        "SELECT kid, public_pem FROM signing_keys WHERE kid = $1",
        [signer.kid],
      );

      if (existing.rows.length > 0) {
        // מפתח קיים עם אותו kid אך תוכן שונה הוא תקלה חמורה: משמעו
        // שחתימות ישנות שנשמרו תחת אותו מזהה כבר לא יאומתו.
        if (existing.rows[0]!.public_pem.trim() !== publicPem.trim()) {
          throw new Error(
            `המפתח ${signer.kid} כבר רשום עם תוכן אחר. ` +
              "אין להשתמש באותו kid לשני מפתחות — יש להנפיק מזהה חדש.",
          );
        }

        return { registered: false, retired: null };
      }

      const retired = await tx.query<{ kid: string }>(
        `UPDATE signing_keys SET retired_at = now()
         WHERE purpose = $1::key_purpose AND retired_at IS NULL
         RETURNING kid`,
        [options.purpose],
      );

      await tx.query(
        `INSERT INTO signing_keys (kid, purpose, public_pem, kms_key_id)
         VALUES ($1, $2::key_purpose, $3, $4)`,
        [signer.kid, options.purpose, publicPem, options.kmsKeyId ?? "local"],
      );

      return { registered: true, retired: retired.rows[0]?.kid ?? null };
    },
  );
}

/**
 * המפתחות הציבוריים שמכשיר צריך כדי לאמת חתימות.
 *
 * מוחזר גם המפתח הפעיל וגם מפתחות שנפרשו, כי מכשיר שהיה מנותק
 * עדיין מחזיק מדיניות שנחתמה במפתח הישן ולא אמור לדחות אותה.
 */
export async function publicKeyRing(
  pool: pg.Pool,
  purpose: "policy" | "uninstall" | "loosening" | "update",
): Promise<Array<{ kid: string; publicPem: string; active: boolean }>> {
  return withPlatform(
    pool,
    { userId: "system", reason: "שליפת מפתחות ציבוריים" },
    async (tx) => {
      const r = await tx.query<{ kid: string; public_pem: string; retired_at: Date | null }>(
        `SELECT kid, public_pem, retired_at FROM signing_keys
         WHERE purpose = $1::key_purpose
         ORDER BY retired_at NULLS FIRST, created_at DESC`,
        [purpose],
      );

      return r.rows.map((row) => ({
        kid: row.kid,
        publicPem: row.public_pem,
        active: row.retired_at === null,
      }));
    },
  );
}
