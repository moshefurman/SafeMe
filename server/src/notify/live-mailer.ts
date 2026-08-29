import type pg from "pg";

import { withPlatform } from "../db/client.ts";
import { createMailer, type Mailer, type MailChoice } from "./mailer.ts";

/**
 * הדוור החי.
 *
 * ההגדרות יושבות במסד ומשתנות מהפורטל, ולכן אי אפשר לבנות דוור פעם
 * אחת בעליית השרת ולהחזיק בו. מצד שני אי אפשר גם לקרוא מהמסד בכל
 * הודעה — הסורק שולח בלולאה.
 *
 * הפתרון הוא מטמון קצר: שינוי במסך נכנס לתוקף תוך דקה, וזה מספיק
 * מהר בשביל מנהל שלוחץ "שלח בדיקה" ומספיק זול בשביל לולאה.
 */

const SYSTEM = {
  userId: "00000000-0000-0000-0000-000000000000",
  reason: "קריאת הגדרות דואר",
};

const TTL_MS = 60_000;

export interface MailStatus {
  provider: "none" | "console" | "resend";
  fromAddress: string | null;
  replyTo: string | null;
  /** האם המפתח קיים בסביבה. לא מה הוא. */
  hasApiKey: boolean;
  lastOkAt: Date | null;
  lastErrorAt: Date | null;
  lastError: string | null;
}

interface Row {
  provider: "none" | "console" | "resend";
  from_address: string | null;
  reply_to: string | null;
  last_ok_at: Date | null;
  last_error_at: Date | null;
  last_error: string | null;
}

export async function readMailSettings(pool: pg.Pool): Promise<Row> {
  return withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<Row>(
      `SELECT provider, from_address, reply_to, last_ok_at, last_error_at, last_error
         FROM mail_settings WHERE id = 1`,
    );

    return r.rows[0] ?? {
      provider: "none",
      from_address: null,
      reply_to: null,
      last_ok_at: null,
      last_error_at: null,
      last_error: null,
    };
  });
}

/**
 * דוור שקורא את ההגדרות בעצמו ורושם את התוצאה.
 *
 * הרישום הוא מה שהופך "האם הדואר עובד" לשאלה שאפשר לענות עליה
 * במסך, במקום לחכות שהתראה אמיתית לא תגיע.
 */
export class LiveMailer implements Mailer {
  readonly name = "live";

  private readonly pool: pg.Pool;
  private readonly apiKey: string | undefined;

  private cached: { mailer: Mailer; at: number } | null = null;

  constructor(pool: pg.Pool, apiKey: string | undefined) {
    this.pool = pool;
    this.apiKey = apiKey;
  }

  /** מאלץ קריאה מחדש. נקרא אחרי שמירה במסך. */
  invalidate(): void {
    this.cached = null;
  }

  private async resolve(): Promise<Mailer> {
    if (this.cached !== null && Date.now() - this.cached.at < TTL_MS) {
      return this.cached.mailer;
    }

    const row = await readMailSettings(this.pool);

    const choice: MailChoice = {
      provider: row.provider,
      apiKey: this.apiKey,
      from: row.from_address ?? undefined,
      replyTo: row.reply_to,
    };

    const mailer = createMailer(choice);

    this.cached = { mailer, at: Date.now() };

    return mailer;
  }

  async send(message: Parameters<Mailer["send"]>[0]): Promise<void> {
    const mailer = await this.resolve();

    try {
      await mailer.send(message);
      await this.record(null);
    } catch (error) {
      await this.record(error instanceof Error ? error.message : String(error));
      throw error;
    }
  }

  /**
   * רושם את תוצאת השליחה האחרונה.
   *
   * נכשל בשקט: אם הרישום עצמו נכשל, אין טעם להפיל בגללו שליחה
   * שהצליחה — וגם לא להסתיר כישלון שכבר נזרק הלאה.
   */
  private async record(error: string | null): Promise<void> {
    try {
      await withPlatform(this.pool, SYSTEM, async (tx) => {
        await tx.query(
          error === null
            ? "UPDATE mail_settings SET last_ok_at = now() WHERE id = 1"
            : `UPDATE mail_settings
                  SET last_error_at = now(), last_error = left($1, 500)
                WHERE id = 1`,
          error === null ? [] : [error],
        );
      });
    } catch {
      // נבלע במכוון
    }
  }
}
