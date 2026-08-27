import type pg from "pg";

import { withPlatform } from "../db/client.ts";
import { publishPolicy } from "./publish.ts";
import { buildEgressRule } from "./egress.ts";
import type { Signer } from "../crypto/signing.ts";

/**
 * מדיניות ברירת מחדל גלובלית.
 *
 * נוצרה אחרי שנפל בשטח: מכשיר שנרשם לחשבון חדש קיבל 404 על משיכת
 * המדיניות, ורץ בלי הגדרות בכלל. הסוכן אמנם מתנהג שמרנית בלי
 * מדיניות, אבל "בלי מדיניות" אינו מצב שאמור להתקיים — הוא רק אומר
 * שאיש לא הגדיר מה נכון.
 *
 * הרשומה הגלובלית חלה על כל דייר שאין לו מדיניות משלו: השאילתה
 * ב-/api/v1/policy כבר נופלת אליה אחורה. מה שהיה חסר הוא שהיא
 * תתקיים.
 *
 * שתי הכרעות שמובנות כאן במכוון:
 *
 * מצב האכיפה הוא monitor ולא enforce. מכשיר שהרגע הותקן ועוד לא
 * דיווח אף פעימה אינו המקום להתחיל בחסימה — ההורה עוד לא ראה
 * מסך אחד.
 *
 * ו-default-deny כבוי. הפעלתו היא החלטה מפורשת בפורטל, ולא משהו
 * שקורה למישהו כי השרת עלה.
 */

/** גרסה 1 שמורה לתבנית. פרסום ידני יתחיל מ-2 ומעלה. */
const BASELINE_VERSION = 1;

export interface BaselineResult {
  created: boolean;
  version: number | null;
}

export function baselineBody(now: Date): Record<string, unknown> {
  return {
    version: BASELINE_VERSION,
    issuedUtc: now.toISOString(),

    // חלון תוקף רחב: מכשיר שאיבד קשר לשרת ליום שלם עדיין פועל
    // לפי מה שיש לו, במקום להתייחס למדיניות כפגה ולהחמיר מעצמו.
    ttlMinutes: 240,
    graceMinutes: 1440,

    providers: [
      { id: "netfree", displayName: "נטפרי", trustLevel: "high" },
      { id: "rimon", displayName: "רימון", trustLevel: "high" },
      { id: "etrog", displayName: "אתרוג", trustLevel: "medium" },
      { id: "nativ", displayName: "נתיב", trustLevel: "medium" },
    ],

    enforcement: {
      mode: "monitor",
      minScoreForGreen: 85,
      minScoreForYellow: 60,
      onRedAction: "warn",
      egress: buildEgressRule(),
    },
  };
}

/**
 * מוודא שקיימת תבנית גלובלית. אינה דורסת קיימת.
 *
 * נקראת בעליית השרת. כשל אינו מפיל אותה — שרת שעולה בלי תבנית
 * עדיף על שרת שאינו עולה, והמכשירים יקבלו אותה בעלייה הבאה.
 */
export async function ensureBaselinePolicy(
  pool: pg.Pool,
  signer: Signer,
  now: Date = new Date(),
): Promise<BaselineResult> {
  const existing = await withPlatform(
    pool,
    { userId: "system", reason: "בדיקת מדיניות בסיס" },
    async (tx) => {
      const r = await tx.query<{ version: number }>(
        "SELECT version FROM policies WHERE tenant_id IS NULL ORDER BY version DESC LIMIT 1",
      );

      return r.rows[0] ?? null;
    },
  );

  if (existing !== null) return { created: false, version: existing.version };

  const published = await publishPolicy(pool, signer, {
    tenantId: null,
    version: BASELINE_VERSION,
    body: baselineBody(now),
  });

  return { created: true, version: published.version };
}
