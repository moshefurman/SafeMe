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

/*
 * גרסת התבנית.
 *
 * מועלית בכל שינוי בתוכן, וזה מה שגורם לו לחול. בלי המספר הזה
 * "אינה דורסת קיימת" הייתה אומרת שכל תיקון בתבנית אינו מגיע לשום
 * מקום שכבר רץ — וזה בדיוק מה שקרה עם מארח הפורטל.
 *
 * 1 — התבנית הראשונה
 * 2 — מארח הפורטל ב-alwaysAllow, כדי שחסימה לא תנעל גם את המסך
 *     שמסיר אותה
 */
const BASELINE_VERSION = 2;

export interface BaselineResult {
  created: boolean;
  version: number | null;
}

/**
 * המארחים שנשארים פתוחים גם בחסימה מלאה.
 *
 * שניים, ושניהם הכרחיים: ה-API כדי שהמכשיר יוכל לדווח ולקבל
 * שחרור, והפורטל כדי שיהיה **מסך** שאפשר לשחרר ממנו.
 *
 * זה תוקן אחרי שהתגלה בשטח: הסוכן התיר רק את מארח ה-API, והפורטל
 * יושב על מארח אחר. מחשב חסום יכול היה לדווח על עצמו, אבל ההורה
 * שישב מולו לא יכול היה להגיע למסך האישור — והדרך היחידה החוצה
 * עברה במחשב אחר.
 */
export function alwaysAllowHosts(portalUrl: string): string[] {
  /*
   * רק הפורטל.
   *
   * מארח ה-API כבר מותר תמיד: הסוכן גוזר אותו מ-BaseUrl שבתצורה
   * שלו, ואינו זקוק שיאמרו לו. מה שהוא אינו יכול לדעת לבד הוא
   * היכן יושב מרכז הניהול — הוא מעולם לא פונה אליו.
   */
  try {
    const host = new URL(portalUrl).host;

    return host === "" ? [] : [host];
  } catch {
    // כתובת שאינה תקינה מדולגת. תבנית עם מארח חסר עדיפה על עלייה
    // שנכשלת, והחוסר יתגלה בבדיקה ולא בשטח.
    return [];
  }
}

export function baselineBody(now: Date, hosts: readonly string[] = []): Record<string, unknown> {
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

      /*
       * מה שנשאר פתוח גם כשהכול חסום.
       *
       * בלי הפורטל כאן, חסימה הופכת למלכודת: המכשיר מדווח שהוא
       * חסום, וההורה שיושב מולו אינו יכול להגיע למסך שמסיר את
       * החסימה.
       */
      alwaysAllow: {
        hosts: [...hosts],
        ports: [443],
        allowDns: true,
        allowDhcp: true,
        allowLoopback: true,
      },

      minScoreForGreen: 85,
      minScoreForYellow: 60,
      onRedAction: "warn",
      egress: buildEgressRule(),
    },
  };
}

/**
 * מוודא שקיימת תבנית גלובלית מעודכנת.
 *
 * נקראת בעליית השרת. כשל אינו מפיל אותה — שרת שעולה בלי תבנית
 * עדיף על שרת שאינו עולה, והמכשירים יקבלו אותה בעלייה הבאה.
 */
export async function ensureBaselinePolicy(
  pool: pg.Pool,
  signer: Signer,
  portalUrl: string,
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

  // תבנית עדכנית או חדשה יותר נשארת. ידנית שפורסמה מעל אינה נדרסת.
  if (existing !== null && existing.version >= BASELINE_VERSION) {
    return { created: false, version: existing.version };
  }

  const published = await publishPolicy(pool, signer, {
    tenantId: null,
    version: BASELINE_VERSION,
    body: baselineBody(now, alwaysAllowHosts(portalUrl)),
  });

  return { created: true, version: published.version };
}
