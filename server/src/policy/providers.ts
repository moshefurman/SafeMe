import type pg from "pg";

import { withPlatform } from "../db/client.ts";

/**
 * ספקי הסינון המוכרים.
 *
 * הם נתונים ולא קוד, וזו לא הבחנה טכנית: ספק חדש שנכנס לשוק, טווח
 * כתובות שהתווסף, או תעודת שורש שהונפקה מחדש — כל אלה קורים בקצב
 * שאינו קצב שחרור הגרסאות. כל עוד הם היו קבועים בקוד, כל שינוי
 * דרש בנייה ופריסה, ובפועל פשוט לא קרה.
 *
 * הטבלה קיימת מהסכימה הראשונה. מה שנוסף כאן הוא החיבור אליה, וגם
 * הזריעה הראשונית מהערכים שאומתו בשטח.
 */

export type TrustLevel = "low" | "medium" | "high";

/** מה שמזהה ספק. כל הווקטורים אופציונליים, ומספיק אחד. */
export interface Detection {
  rootCa?: {
    thumbprints?: string[];
    subjectPatterns?: string[];
    required?: boolean;
  };
  network?: {
    cidrs?: string[];
    asns?: number[];
    reverseDnsPatterns?: string[];
  };
  httpMarkers?: {
    url?: string;
    headers?: Record<string, string>;
    bodyContains?: string[];
    /*
     * מארחים לקריאת רמת הסינון.
     *
     * חייבים להיות כאלה שדף החסימה שלהם **מזכיר את רמת ההגנה**, וזה
     * מתברר כתלוי בקטגוריה ולא במארח.
     *
     * נמדד מול חשבון אמיתי:
     *
     *   bet365, קטגוריה 41   דף של 12,589 בתים. בלי שם דרגה.
     *   xvideo, קטגוריה 56   דף של 9,055 בתים. ובו "בסיסית".
     *
     * חסימה לפי קטגוריה אינה מזכירה את הרמה, כי לא הרמה גרמה לה.
     * רק חסימה שנובעת מרמת ההגנה כותבת אותה.
     *
     * הגישה היא מעל HTTP: הסינון מנתק את המארחים האלה לפי SNI ולכן
     * אין להם דף מעל HTTPS כלל. והיא מותנית בשער — לחיצת יד למארח
     * אחר, שבה מנפיק התעודה הוא של הספק — כך שמובטח שמה שיחזור הוא
     * דף החסימה ולא האתר.
     */
    levelHosts?: string[];

    /*
     * שמות הדרגות כפי שהספק עצמו מציג אותן.
     *
     * הספק כותב את שם הדרגה בדף החסימה עצמו, ולכן אין צורך למפות
     * מספרים. הסוכן מחפש איזה מהשמות מופיע בדף — רשימה סגורה שיכולה
     * רק לא למצוא, ולעולם לא תמציא דרגה שאינה קיימת.
     *
     * זה בא במקום סולם שתרגם טווחי מספרים לתיאורים. הוא הומצא וטעה:
     * חשבון שרימון מגדירה כ"בסיסית" הוצג כ"סינון מחמיר" — ההפך.
     *
     * הרשימה בשרת ולא בסוכן, כדי שניסוח שהספק ישנה יטופל בלי גרסה.
     */
    levelNames?: string[];
  };

  /**
   * מנפיק התעודה שמוצגת בגלישה בפועל.
   *
   * הווקטור החזק ביותר לספק שמסנן דרך פרוקסי: הוא נמדד על החיבור
   * עצמו, ולא על מה שמותקן במחשב או על הכתובת שממנה הוא יוצא.
   * נמדד בלחיצת יד בלבד, בלי בקשת HTTP ובלי הורדת תוכן.
   */
  tlsIssuer?: {
    patterns?: string[];
    probes?: string[];
  };

  /**
   * מקור הנתונים, לתצוגה בממשק.
   *
   * skeleton — שלד שנזרע במיגרציה, ניחוש סביר שלא אומת מול דבר
   * verified — נמדד בפועל: תעודה שנקראה ממכונה, טווח שנבדק ב-RDAP
   *
   * ההבחנה חשובה כי שלד **נראה** כמו כלל עובד. "CN=Etrog*" ייראה
   * ברשימה בדיוק כמו טביעת אצבע אמיתית, ולא יתאים לעולם.
   *
   * אינו משמש עוד כשער לזריעה: ברגע שפריסה אחת סימנה verified,
   * שער כזה חוסם כל נתון חדש מהקוד. מי ערך אחרון הוא הקריטריון
   * הנכון, והוא ב-updated_by.
   */
  dataStatus?: "skeleton" | "verified";
}

export interface ProviderRow {
  key: string;
  displayName: string;
  trustLevel: TrustLevel;
  enabled: boolean;
  detection: Detection;
  sortOrder: number;
}

const SYSTEM = { userId: "system", reason: "ניהול ספקי סינון" };

/*
 * ─────────────────────────────────────────── הזריעה הראשונית
 *
 * מה שרשום כאן אומת בפועל ולא נלקח ממסמך: טביעות האצבע נקראו
 * ממאגר התעודות של מכונה מסוננת, והטווח נבדק מול RDAP של RIPE
 * ורשום שם בשם RIMON1-NET.
 *
 * לאתרוג ולנתיב אין כללים, ובמכוון: אין לי נתונים מאומתים עליהם.
 * ניחוש כאן גרוע מחוסר — הוא היה מזהה ספק שאינו שם, או נכשל בשקט
 * ומשאיר את המשפחה בלי הסבר. הם מופיעים כדי שיהיה לאן להוסיף.
 */
const SEED: ProviderRow[] = [
  {
    key: "netfree",
    displayName: "נטפרי",
    trustLevel: "high",
    enabled: true,
    sortOrder: 10,
    detection: {
      /*
       * נטפרי מסננת דרך תעודת שורש משלה, ולכן נוכחותה במאגר היא
       * הסימן החזק ביותר — היא נדרשת כדי שהדפדפן יסמוך על הסינון.
       *
       * עשר טביעות: הם מנפיקים כמה שורשים במקביל (RSA, ECC,
       * ED25519) ובשתי סדרות, וכל מכונה נושאת תת-קבוצה.
       */
      rootCa: {
        thumbprints: [
          "F30D2345BE5A0E9F3F4FCC49E471BF3CDCF38346",
          "CEDE8E3BDEC3EBF59B2390E421547B1654430B2E",
          "B638708D5947B8F323097821D80EC4246D8E058D",
          "AD42563A2B00F3D3F076333551B18C6F06202BD5",
          "9A77108FE30DD74CD4406C77B14084342E946BAD",
          "81AF4F6325DA3783F0C9F89823ECF38580320148",
          "6337F278671D9207C03A74B9D818E5B80F225856",
          "5789E624025AE3A6EDA3BEC8427DD9C259EB6457",
          "1831EC6A8E9886841E3B6F26CD3A396F2B5C9B3B",
          "07A149023FC4E4D49CE4110A36D330117EE648A3",
        ],
        subjectPatterns: ["*O=NetFree*", "*netfree.link*"],
        required: false,
      },

      /*
       * הווקטור החי היחיד של נטפרי, ובלעדיו אין לה זיהוי בכלל.
       *
       * עד כאן נטפרי זוהתה בתעודת השורש שלה בלבד, והתעודה ירדה
       * למשקל אפס — היא נשארת מותקנת גם כשהמחשב עבר לרשת סלולרית
       * זרה, ולכן אינה יכולה להעיד על ההווה. בלי מה שכאן, נטפרי
       * הייתה הופכת לבלתי ניתנת לזיהוי.
       *
       * השאילתה מחזירה את הספק כפי שנטפרי רואה אותו על החיבור
       * שממנו הבקשה יצאה. נמדד מרשת ללא סינון:
       *
       *   {"isp":"Telzar 019 International Telecommunications Services LTD"}
       *
       * המילה netfree אינה מופיעה שם, וההשוואה אינה תלוית רישיות.
       *
       * הצד החיובי טרם נמדד. יש גם http://api.internal.netfree.link/
       * שמחזיר מבחוץ 404 עם "אתה לא בנטפרי" — לא נבחר כאן משום
       * שהוא HTTP בלבד, וראיה לסינון שאפשר לזייף בדרך אינה ראיה.
       */
      httpMarkers: {
        url: "https://netfree.link/api/geo/get-isp",
        headers: {},
        bodyContains: ["netfree"],
      },

      dataStatus: "verified",
    },
  },
  {
    key: "rimon",
    displayName: "רימון",
    trustLevel: "high",
    enabled: true,
    sortOrder: 20,
    detection: {
      /*
       * רימון מסננת ברמת הספק: המחשב יוצא לכל האינטרנט דרך הרשת
       * שלה, ואין תעודה להתקין. הסימן הוא הכתובת שממנה הוא יוצא.
       */
      network: {
        cidrs: ["213.151.48.0/20"],
        reverseDnsPatterns: ["*.rimon.net.il", "*rimon*"],
      },

      /*
       * רימון מסננת דרך NetSpark, ובגלישה רגילה היא שקופה לגמרי —
       * התעודות שמתקבלות הן האמיתיות. אבל על מארח שהיא מגישה עליו
       * דף חסימה היא **חייבת** להציג תעודה משלה, ושם המנפיק הוא
       * חתימה שאי אפשר לזייף.
       *
       * נמדד על מכונה מחוברת: bet365 החזיר
       * E=support@netspark.com, בעוד שוויקיפדיה ו-GitHub החזירו
       * מנפיקים אמיתיים.
       *
       * המארח נבחר דווקא כזה שמקבל דף ולא ניתוק — ניתוק אינו מציג
       * תעודה, ואין ממנו מה ללמוד על זהות.
       */
      tlsIssuer: {
        patterns: ["*netspark*", "*rimon*"],
        probes: ["www.bet365.com"],
      },

      /*
       * הווקטור החזק והזול ביותר, ונמדד באותה בדיקה: דף החסימה
       * של רימון נושא כותרת HTTP בשם "Rimon" עם הערך RWC_BLOCK.
       *
       * כותרת אחת, בלי פענוח תעודות ובלי טווחי כתובות. וגוף אותה
       * תשובה מכיל את רמת הסינון של החשבון — מה שמאפשר לזהות לא
       * רק שהסינון פעיל, אלא כמה הוא מחמיר.
       */
      httpMarkers: {
        url: "https://www.bet365.com",
        headers: { Rimon: "*" },
        bodyContains: ["cause=url_level", "urllevel="],
        levelHosts: ["xvideo.com"],

        /*
         * נמדד מול חשבון אמיתי: דף החסימה החזיר level=-30, ורימון
         * מציגה אותו למשתמש כ"בסיסית".
         *
         * שאר הדרגות טרם נמדדו. כשתימדד עוד אחת — שינוי בחשבון,
         * קריאת דף החסימה, והוספת שורה כאן.
         */
        levelNames: ["בסיסית", "בינונית", "גבוהה", "הרמטית"],
      },

      dataStatus: "verified",
    },
  },
  /*
   * אלה נשארים שלד, ובמכוון: אין לי עליהם נתונים מאומתים.
   * הם אינם מופיעים ב-SEED כדי שהזריעה לא תדרוס את מה שכבר
   * במיגרציה, והממשק מסמן אותם כשלד.
   */
];

/**
 * מסנכרנת את הספקים שלא נערכו בממשק.
 *
 * מחזירה כמה שורות נגעו — הערך הזה קובע אם המדיניות מתפרסמת מחדש,
 * ולכן הוא נספר רק כשהתוכן באמת השתנה.
 */
export async function seedProviders(pool: pg.Pool): Promise<number> {
  return withPlatform(pool, SYSTEM, async (tx) => {
    let touched = 0;

    for (const p of SEED) {
      /*
       * מי ערך אחרון, ולא מה סומן בתוכן.
       *
       * updated_by ריק פירושו שהשורה מעולם לא נערכה בממשק — היא
       * נזרעה, ורק נזרעה. שורה כזו מקבלת את הנתונים העדכניים
       * מהקוד, וזה בדיוק מה שאמור לקרות כשמתגלה וקטור זיהוי חדש.
       *
       * updated_by מלא פירושו שאדם נגע בה, ואז העריכה שלו היא
       * מקור האמת. זריעה שדורסת אותה הייתה מוחקת את עבודתו בכל
       * עלייה של השרת.
       *
       * הניסיון הראשון השווה סימון dataStatus בתוך התוכן, וזו
       * הייתה טעות: פריסה אחת סימנה verified, ומאותו רגע הזריעה
       * חסמה את עצמה מלהכניס נתונים חדשים. שני וקטורי זיהוי
       * שהתגלו אחר כך לא הגיעו לשום מחשב.
       */
      const r = await tx.query(
        `INSERT INTO providers (key, display_name, trust_level, enabled, detection, sort_order)
         VALUES ($1, $2, $3::trust_level, $4, $5::jsonb, $6)
         ON CONFLICT (key) DO UPDATE
           SET detection = EXCLUDED.detection,
               updated_at = now()
         WHERE providers.updated_by IS NULL
           AND providers.detection IS DISTINCT FROM EXCLUDED.detection`,
        [p.key, p.displayName, p.trustLevel, p.enabled, JSON.stringify(p.detection), p.sortOrder],
      );

      touched += r.rowCount ?? 0;
    }

    return touched;
  });
}

/** הספקים כפי שהם, לפי סדר התצוגה. */
export async function listProviders(pool: pg.Pool): Promise<ProviderRow[]> {
  return withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{
      key: string;
      display_name: string;
      trust_level: TrustLevel;
      enabled: boolean;
      detection: Detection;
      sort_order: number;
    }>(
      "SELECT key, display_name, trust_level, enabled, detection, sort_order FROM providers ORDER BY sort_order, key",
    );

    return r.rows.map((row) => ({
      key: row.key,
      displayName: row.display_name,
      trustLevel: row.trust_level,
      enabled: row.enabled,
      detection: row.detection,
      sortOrder: row.sort_order,
    }));
  });
}

/**
 * הצורה שנכנסת לחבילת המדיניות.
 *
 * רק מה שמופעל. ספק מכובה נשאר בטבלה עם כל הכללים שלו, כדי שכיבוי
 * יהיה הפיך — אבל אינו מגיע למחשבים.
 */
export function toPolicyProviders(providers: readonly ProviderRow[]): unknown[] {
  return providers
    .filter((p) => p.enabled)
    .map((p) => ({
      id: p.key,
      displayName: p.displayName,
      trustLevel: p.trustLevel,
      ...(p.detection.rootCa ? { rootCa: p.detection.rootCa } : {}),
      ...(p.detection.network ? { network: p.detection.network } : {}),
      ...(p.detection.httpMarkers ? { httpMarkers: p.detection.httpMarkers } : {}),
      ...(p.detection.tlsIssuer ? { tlsIssuer: p.detection.tlsIssuer } : {}),
    }));
}

/**
 * בדיקת תקינות של כללי זיהוי.
 *
 * מחזירה הודעה, או null כשהכול תקין. שני סוגי טעות נבדקים כאן, וכל
 * אחד נכשל אחרת:
 *
 * טביעת אצבע שגויה **אינה** נכשלת — היא פשוט לעולם לא מתאימה,
 * והספק לא יזוהה בלי שאיש יבין למה.
 *
 * טווח כתובות רחב מדי כן "עובד", וזה גרוע יותר: הוא יזהה כל מחשב
 * בעולם כמסונן.
 */
export function validateDetection(detection: Detection): string | null {
  const thumbprints = detection.rootCa?.thumbprints ?? [];

  for (const t of thumbprints) {
    // SHA-1 הוא 40 תווים, SHA-256 הוא 64. שניהם מקובלים.
    if (!/^[0-9A-Fa-f]{40}$|^[0-9A-Fa-f]{64}$/.test(t.trim())) {
      return `טביעת אצבע לא תקינה: ${t}. נדרשים 40 או 64 תווים הקסדצימליים.`;
    }
  }

  for (const cidr of detection.network?.cidrs ?? []) {
    const match = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(cidr.trim());

    if (!match) return `טווח לא תקין: ${cidr}. הצורה היא 213.151.48.0/20.`;

    const octets = match[1]!.split(".").map(Number);

    if (octets.some((o) => o > 255)) return `טווח לא תקין: ${cidr}.`;

    const bits = Number(match[2]);

    if (bits > 32) return `טווח לא תקין: ${cidr}.`;

    /*
     * טווח רחב מ-/8 מזהה חלק ניכר מהאינטרנט כמסונן. זו אינה
     * הרפיה של הגדרה — זו ביטול מוחלט של הבדיקה.
     */
    if (bits < 8) return `הטווח ${cidr} רחב מדי. נדרש /8 או צר יותר.`;
  }

  for (const asn of detection.network?.asns ?? []) {
    if (!Number.isInteger(asn) || asn <= 0 || asn > 4_294_967_295) {
      return `מספר ASN לא תקין: ${asn}.`;
    }
  }

  /*
   * ספק בלי אף כלל אינו נדחה כאן.
   *
   * הוא לא יזוהה לעולם, אבל זה מצב לגיטימי — אתרוג ונתיב יושבים
   * בדיוק שם, כדי שיהיה לאן להוסיף. הממשק מסמן אותם, וזו הדרך
   * הנכונה: להראות, לא לחסום.
   */
  return null;
}

/** האם לספק יש בכלל במה להיתפס. */
export function hasAnyRule(detection: Detection): boolean {
  return (
    (detection.rootCa?.thumbprints?.length ?? 0) > 0
    || (detection.rootCa?.subjectPatterns?.length ?? 0) > 0
    || (detection.network?.cidrs?.length ?? 0) > 0
    || (detection.network?.asns?.length ?? 0) > 0
    || (detection.network?.reverseDnsPatterns?.length ?? 0) > 0
    || typeof detection.httpMarkers?.url === "string"
    || (detection.tlsIssuer?.patterns?.length ?? 0) > 0
  );
}
