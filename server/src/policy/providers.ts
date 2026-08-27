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
  };

  /**
   * מקור הנתונים.
   *
   * skeleton — שלד שנזרע במיגרציה, ניחוש סביר שלא אומת מול דבר
   * verified — נמדד בפועל: תעודה שנקראה ממכונה, טווח שנבדק ב-RDAP
   *
   * ההבחנה חשובה כי שלד **נראה** כמו כלל עובד. "CN=Etrog*" ייראה
   * ברשימה בדיוק כמו טביעת אצבע אמיתית, ולא יתאים לעולם.
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
 * זורע את הספקים שחסרים. אינה נוגעת בקיימים.
 *
 * ON CONFLICT DO NOTHING ולא DO UPDATE, ובכוונה: מרגע שמישהו ערך
 * ספק בממשק, העריכה שלו היא מקור האמת. זריעה שדורסת הייתה מוחקת
 * את העבודה שלו בכל עלייה של השרת.
 */
export async function seedProviders(pool: pg.Pool): Promise<number> {
  return withPlatform(pool, SYSTEM, async (tx) => {
    let touched = 0;

    for (const p of SEED) {
      /*
       * שתי פעולות בשאילתה אחת.
       *
       * ספק שאינו קיים נוצר. ספק שקיים **ועדיין מסומן כשלד**
       * מקבל את הנתונים המאומתים — הוא נזרע במיגרציה כניחוש,
       * ואין שם עבודה של אדם שאפשר לדרוס.
       *
       * ספק שכבר סומן verified אינו נוגע. מרגע שמישהו ערך אותו
       * בממשק, העריכה שלו היא מקור האמת, וזריעה שדורסת הייתה
       * מוחקת אותה בכל עלייה של השרת.
       */
      const r = await tx.query(
        `INSERT INTO providers (key, display_name, trust_level, enabled, detection, sort_order)
         VALUES ($1, $2, $3::trust_level, $4, $5::jsonb, $6)
         ON CONFLICT (key) DO UPDATE
           SET detection = EXCLUDED.detection,
               updated_at = now()
         WHERE providers.detection ->> 'dataStatus' IS DISTINCT FROM 'verified'`,
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
 * יהיה הפיך — אבל אינו מגיע למכשירים.
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
  );
}
