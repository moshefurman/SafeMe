/**
 * מי מקבל איזה עדכון, ומתי.
 *
 * מופרד מהשאילתה ומהמסלול כדי שיהיה נבדק בלי בסיס נתונים ובלי שרת.
 * כל כלל כאן הוא כלל בטיחות, ולא אופטימיזציה.
 */

export interface Version {
  major: number;
  minor: number;
  patch: number;
}

export interface Release {
  version: string;
  parsed: Version;
  downloadUrl: string;
  sha256: string;
  sizeBytes: number;
  minFrom: Version;
  rolloutPercent: number;
}

export type SkipReason =
  | "no_releases"
  | "unparsable_current"
  | "not_newer"
  | "too_old_to_jump"
  | "not_in_rollout";

export type Decision =
  | { offer: Release }
  | { offer: null; reason: SkipReason };

const SEMVER = /^(\d+)\.(\d+)\.(\d+)$/;

export function parseVersion(text: string): Version | null {
  const match = SEMVER.exec(text.trim());

  if (match === null) return null;

  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
  };
}

/** מחזיר שלילי, אפס או חיובי — כמו כל משווה. */
export function compareVersions(a: Version, b: Version): number {
  return a.major - b.major || a.minor - b.minor || a.patch - b.patch;
}

/**
 * בוחר עדכון למכשיר, או מסביר למה לא.
 *
 * המועמדים מגיעים ממוינים מהחדש לישן, ומסוננים מגרסאות שנפסלו.
 * הדלי מחושב בבסיס הנתונים כי הוא חייב להיות יציב לצמד
 * מכשיר-גרסה; הגרלה בכל פעימה הייתה מכניסה ומוציאה מכשיר מההפצה
 * חליפות, ומתחילה הורדה שלא תושלם לעולם.
 */
export function decideUpdate(
  currentVersion: string,
  candidates: readonly Release[],
  bucketOf: (version: string) => number,
): Decision {
  if (candidates.length === 0) return { offer: null, reason: "no_releases" };

  const current = parseVersion(currentVersion);

  // גרסה שאי אפשר לפענח: לא מציעים כלום. סוכן שמדווח גרסה משובשת
  // הוא סוכן שמשהו אצלו לא בסדר, ועדכון מרחוק אינו התשובה.
  if (current === null) return { offer: null, reason: "unparsable_current" };

  let closest: SkipReason = "not_newer";

  for (const release of candidates) {
    // ---- הגנה מפני שדרוג לאחור ----
    //
    // "עדכון" לגרסה ישנה יותר עם פרצה ידועה הוא דרך תקיפה מלאה,
    // והוא נראה בדיוק כמו עדכון תקין. שווה או ישן יותר — נדחה.
    if (compareVersions(release.parsed, current) <= 0) continue;

    // ---- קפיצה גדולה מדי ----
    //
    // שדרוג שמדלג על שינויי מבנה שנעשו בדרך הוא מה שהופך מכשיר
    // ללבנה, ומכשיר שהפך ללבנה אי אפשר לתקן מרחוק — כי הכלי
    // לתיקון הוא הסוכן עצמו.
    if (compareVersions(current, release.minFrom) < 0) {
      closest = "too_old_to_jump";
      continue;
    }

    if (bucketOf(release.version) >= release.rolloutPercent) {
      closest = "not_in_rollout";
      continue;
    }

    return { offer: release };
  }

  return { offer: null, reason: closest };
}
