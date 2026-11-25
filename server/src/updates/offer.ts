/**
 * הרכבת הצעת עדכון למחשב, חתומה.
 *
 * ההצעה אינה רק "יש גרסה חדשה". היא גם ההיתר היחיד שבגללו השמירה
 * הכפולה תסבול עצירה של השירות בלי לזעוק חבלה — ולכן היא קשורה
 * למחשב מסוים ובעלת תוקף קצר. היתר כללי או ארוך טווח היה מעניק
 * לתוקף חלון קבוע שבו אפשר לעצור את ההגנה.
 */

import type pg from "pg";
import { buildEnvelope, type Signer, type SignedEnvelope } from "../crypto/signing.ts";
import { compareVersions, decideUpdate, parseVersion, type Release } from "./decide.ts";

/** כמה זמן ההצעה תקפה, ובתוכו גם חלון העדכון שהשומר מכיר. */
export const OFFER_TTL_MINUTES = 30;

interface ReleaseRow {
  version: string;
  v_major: number;
  v_minor: number;
  v_patch: number;
  download_url: string;
  sha256: string;
  size_bytes: string;
  min_from_major: number;
  min_from_minor: number;
  min_from_patch: number;
  rollout_percent: number;
  bucket: string;
}

export interface UpdateOffer {
  version: string;
  downloadUrl: string;

  // כתובת גיבוי, כשההורדה הישירה נכשלת. נשלחת רק לסוכן שיודע לנסות
  // אותה (מגרסת הסף ומעלה). נעדרת בהצעה לסוכן ישן.
  fallbackUrl?: string;

  sha256: string;
  sizeBytes: number;
  hwidHash: string;
  issuedUtc: string;
  expiresUtc: string;
}

/**
 * הגרסה הראשונה שיודעת לנפול מהורדה ישירה לכתובת גיבוי.
 *
 * ממנה ומעלה: הראשית היא GitHub והגיבוי הוא שרת FilterPlus. מתחתיה
 * הסוכן מקבל את כתובת ה-Render ישירות, כי אין לו לוגיקת נפילה
 * והורדה ישירה מ-GitHub הייתה נשברת אצל מחשב מסונן.
 */
const FALLBACK_MIN = { major: 1, minor: 1, patch: 51 };

/**
 * מחזיר מעטפה חתומה, או null כשאין מה להציע.
 *
 * הדלי מחושב בשאילתה ולא כאן, כי הוא חייב להיות יציב לצמד
 * מחשב-גרסה. חישוב מקומי היה תלוי בגרסת המימוש ומשתנה איתה.
 */
export async function buildUpdateOffer(
  tx: { query: pg.ClientBase["query"] },
  signer: Signer,
  device: { deviceId: string; hwidHash: string },
  currentVersion: string | null,
  now: Date,
  baseUrl: string | null,
): Promise<SignedEnvelope | null> {
  if (!currentVersion || parseVersion(currentVersion) === null) return null;

  const rows = await tx.query<ReleaseRow>(
    `SELECT version, v_major, v_minor, v_patch,
            download_url, encode(sha256, 'hex') AS sha256, size_bytes,
            min_from_major, min_from_minor, min_from_patch, rollout_percent,
            app.rollout_bucket($1, version) AS bucket
       FROM agent_releases
      WHERE revoked_at IS NULL
        AND channel = 'stable'
        AND rollout_percent > 0
      ORDER BY v_major DESC, v_minor DESC, v_patch DESC
      LIMIT 20`,
    [device.deviceId],
  );

  if (rows.rows.length === 0) return null;

  const buckets = new Map<string, number>();

  const candidates: Release[] = rows.rows.map((r) => {
    buckets.set(r.version, Number(r.bucket));

    return {
      version: r.version,
      parsed: { major: r.v_major, minor: r.v_minor, patch: r.v_patch },
      downloadUrl: r.download_url,
      sha256: r.sha256,
      sizeBytes: Number(r.size_bytes),
      minFrom: {
        major: r.min_from_major,
        minor: r.min_from_minor,
        patch: r.min_from_patch,
      },
      rolloutPercent: r.rollout_percent,
    };
  });

  const decision = decideUpdate(
    currentVersion,
    candidates,
    (version) => buckets.get(version) ?? 100,
  );

  if (decision.offer === null) return null;

  // כתובת המאגר (GitHub) והכתובת דרך שרת FilterPlus. השרת זורם את אותו
  // בינארי, כך שהסכום החתום תקף לשתיהן. baseUrl הוא המארח שהסוכן פנה
  // אליו בפעימה הזו — לכן מובטח שהוא נגיש לו.
  const repoUrl = decision.offer.downloadUrl;
  const proxyUrl = baseUrl
    ? `${baseUrl}/api/v1/update/${encodeURIComponent(decision.offer.version)}`
    : null;

  // סוכן חדש מנסה GitHub קודם וחוסך רוחב פס, ונופל לשרת רק כשצריך.
  // סוכן ישן אינו יודע לנפול, ולכן מקבל את השרת ישירות — מחשב מסונן
  // חייב כתובת שהוא בוודאות מגיע אליה.
  const supportsFallback =
    compareVersions(parseVersion(currentVersion)!, FALLBACK_MIN) >= 0;

  const offer: UpdateOffer = {
    version: decision.offer.version,

    downloadUrl: supportsFallback ? repoUrl : (proxyUrl ?? repoUrl),
    ...(supportsFallback && proxyUrl ? { fallbackUrl: proxyUrl } : {}),

    sha256: decision.offer.sha256,
    sizeBytes: decision.offer.sizeBytes,

    // קשירה למחשב. בלעדיה, הצעה שנלכדה ברשת משמשת כהיתר עצירה
    // עבור כל מחשב אחר.
    hwidHash: device.hwidHash,

    issuedUtc: now.toISOString(),
    expiresUtc: new Date(now.getTime() + OFFER_TTL_MINUTES * 60_000).toISOString(),
  };

  const built = await buildEnvelope(signer, offer);
  return built.envelope;
}
