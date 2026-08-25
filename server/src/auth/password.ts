import { randomBytes, scrypt, timingSafeEqual, type ScryptOptions } from "node:crypto";
import { promisify } from "node:util";

/**
 * גיבוב סיסמאות ב-scrypt.
 *
 * scrypt נבחר על פני bcrypt ו-argon2 משתי סיבות: הוא מובנה ב-Node ואינו
 * דורש תלות מקומית שצריך להדר, והוא עמיד לחומרה ייעודית בזכות דרישת
 * הזיכרון. הפרמטרים נשמרים בתוך המחרוזת עצמה, כך שאפשר יהיה להעלות
 * אותם בעתיד בלי לשבור סיסמאות קיימות.
 */

// promisify מאבד את העומס עם options, ולכן הטיפוס נקבע במפורש
const scryptAsync = promisify(scrypt) as (
  password: string,
  salt: Buffer,
  keylen: number,
  options: ScryptOptions,
) => Promise<Buffer>;

/** N=16384 · r=8 · p=1 — כ-16MB ו-100ms לגיבוב על שרת טיפוסי. */
const PARAMS = { N: 16_384, r: 8, p: 1, keyLength: 32, saltLength: 16 } as const;

const MAX_MEM = 64 * 1024 * 1024;

export async function hashPassword(password: string): Promise<string> {
  if (password.length < 12) {
    throw new Error("סיסמה חייבת להכיל לפחות 12 תווים");
  }

  const salt = randomBytes(PARAMS.saltLength);

  const derived = await scryptAsync(password.normalize("NFKC"), salt, PARAMS.keyLength, {
    N: PARAMS.N,
    r: PARAMS.r,
    p: PARAMS.p,
    maxmem: MAX_MEM,
  });

  return [
    "scrypt",
    PARAMS.N,
    PARAMS.r,
    PARAMS.p,
    salt.toString("base64url"),
    derived.toString("base64url"),
  ].join("$");
}

/**
 * מאמת סיסמה. ההשוואה בזמן קבוע, וכל תקלה בפענוח מוחזרת כ"לא תואם"
 * ולא כשגיאה — כדי שלא ניתן יהיה להבחין בין חשבון פגום לסיסמה שגויה.
 */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  try {
    const parts = stored.split("$");

    if (parts.length !== 6 || parts[0] !== "scrypt") return false;

    const N = Number(parts[1]);
    const r = Number(parts[2]);
    const p = Number(parts[3]);
    const salt = Buffer.from(parts[4]!, "base64url");
    const expected = Buffer.from(parts[5]!, "base64url");

    if (!Number.isInteger(N) || !Number.isInteger(r) || !Number.isInteger(p)) return false;

    const derived = await scryptAsync(password.normalize("NFKC"), salt, expected.length, {
      N,
      r,
      p,
      maxmem: MAX_MEM,
    });

    return timingSafeEqual(derived, expected);
  } catch {
    return false;
  }
}

/** האם הגיבוב נוצר בפרמטרים ישנים ויש לרענן אותו בכניסה הבאה. */
export function needsRehash(stored: string): boolean {
  const parts = stored.split("$");

  if (parts.length !== 6 || parts[0] !== "scrypt") return true;

  return Number(parts[1]) < PARAMS.N;
}
