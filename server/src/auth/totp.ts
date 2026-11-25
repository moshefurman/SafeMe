import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * אימות דו-שלבי בתקן TOTP (RFC 6238) מעל HOTP (RFC 4226).
 *
 * ממומש כאן ולא נלקח מספרייה משתי סיבות: זהו אלגוריתם קצר ויציב שלא
 * השתנה מ-2011, והוא נמצא בנתיב הקריטי של הנפקת קודי הסרה — כל תלות
 * חיצונית שם היא משטח תקיפה נוסף בשרשרת האספקה.
 *
 * המימוש נבדק מול וקטורי הבדיקה הרשמיים של RFC 6238.
 */

const DIGITS = 6;
const PERIOD_SECONDS = 30;

/**
 * חלון סובלנות של צעד אחד לכל כיוון.
 *
 * מכסה סטיית שעון סבירה בטלפון וגם משתמש שהתחיל להקליד רגע לפני
 * שהקוד התחלף. חלון רחב יותר היה מכפיל את מרחב הניחוש בלי צורך.
 */
const WINDOW = 1;

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function generateSecret(bytes = 20): string {
  return base32Encode(randomBytes(bytes));
}

function base32Encode(data: Buffer): string {
  let out = "";
  let buffer = 0;
  let bits = 0;

  for (const byte of data) {
    buffer = (buffer << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      bits -= 5;
      out += BASE32[(buffer >> bits) & 0x1f];
    }
  }

  if (bits > 0) out += BASE32[(buffer << (5 - bits)) & 0x1f];

  return out;
}

export function base32Decode(text: string): Buffer {
  const clean = text.replace(/[\s=-]/g, "").toUpperCase();
  const out: number[] = [];

  let buffer = 0;
  let bits = 0;

  for (const ch of clean) {
    const value = BASE32.indexOf(ch);

    if (value < 0) throw new Error(`תו לא חוקי בסוד ה-TOTP: '${ch}'`);

    buffer = (buffer << 5) | value;
    bits += 5;

    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }

  return Buffer.from(out);
}

/** HOTP לפי RFC 4226. אלגוריתם הגיבוב פרמטרי לצורך וקטורי הבדיקה. */
export function hotp(
  secret: Buffer,
  counter: number,
  digits = DIGITS,
  algorithm: "sha1" | "sha256" | "sha512" = "sha1",
): string {
  const buffer = Buffer.alloc(8);

  // מונה בן 64 ביט. JavaScript מדייק עד 2^53, ומספיק כאן בהפרש עצום.
  buffer.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
  buffer.writeUInt32BE(counter >>> 0, 4);

  const digest = createHmac(algorithm, secret).update(buffer).digest();

  // חיתוך דינמי: ארבעת הביטים האחרונים בוחרים מאיפה לקרוא
  const offset = digest[digest.length - 1]! & 0x0f;

  const binary =
    ((digest[offset]! & 0x7f) << 24) |
    ((digest[offset + 1]! & 0xff) << 16) |
    ((digest[offset + 2]! & 0xff) << 8) |
    (digest[offset + 3]! & 0xff);

  return (binary % 10 ** digits).toString().padStart(digits, "0");
}

export function totp(
  secretBase32: string,
  atSeconds: number = Math.floor(Date.now() / 1000),
  period = PERIOD_SECONDS,
): string {
  return hotp(base32Decode(secretBase32), Math.floor(atSeconds / period));
}

/**
 * מאמת קוד מול חלון סובלנות.
 *
 * ההשוואה בזמן קבוע בכל צעד. אמנם הקוד קצר, אך זליגת תזמון כאן
 * תאפשר לגזור אותו ספרה-ספרה.
 */
export function verifyTotp(
  secretBase32: string,
  code: string,
  atSeconds: number = Math.floor(Date.now() / 1000),
): boolean {
  const clean = code.replace(/\s/g, "");

  if (!/^\d{6}$/.test(clean)) return false;

  const secret = base32Decode(secretBase32);
  const step = Math.floor(atSeconds / PERIOD_SECONDS);
  const supplied = Buffer.from(clean, "utf8");

  let matched = false;

  for (let offset = -WINDOW; offset <= WINDOW; offset += 1) {
    const candidate = Buffer.from(hotp(secret, step + offset), "utf8");

    // ללא break: הלולאה רצה תמיד את כל הצעדים, כדי שמשך הריצה
    // לא יסגיר באיזה צעד נמצאה ההתאמה
    if (candidate.length === supplied.length && timingSafeEqual(candidate, supplied)) {
      matched = true;
    }
  }

  return matched;
}

/** מזהה otpauth לסריקה באפליקציית האימות. */
export function buildOtpAuthUri(secretBase32: string, account: string, issuer = "FilterPlus"): string {
  const label = encodeURIComponent(`${issuer}:${account}`);

  const params = new URLSearchParams({
    secret: secretBase32,
    issuer,
    algorithm: "SHA1",
    digits: String(DIGITS),
    period: String(PERIOD_SECONDS),
  });

  return `otpauth://totp/${label}?${params.toString()}`;
}
