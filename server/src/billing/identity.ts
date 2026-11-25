import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * אימות זהות לצורך בקשת הסרה.
 *
 * נשמרות ארבע הספרות האחרונות של תעודת הזהות בלבד, וגם הן רק כ-hash
 * עם salt ייחודי לכל לקוח. שתי סיבות: החוק מטיל חובות כבדות על מאגר
 * שמכיל מספרי זהות, ודלף מסד נתונים לא אמור לחשוף אפילו את הארבע.
 *
 * ה-salt הייחודי חיוני כאן במיוחד: מרחב הערכים הוא 10,000 בלבד,
 * ובלי salt טבלת קשת אחת הייתה פותחת את כל המאגר.
 */

const CONTEXT = "FilterPlus/identity/v1";

export interface IdentityDigest {
  hash: Buffer;
  salt: Buffer;
}

export function hashIdLast4(digits: string, salt: Buffer = randomBytes(16)): IdentityDigest {
  if (!/^\d{4}$/.test(digits)) {
    throw new Error("נדרשות ארבע ספרות");
  }

  const hash = createHash("sha256")
    .update(CONTEXT)
    .update(salt)
    .update(digits, "utf8")
    .digest();

  return { hash, salt };
}

/**
 * השוואה בזמן קבוע.
 *
 * מרחב של 10,000 ערכים קטן דיו כדי שדליפת תזמון תהיה משמעותית,
 * ולכן ההשוואה חייבת להיות קבועה ומספר הניסיונות מוגבל ל-3.
 */
export function verifyIdLast4(digits: string, stored: IdentityDigest): boolean {
  if (!/^\d{4}$/.test(digits)) return false;

  const candidate = hashIdLast4(digits, stored.salt).hash;

  return candidate.length === stored.hash.length && timingSafeEqual(candidate, stored.hash);
}
