/**
 * שם קובץ המתקין, ובתוכו אסימון ההתקנה.
 *
 * מראה מדויקת של InstallerToken בצד ה-C#. שני הצדדים חייבים להסכים
 * על אותו פורמט בדיוק: השרת בונה את השם, והמתקין קורא אותו בחזרה.
 * סטייה כאן פירושה מתקין שלא יודע לאיזה חשבון להתחבר.
 *
 * הרעיון: קובץ אחד חתום משרת את כל הלקוחות, וההתאמה האישית היא
 * השם בלבד. שינוי שם אינו פוגע בחתימת Authenticode, שמכסה את התוכן.
 */

export const TOKEN_PREFIX = "ENR-";
export const TOKEN_BODY_LENGTH = 24;

const PRODUCT = "SafeMe-Setup";

/*
 * הגבולות דורשים שהאסימון לא יהיה חלק מרצף הקסדצימלי ארוך יותר,
 * כדי שרצף כזה לא ייחתך באמצע ויתקבל כאסימון תקין.
 */
// i ולא רק g: מערכות קבצים ודפדפנים משנים רישיות, והצד ה-C#
// משתמש ב-IgnoreCase. בלי הדגל הזה שם קובץ באותיות קטנות היה
// מוחזר כ"אין אסימון" בשרת ומתקבל אצל הסוכן — שתי תשובות שונות
// לאותו קלט.
const TOKEN_PATTERN = /(?<![0-9A-Fa-f])ENR-([0-9A-Fa-f]{24})(?![0-9A-Fa-f])/gi;

/** מחלץ אסימון משם קובץ, או null. */
export function tokenFromFileName(name: string | null | undefined): string | null {
  if (!name) return null;

  // רק מרכיב השם, כמו Path.GetFileName בצד השני
  const base = name.trim().split(/[\\/]/).pop() ?? "";

  if (base === "") return null;

  const matches = [...base.matchAll(TOKEN_PATTERN)];

  // שני אסימונים בשם אחד: ניחוש בין השניים גרוע מסירוב, כי הוא
  // היה מחבר את המכשיר לחשבון שרירותי.
  if (matches.length !== 1) return null;

  return TOKEN_PREFIX + matches[0]![1]!.toUpperCase();
}

/** בונה את שם הקובץ להורדה. */
export function fileNameForToken(token: string): string {
  const normalized = token.trim().toUpperCase();

  if (!isWellFormed(normalized)) {
    throw new Error(`אסימון בפורמט לא צפוי: ${token}`);
  }

  return `${PRODUCT}-${normalized}.exe`;
}

/** בודק שהאסימון בפורמט שהשרת מנפיק. */
export function isWellFormed(token: string | null | undefined): boolean {
  if (!token) return false;

  const trimmed = token.trim();
  const matches = [...trimmed.matchAll(TOKEN_PATTERN)];

  return (
    matches.length === 1 &&
    matches[0]!.index === 0 &&
    matches[0]![0].length === trimmed.length
  );
}
