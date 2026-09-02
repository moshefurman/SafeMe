/*
 * היתרים להורדת רצפת המדיניות: התאמת הטבלה לצינור שמשתמש בה.
 *
 * הטבלה קיימת מ-0003 — מהיום הראשון — עם RLS והרשאות מ-0006, ואף
 * שורה לא נכתבה בה מעולם. כל מנגנון ההיתר היה בנוי בסוכן: הפרדת
 * מפתחות, nonce חד-פעמי, תוקף, התאמה לרצפה — ולא הייתה דרך להנפיק
 * אחד. הצד הקשה היה גמור, והצינור חסר.
 *
 * הצורה המקורית שמרה חתימה בטבלה (signature, signing_kid) ודרשה
 * mfa_verified_at. הצינור שנבנה חותם ברגע המסירה, במפתח ההיתרים
 * בלבד, ואימות ה-MFA נאכף במסלול (requirePlatformMfa) ולא נרשם
 * לשורה. השדות נשארים, ריקים — לא מוחקים עמודה שאולי עוד תשמש.
 *
 * ---
 *
 * שני שדות זמן חדשים, ולא אחד.
 *
 * delivered_at: נמסר לסוכן. מאפשר למסור בפעימה הבאה בלי למסור שוב
 * ושוב, ולדעת שהיתר שהונפק לא הגיע.
 *
 * applied_at (לשעבר consumed_at): הסוכן דיווח שהחיל. זה, ולא
 * המסירה, מה שמעדכן את הרצפה הרשומה ב-devices. הסוכן מאמת את
 * ההיתר בעצמו ורשאי לדחות אותו, ורצפה שנרשמה כמונמכת בעוד המחשב
 * סירב הייתה מכשילה כל היתר עתידי — כולם היו יוצאים מרצפה שאינה
 * קיימת.
 */

ALTER TABLE loosening_grants
  /* ה-nonce נשלח לסוכן כמחרוזת ומושווה שם כמחרוזת. הטבלה ריקה. */
  ALTER COLUMN nonce TYPE text USING encode(nonce, 'hex'),
  ALTER COLUMN reason DROP NOT NULL,
  ALTER COLUMN mfa_verified_at DROP NOT NULL,
  ALTER COLUMN signature DROP NOT NULL,
  ALTER COLUMN signing_kid DROP NOT NULL,
  ADD COLUMN IF NOT EXISTS delivered_at timestamptz;

ALTER TABLE loosening_grants RENAME COLUMN consumed_at TO applied_at;

/* ייחודי לבדו, לא רק בתוך מחשב: הסוכן דוחה nonce חוזר, והשרת לא ינפיק כזה. */
ALTER TABLE loosening_grants ADD CONSTRAINT loosening_grants_nonce_key UNIQUE (nonce);

CREATE INDEX IF NOT EXISTS loosening_grants_pending_idx
  ON loosening_grants (device_id) WHERE delivered_at IS NULL;

COMMENT ON TABLE loosening_grants IS
  'היתרים להורדת רצפה. נמסרים בפעימה, חד-פעמיים, וחתומים במפתח נפרד.';
