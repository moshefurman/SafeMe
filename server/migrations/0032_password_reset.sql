/*
 * איפוס סיסמה בקישור חד-פעמי.
 *
 * עד כה לא היה שום מסלול התאוששות: משתמש ששכח סיסמה היה נעול
 * מחוץ לחשבון, ומנהל הפלטפורמה נחלץ רק דרך סקריפט שרץ כבעל
 * הסכמה. עם אלפי הורים זו פנייה שבועית קבועה למוקד על משהו
 * שאמור לפתור את עצמו.
 *
 * הבנייה חיכתה לדואר יוצא, ובצדק — מסך שמבטיח קישור שלא נשלח
 * גרוע מהיעדר המסך.
 *
 * ---
 *
 * האסימון נשמר מגובב בלבד.
 *
 * מסד שדלף אינו מקנה יכולת להיכנס לחשבונות: מה ששמור כאן אינו
 * מספיק כדי לבנות את הקישור. זה אותו דפוס בדיוק כמו אסימוני
 * הרישום ואסימוני ביטול ההתראות, ומאותה סיבה.
 */

CREATE TABLE password_resets (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  token_hash bytea NOT NULL UNIQUE,

  /*
   * תוקף קצר.
   *
   * שעה מספיקה למי שביקש ופותח את המייל, וקצרה מספיק כדי שקישור
   * ששכב בתיבה לא יהיה מפתח פתוח לחשבון. תיבת דואר שנפרצת חודש
   * אחר כך אינה אמורה לפתוח את SafeMe.
   */
  expires_at timestamptz NOT NULL DEFAULT now() + interval '1 hour',

  /* שימוש אחד. NULL = טרם נוצל. */
  used_at    timestamptz,

  /*
   * מי ביקש, לצורך זיהוי דפוס.
   *
   * בקשות חוזרות מכתובת אחת על חשבונות שונים הן סריקה, לא
   * שכחה — וזה מה שיאפשר לזהות אותה בדיעבד.
   */
  requested_ip text,
  created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX password_resets_user_idx    ON password_resets (user_id, created_at DESC);
CREATE INDEX password_resets_expiry_idx  ON password_resets (expires_at);

/*
 * בלי RLS ובלי הרשאות לאפליקציה על קריאה חופשית.
 *
 * הטבלה אינה שייכת לדייר — משתמש שמבקש איפוס עדיין לא מזוהה,
 * ואין הקשר דייר שאפשר לסנן לפיו. הגישה נעשית תמיד דרך
 * withPlatform, ולעולם לא לפי מזהה שהמשתמש שלח.
 */
GRANT SELECT, INSERT, UPDATE ON password_resets TO safeme_app;

COMMENT ON TABLE password_resets IS
  'אסימוני איפוס סיסמה, מגובבים. שעה, שימוש אחד.';
