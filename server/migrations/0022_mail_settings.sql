-- ============================================================================
--  SafeMe · 0022 · דואר יוצא
--
--  הבחירה בספק ובכתובת השולח הייתה משתנה סביבה, כלומר פריסה מחדש
--  לכל שינוי — ובלי שום דרך לדעת אם הדואר בכלל עובד עד שהתראה
--  אמיתית לא תגיע. זה הפוך בדיוק: התראה שלא נשלחה היא הכשל שאסור
--  שיהיה שקט.
--
--  מה שכאן ומה שלא, ולמה:
--
--    ספק, כתובת שולח, כתובת מענה   כאן. הגדרה, לא סוד.
--    מפתח ה-API                     בסביבת השרת בלבד.
--
--  המפתח אינו כאן ובכוונה. סוד שנשמר במסד עובר דרך טופס בדפדפן,
--  דרך יומני השרת, ודרך כל גיבוי — והמסך שעורך אותו הופך ליעד.
--  שמירתו בסביבה משאירה אותו במקום אחד שאיש אינו קורא ממנו.
--  המסך מראה אם הוא קיים, ולא מה הוא.
-- ============================================================================

CREATE TABLE mail_settings (
  /*
   * שורה אחת בלבד. המפתח הקבוע הוא מה שאוכף את זה — בלעדיו היו
   * מצטברות שורות ואיש לא היה יודע איזו פעילה.
   */
  id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),

  provider text NOT NULL DEFAULT 'none'
    CHECK (provider IN ('none', 'console', 'resend')),

  from_address text,
  reply_to     text,

  /*
   * תוצאת השליחה האחרונה.
   *
   * זו הסיבה העיקרית שהטבלה קיימת. בלעדיה אין שום דרך לענות על
   * "האם הדואר עובד" חוץ מלחכות שהתראה אמיתית לא תגיע.
   */
  last_ok_at    timestamptz,
  last_error_at timestamptz,
  last_error    text,

  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid REFERENCES users(id) ON DELETE SET NULL,

  CONSTRAINT real_provider_needs_sender CHECK (
    provider <> 'resend' OR from_address IS NOT NULL
  )
);

COMMENT ON TABLE mail_settings IS
  'הדואר היוצא. המפתח אינו כאן — הוא בסביבת השרת בלבד.';

INSERT INTO mail_settings (id, provider) VALUES (1, 'none')
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------- הרשאות

GRANT SELECT, UPDATE ON mail_settings TO safeme_app;

ALTER TABLE mail_settings ENABLE ROW LEVEL SECURITY;

/*
 * הגדרה גלובלית, ולכן צוות החברה בלבד.
 *
 * דייר שיכול לשנות את כתובת השולח יכול לגרום להתראות של דיירים
 * אחרים להישלח בשמו — או להיחסם כספאם. אין שום סיבה שהוא יראה
 * את השורה הזו בכלל.
 */
CREATE POLICY mail_settings_platform_only ON mail_settings
  USING (app.is_platform())
  WITH CHECK (app.is_platform());
