-- ============================================================================
--  SafeMe · 0012 · רישום עצמי
--
--  לקוח פותח חשבון בעצמו, בלי אשראי ובלי מגע אנושי, ומתחיל 30 יום
--  ניסיון. זה משנה שתי הנחות שהיו בבסיס האפיון:
--
--    1. עד כה כל חשבון נוצר על ידי החברה. עכשיו יש דלת פתוחה לאינטרנט,
--       ולכן היא צריכה הגבלת קצב ואימות כתובת מייל.
--    2. פרופיל האימות (7.2) הסתמך על אשראי. בניסיון ללא אשראי אין
--       למה להשוות, ולכן נדרש נתיב אימות נפרד לתקופה הזו.
-- ============================================================================

ALTER TABLE users
  ADD COLUMN email_verified_at timestamptz,
  ADD COLUMN email_verify_hash bytea,
  ADD COLUMN email_verify_sent_at timestamptz;

CREATE INDEX users_email_verify_idx ON users (email_verify_hash)
  WHERE email_verify_hash IS NOT NULL;

COMMENT ON COLUMN users.email_verified_at IS
  'אימות כתובת. חשבון שנפתח בעצמו ולא אומת מוגבל, ראה billing/trial.ts.';

ALTER TABLE tenants
  ADD COLUMN created_via text NOT NULL DEFAULT 'staff';

COMMENT ON COLUMN tenants.created_via IS
  'staff = נוצר על ידי החברה · self_signup = נפתח על ידי הלקוח';

-- ---------------------------------------------------------------- הגבלת קצב

/*
 * רישום עצמי הוא דלת פתוחה לאינטרנט. בלי הגבלה אפשר לפתוח אלפי
 * חשבונות ולמלא את בסיס הנתונים, או לייצר ניסיונות אינסופיים
 * בכתובות מייל חד-פעמיות.
 */
CREATE TABLE signup_attempts (
  id      bigserial PRIMARY KEY,
  ip      inet,
  email   citext NOT NULL,
  at      timestamptz NOT NULL DEFAULT now(),
  success boolean NOT NULL
);

CREATE INDEX signup_attempts_ip_idx    ON signup_attempts (ip, at DESC);
CREATE INDEX signup_attempts_email_idx ON signup_attempts (email, at DESC);

CREATE OR REPLACE FUNCTION app.recent_signups(p_ip inet, p_window interval)
RETURNS bigint
LANGUAGE sql STABLE AS $$
  SELECT count(*) FROM signup_attempts
  WHERE p_ip IS NOT NULL AND ip = p_ip AND at > now() - p_window;
$$;

GRANT SELECT, INSERT, DELETE ON signup_attempts TO safeme_app;
GRANT USAGE, SELECT ON SEQUENCE signup_attempts_id_seq TO safeme_app;

ALTER TABLE signup_attempts ENABLE ROW LEVEL SECURITY;

CREATE POLICY signup_attempts_platform ON signup_attempts
  USING (app.is_platform()) WITH CHECK (app.is_platform());

-- ---------------------------------------------------------------- אימות זהות
--
-- פרופיל האימות תוכנן סביב אשראי. בניסיון ללא אשראי הוא ריק, ולכן
-- נוסף סימון מפורש של מה שקיים בפועל — כדי שמסך המוקד לא ינסה
-- לאמת מול נתון שאינו שם.

ALTER TABLE verification_profiles
  ADD COLUMN method text NOT NULL DEFAULT 'none';

COMMENT ON COLUMN verification_profiles.method IS
  'none = אין נתוני אימות (ניסיון ללא אשראי) · id_only · id_and_card';

UPDATE verification_profiles
   SET method = CASE
     WHEN card_token IS NOT NULL AND id_last4_hash IS NOT NULL THEN 'id_and_card'
     WHEN id_last4_hash IS NOT NULL THEN 'id_only'
     ELSE 'none'
   END;
