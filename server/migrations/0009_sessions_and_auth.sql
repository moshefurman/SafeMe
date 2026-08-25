-- ============================================================================
--  SafeMe · 0009 · הפעלות משתמש ואימות
--
--  הפעלות נשמרות בצד השרת ולא רק בעוגייה חתומה, כדי שאפשר יהיה לבטל
--  הפעלה מיידית: עובד שעזב, מכשיר שנגנב, או חשד לחשבון פרוץ.
--  עוגייה חתומה בלבד תקפה עד שתפוג, ואי אפשר לשלול אותה.
-- ============================================================================

CREATE TABLE sessions (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  -- null עבור משתמשי פלטפורמה. משוכפל מ-users כדי ש-RLS יעבוד
  -- בלי תת-שאילתה, כמו בשאר הטבלאות.
  tenant_id      uuid REFERENCES tenants(id) ON DELETE CASCADE,

  -- האסימון עצמו לעולם אינו נשמר, רק ה-hash שלו. דלף מסד נתונים
  -- אינו מאפשר להתחזות למשתמש מחובר.
  token_hash     bytea UNIQUE NOT NULL,
  csrf_hash      bytea NOT NULL,

  created_at     timestamptz NOT NULL DEFAULT now(),
  expires_at     timestamptz NOT NULL,
  last_seen_at   timestamptz NOT NULL DEFAULT now(),
  revoked_at     timestamptz,

  -- מתי אומת הגורם השני בפעם האחרונה. פעולות רגישות דורשות
  -- אימות טרי ולא רק "התחבר פעם עם MFA". ראה 3.2.4.
  mfa_verified_at timestamptz,

  ip             inet,
  user_agent     text
);

CREATE INDEX sessions_user_idx    ON sessions (user_id, created_at DESC);
CREATE INDEX sessions_tenant_idx  ON sessions (tenant_id);
CREATE INDEX sessions_expiry_idx  ON sessions (expires_at) WHERE revoked_at IS NULL;

COMMENT ON COLUMN sessions.mfa_verified_at IS
  'אימות שני טרי. פעולות הקלה דורשות אותו מחדש, לא רק בכניסה.';

-- ---------------------------------------------------------------- הגבלת קצב
--
-- נשמר בנפרד מ-audit_log כי כאן מוחקים רשומות ישנות, ושם אסור למחוק.

CREATE TABLE login_attempts (
  id         bigserial PRIMARY KEY,
  email      citext NOT NULL,
  ip         inet,
  at         timestamptz NOT NULL DEFAULT now(),
  success    boolean NOT NULL,
  -- password | mfa | session
  stage      text NOT NULL DEFAULT 'password'
);

CREATE INDEX login_attempts_email_idx ON login_attempts (email, at DESC);
CREATE INDEX login_attempts_ip_idx    ON login_attempts (ip, at DESC);

/*
 * ספירת כשלונות בחלון זמן. משמש גם לנעילת חשבון וגם לחסימת כתובת,
 * כי תוקף שמנסה סיסמאות על חשבונות רבים לא ייתפס על ידי מונה לחשבון.
 */
CREATE OR REPLACE FUNCTION app.recent_login_failures(
  p_email citext, p_ip inet, p_window interval)
RETURNS TABLE (by_email bigint, by_ip bigint)
LANGUAGE sql STABLE AS $$
  SELECT
    count(*) FILTER (WHERE email = p_email),
    count(*) FILTER (WHERE p_ip IS NOT NULL AND ip = p_ip)
  FROM login_attempts
  WHERE NOT success AND at > now() - p_window;
$$;

-- ---------------------------------------------------------------- הרשאות ו-RLS

GRANT SELECT, INSERT, UPDATE, DELETE ON sessions TO safeme_app;
GRANT SELECT, INSERT, DELETE ON login_attempts TO safeme_app;
GRANT USAGE, SELECT ON SEQUENCE login_attempts_id_seq TO safeme_app;

ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;

/*
 * שתי מדיניות נפרדות במכוון:
 *
 * שכבת האימות רצה בהקשר פלטפורמה, כי בזמן חיפוש ההפעלה עוד לא ידוע
 * לאיזה דייר היא שייכת. זו נקודת האתחול של כל בקשה.
 *
 * לאחר שההקשר נקבע, דייר רואה רק את ההפעלות שלו — כדי שמסך
 * "המכשירים המחוברים שלי" לא ידלוף הפעלות של לקוחות אחרים.
 */
CREATE POLICY sessions_isolation ON sessions
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());

-- ניסיונות התחברות אינם שייכים לדייר: הם קורים לפני שידוע מיהו.
-- הגישה אליהם מוגבלת להקשר פלטפורמה בלבד.
ALTER TABLE login_attempts ENABLE ROW LEVEL SECURITY;

CREATE POLICY login_attempts_platform ON login_attempts
  USING (app.is_platform()) WITH CHECK (app.is_platform());

-- ---------------------------------------------------------------- אימות מבני

DO $$
BEGIN
  -- אם יום אחד מישהו יוסיף עמודה לאסימון גולמי, זה ייתפס כאן
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'sessions'
      AND column_name IN ('token', 'csrf', 'secret')
  ) THEN
    RAISE EXCEPTION 'טבלת sessions אינה רשאית להחזיק אסימון גולמי';
  END IF;
END
$$;
