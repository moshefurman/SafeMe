-- ============================================================================
--  SafeMe · 0020 · התראות
--
--  עד כאן ההתראות הלכו לכתובת שנרשמה בפתיחת החשבון, ואי אפשר היה
--  לשנות דבר — לא לאן, ולא על מה.
--
--  הכתובת היא נקודת התורפה הזולה ביותר במוצר כולו. מי שמשיג גישה
--  לחשבון ההורה אינו צריך לגעת בסינון בכלל: די שיפנה את ההתראות
--  לכתובת שלו, וההגנה נשארת פעילה בזמן שאיש אינו רואה דבר. זו
--  עקיפה שלא משאירה שום סימן.
--
--  לכן ההחלפה מושהית ומודיעה לשתי הכתובות. ההשהיה אינה בירוקרטיה —
--  היא החלון שבו ההורה רואה "מישהו מנסה לשנות" ועוצר.
-- ============================================================================

-- ---------------------------------------------------------------- ערוץ

/*
 * מתי לשלוח, לכל סוג התראה בנפרד.
 *
 * "יומי" קיים כדי שהורה שמוצף יוריד תדירות במקום לכבות לגמרי —
 * וכיבוי מלא של הכול הוא בדיוק מה שהופך את המוצר לחסר ערך.
 */
CREATE TYPE alert_channel AS ENUM ('off', 'immediate', 'daily');

-- ---------------------------------------------------------------- הגדרות

CREATE TABLE notification_settings (
  tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,

  /*
   * כתובת ההתראות.
   *
   * מפורשת ולא נגזרת מהמשתמש, כי הן שני דברים שונים: הכתובת שנכנסים
   * בה למערכת והכתובת שמקבלת התראה. הורה שנכנס עם Google עשוי לרצות
   * שההתראות ילכו לכתובת שהוא באמת קורא.
   */
  primary_email text NOT NULL CHECK (position('@' in primary_email) > 1),

  on_device_silent alert_channel NOT NULL DEFAULT 'immediate',
  on_unfiltered    alert_channel NOT NULL DEFAULT 'immediate',
  on_new_network   alert_channel NOT NULL DEFAULT 'immediate',
  on_tamper        alert_channel NOT NULL DEFAULT 'immediate',
  on_lockout       alert_channel NOT NULL DEFAULT 'immediate',

  weekly_digest boolean NOT NULL DEFAULT true,

  /*
   * שעות שקט, בשעון המקומי של הדייר.
   *
   * חשד לחבלה אינו מכבד אותן, ובמכוון: השעות שבהן ההורה ישן הן
   * בדיוק השעות שבהן כדאי לנסות. שקט הוא נוחות, לא השתקה.
   */
  quiet_from smallint CHECK (quiet_from BETWEEN 0 AND 23),
  quiet_to   smallint CHECK (quiet_to   BETWEEN 0 AND 23),

  CONSTRAINT quiet_hours_complete CHECK ((quiet_from IS NULL) = (quiet_to IS NULL)),

  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid REFERENCES users(id) ON DELETE SET NULL
);

COMMENT ON TABLE notification_settings IS
  'לאן ההתראות הולכות ועל מה. שורה אחת לדייר.';

-- ---------------------------------------------------------------- כתובות נוספות

/*
 * כתובת נוספת נכנסת לתוקף רק אחרי אימות בכתובת עצמה.
 *
 * בלי זה, הוספת כתובת הייתה דרך לשלוח את ההתראות למי שרוצה לדעת
 * מתי אפשר לפעול — ואף אחד לא היה מבחין, כי הכתובת הראשית ממשיכה
 * לקבל כרגיל.
 */
CREATE TABLE notification_recipients (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

  email      text NOT NULL CHECK (position('@' in email) > 1),

  verify_hash bytea,
  verify_expires_at timestamptz,
  verified_at timestamptz,

  created_at timestamptz NOT NULL DEFAULT now(),
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,

  UNIQUE (tenant_id, email),

  CONSTRAINT verified_has_no_pending_token CHECK (
    verified_at IS NULL OR verify_hash IS NULL
  )
);

CREATE INDEX notification_recipients_active_idx
  ON notification_recipients (tenant_id)
  WHERE verified_at IS NOT NULL;

COMMENT ON TABLE notification_recipients IS
  'כתובות נוספות. מקבלות התראות רק אחרי אימות בכתובת עצמה.';

-- ---------------------------------------------------------------- החלפת הכתובת

/*
 * החלפת הכתובת הראשית, מושהית.
 *
 * ההשהיה היא כל ההגנה כאן. ההודעה יוצאת לשתי הכתובות ברגע הבקשה,
 * והשינוי נכנס לתוקף רק אחרי החלון — כך שגם מי שהשיג גישה לחשבון
 * אינו יכול לנתק את ההורה מההתראות בלי שההורה יראה זאת ויספיק
 * לעצור.
 *
 * הביטול אינו דורש כניסה לחשבון, ובמכוון: מי שמשיג גישה לחשבון
 * יכול לבטל את הביטול. הקישור במייל הוא הדבר היחיד שהוא אינו
 * שולט בו.
 */
CREATE TABLE email_change_requests (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

  from_email text NOT NULL,
  new_email  text NOT NULL CHECK (position('@' in new_email) > 1),

  requested_at timestamptz NOT NULL DEFAULT now(),
  requested_by uuid REFERENCES users(id) ON DELETE SET NULL,
  requested_ip text,

  /* מתי הוא נכנס לתוקף אם איש לא עצר. */
  effective_at timestamptz NOT NULL,

  applied_at   timestamptz,
  cancelled_at timestamptz,
  cancelled_by uuid REFERENCES users(id) ON DELETE SET NULL,

  /* גיבוב של אסימון הביטול שנשלח בשתי ההודעות. */
  cancel_hash bytea NOT NULL,

  CONSTRAINT change_not_both_applied_and_cancelled CHECK (
    applied_at IS NULL OR cancelled_at IS NULL
  )
);

/* בקשה פתוחה אחת לכל דייר. שתיים במקביל היו הופכות את ההשהיה לחסרת ערך. */
CREATE UNIQUE INDEX email_change_one_open_per_tenant
  ON email_change_requests (tenant_id)
  WHERE applied_at IS NULL AND cancelled_at IS NULL;

CREATE INDEX email_change_due_idx
  ON email_change_requests (effective_at)
  WHERE applied_at IS NULL AND cancelled_at IS NULL;

COMMENT ON TABLE email_change_requests IS
  'החלפת כתובת ההתראות. מושהית, ומודיעה לשתי הכתובות.';

-- ---------------------------------------------------------------- הרשאות

GRANT SELECT, INSERT, UPDATE          ON notification_settings   TO safeme_app;
GRANT SELECT, INSERT, UPDATE, DELETE  ON notification_recipients TO safeme_app;
GRANT SELECT, INSERT, UPDATE          ON email_change_requests   TO safeme_app;

ALTER TABLE notification_settings   ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_recipients ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_change_requests   ENABLE ROW LEVEL SECURITY;

CREATE POLICY notification_settings_isolation ON notification_settings
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());

CREATE POLICY notification_recipients_isolation ON notification_recipients
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());

CREATE POLICY email_change_requests_isolation ON email_change_requests
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());

-- ---------------------------------------------------------------- מילוי ראשוני

/*
 * כל דייר קיים מקבל שורה עם כתובת הבעלים.
 *
 * בלי זה חשבון ותיק היה נשאר בלי הגדרות, והקוד היה צריך לטפל בשני
 * מצבים לנצח — או גרוע מזה, להפסיק לשלוח לו התראות.
 */
INSERT INTO notification_settings (tenant_id, primary_email)
SELECT t.id, u.email
  FROM tenants t
  JOIN LATERAL (
    SELECT email FROM users
     WHERE tenant_id = t.id AND role = 'tenant_owner'
     ORDER BY created_at
     LIMIT 1
  ) u ON true
ON CONFLICT (tenant_id) DO NOTHING;
