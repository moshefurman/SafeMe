-- ============================================================================
--  FilterPlus · 0044 · נאמן נפרד מבעל החשבון
--
--  עד כאן מי שהחזיק בכניסה לחשבון היה גם מי שאישר לעצמו: בעל חשבון
--  אישי יכול היה להנפיק לעצמו קוד הסרה או לכבות רשימה לבנה בלחיצה.
--  "אישור נוסף" היה קוד מאפליקציית האימות של אותו אדם.
--
--  נאמן הוא אדם אחר. הוא אינו נכנס לחשבון ואין לו סיסמה: הוא מקבל
--  דוא"ל עם קישור, ומאשר או דוחה. בעל החשבון בוחר אחד משני מצבים:
--
--    inform   הנאמן מקבל הודעה על כל הקלה, והיא מתבצעת מיד.
--    approve  הקלה והסרה ממתינות עד שנאמן מאשר. אין פקיעה ואין
--             אישור אוטומטי: בקשה נשארת תלויה עד שעונים עליה.
--
--  הסרה של נאמן היא עצמה הקלה, ולכן אינה מיידית: הנאמן מאשר אותה,
--  או שהיא נכנסת לתוקף אחרי שבעה ימים שבהם הוא יכול לעצור אותה.
--
--  tenants אינה משתנה. המצב יושב בטבלה משלו, כי טבלאות הליבה שייכות
--  לתפקיד אחר ואינן ניתנות לשינוי מכאן (ראו 0042).
-- ============================================================================

-- ---------------------------------------------------------------- מצב הנאמנות

CREATE TABLE trustee_settings (
  tenant_id  uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,

  mode       text NOT NULL DEFAULT 'approve',

  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid REFERENCES users(id) ON DELETE SET NULL,

  CONSTRAINT trustee_mode_known CHECK (mode IN ('inform', 'approve'))
);

COMMENT ON TABLE trustee_settings IS
  'מה הנאמן עושה בחשבון: רק מקבל הודעות, או מאשר הקלות והסרה. חסר שורה פירושו approve.';

-- ---------------------------------------------------------------- הנאמנים

CREATE TABLE trustees (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

  name        text NOT NULL,
  email       text NOT NULL,

  -- נאמן אינו פעיל עד שאישר בעצמו שהוא מקבל את התפקיד. בלי זה אפשר
  -- היה "למנות" כתובת שאיש אינו קורא, ולהציג חשבון כמוגן.
  verify_hash   text,
  verified_at   timestamptz,

  -- הסרה ממתינה. הנאמן מאשר אותה או עוצר אותה בקישור; אם לא ענה,
  -- היא נכנסת לתוקף במועד הזה.
  removal_requested_at timestamptz,
  removal_effective_at timestamptz,
  removal_hash         text,

  created_at  timestamptz NOT NULL DEFAULT now(),
  created_by  uuid REFERENCES users(id) ON DELETE SET NULL,

  CONSTRAINT trustee_email_unique UNIQUE (tenant_id, email),
  CONSTRAINT trustee_name_length CHECK (length(name) BETWEEN 1 AND 80),
  CONSTRAINT trustee_email_shape CHECK (email = lower(email) AND email LIKE '%_@_%')
);

CREATE INDEX trustees_tenant_idx ON trustees (tenant_id);
CREATE INDEX trustees_verify_idx ON trustees (verify_hash) WHERE verify_hash IS NOT NULL;
CREATE INDEX trustees_removal_idx ON trustees (removal_hash) WHERE removal_hash IS NOT NULL;

COMMENT ON TABLE trustees IS
  'נאמני החשבון: אנשים מחוץ לחשבון שמאשרים הקלות והסרה בקישור שנשלח אליהם.';

-- ---------------------------------------------------------------- בקשות לאישור

CREATE TABLE trustee_requests (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  requested_by uuid REFERENCES users(id) ON DELETE SET NULL,

  -- מה התבקש, במילים שהנאמן קורא בדוא"ל
  summary      text NOT NULL,

  -- הפעולה עצמה. אחרי האישור בעל החשבון מבצע אותה שוב, והשרת מזהה
  -- אותה לפי השיטה, הנתיב וגיבוב הגוף. האישור תקף לפעולה הזו בלבד.
  method       text NOT NULL,
  path         text NOT NULL,
  body         jsonb NOT NULL DEFAULT '{}'::jsonb,
  body_hash    text NOT NULL,

  status       text NOT NULL DEFAULT 'pending',
  decide_hash  text,

  created_at   timestamptz NOT NULL DEFAULT now(),
  decided_at   timestamptz,
  decided_by   uuid REFERENCES trustees(id) ON DELETE SET NULL,
  executed_at  timestamptz,

  CONSTRAINT trustee_request_status_known CHECK (
    status IN ('pending', 'approved', 'denied', 'cancelled', 'executed')
  )
);

CREATE INDEX trustee_requests_tenant_idx ON trustee_requests (tenant_id, created_at DESC);
CREATE INDEX trustee_requests_decide_idx ON trustee_requests (decide_hash) WHERE decide_hash IS NOT NULL;
CREATE INDEX trustee_requests_match_idx ON trustee_requests (tenant_id, body_hash) WHERE status IN ('pending', 'approved');

COMMENT ON TABLE trustee_requests IS
  'בקשות של בעל החשבון להקלה או להסרה, שממתינות לנאמן. אין להן פקיעה.';

-- ---------------------------------------------------------------- הרשאות ובידוד

GRANT SELECT, INSERT, UPDATE, DELETE ON trustee_settings TO safeme_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON trustees         TO safeme_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON trustee_requests TO safeme_app;

ALTER TABLE trustee_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE trustees         ENABLE ROW LEVEL SECURITY;
ALTER TABLE trustee_requests ENABLE ROW LEVEL SECURITY;

CREATE POLICY trustee_settings_isolation ON trustee_settings
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());

CREATE POLICY trustees_isolation ON trustees
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());

CREATE POLICY trustee_requests_isolation ON trustee_requests
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());
