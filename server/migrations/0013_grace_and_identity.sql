-- ============================================================================
--  SafeMe · 0013 · תקופת חסד וזהות לאימות הסרה
--
--  שתי החלטות מוצר שהתקבלו יחד:
--
--  1. אחרי 30 יום יש שבוע חסד. מי ששכח לשלם אינו נופל מצוק, וההגנה
--     ממשיכה לפעול לאורך כל התקופה.
--
--  2. אימות בקשת הסרה בתקופת הניסיון מבוסס על 4 ספרות תעודת זהות
--     וקישור אישור למייל, כי אין אשראי להשוות מולו.
--
--     המסקנה המחייבת: את 4 הספרות חייבים לאסוף **בהרשמה**. אי אפשר
--     לבקש אותן בזמן ההסרה, כי אז אין מול מה להשוות ו"האימות" היה
--     בסך הכול בקשה להקליד ארבע ספרות כלשהן.
-- ============================================================================

ALTER TABLE tenants
  ADD COLUMN grace_days integer NOT NULL DEFAULT 7
    CHECK (grace_days >= 0 AND grace_days <= 30);

COMMENT ON COLUMN tenants.grace_days IS
  'ימי חסד אחרי סוף הניסיון. ההגנה ממשיכה לפעול לאורך כל התקופה.';

-- ---------------------------------------------------------------- אסימוני הסרה
--
-- קישור האישור שנשלח למייל בעת בקשת הסרה. נפרד מ-uninstall_requests
-- כי הוא נוצר לפני שיש אתגר מהמכשיר: המשתמש מבקש מהפורטל, מאשר
-- במייל, ורק אז מקבל קוד.

CREATE TABLE uninstall_approvals (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  device_id      uuid,

  requested_by   uuid REFERENCES users(id) ON DELETE SET NULL,
  requested_at   timestamptz NOT NULL DEFAULT now(),

  -- אימות זהות: 4 ספרות ת"ז שנקלטו בהרשמה
  id_verified    boolean NOT NULL DEFAULT false,
  id_attempts    int NOT NULL DEFAULT 0 CHECK (id_attempts <= 3),

  -- קישור האישור. נשמר כ-hash, כמו כל אסימון אחר במערכת.
  approval_hash  bytea NOT NULL,
  approved_at    timestamptz,
  expires_at     timestamptz NOT NULL DEFAULT now() + interval '24 hours',

  -- חלון הצינון מ-7.5 חל גם כאן
  effective_at   timestamptz,
  cancelled_at   timestamptz,

  status         text NOT NULL DEFAULT 'pending',

  CONSTRAINT approval_needs_identity CHECK (
    approved_at IS NULL OR id_verified
  )
);

CREATE INDEX uninstall_approvals_tenant_idx ON uninstall_approvals (tenant_id, requested_at DESC);
CREATE INDEX uninstall_approvals_hash_idx   ON uninstall_approvals (approval_hash)
  WHERE status = 'pending';

GRANT SELECT, INSERT, UPDATE ON uninstall_approvals TO safeme_app;

ALTER TABLE uninstall_approvals ENABLE ROW LEVEL SECURITY;

CREATE POLICY uninstall_approvals_isolation ON uninstall_approvals
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());

COMMENT ON TABLE uninstall_approvals IS
  'אישור הסרה לחשבון ללא אשראי: 4 ספרות ת"ז + קישור אישור למייל.';

-- ---------------------------------------------------------------- אימות מבני

DO $$
BEGIN
  -- אותו איסור כמו ב-verification_profiles: אין לשמור ת"ז מלאה
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'uninstall_approvals'
      AND column_name ~* '(id_number|full_id|pan|card_number)'
  ) THEN
    RAISE EXCEPTION 'uninstall_approvals אינה רשאית להחזיק מספר זהות מלא';
  END IF;
END
$$;
