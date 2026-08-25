-- ============================================================================
--  SafeMe · 0010 · פקודות למכשיר
--
--  הצנרת שהייתה חסרה: הפורטל יוצר פקודה, והמכשיר אוסף אותה בפעימה
--  הבאה. אין חיבור מתמיד ואין דחיפה — מכשיר שכבוי פשוט יאסוף כשיחזור.
--
--  שני כללים מהאפיון מעוגנים כאן במבנה ולא רק בקוד:
--    * לכל נעילה יש זמן סיום (3.2.2 בסוכן), ולכן minutes הוא שדה חובה
--      עם טווח, ולא פרמטר חופשי.
--    * פקודה שלא נאספה תוך זמן סביר פגה, כדי שמכשיר שחוזר אחרי שבוע
--      לא ייחסם פתאום בגלל בקשה ישנה ששכחו ממנה.
-- ============================================================================

CREATE TYPE command_status AS ENUM ('pending', 'delivered', 'acked', 'expired', 'cancelled');

CREATE TYPE command_type AS ENUM ('lockout', 'release_lockout', 'run_audit', 'refresh_policy');

CREATE TABLE device_commands (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id    uuid NOT NULL,
  tenant_id    uuid NOT NULL,

  type         command_type NOT NULL,
  args         jsonb NOT NULL DEFAULT '{}'::jsonb,
  reason       text,

  status       command_status NOT NULL DEFAULT 'pending',
  created_by   uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz,
  acked_at     timestamptz,
  expires_at   timestamptz NOT NULL DEFAULT now() + interval '24 hours',

  FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE,

  -- נעילה חייבת משך מפורש בטווח שפוי. ראה 3.2.2 באפיון הסוכן.
  CONSTRAINT command_lockout_has_duration CHECK (
    type <> 'lockout' OR (
      (args->>'minutes') ~ '^[0-9]+$' AND
      (args->>'minutes')::int BETWEEN 1 AND 1440
    )
  )
);

CREATE INDEX device_commands_pending_idx
  ON device_commands (device_id, created_at)
  WHERE status = 'pending';

CREATE INDEX device_commands_tenant_idx ON device_commands (tenant_id, created_at DESC);

COMMENT ON TABLE device_commands IS
  'תור פקודות לאיסוף בפעימה. אין דחיפה למכשיר ואין חיבור מתמיד.';

-- ---------------------------------------------------------------- פקיעה

/*
 * מסמן פקודות שלא נאספו בזמן. נקרא מהמשימה המתוזמנת, וגם בכל
 * איסוף — כדי שמכשיר שחוזר אחרי שבוע לא יקבל בקשה ישנה.
 */
CREATE OR REPLACE FUNCTION app.expire_stale_commands()
RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
  affected integer;
BEGIN
  UPDATE device_commands
     SET status = 'expired'
   WHERE status = 'pending' AND expires_at <= now();

  GET DIAGNOSTICS affected = ROW_COUNT;

  RETURN affected;
END
$$;

-- ---------------------------------------------------------------- הרשאות

GRANT SELECT, INSERT, UPDATE ON device_commands TO safeme_app;

ALTER TABLE device_commands ENABLE ROW LEVEL SECURITY;

CREATE POLICY device_commands_isolation ON device_commands
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());
