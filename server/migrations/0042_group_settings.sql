-- ============================================================================
--  SafeMe · 0042 · הגדרות קבוצתיות
--
--  device_groups קיימת מ-0003 אבל רדומה. המיגרציה הזו מוסיפה טבלאות
--  הגדרות ברמת קבוצה — שעות חסימה ורשימה לבנה — שממוזגות לתוך שכבת
--  המחשב (device-overlay). קבוצה שמגדירה "אין אינטרנט אחרי 22:00"
--  מחילה את זה על כל מחשבי הקבוצה, בלי להגדיר כל אחד בנפרד.
--
--  הדפוס זהה ל-0024 (device_schedules) ו-0040 (device_whitelist):
--  הטבלאות שומרות כוונה, והמדיניות החתומה נגזרת מהן.
-- ============================================================================

-- device_groups כבר קיימת מ-0003, וה-RLS וה-GRANT שלה כבר הוחלו
-- (הטבלה שייכת ל-postgres ואינה ניתנת לשינוי מכאן).

-- ---------------------------------------------------------------- שעות חסימה לקבוצה

CREATE TABLE group_schedules (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  group_id   uuid NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

  days       smallint[] NOT NULL DEFAULT '{}',
  from_time  time NOT NULL,
  to_time    time NOT NULL,
  label      text,
  enabled    boolean NOT NULL DEFAULT true,

  created_at timestamptz NOT NULL DEFAULT now(),
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,

  CONSTRAINT group_schedule_has_length CHECK (from_time <> to_time),
  CONSTRAINT group_schedule_days_valid CHECK (
    days <@ ARRAY[0,1,2,3,4,5,6]::smallint[]
  )
);

CREATE INDEX group_schedules_group_idx ON group_schedules (group_id);

COMMENT ON TABLE group_schedules IS
  'שעות חסימה ברמת קבוצה. מבנה זהה ל-device_schedules. ממוזג לשכבת המחשב.';

-- ---------------------------------------------------------------- רשימה לבנה לקבוצה

CREATE TABLE group_whitelist (
  group_id   uuid PRIMARY KEY REFERENCES device_groups(id) ON DELETE CASCADE,
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

  enabled    boolean NOT NULL DEFAULT false,

  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid REFERENCES users(id) ON DELETE SET NULL
);

COMMENT ON TABLE group_whitelist IS
  'רשימה לבנה ברמת קבוצה: האם פעילה. ממוזגת לשכבת המחשב.';

-- ---------------------------------------------------------------- אתרים מאושרים לקבוצה

CREATE TABLE group_whitelist_domains (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  group_id   uuid NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

  domain     text NOT NULL,
  source     text NOT NULL DEFAULT 'manual',

  created_at timestamptz NOT NULL DEFAULT now(),
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,

  CONSTRAINT group_whitelist_domain_unique UNIQUE (group_id, domain),
  CONSTRAINT group_whitelist_domain_shape CHECK (
    domain = lower(domain)
    AND length(domain) BETWEEN 3 AND 253
    AND domain ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
  ),
  CONSTRAINT group_whitelist_domain_source CHECK (source IN ('manual', 'learned'))
);

COMMENT ON TABLE group_whitelist_domains IS
  'אתרים מאושרים ברמת קבוצה. מבנה זהה ל-device_whitelist_domains.';

-- ---------------------------------------------------------------- הרשאות ובידוד

GRANT SELECT, INSERT, UPDATE, DELETE ON group_schedules          TO safeme_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON group_whitelist          TO safeme_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON group_whitelist_domains  TO safeme_app;

ALTER TABLE group_schedules          ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_whitelist          ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_whitelist_domains  ENABLE ROW LEVEL SECURITY;

CREATE POLICY group_schedules_isolation ON group_schedules
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());

CREATE POLICY group_whitelist_isolation ON group_whitelist
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());

CREATE POLICY group_whitelist_domains_isolation ON group_whitelist_domains
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());
