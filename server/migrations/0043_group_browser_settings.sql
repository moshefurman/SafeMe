-- ============================================================================
--  SafeMe · 0043 · הגדרות דפדפן ברמת קבוצה
--
--  מאפשרת להגדיר יוטיוב שמע בלבד, הסתרת תמונות, ערוצים מותרים,
--  סינון תמונות AI ומילים חסומות — ברמת קבוצה, ולא רק ברמת הדייר.
--
--  ההגדרות נשמרות כ-JSONB כדי שהוספת שדה חדש לא תדרוש מיגרציה.
--  המבנה זהה לזה שב-enforcement.browser במדיניות:
--  { youtubeAudioOnly, youtubeHideThumbnails, youtubeAllowedChannels,
--    aiSafeMode, aiBlockedKeywords }
-- ============================================================================

CREATE TABLE group_browser_settings (
  group_id    uuid PRIMARY KEY REFERENCES device_groups(id) ON DELETE CASCADE,
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

  settings    jsonb NOT NULL DEFAULT '{}',

  updated_at  timestamptz NOT NULL DEFAULT now(),
  updated_by  uuid REFERENCES users(id) ON DELETE SET NULL
);

COMMENT ON TABLE group_browser_settings IS
  'הגדרות דפדפן (יוטיוב, AI) ברמת קבוצה. דורסות את הגדרות הדייר עבור מחשבי הקבוצה.';

GRANT SELECT, INSERT, UPDATE, DELETE ON group_browser_settings TO safeme_app;

ALTER TABLE group_browser_settings ENABLE ROW LEVEL SECURITY;

CREATE POLICY group_browser_settings_isolation ON group_browser_settings
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());
