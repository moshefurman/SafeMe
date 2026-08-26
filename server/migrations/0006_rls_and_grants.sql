-- ============================================================================
--  SafeMe · 0006 · בידוד דיירים (RLS) והרשאות
--
--  זו השכבה הראשונה מתוך השתיים שבסעיף 2.2. השנייה היא שכבת השירות.
--
--  הנחת יסוד קריטית: האפליקציה מתחברת כ-safeme_app, לעולם לא כ-safeme_owner.
--  RLS אינו חל על בעל הטבלה, ולכן חיבור כ-owner מבטל את כל הקובץ הזה.
--  אכיפה מעשית: מחרוזת החיבור של האפליקציה נבדקת בעליית התהליך
--  (ראה src/db/client.ts).
-- ============================================================================

-- BYPASSRLS הוא בדיוק מה שהשם אומר: תפקיד שמוגדר כך מתעלם מכל
-- מדיניות RLS. עבור משתמש האפליקציה זה היה מבטל את בידוד הדיירים
-- לחלוטין, בשקט.
--
-- ברירת המחדל לתפקיד חדש היא NOBYPASSRLS, ולכן ברוב המקרים אין מה
-- לעשות. הצהרה גורפת כאן הייתה דורשת superuser ונכשלת אצל כל ספק
-- מנוהל — עבור פעולה שאינה נחוצה.
--
-- לכן: בודקים, ומתקנים רק אם צריך. ואם צריך ואי אפשר — נכשלים.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'safeme_app' AND rolbypassrls) THEN
    BEGIN
      EXECUTE 'ALTER ROLE safeme_app NOBYPASSRLS';
    EXCEPTION
      WHEN insufficient_privilege THEN
        RAISE EXCEPTION
          'safeme_app מוגדר BYPASSRLS ואין הרשאה להסיר זאת. בידוד הדיירים לא ייאכף עליו.';
    END;
  END IF;
END
$$;

-- ---------------------------------------------------------------- הרשאות בסיס

GRANT SELECT, INSERT, UPDATE, DELETE ON
  tenants, licenses, users, verification_profiles, enroll_tokens,
  device_groups, devices, device_state, device_tokens,
  policies, device_policy_assignments, loosening_grants,
  events, alerts, quiet_windows, uninstall_requests
TO safeme_app;

-- טלמטריה וביקורת: כתיבה בלבד, ללא עדכון ומחיקה
GRANT SELECT, INSERT ON heartbeats TO safeme_app;
GRANT SELECT, INSERT ON audit_log  TO safeme_app;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM safeme_app;

-- קטלוג הספקים ומפתחות החתימה: קריאה לכולם, כתיבה דרך הפלטפורמה בלבד
GRANT SELECT ON providers, provider_history, signing_keys TO safeme_app;
GRANT INSERT, UPDATE ON providers, provider_history, signing_keys TO safeme_app;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO safeme_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO safeme_app;

-- ---------------------------------------------------------------- מדיניות RLS

-- הדייר עצמו
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenants_isolation ON tenants
  USING (app.is_platform() OR id = app.current_tenant())
  WITH CHECK (app.is_platform());

-- טבלאות שנושאות tenant_id ישירות. תבנית זהה לכולן.
DO $$
DECLARE
  t text;
  tables text[] := ARRAY[
    'licenses', 'users', 'verification_profiles', 'enroll_tokens',
    'device_groups', 'devices', 'device_state', 'device_tokens',
    'device_policy_assignments', 'loosening_grants',
    'heartbeats', 'events', 'alerts', 'quiet_windows', 'uninstall_requests'
  ];
BEGIN
  FOREACH t IN ARRAY tables LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);

    EXECUTE format($f$
      CREATE POLICY %1$I_isolation ON %1$I
        USING (app.is_platform() OR tenant_id = app.current_tenant())
        WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant())
    $f$, t);
  END LOOP;
END
$$;

-- מדיניות: תבניות גלובליות (tenant_id IS NULL) גלויות לכל דייר,
-- אך ניתנות לכתיבה על ידי הפלטפורמה בלבד.
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
CREATE POLICY policies_read ON policies FOR SELECT
  USING (app.is_platform() OR tenant_id = app.current_tenant() OR tenant_id IS NULL);

CREATE POLICY policies_write ON policies FOR INSERT
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());

CREATE POLICY policies_update ON policies FOR UPDATE
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());

-- יומן ביקורת: הדייר רואה את שלו, הפלטפורמה רואה הכול.
-- כתיבה מותרת תמיד, כדי שאפשר יהיה לתעד גם פעולות שנכשלו בבידוד.
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY audit_read ON audit_log FOR SELECT
  USING (app.is_platform() OR tenant_id = app.current_tenant());

CREATE POLICY audit_write ON audit_log FOR INSERT WITH CHECK (true);

-- קטלוג הספקים: קריאה לכולם. עריכה רק לפלטפורמה, ראה פרק 9.
ALTER TABLE providers ENABLE ROW LEVEL SECURITY;
CREATE POLICY providers_read ON providers FOR SELECT USING (true);
CREATE POLICY providers_write ON providers FOR INSERT WITH CHECK (app.is_platform());
CREATE POLICY providers_update ON providers FOR UPDATE
  USING (app.is_platform()) WITH CHECK (app.is_platform());

ALTER TABLE provider_history ENABLE ROW LEVEL SECURITY;
CREATE POLICY provider_history_read ON provider_history FOR SELECT
  USING (app.is_platform());
CREATE POLICY provider_history_write ON provider_history FOR INSERT
  WITH CHECK (app.is_platform());

-- מפתחות חתימה: החלק הציבורי נדרש לכל בקשה, לכן קריאה פתוחה.
ALTER TABLE signing_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY signing_keys_read ON signing_keys FOR SELECT USING (true);
CREATE POLICY signing_keys_write ON signing_keys FOR INSERT
  WITH CHECK (app.is_platform());
CREATE POLICY signing_keys_update ON signing_keys FOR UPDATE
  USING (app.is_platform()) WITH CHECK (app.is_platform());

-- ---------------------------------------------------------------- בדיקת שפיות
--
-- מאמת שלא נשארה טבלה עם נתוני דייר בלי RLS. נכשל בזמן המיגרציה,
-- ולא בזמן שדייר אחד רואה את הנתונים של אחר.

DO $$
DECLARE
  missing text;
BEGIN
  SELECT string_agg(c.relname, ', ')
    INTO missing
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id'
  WHERE n.nspname = 'public'
    AND c.relkind IN ('r', 'p')
    AND NOT c.relrowsecurity;

  IF missing IS NOT NULL THEN
    RAISE EXCEPTION 'טבלאות עם tenant_id ללא RLS: %', missing;
  END IF;
END
$$;
