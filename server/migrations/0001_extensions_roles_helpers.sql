-- ============================================================================
--  SafeMe · 0001 · הרחבות, תפקידים ופונקציות עזר
--
--  מריצים כמשתמש בעל הרשאות superuser או owner על בסיס הנתונים.
--  קובץ זה מגדיר את שני התפקידים שכל שאר המערכת נשענת עליהם:
--
--    safeme_owner  — בעל הסכמה. מריץ מיגרציות. RLS אינו חל עליו.
--    safeme_app    — משתמש האפליקציה. RLS נאכף עליו בכפייה.
--
--  ההפרדה הזו היא תנאי לבידוד הדיירים. אם האפליקציה תתחבר כ-owner,
--  כל מדיניות ה-RLS במסמך הופכת לקישוט.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid, digest
CREATE EXTENSION IF NOT EXISTS "citext";     -- כתובות מייל ללא תלות ברישיות

-- ---------------------------------------------------------------- תפקידים

-- אסור בתכלית האיסור שמיגרציות ירוצו כמשתמש האפליקציה: כל הטבלאות
-- היו נוצרות בבעלותו, RLS לא היה חל עליו, וכל דייר היה רואה את
-- הנתונים של כולם. בלי שום שגיאה שתסגיר זאת.
DO $$
BEGIN
  IF current_user = 'safeme_app' THEN
    RAISE EXCEPTION 'אין להריץ מיגרציות כ-safeme_app. RLS אינו חל על בעל הטבלה.';
  END IF;
END
$$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'safeme_app') THEN
    CREATE ROLE safeme_app LOGIN;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'safeme_owner') THEN
    CREATE ROLE safeme_owner LOGIN;
  END IF;
END
$$;

-- הסיסמאות נקבעות בפריסה, לא כאן:
--   ALTER ROLE safeme_app   WITH PASSWORD '...';
--   ALTER ROLE safeme_owner WITH PASSWORD '...';

-- ---------------------------------------------------------------- הסכמה
--
-- CREATE SCHEMA ... AUTHORIZATION דורש שהמשתמש המריץ יוכל לעשות
-- SET ROLE לתפקיד היעד. אצל ספק מנוהל זה לרוב לא מתקיים: המשתמש
-- שניתן לך יכול ליצור תפקידים, ומקבל עליהם ADMIN, אך לא בהכרח SET.
-- הבחנה זו השתנתה בין גרסאות Postgres.
--
-- לכן לא מנסים לחזות את ההרשאה אלא פשוט מנסים ונופלים אחורה. זה
-- גם עמיד יותר: מודל ההרשאות ימשיך להשתנות בין גרסאות ובין ספקים.
--
-- והנפילה אחורה בטוחה, כי הבעלות עצמה אינה מה שמגן. מה שמגן הוא
-- ש-safeme_app **אינו** הבעלים ו-RLS נאכף עליו. מי שמריץ מיגרציות
-- הופך לבעלים ממילא, ובכל מסלול הוא אינו משתמש האפליקציה — וזה
-- נאכף בראש הקובץ.

DO $$
BEGIN
  BEGIN
    EXECUTE 'CREATE SCHEMA IF NOT EXISTS app AUTHORIZATION safeme_owner';
  EXCEPTION
    WHEN insufficient_privilege OR invalid_grant_operation THEN
      EXECUTE 'CREATE SCHEMA IF NOT EXISTS app';
      RAISE NOTICE
        'הסכמה app נוצרה בבעלות % ולא safeme_owner. זה תקין אצל ספק מנוהל.',
        current_user;
  END;
END
$$;

GRANT USAGE ON SCHEMA public, app TO safeme_app;

-- ---------------------------------------------------------------- הקשר הבקשה
--
-- כל טרנזקציה של האפליקציה מצהירה מי היא, באמצעות שני משתני סשן:
--
--   app.tenant_id  — מזהה הדייר שהבקשה פועלת בשמו
--   app.platform   — 'on' כאשר הפועל הוא משתמש פלטפורמה (צוות החברה)
--
-- שניהם נקבעים ב-SET LOCAL ולכן פגים בסוף הטרנזקציה. זה מכוון:
-- חיבור שחוזר ל-pool לא יכול לגרור הקשר של בקשה קודמת.

CREATE OR REPLACE FUNCTION app.current_tenant() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid;
$$;

CREATE OR REPLACE FUNCTION app.is_platform() RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT COALESCE(current_setting('app.platform', true), 'off') = 'on';
$$;

-- שימו לב לסמנטיקה: אם app.tenant_id לא הוגדר, current_tenant() מחזירה NULL,
-- וכל השוואה מולה מחזירה NULL, כלומר "לא מורשה". ברירת המחדל היא דחייה.

COMMENT ON FUNCTION app.current_tenant() IS
  'מזהה הדייר של הבקשה הנוכחית. NULL כאשר לא הוגדר, ואז RLS דוחה הכול.';

COMMENT ON FUNCTION app.is_platform() IS
  'האם הבקשה מבוצעת על ידי משתמש פלטפורמה. מדלג על בידוד הדיירים.';
