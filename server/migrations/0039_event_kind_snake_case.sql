-- ============================================================================
--  SafeMe · 0039 · שם אירוע חבלה בצורה אחת
--
--  הסוכן שולח את סוג אירוע החבלה ב-camelCase ("trayAppKilled"), השרת
--  דירג לפי רשימות ב-PascalCase, והפורטל תרגם לפי snake_case. שום
--  השוואה לא התאימה: כל אירוע נשמר כ-"אזהרה", אירוע מידע העיר הורה
--  במייל עם שם באנגלית, והפורטל הציג שמות גולמיים.
--
--  מעתה השרת מנרמל ל-snake_case בקליטה, כמו שאר העמודות. השורות
--  שכבר נשמרו מומרות כאן באותו כלל, והחומרה שלהן נקבעת מחדש לפי
--  הסוג — אותו מיפוי כמו ב-telemetry/severity.ts.
--
--  סוגים שאינם חבלה ("device.silent", "network.new", "audit.report")
--  אינם מכילים אות גדולה ואינם נוגעים.
-- ============================================================================

UPDATE events
   SET kind = lower(regexp_replace(kind, '([a-z0-9])([A-Z])', '\1_\2', 'g'))
 WHERE kind ~ '[A-Z]';

UPDATE events
   SET severity = CASE
     WHEN kind IN ('coverage_gap', 'wfp_filters_missing', 'policy_signature_invalid',
                   'state_file_missing', 'state_file_tampered', 'clock_rolled_back',
                   'offline_expiry_near') THEN 'critical'
     WHEN kind IN ('tray_app_killed', 'service_crash') THEN 'info'
     ELSE 'warning'
   END
 WHERE kind IN ('coverage_gap', 'wfp_filters_missing', 'policy_signature_invalid',
                'state_file_missing', 'state_file_tampered', 'clock_rolled_back',
                'offline_expiry_near', 'tray_app_killed', 'service_crash',
                'service_stop_attempt', 'uninstall_brute_force', 'bfe_unavailable',
                'promotion_attempted');
