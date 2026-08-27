-- ============================================================================
--  SafeMe · 0017 · רשימה שחורה של רשתות
--
--  חסימה של רשת בודדת כבר קיימת: known_networks.approval = 'blocked'.
--  מה שחסר הוא חסימה של רשת ש**טרם נראתה**.
--
--  הורה שיודע שהשכן משאיר רשת פתוחה, או שאינו רוצה שום רשת אלחוטית
--  לא מסוננת לעולם, אינו יכול לחסום אותה מראש — הוא חייב לחכות שהילד
--  יתחבר, ורק אז לחסום. הכלל כאן הופך את הסדר: החסימה קודמת לחיבור.
--
--  ובמכוון זו רשימה של **כללים** ולא של רשתות. רשימה של שמות ספציפיים
--  היא בדיוק אותה בעיה של רשימת כלי העקיפה — היא נכתבת אחרי שכבר
--  התחברו, ומפגרת אחרי הרשת הבאה.
-- ============================================================================

CREATE TYPE block_rule_kind AS ENUM (
  -- תבנית בשם הרשת. תומכת בכוכבית: "*אורח*", "Free*"
  'ssid',

  -- טווח כתובות של השער. תופס נתב מסוים גם כששמו משתנה.
  'gateway',

  -- קטגוריה שנגזרת ממה שהסוכן כבר מודד ממילא
  'category'
);

CREATE TABLE network_block_rules (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

  kind        block_rule_kind NOT NULL,

  /*
   * מה להשוות.
   *
   * ל-ssid    — תבנית עם כוכבית
   * ל-gateway — טווח CIDR
   * ל-category — אחד מ: open, hotspot, unfiltered
   */
  pattern     text NOT NULL CHECK (length(btrim(pattern)) > 0),

  /* למה. מוצג להורה כשרשת נחסמת, ולכן הוא כותב אותו בעצמו. */
  note        text,

  enabled     boolean NOT NULL DEFAULT true,

  created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),

  /* כמה פעמים הכלל תפס. מראה להורה מה עובד ומה סתם יושב שם. */
  hit_count   int NOT NULL DEFAULT 0,
  last_hit_at timestamptz,

  -- אותו כלל פעמיים אינו שגיאה חמורה, אבל הוא מבלבל בתצוגה
  UNIQUE (tenant_id, kind, pattern)
);

CREATE INDEX network_block_rules_tenant_idx
  ON network_block_rules (tenant_id) WHERE enabled;

COMMENT ON TABLE network_block_rules IS
  'כללי חסימה שחלים גם על רשתות שטרם נראו.';

-- ---------------------------------------------------------------- הרשאות

GRANT SELECT, INSERT, UPDATE, DELETE ON network_block_rules TO safeme_app;

ALTER TABLE network_block_rules ENABLE ROW LEVEL SECURITY;

CREATE POLICY network_block_rules_isolation ON network_block_rules
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());

-- ---------------------------------------------------------------- מקור החסימה
--
-- רשת שנחסמה בגלל כלל נראית זהה לרשת שההורה חסם ידנית, ואינה זהה:
-- הראשונה משתחררת כשמבטלים את הכלל, והשנייה לא. בלי ההבחנה הזו
-- ההורה מבטל כלל ולא מבין למה הרשת עדיין חסומה.

ALTER TABLE known_networks
  ADD COLUMN blocked_by_rule uuid REFERENCES network_block_rules(id) ON DELETE SET NULL;

COMMENT ON COLUMN known_networks.blocked_by_rule IS
  'הכלל שגרם לחסימה. NULL = החלטה ידנית של ההורה.';
