-- ============================================================================
--  SafeMe · 0040 · רשימה לבנה לכל מחשב
--
--  מצב שבו המחשב גולש רק לאתרים שההורה אישר. כל השאר אינו נפתח —
--  לא כי זוהה כמזיק, אלא כי איש לא אמר שהוא מותר.
--
--  הקושי הוא שאתר אחד נטען מעשרות שמות: תמונות משם אחד, גופנים
--  משני, כניסה משלישי. הורה שיאשר רק את מה שכתוב בשורת הכתובת
--  יקבל דף שבור. לכן יש "מצב למידה": חלון זמן קצוב שבו הסוכן רושם
--  כל שם שהמחשב ביקש, וההורה בוחר מתוך מה שנצפה.
--
--  כמו בחלונות הזמן (0024), הטבלאות שומרות את הכוונה של ההורה,
--  והמדיניות החתומה נגזרת מהן ומתפרסמת מחדש בכל שינוי.
-- ============================================================================

/*
 * ערך חדש למצב המחשב.
 *
 * מחשב ברשימה לבנה אינו "מסונן על ידי ספק" ואינו "לא מסונן": הוא
 * מוגן בדרך אחרת, והצגתו באדום הייתה מבהילה הורה שעשה בדיוק את
 * הדבר המחמיר ביותר שהמוצר מציע.
 *
 * ADD VALUE רץ כאן בתוך הטרנזקציה של המיגרציה, וזה מותר מאז
 * PostgreSQL 12 — כל עוד הערך החדש אינו בשימוש באותה טרנזקציה.
 * לכן שום דבר בהמשך הקובץ אינו כותב אותו. תקדים: 0015, 0028.
 */
ALTER TYPE security_status ADD VALUE IF NOT EXISTS 'whitelist';

-- ---------------------------------------------------------------- הגדרה

CREATE TABLE device_whitelist (
  device_id  uuid PRIMARY KEY,
  tenant_id  uuid NOT NULL,

  enabled    boolean NOT NULL DEFAULT false,

  /*
   * סוף חלון הלמידה. NULL או זמן שעבר פירושם שאין למידה.
   *
   * זמן מוחלט ולא "דולק/כבוי": הסוכן מושך מדיניות אחת לכמה דקות
   * ואינו מקבל דחיפות, ולכן כיבוי שתלוי בהודעה נוספת היה משאיר
   * מחשב פתוח עד שההודעה תגיע — או לנצח, אם לא תגיע. עם זמן חתום
   * בתוך המדיניות הסוכן מפסיק לבד.
   *
   * הלמידה אינה תלויה ב-enabled. הורה רשאי ללמוד קודם ולהפעיל
   * אחר כך, וזה הסדר ההגיוני: אחרת ההפעלה שוברת את כל האתרים
   * עד שהלמידה מסתיימת.
   */
  learning_until      timestamptz,
  learning_started_at timestamptz,

  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid REFERENCES users(id) ON DELETE SET NULL,

  FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE
);

COMMENT ON TABLE device_whitelist IS
  'רשימה לבנה למחשב: האם פעילה, ועד מתי נמשכת הלמידה. המדיניות החתומה נגזרת מכאן.';

-- ---------------------------------------------------------------- אתרים מאושרים

CREATE TABLE device_whitelist_domains (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id  uuid NOT NULL,
  tenant_id  uuid NOT NULL,

  /*
   * שם מתחם בלבד: אותיות קטנות, בלי סכימה, נתיב, פורט או כוכבית.
   *
   * רשומה מתירה את עצמה ואת כל תת־המתחמים שלה, ולכן אין צורך
   * בכוכבית — והיעדרה חוסך שאלה שאין לה תשובה אחת ("האם ‎*.x
   * כולל את x עצמו?").
   *
   * האילוץ כאן הוא רשת ביטחון ולא הבדיקה. הנרמול נעשה בשרת
   * (policy/whitelist.ts), ושורה שעקפה אותו הייתה נחתמת למדיניות
   * ונשלחת לסוכן בצורה שהוא אינו מצפה לה.
   */
  domain     text NOT NULL,

  /* 'manual' הוקלד ביד, 'learned' סומן מתוך מה שנצפה בלמידה. */
  source     text NOT NULL DEFAULT 'manual',

  created_at timestamptz NOT NULL DEFAULT now(),
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,

  FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE,

  CONSTRAINT whitelist_domain_unique UNIQUE (device_id, domain),
  CONSTRAINT whitelist_domain_shape CHECK (
    domain = lower(domain)
    AND length(domain) BETWEEN 3 AND 253
    AND domain ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
  ),
  CONSTRAINT whitelist_domain_source CHECK (source IN ('manual', 'learned'))
);

COMMENT ON TABLE device_whitelist_domains IS
  'האתרים שהמחשב רשאי לגלוש אליהם במצב רשימה לבנה. כל רשומה כוללת את תת־המתחמים שלה.';

-- ---------------------------------------------------------------- מה שנצפה בלמידה

CREATE TABLE device_whitelist_observed (
  device_id  uuid NOT NULL,
  tenant_id  uuid NOT NULL,
  domain     text NOT NULL,

  hits          bigint NOT NULL DEFAULT 0,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at  timestamptz NOT NULL DEFAULT now(),

  /* ההורה הסיר מהרשימה. השורה נשארת כדי שלא תצוץ שוב בדיווח הבא. */
  dismissed  boolean NOT NULL DEFAULT false,

  /*
   * מה אמרה בדיקת התוכן, אם נעשתה.
   *
   * הבדיקה החיה נעשית ברגע האישור ולא ברגע התצוגה — מאות שאילתות
   * החוצה בכל פתיחת מסך הן לא משהו שרוצים. התוצאה נשמרת כאן כדי
   * שאתר שנדחה פעם יוצג כחסום גם בפעם הבאה, ולא יחזור להיראות
   * כמו משהו שאפשר לאשר.
   */
  verdict    text,
  checked_at timestamptz,

  PRIMARY KEY (device_id, domain),
  FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE,

  CONSTRAINT whitelist_observed_verdict CHECK (verdict IS NULL OR verdict IN ('ok', 'blocked')),
  CONSTRAINT whitelist_observed_shape CHECK (
    domain = lower(domain) AND length(domain) BETWEEN 1 AND 253
  )
);

COMMENT ON TABLE device_whitelist_observed IS
  'שמות שהמחשב ביקש בזמן למידה. חומר גלם לבחירת ההורה, לא רשימת היתר.';

-- ---------------------------------------------------------------- הרשאות ובידוד

/*
 * בדיוק הדפוס של 0024, ובכוונה מועתק ולא נכתב מחדש.
 *
 * 0029 שכחה את ה-GRANT (ALTER DEFAULT PRIVILEGES מכסה רצפים בלבד,
 * לא טבלאות) וכתבה את תנאי ה-RLS ביד עם שם הגדרה שאינו קיים, בלי
 * WITH CHECK ובלי ענף הפלטפורמה. שלוש טעויות, ושתי מיגרציות תיקון
 * (0030, 0031). כאן שלושתן במקומן מההתחלה.
 */
GRANT SELECT, INSERT, UPDATE, DELETE ON device_whitelist          TO safeme_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON device_whitelist_domains  TO safeme_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON device_whitelist_observed TO safeme_app;

ALTER TABLE device_whitelist          ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_whitelist_domains  ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_whitelist_observed ENABLE ROW LEVEL SECURITY;

CREATE POLICY device_whitelist_isolation ON device_whitelist
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());

CREATE POLICY device_whitelist_domains_isolation ON device_whitelist_domains
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());

CREATE POLICY device_whitelist_observed_isolation ON device_whitelist_observed
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());
