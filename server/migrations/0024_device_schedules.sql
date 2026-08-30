-- ============================================================================
--  SafeMe · 0024 · חלונות זמן לכל מחשב
--
--  לסוכן כבר היה מנגנון: ScheduleRule עם ימים ושעות, ובודק האכיפה
--  שמכריע לפיו. מה שלא היה הוא דרך להגדיר אותו — הכללים הגיעו רק
--  בתוך מדיניות שנכתבה ביד.
--
--  הטבלה שומרת את הכוונה של ההורה. המדיניות החתומה נגזרת ממנה
--  ומתפרסמת מחדש בכל שינוי, ולכן היא אינה מקור האמת אלא תוצר.
--  זה מה שמאפשר לערוך חלון בלי לגעת בחתימה, ולבנות אותה מחדש בכל
--  רגע ממה שנשמר.
-- ============================================================================

CREATE TABLE device_schedules (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id  uuid NOT NULL,
  tenant_id  uuid NOT NULL,

  /*
   * ימי השבוע שבהם החלון פעיל, לפי DayOfWeek של .NET:
   * 0 ראשון עד 6 שבת.
   *
   * מערך ריק פירושו כל ימות השבוע, וזה מה שהסוכן כבר עושה —
   * ScheduleRule מדלג על בדיקת היום כשהרשימה ריקה.
   */
  days       smallint[] NOT NULL DEFAULT '{}',

  /*
   * שעון מקומי של המחשב, לא UTC.
   *
   * הורה שאומר "אין אינטרנט אחרי עשר" מתכוון לעשר אצלו, ומחשב
   * שנוסע לחו"ל צריך להמשיך להיחסם בעשר המקומית שלו. המרה ל-UTC
   * הייתה הופכת את הכלל למשהו אחר בכל אזור זמן.
   */
  from_time  time NOT NULL,
  to_time    time NOT NULL,

  label      text,
  enabled    boolean NOT NULL DEFAULT true,

  created_at timestamptz NOT NULL DEFAULT now(),
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,

  FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE,

  /*
   * חלון שמתחיל ונגמר באותה שעה אינו חוסם דבר — או חוסם הכול,
   * תלוי בפירוש. שני פירושים לאותה שורה הם שורה שלא נבדקה.
   */
  CONSTRAINT schedule_has_length CHECK (from_time <> to_time),

  CONSTRAINT schedule_days_valid CHECK (
    days <@ ARRAY[0,1,2,3,4,5,6]::smallint[]
  )
);

CREATE INDEX device_schedules_device_idx ON device_schedules (device_id);

COMMENT ON TABLE device_schedules IS
  'חלונות זמן שבהם המחשב חסום. שעון מקומי. המדיניות החתומה נגזרת מכאן.';

GRANT SELECT, INSERT, UPDATE, DELETE ON device_schedules TO safeme_app;

ALTER TABLE device_schedules ENABLE ROW LEVEL SECURITY;

CREATE POLICY device_schedules_isolation ON device_schedules
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());
