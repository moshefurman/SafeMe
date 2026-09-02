/*
 * יכולות שנקנות, וקרדיט לשינויים.
 *
 * שני מנגנונים נפרדים שמשרתים את אותה מטרה: להפוך "מה מותר לחשבון
 * הזה" לנתון, ולא לקוד.
 *
 * ---
 *
 * יכולות על התוכנית, ומועתקות למנוי.
 *
 * אותו היגיון כמו המחיר ומגבלת המחשבים: לקוח שקנה תוכנית שכללה
 * הגדרה לכל מחשב ממשיך לקבל אותה גם אם התוכנית שונתה. קריאה
 * מהתוכנית בכל בדיקה הייתה שוללת יכולת מלקוח קיים בשקט.
 */

ALTER TABLE plans
  /*
   * מערך שמות, ולא עמודה לכל יכולת.
   *
   * יכולת חדשה היא החלטה עסקית שתקרה שוב ושוב, ועמודה לכל אחת
   * פירושה מיגרציה בכל פעם. מערך מאבד אימות טיפוסים במסד, וזה
   * המחיר — הקוד מאמת מול רשימה סגורה.
   */
  ADD COLUMN features text[] NOT NULL DEFAULT '{}';

ALTER TABLE subscriptions
  ADD COLUMN features text[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN plans.features IS
  'יכולות שהתוכנית כוללת. per_device_policy = הגדרה נפרדת לכל מחשב.';

COMMENT ON COLUMN subscriptions.features IS
  'היכולות כפי שנמכרו. אינן נקראות מהתוכנית, כדי שעדכון מחירון לא ישלול.';

-- ---------------------------------------------------------------- קרדיט

/*
 * קרדיט לשינויים.
 *
 * חלק מהשינויים במערכת עולים כסף — הורדת רצפת המדיניות, שינוי
 * הגדרת ההסרה — כי הם דורשים אדם מהמוקד שיוודא שמי שמבקש הוא
 * באמת בעל החשבון.
 *
 * אבל לגבות על כל שינוי הופך כל טעות קטנה לשיחת טלפון משלמת, וזה
 * מרגיז לקוח שלא עשה דבר רע. קרדיט פותר את שניהם: כמה שינויים
 * ראשונים כלולים, ומעבר להם משלמים.
 *
 * ---
 *
 * ספר תנועות ולא מונה.
 *
 * מונה יחיד עונה "כמה נשאר" ואינו עונה "למה". כשלקוח יטען שלא
 * ביקש שינוי, או שנגבו ממנו פעמיים, הספר הוא התשובה — והוא גם מה
 * שמאפשר לתקן טעות בלי לנחש מה היה הערך הקודם.
 */
CREATE TABLE credit_entries (
  id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

  /*
   * חיובי = הוספה, שלילי = צריכה.
   *
   * שתי עמודות נפרדות היו מחייבות לזכור בכל שאילתה לחסר אחת
   * מהשנייה, וסכום פשוט הוא מה שהופך את היתרה לשאילתה אחת.
   */
  amount int NOT NULL CHECK (amount <> 0),

  /* מה נעשה. טקסט חופשי מוגבל, כי הרשימה תגדל. */
  reason text NOT NULL,

  /* מי — מנהל פלטפורמה שהוסיף, או NULL כשהמערכת צרכה. */
  actor_id uuid REFERENCES users(id) ON DELETE SET NULL,

  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX credit_entries_tenant_idx ON credit_entries (tenant_id, created_at DESC);

ALTER TABLE credit_entries ENABLE ROW LEVEL SECURITY;

CREATE POLICY credit_entries_isolation ON credit_entries
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());

/*
 * צריכה נעשית על ידי השרת, והוספה על ידי מנהל פלטפורמה בלבד.
 * לאפליקציה אין UPDATE ואין DELETE: תנועה שנרשמה אינה משתנה,
 * ותיקון נעשה בתנועה נגדית. ספר שאפשר לערוך אינו ספר.
 */
GRANT SELECT, INSERT ON credit_entries TO safeme_app;

-- ---------------------------------------------------------------- רשת למחשב

/*
 * רשת שאושרה למחשב אחד, ולא לכל החשבון.
 *
 * היום אישור רשת חל על כל המחשבים: הורה שמאשר את הרשת בבית של
 * סבתא מאשר אותה גם לילד השני. במשפחה אחת זה נוח; בארגון, או
 * במשפחה שרוצה הגדרה שונה לכל ילד, זה בדיוק ההפך.
 *
 * NULL הוא ברירת המחדל ופירושו "כל החשבון" — כך שכל הרשתות
 * הקיימות ממשיכות להתנהג כפי שהתנהגו, ומי שלא קנה את היכולת
 * אינו רואה שינוי.
 */
ALTER TABLE known_networks
  ADD COLUMN device_id uuid REFERENCES devices(id) ON DELETE CASCADE;

/*
 * הייחודיות מתחשבת במחשב.
 *
 * אותה רשת יכולה להופיע פעם אחת ברמת החשבון ופעם לכל מחשב שיש לו
 * הכרעה משלו. בלי זה, אישור למחשב אחד היה מתנגש באישור הכללי.
 *
 * COALESCE ולא NULLS NOT DISTINCT: תמיכה בו תלויה בגרסת המסד,
 * ומזהה קבוע עושה את אותו דבר בכל גרסה.
 */
/*
 * האילוץ הישן הוא UNIQUE ברמת הטבלה, לא אינדקס עצמאי.
 *
 * DROP INDEX לא היה תופס אותו, וההוספה של האינדקס החדש הייתה
 * מצליחה בזמן שהאילוץ הישן ממשיך לחסום — כלומר הרשת למחשב הייתה
 * נדחית על התנגשות שאיש לא היה מבין מאיפה היא.
 *
 * DO ולא שם קבוע: השם נוצר על ידי המסד, ופריסה שהתקינה את הסכמה
 * בדרך אחרת עשויה לשאת שם אחר. חיפוש לפי העמודות מוצא אותו בכל
 * מקרה.
 */
DO $$
DECLARE
  constraint_name text;
BEGIN
  SELECT c.conname INTO constraint_name
    FROM pg_constraint c
    JOIN pg_class t ON t.oid = c.conrelid
   WHERE t.relname = 'known_networks'
     AND c.contype = 'u'
     AND c.conkey = ARRAY(
       SELECT a.attnum FROM pg_attribute a
        WHERE a.attrelid = t.oid AND a.attname IN ('tenant_id', 'fingerprint')
        ORDER BY a.attnum
     )
   LIMIT 1;

  IF constraint_name IS NOT NULL THEN
    EXECUTE format('ALTER TABLE known_networks DROP CONSTRAINT %I', constraint_name);
  END IF;
END $$;

CREATE UNIQUE INDEX known_networks_scope_idx
  ON known_networks (tenant_id, fingerprint,
                     COALESCE(device_id, '00000000-0000-0000-0000-000000000000'::uuid));

COMMENT ON COLUMN known_networks.device_id IS
  'NULL = הכרעה לכל החשבון. מזהה = הכרעה למחשב הזה בלבד, ביכולת per_device_policy.';
