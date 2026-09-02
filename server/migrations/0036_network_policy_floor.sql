/*
 * רצפת מדיניות הרשתות.
 *
 * מדיניות הרשתות היא הגדרה של החשבון עם שלוש דרגות: strict חוסם
 * כל רשת חדשה עד אישור, balanced מאשר אוטומטית רשת שכבר מסוננת,
 * ו-lenient מתיר הכול ורק מתריע.
 *
 * הבעיה: ההורה יכול לשנות אותה בכל רגע. מי שהחליט בהתקנה על סינון
 * הדוק יכול לרדת ל"מקל" בשלוש לחיצות, ברגע שההגבלה מפריעה לו —
 * וזה בדיוק הרגע שבו הוא הכי פחות רוצה להחליט.
 *
 * ---
 *
 * הרצפה היא ההתחייבות שהוא לוקח על עצמו בהתקנה, כשהוא צלול.
 *
 * אותו רעיון בדיוק כמו הגדרת ההסרה: נקבע פעם אחת בהתקנה, ושינוי
 * דורש מוקד. ההבדל הוא שכאן ההגבלה חלה על טווח ולא על מתג — הוא
 * רשאי להחמיר מתי שירצה, ואינו רשאי להקל מתחת למה שקבע.
 *
 * ברירת המחדל היא lenient, כלומר "בלי רצפה". חשבונות קיימים אינם
 * משנים התנהגות, ומי שלא בחר אינו מוגבל.
 */

ALTER TABLE tenants
  ADD COLUMN network_policy_floor network_policy NOT NULL DEFAULT 'lenient',

  /*
   * מי שינה ומתי, כמו בהגדרת ההסרה.
   *
   * NULL פירושו שהרצפה עדיין כפי שנקבעה בהתקנה, וזה מה שמאפשר
   * להתקנה הראשונה לקבוע בלי לתת להתקנה שנייה לשנות.
   */
  ADD COLUMN network_policy_floor_changed_at timestamptz,
  ADD COLUMN network_policy_floor_changed_by uuid REFERENCES users(id) ON DELETE SET NULL;

COMMENT ON COLUMN tenants.network_policy_floor IS
  'המצב המתירני ביותר שהחשבון רשאי לבחור. שינוי דרך המוקד בלבד.';

/*
 * ---------------------------------------------------------------- אכיפה
 *
 * האילוץ במסד ולא רק בקוד.
 *
 * מסלול שיישכח, סקריפט תחזוקה, או תיקון ידני — כל אחד מהם יכול
 * לכתוב מדיניות שמקלה מהרצפה. כאן זה פשוט לא ייכתב.
 *
 * הסדר: strict הוא המחמיר ביותר, lenient המתירני ביותר. מדיניות
 * מותרת כשהיא אינה מתירנית יותר מהרצפה.
 */
ALTER TABLE tenants
  ADD CONSTRAINT tenants_network_policy_within_floor CHECK (
    CASE network_policy
      WHEN 'strict'   THEN 1
      WHEN 'balanced' THEN 2
      ELSE 3
    END
    <=
    CASE network_policy_floor
      WHEN 'strict'   THEN 1
      WHEN 'balanced' THEN 2
      ELSE 3
    END
  );
