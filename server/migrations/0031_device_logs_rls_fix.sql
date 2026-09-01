/*
 * תיקון מדיניות ה-RLS של טבלת היומנים.
 *
 * 0029 כתבה את התנאי ידנית:
 *
 *   USING (tenant_id = current_setting('safeme.tenant_id', true)::uuid)
 *
 * ו-safeme.tenant_id אינו קיים. withTenant מגדיר app.tenant_id,
 * ו-app.current_tenant() קוראת משם. השם המומצא מחזיר NULL, ההשוואה
 * מחזירה NULL, וה-INSERT נדחה כהפרת מדיניות.
 *
 * כך זה נראה בשטח: הסוכן אסף יומן, שלח, וקיבל 500. שלוש פעמים,
 * בלי שום רמז לסיבה — כי גם הדיווח על הכישלון היה שקט.
 *
 * ---
 *
 * ושתי טעויות במדיניות אחת, לא אחת.
 *
 * חסר גם WITH CHECK, וגם ענף app.is_platform(). כל טבלה אחרת
 * במערכת משתמשת בשני העוזרים האלה בדיוק, ומדיניות שנכתבת מחדש
 * במקום להעתיק את הדפוס היא בדיוק המקום שבו נופלים.
 *
 * בלי ענף הפלטפורמה, גם התמיכה לא הייתה יכולה לקרוא את היומנים
 * שנאספו — כלומר התכונה הייתה חצי מתה גם אילו ה-INSERT היה עובר.
 */

DROP POLICY IF EXISTS device_logs_tenant ON device_logs;

CREATE POLICY device_logs_isolation ON device_logs
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());
