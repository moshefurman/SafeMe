-- ============================================================================
--  SafeMe · 0021 · לכל דייר יש הגדרות התראה
--
--  0020 מילא את הדיירים שהיו קיימים, ושכח את אלה שייווצרו אחר כך.
--  התוצאה הייתה הכשל הגרוע ביותר שאפשר במוצר הזה: חשבון חדש נראה
--  תקין לגמרי ופשוט לא מקבל שום התראה. איש לא היה מגלה, כי אין
--  שום סימן לכך שהודעה לא נשלחה.
--
--  זה נתפס בבדיקה, ולא בשטח. אבל הוא נתפס רק מפני שבדיקה קיימת
--  יצרה דייר חדש — כלומר במקרה.
--
--  הטריגר במקום קריאה בקוד: יש כמה מסלולים שיוצרים דייר — הרשמה,
--  כניסה דרך Google, זריעת דמו, בדיקות — ומסלול שיתווסף מחר ישכח
--  אותה בדיוק כמו ש-0020 שכח.
-- ============================================================================

CREATE OR REPLACE FUNCTION app.ensure_notification_settings()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  /*
   * נקבע לפי בעל החשבון הראשון, וזו נקודת ההתחלה הנכונה: הכתובת
   * שנרשמה היא הכתובת שההורה מצפה לקבל בה. משם הוא חופשי להחליף,
   * דרך המסלול המושהה.
   */
  IF NEW.role = 'tenant_owner' AND NEW.tenant_id IS NOT NULL THEN
    INSERT INTO notification_settings (tenant_id, primary_email)
    VALUES (NEW.tenant_id, NEW.email)
    ON CONFLICT (tenant_id) DO NOTHING;
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER users_ensure_notification_settings
  AFTER INSERT ON users
  FOR EACH ROW
  EXECUTE FUNCTION app.ensure_notification_settings();

COMMENT ON FUNCTION app.ensure_notification_settings() IS
  'דייר בלי הגדרות התראה אינו מקבל דבר, ובשקט. הטריגר מונע את זה בכל מסלול.';

-- השלמה לדיירים שנוצרו בין 0020 לכאן
INSERT INTO notification_settings (tenant_id, primary_email)
SELECT t.id, u.email
  FROM tenants t
  JOIN LATERAL (
    SELECT email FROM users
     WHERE tenant_id = t.id AND role = 'tenant_owner'
     ORDER BY created_at
     LIMIT 1
  ) u ON true
ON CONFLICT (tenant_id) DO NOTHING;
