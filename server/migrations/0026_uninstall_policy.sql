/*
 * מי רשאי לשחרר מחשב, ואיך.
 *
 * ההורה בוחר בעצמו בין שתי דרכים, ושתיהן לגיטימיות:
 *
 *   self_service  — הוא מנפיק לעצמו קוד הסרה בפורטל
 *   support_only  — רק המוקד מנפיק, בתשלום
 *
 * הבחירה השנייה היא חיכוך מכוון. מי שקנה את המוצר כדי לגדור את
 * עצמו יודע שברגע החולשה הוא ימצא כל דרך, ולכן הוא בוחר מראש
 * שתהיה דרך אחת שעוברת דרך אדם אחר.
 *
 * וזו הנקודה שהופכת את זה לאמיתי: השינוי אינו סימטרי.
 */

CREATE TYPE uninstall_policy AS ENUM ('self_service', 'support_only');

ALTER TABLE tenants
  /*
   * ברירת המחדל היא העצמאית.
   *
   * חשבון חדש אינו יודע עדיין מה הוא רוצה, וכליאה בברירת מחדל
   * היא ההפך מבחירה. מי שרוצה את החיכוך יבחר בו, וזו בחירה
   * שנעשית פעם אחת ומודעת.
   */
  ADD COLUMN uninstall_policy uninstall_policy NOT NULL DEFAULT 'self_service',

  /* מתי השתנתה לאחרונה ובידי מי, לצורך בירור בדיעבד. */
  ADD COLUMN uninstall_policy_changed_at timestamptz,
  ADD COLUMN uninstall_policy_changed_by uuid REFERENCES users(id) ON DELETE SET NULL;

COMMENT ON COLUMN tenants.uninstall_policy IS
  'self_service: ההורה מנפיק לעצמו. support_only: רק המוקד, בתשלום. נבחר פעם אחת, ושינוי עובר דרך המוקד בתשלום.';

/*
 * ---------------------------------------------------------------- הנעילה
 *
 * ההורה בוחר פעם אחת, ומשם ההגדרה נעולה.
 *
 * בלי זה ההגדרה חסרת ערך: מי שבחר "רק דרך המוקד" ומתפתה בשתיים
 * בלילה פשוט מחזיר אותה ל"לבד" ומסיר. גדר שאפשר לפתוח מבפנים
 * אינה גדר, והיא גרועה מהיעדרה כי היא יוצרת ביטחון שאינו קיים.
 *
 * וזה נכון לשני הכיוונים ולא רק להקלה. הבחירה עצמה היא ההתחייבות,
 * ושינוי שלה — לכל כיוון — עובר דרך אדם אחר ובתשלום. מי שיודע
 * שהוא יתחרט הוא בדיוק מי שההגדרה נועדה לו.
 *
 * uninstall_policy_changed_at ריק פירושו שטרם נבחר. זו הבחירה
 * הראשונה, והיא היחידה שההורה עושה לבדו.
 *
 * המוקד עובד בהקשר פלטפורמה, ולכן הוא — ורק הוא — יכול לשנות
 * אחריה.
 */
CREATE OR REPLACE FUNCTION app.guard_uninstall_policy()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.uninstall_policy IS NOT DISTINCT FROM OLD.uninstall_policy THEN
    RETURN NEW;
  END IF;

  IF NOT app.is_platform() AND OLD.uninstall_policy_changed_at IS NOT NULL THEN
    RAISE EXCEPTION
      'שינוי אופן ההסרה מחייב פנייה למוקד. הבחירה נעשית פעם אחת.'
      USING ERRCODE = 'check_violation';
  END IF;

  NEW.uninstall_policy_changed_at := now();

  RETURN NEW;
END;
$$;

CREATE TRIGGER tenants_uninstall_policy_ratchet
  BEFORE UPDATE OF uninstall_policy ON tenants
  FOR EACH ROW
  EXECUTE FUNCTION app.guard_uninstall_policy();

/*
 * ---------------------------------------------------------------- חיוב
 *
 * כל קוד שהמוקד מנפיק הוא בתשלום, וזה נרשם ברגע ההנפקה.
 *
 * הרישום כאן ולא במערכת חיוב חיצונית: מה שקובע אם מגיע חיוב הוא
 * העובדה שאדם במוקד הנפיק קוד, והיא ידועה בדיוק כאן. גבייה בפועל
 * נעשית מחוץ למערכת, ועדיין צריך מקום אחד שיודע כמה ולמי.
 */
CREATE TABLE uninstall_issuances (
  id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  device_id    uuid,

  issued_at    timestamptz NOT NULL DEFAULT now(),
  issued_by    uuid REFERENCES users(id) ON DELETE SET NULL,

  /* self_service אינו מחויב; support הוא תמיד. */
  channel      text NOT NULL CHECK (channel IN ('self_service', 'support')),
  billable     boolean NOT NULL,

  reason       text,

  CONSTRAINT support_is_always_billable
    CHECK ((channel = 'support') = billable)
);

CREATE INDEX uninstall_issuances_tenant_idx
  ON uninstall_issuances (tenant_id, issued_at DESC);

CREATE INDEX uninstall_issuances_billable_idx
  ON uninstall_issuances (issued_at DESC) WHERE billable;

COMMENT ON TABLE uninstall_issuances IS
  'כל קוד הסרה שהונפק. הנפקת מוקד היא תמיד בתשלום, והאילוץ אוכף זאת.';

-- ---------------------------------------------------------------- הרשאות

GRANT SELECT, INSERT ON uninstall_issuances TO safeme_app;

ALTER TABLE uninstall_issuances ENABLE ROW LEVEL SECURITY;

CREATE POLICY uninstall_issuances_isolation ON uninstall_issuances
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());
