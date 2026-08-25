-- ============================================================================
--  SafeMe · 0008 · ניתוק המפתח הזר של יומן הביקורת
--
--  התגלה בהרצת ה-POC: מחיקת דייר נכשלה עם
--    "audit_log הוא append-only: UPDATE נדחה"
--
--  הסיבה: audit_log.tenant_id הוגדר עם ON DELETE SET NULL. מחיקת דייר
--  גררה UPDATE על שורות היומן, והטריגר שהופך אותו ל-append-only חסם
--  אותו — ובצדק. התוצאה: אי אפשר היה למחוק דייר כלל.
--
--  התיקון הנכון אינו להחליש את הטריגר אלא להסיר את המפתח הזר.
--  יומן ביקורת הוא רישום היסטורי: הוא מתעד מה קרה בזמן שקרה, ואסור
--  שישתנה בדיעבד בגלל מחיקה מאוחרת. אם דייר נמחק, העובדה שהונפק לו
--  קוד הסרה בעבר נשארת נכונה ותקפה.
--
--  tenant_id נשאר עמודה רגילה לצורך סינון ולצורך RLS.
-- ============================================================================

ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_tenant_id_fkey;

COMMENT ON COLUMN audit_log.tenant_id IS
  'ללא מפתח זר במכוון. היומן שורד מחיקת דייר ואינו משתנה בדיעבד. ראה 0008.';

-- אימות: לא נשאר אף מפתח זר שעלול לגרור שינוי ביומן
DO $$
DECLARE
  remaining text;
BEGIN
  SELECT string_agg(conname, ', ')
    INTO remaining
  FROM pg_constraint
  WHERE conrelid = 'audit_log'::regclass
    AND contype = 'f';

  IF remaining IS NOT NULL THEN
    RAISE EXCEPTION 'ל-audit_log נותרו מפתחות זרים שעלולים לגרור UPDATE: %', remaining;
  END IF;
END
$$;
