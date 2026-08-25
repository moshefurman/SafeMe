-- ============================================================================
--  SafeMe · 0011 · תקופת ניסיון
--
--  30 יום חינם מרגע פתיחת החשבון.
--
--  המצב נשמר על הדייר ולא על הרישיון, כי הניסיון שייך ללקוח ולא
--  למכשיר: משפחה שמתקינה מכשיר שני ביום העשרים אינה מקבלת 30 יום
--  נוספים עבורו.
-- ============================================================================

CREATE TYPE billing_plan AS ENUM ('trial', 'paid', 'expired', 'canceled');

ALTER TABLE tenants
  ADD COLUMN plan             billing_plan NOT NULL DEFAULT 'trial',
  ADD COLUMN trial_started_at timestamptz,
  ADD COLUMN trial_ends_at    timestamptz,
  ADD COLUMN paid_until       timestamptz;

COMMENT ON COLUMN tenants.trial_ends_at IS
  'סוף תקופת הניסיון. לאחריו ההתנהגות נקבעת ב-billing/trial.ts.';

-- ---------------------------------------------------------------- אתחול
--
-- המילוי לאחור חייב לקדום את ה-CHECK: הוספת העמודה נותנת לכל
-- הדיירים הקיימים plan='trial' עם trial_ends_at ריק, וה-CHECK
-- היה נכשל עליהם ברגע הוספתו.

/*
 * דיירים קיימים מקבלים ניסיון שמתחיל מרגע יצירתם, כדי שלא יראו
 * לפתע "פג תוקף" רק משום שהעמודה נוספה עכשיו.
 */
UPDATE tenants
   SET trial_started_at = created_at,
       trial_ends_at    = created_at + interval '30 days'
 WHERE trial_ends_at IS NULL;

-- דייר בניסיון חייב תאריך סיום. בלעדיו אי אפשר לדעת מתי הוא נגמר,
-- וזה בדיוק סוג הנתון החסר שמתגלה רק כשלקוח מתלונן.
ALTER TABLE tenants
  ADD CONSTRAINT tenants_trial_has_end CHECK (
    plan <> 'trial' OR trial_ends_at IS NOT NULL
  );

-- ---------------------------------------------------------------- ברירת מחדל

/*
 * פתיחת ניסיון לדייר חדש. נקרא ביצירת חשבון, כדי שהתאריכים ייקבעו
 * במקום אחד ולא יתפזרו על פני הקוד.
 */
CREATE OR REPLACE FUNCTION app.start_trial(p_tenant uuid, p_days integer DEFAULT 30)
RETURNS timestamptz
LANGUAGE plpgsql AS $$
DECLARE
  ends_at timestamptz;
BEGIN
  ends_at := now() + make_interval(days => p_days);

  UPDATE tenants
     SET plan = 'trial',
         trial_started_at = now(),
         trial_ends_at = ends_at
   WHERE id = p_tenant
     -- ניסיון נפתח פעם אחת בלבד. סגירה ופתיחה מחדש של חשבון
     -- אינה דרך לקבל עוד 30 יום.
     AND trial_started_at IS NULL;

  SELECT t.trial_ends_at INTO ends_at FROM tenants t WHERE t.id = p_tenant;

  RETURN ends_at;
END
$$;

CREATE INDEX tenants_trial_ends_idx ON tenants (trial_ends_at)
  WHERE plan = 'trial';
