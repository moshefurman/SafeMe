/*
 * תוכניות מנוי ומנויים.
 *
 * עד כה היה מנגנון ניסיון בלבד: plan, trial_ends_at ו-paid_until על
 * הדייר, בלי שום דרך לגבות כסף ובלי הגבלה על מספר המחשבים.
 * max_devices יושב בטבלת הרישיונות מהיום הראשון ואינו נאכף בשום
 * מקום — כלומר כל חשבון יכול לרשום מחשבים בלי גבול.
 *
 * ---
 *
 * המחירים בטבלה ולא בקוד.
 *
 * שינוי מחיר הוא החלטה עסקית, ופריסה חדשה לכל שינוי היא מתכון
 * לטעות ברגע לחוץ. וחשוב מזה: מנוי קיים חייב להמשיך בתנאים שבהם
 * נמכר, גם אחרי שהמחיר עלה — ולכן המנוי שומר את המחיר שנקבע לו
 * ואינו קורא אותו מהתוכנית בכל חידוש.
 */

CREATE TABLE plans (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),

  /* מזהה יציב לשימוש בקוד ובקישורים. לא משתנה גם כששם התצוגה משתנה. */
  code         text UNIQUE NOT NULL CHECK (code ~ '^[a-z0-9-]{2,40}$'),
  name         text NOT NULL,

  device_limit int NOT NULL CHECK (device_limit > 0 AND device_limit <= 1000),

  /*
   * באגורות, לא בשקלים.
   *
   * מחיר בנקודה צפה הוא שגיאת עיגול שמצטברת על פני אלפי חיובים,
   * וסכום שאינו מסתדר בסוף חודש הוא בדיוק מה שאי אפשר להסביר
   * ללקוח. מספר שלם של אגורות אינו סובל מזה.
   *
   * כולל מע"מ: זה מה שמוצג להורה, וזה מה שיירד מהכרטיס.
   */
  monthly_agorot int NOT NULL CHECK (monthly_agorot >= 0),

  /*
   * מחיר שנתי, ולא אחוז הנחה.
   *
   * אחוז מחייב חישוב בכל תצוגה ומייצר עיגולים שונים במקומות שונים.
   * הסכום השנתי הוא מה שמחייבים, וההנחה נגזרת ממנו לתצוגה.
   */
  yearly_agorot  int NOT NULL CHECK (yearly_agorot >= 0),

  active     boolean NOT NULL DEFAULT true,
  sort_order int     NOT NULL DEFAULT 0,

  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE plans IS 'תוכניות מנוי. מחירים באגורות כולל מע"מ.';

CREATE TYPE billing_interval  AS ENUM ('monthly', 'yearly');

/*
 * מצבי המנוי.
 *
 *   trialing  תקופת ניסיון, טרם חויב
 *   active    שולם, בתוקף
 *   past_due  חיוב נכשל, בתקופת חסד — הפורטל עדיין פתוח
 *   unpaid    החסד נגמר. הפורטל נסגר, וההגנה במחשבים נמשכת
 *   canceled  בוטל על ידי הלקוח או על ידינו
 *
 * ההבחנה בין past_due ל-unpaid היא כל מנגנון הגבייה: הראשון מנסה
 * שוב ומזכיר, השני כבר ויתר. איחודם היה הופך כישלון חיוב אחד
 * לניתוק מיידי.
 */
CREATE TYPE subscription_status AS ENUM
  ('trialing', 'active', 'past_due', 'unpaid', 'canceled');

CREATE TABLE subscriptions (
  id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),

  /*
   * מנוי אחד לדייר.
   *
   * שני מנויים פעילים לאותו חשבון פירושם שתי מגבלות מחשבים ושני
   * חיובים, ואיש אינו יודע איזה קובע. האילוץ החלקי מתיר היסטוריה
   * של מנויים שהסתיימו.
   */
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  plan_id   uuid NOT NULL REFERENCES plans(id),

  interval_unit billing_interval    NOT NULL,
  status        subscription_status NOT NULL DEFAULT 'trialing',

  /*
   * המחיר והמגבלה כפי שנמכרו, ולא כפי שהם בתוכנית היום.
   *
   * לקוח שקנה במחיר מסוים ממשיך בו גם אחרי עדכון מחירון. קריאה
   * מהתוכנית בכל חידוש הייתה מעלה מחיר ללקוחות קיימים בשקט —
   * וזו גם בעיה חוקית, לא רק הוגנות.
   */
  price_agorot int NOT NULL CHECK (price_agorot >= 0),
  device_limit int NOT NULL CHECK (device_limit > 0),

  /* מזהה אמצעי התשלום אצל הסולק. לעולם לא מספר כרטיס. */
  provider          text,
  provider_ref      text,
  card_last4        char(4) CHECK (card_last4 ~ '^[0-9]{4}$'),
  card_expires      text,

  current_period_end timestamptz,

  /*
   * ביטול שנכנס לתוקף בסוף התקופה.
   *
   * מי שביטל שילם עד סוף החודש, ומגיע לו לקבל אותו. ביטול מיידי
   * היה גובה כסף ולא נותן שירות.
   */
  cancel_at_period_end boolean NOT NULL DEFAULT false,
  canceled_at          timestamptz,

  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX subscriptions_one_live_per_tenant
  ON subscriptions (tenant_id)
  WHERE status <> 'canceled';

CREATE INDEX subscriptions_renewal_idx
  ON subscriptions (current_period_end)
  WHERE status IN ('active', 'past_due');

/*
 * כל ניסיון חיוב, מוצלח או לא.
 *
 * לא רק לתיעוד: זו התשובה ל"האם חייבתם אותי פעמיים" ול"למה
 * הכרטיס נדחה", ובלעדיה כל בירור מול לקוח נשען על מה שהסולק
 * זוכר.
 */
CREATE TABLE payments (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  subscription_id uuid NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
  tenant_id       uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

  amount_agorot int  NOT NULL CHECK (amount_agorot >= 0),
  succeeded     boolean NOT NULL,

  provider      text,
  provider_ref  text,

  /* הסיבה כפי שהסולק החזיר. מה שצריך כדי לענות ללקוח. */
  failure_reason text,

  /* קישור לקבלה שהונפקה. חובה חוקית על כל חיוב שנגבה. */
  receipt_url    text,

  charged_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX payments_tenant_idx ON payments (tenant_id, charged_at DESC);

-- ---------------------------------------------------------------- RLS

ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE payments      ENABLE ROW LEVEL SECURITY;

/*
 * אותו דפוס כמו כל טבלה אחרת, ובכוונה.
 *
 * מדיניות שנכתבת מחדש במקום להעתיק את הדפוס היא בדיוק המקום שבו
 * נופלים — קרה לנו אתמול עם טבלת היומנים, ועלה שלושה סבבים.
 */
CREATE POLICY subscriptions_isolation ON subscriptions
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());

CREATE POLICY payments_isolation ON payments
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());

/* התוכניות גלויות לכולם: הן המחירון, והוא ממילא מוצג באתר. */
GRANT SELECT ON plans TO safeme_app;
GRANT INSERT, UPDATE ON plans TO safeme_app;

GRANT SELECT, INSERT, UPDATE ON subscriptions TO safeme_app;
GRANT SELECT, INSERT ON payments TO safeme_app;

-- ---------------------------------------------------------------- זריעה

/*
 * התוכנית הבסיסית: שלושה מחשבים.
 *
 * נזרעת כבויה ובמחיר אפס, ובכוונה. המחיר הוא החלטה עסקית ולא
 * ברירת מחדל טכנית — ומספר שהומצא כאן היה נראה אמיתי במסך, נמכר
 * למישהו, ומחייב אותנו לכבד אותו.
 *
 * מנהל הפלטפורמה קובע מחיר ומפעיל. עד אז אין מה למכור, וזה מצב
 * גלוי ולא שקט.
 */
INSERT INTO plans (code, name, device_limit, monthly_agorot, yearly_agorot, active, sort_order)
VALUES ('family-3', 'משפחה · 3 מחשבים', 3, 0, 0, false, 10)
ON CONFLICT (code) DO NOTHING;
