/*
 * היתרים להורדת רצפת המדיניות.
 *
 * הרצפה נקבעת בהתקנה ונחתמת, והסוכן דוחה כל מדיניות שמקלה ממנה.
 * זו ההגנה החזקה ביותר במוצר: גם שרת שנפרץ אינו יכול לכבות אכיפה,
 * כי הרצפה אינה מגיעה ממנו.
 *
 * כל מנגנון ההיתר היה בנוי בסוכן — הפרדת מפתחות, nonce חד-פעמי,
 * תוקף, והתאמה לרצפה הנוכחית — ולא הייתה דרך להנפיק אחד. הצד הקשה
 * היה גמור והצינור חסר.
 *
 * ---
 *
 * הטבלה קיימת בשביל ה-nonce.
 *
 * הסוכן דוחה שימוש חוזר, אבל השרת חייב לזכור מה הנפיק כדי לא
 * להנפיק פעמיים את אותו דבר, וכדי לענות "מי אישר להוריד רצפה
 * במחשב הזה" — שאלה שתישאל בדיוק כשמשהו השתבש.
 */

CREATE TABLE loosening_grants (
  id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id uuid NOT NULL,
  tenant_id uuid NOT NULL,

  /* המזהה החד-פעמי שנחתם בתוך ההיתר. */
  nonce text UNIQUE NOT NULL,

  from_floor jsonb NOT NULL,
  to_floor   jsonb NOT NULL,

  reason      text,
  approved_by uuid REFERENCES users(id) ON DELETE SET NULL,

  issued_at  timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,

  /*
   * מתי נמסר לסוכן.
   *
   * NULL = ממתין. זה מה שמאפשר למסור אותו בפעימה הבאה בלי למסור
   * אותו שוב ושוב, ולדעת שהיתר שהונפק לא הגיע.
   */
  delivered_at timestamptz,

  /*
   * מתי הסוכן דיווח שהחיל.
   *
   * זה, ולא delivered_at, מה שמעדכן את הרצפה הרשומה ב-devices.
   * הסוכן מאמת את ההיתר בעצמו ורשאי לדחות אותו, ורצפה שנרשמה
   * כמונמכת בעוד המחשב סירב הייתה מכשילה כל היתר עתידי — כולם
   * היו יוצאים מרצפה שאינה קיימת.
   */
  applied_at timestamptz,

  FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX loosening_grants_pending_idx
  ON loosening_grants (device_id) WHERE delivered_at IS NULL;

ALTER TABLE loosening_grants ENABLE ROW LEVEL SECURITY;

CREATE POLICY loosening_grants_isolation ON loosening_grants
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());

GRANT SELECT, INSERT, UPDATE ON loosening_grants TO safeme_app;

COMMENT ON TABLE loosening_grants IS
  'היתרים להורדת רצפה. נמסרים בפעימה, חד-פעמיים, וחתומים במפתח נפרד.';
