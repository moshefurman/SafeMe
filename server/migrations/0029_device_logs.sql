/*
 * יומנים מהמחשב, לפי בקשה.
 *
 * כשמשהו נשבר אצל לקוח אין דרך לדעת מה קרה. יומן האירועים של
 * Windows יושב על המחשב שלו, והוא לא יידע לפתוח אותו, ואנחנו לא
 * נהיה שם. כל אבחון ב-1.9.2026 דרש גישה למכונה — ובשדה לא תהיה
 * כזו.
 *
 * ---
 *
 * שני כללים שמעצבים את הטבלה הזו, ושניהם על פרטיות.
 *
 * ראשית, לפי בקשה בלבד. אין איסוף רציף ואין שליחה אוטומטית: יומן
 * נאסף רק אחרי שמישהו לחץ, וזה נרשם ביומן הביקורת עם מי לחץ ומתי.
 * מוצר שמושך יומנים ממחשבי לקוחות מתי שבא לו הוא מוצר אחר.
 *
 * שנית, תוקף קצר. היומן נועד לפתור תקלה אחת, לא להצטבר. שבועיים
 * ואז נמחק, וזה גם מה שמונע מהטבלה להפוך למאגר מידע על לקוחות
 * שאיש לא התכוון ליצור.
 */

CREATE TABLE device_logs (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id   uuid NOT NULL,
  tenant_id   uuid NOT NULL,

  /*
   * הפקודה שבעקבותיה נאסף.
   *
   * NULL אפשרי, למקרה שהסוכן ישלח יזום בעתיד — אבל היום כל שורה
   * כאן מצביעה על בקשה מפורשת, וזה מה שמאפשר לענות "מי ביקש".
   */
  command_id  uuid REFERENCES device_commands(id) ON DELETE SET NULL,

  agent_version text,

  /*
   * התוכן, דחוס.
   *
   * gzip ולא טקסט גולמי: יומן אירועים של יממה הוא מאות קילובייטים
   * של שורות חוזרות, והוא מתכווץ פי עשרה. הגבול נאכף גם בשרת וגם
   * בסוכן — צד אחד שסומך על השני הוא צד אחד שאפשר לעקוף.
   */
  body        bytea NOT NULL,
  byte_length int   NOT NULL CHECK (byte_length > 0 AND byte_length <= 4194304),

  collected_at timestamptz NOT NULL,
  received_at  timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL DEFAULT now() + interval '14 days',

  FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX device_logs_device_idx  ON device_logs (device_id, received_at DESC);
CREATE INDEX device_logs_expiry_idx  ON device_logs (expires_at);

ALTER TABLE device_logs ENABLE ROW LEVEL SECURITY;

/*
 * דייר רואה רק את שלו, כמו בכל טבלה אחרת.
 *
 * ההורה רשאי לראות מה נשלח ממחשביו. יומן שנאסף ממחשב שלו והוא
 * אינו יכול לראות הוא בדיוק מה שהופך תמיכה למעקב.
 */
CREATE POLICY device_logs_tenant ON device_logs
  USING (tenant_id = current_setting('safeme.tenant_id', true)::uuid);

COMMENT ON TABLE device_logs IS
  'יומנים שנאספו ממחשב לפי בקשה מפורשת. נמחקים אחרי שבועיים.';
