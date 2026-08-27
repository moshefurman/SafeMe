-- ============================================================================
--  SafeMe · 0016 · רשתות מוכרות והיסטוריית חיבורים
--
--  רשת חדשה אינה מאושרת. זו הרחבה של אותו עיקרון שמנחה את כל המוצר:
--  ברירת המחדל היא דחייה, ולהתיר צריך פעולה מפורשת.
--
--  מה שמייחד את הרשתות הוא שיש דרגת ביניים שהגיונית: רשת חדשה שכבר
--  עוברת דרך ספק סינון מאושר אינה סיכון, וחסימתה רק מרגילה את ההורה
--  לאשר בלי לקרוא.
-- ============================================================================

-- ---------------------------------------------------------------- מדיניות

/*
 * שלוש רמות. ההבדל ביניהן הוא רק במה קורה לרשת חדשה שכבר מסוננת —
 * רשת לא מסוננת נחסמת בכולן, ונקודה חמה מטלפון נחסמת בכולן תמיד.
 */
CREATE TYPE network_policy AS ENUM (
  'strict',    -- כל רשת חדשה נחסמת עד אישור
  'balanced',  -- רשת חדשה שמסוננת מאושרת אוטומטית
  'lenient'    -- רשת חדשה מותרת, וההורה מקבל התראה
);

CREATE TYPE network_approval AS ENUM ('pending', 'approved', 'blocked');

ALTER TABLE tenants
  ADD COLUMN network_policy network_policy NOT NULL DEFAULT 'balanced';

COMMENT ON COLUMN tenants.network_policy IS
  'מה קורה לרשת חדשה. ההבדל בין הרמות נוגע רק לרשת שכבר מסוננת.';

-- ---------------------------------------------------------------- רשתות

CREATE TABLE known_networks (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

  /*
   * טביעת האצבע של הרשת.
   *
   * SSID לבדו אינו מספיק: ילד יקרא לנקודה החמה בטלפון בדיוק כמו
   * הרשת בבית. כתובת החומרה של השער מזהה את הנתב הפיזי, ולכן היא
   * הבסיס — עם נפילה אחורה לשם ולשער כשהיא אינה זמינה.
   */
  fingerprint    text NOT NULL,

  ssid           text,
  gateway_ip     text,
  gateway_mac    text,

  approval       network_approval NOT NULL DEFAULT 'pending',

  /* מה המסווג חשב עליה. נשמר כדי שההורה יראה למה נשאל. */
  hotspot_confidence text,
  hotspot_reasons    jsonb NOT NULL DEFAULT '[]'::jsonb,

  /* ספק הסינון שזוהה כשהמכשיר היה מחובר אליה, אם היה. */
  detected_provider  text,

  first_seen_at  timestamptz NOT NULL DEFAULT now(),
  last_seen_at   timestamptz NOT NULL DEFAULT now(),

  decided_by     uuid REFERENCES users(id) ON DELETE SET NULL,
  decided_at     timestamptz,
  note           text,

  CONSTRAINT network_decision_has_time CHECK (
    (approval = 'pending') = (decided_at IS NULL)
  ),

  UNIQUE (tenant_id, fingerprint)
);

CREATE INDEX known_networks_pending_idx
  ON known_networks (tenant_id, first_seen_at DESC)
  WHERE approval = 'pending';

COMMENT ON TABLE known_networks IS
  'רשתות שהמכשירים של הדייר נתקלו בהן. חדשה אינה מאושרת.';

-- ---------------------------------------------------------------- סשנים

/*
 * חיבור אחד לרשת אחת.
 *
 * שורה נפתחת בהתחברות ונסגרת בניתוק — לא רשומה לכל פעימה. זה אותו
 * שיעור שלמדנו בטלמטריה: בבית ממוצע זה כמה עשרות שורות בחודש במקום
 * עשרות אלפים.
 */
CREATE TABLE network_sessions (
  id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  device_id    uuid NOT NULL,
  tenant_id    uuid NOT NULL,
  network_id   uuid NOT NULL REFERENCES known_networks(id) ON DELETE CASCADE,

  started_at   timestamptz NOT NULL DEFAULT now(),
  ended_at     timestamptz,

  /* מה קרה בסשן הזה: הותר, נחסם, או המתין לאישור. */
  outcome      text NOT NULL DEFAULT 'allowed'
               CHECK (outcome IN ('allowed', 'blocked', 'pending')),

  FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE,

  CONSTRAINT session_ends_after_start CHECK (ended_at IS NULL OR ended_at >= started_at)
);

CREATE INDEX network_sessions_device_idx ON network_sessions (device_id, started_at DESC);
CREATE INDEX network_sessions_open_idx   ON network_sessions (device_id) WHERE ended_at IS NULL;

COMMENT ON TABLE network_sessions IS
  'חיבור אחד לרשת. שורה לכל חיבור, לא לכל פעימה.';

-- ---------------------------------------------------------------- הרשאות

GRANT SELECT, INSERT, UPDATE ON known_networks   TO safeme_app;
GRANT SELECT, INSERT, UPDATE ON network_sessions TO safeme_app;

ALTER TABLE known_networks   ENABLE ROW LEVEL SECURITY;
ALTER TABLE network_sessions ENABLE ROW LEVEL SECURITY;

CREATE POLICY known_networks_isolation ON known_networks
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());

CREATE POLICY network_sessions_isolation ON network_sessions
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());
