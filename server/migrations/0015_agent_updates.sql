-- ============================================================================
--  SafeMe · 0015 · עדכוני סוכן
--
--  עדכון הוא הרצת קוד שרירותי בהרשאות SYSTEM על מחשב מוגן. זו הסמכות
--  החזקה ביותר שיש למערכת — חזקה יותר מהסרה, וחזקה בהרבה ממדיניות.
--
--  לכן מפתח רביעי ונפרד. שיתוף מפתח המדיניות עם עדכונים היה מבטל את
--  כל ההיגיון של שלושת המפתחות הקודמים: מי שיכול לחתום מדיניות היה
--  יכול להריץ קוד על כל מחשב בשטח.
-- ============================================================================

ALTER TYPE key_purpose ADD VALUE IF NOT EXISTS 'update';

-- ---------------------------------------------------------------- גרסאות

CREATE TABLE agent_releases (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),

  version       text NOT NULL UNIQUE
                CHECK (version ~ '^[0-9]+\.[0-9]+\.[0-9]+$'),

  -- הרכיבים נשמרים בנפרד כי השוואת גרסאות כטקסט שגויה:
  -- '1.10.0' < '1.9.0' לקסיקוגרפית, וזה בדיוק ההפך מהנכון.
  v_major       int NOT NULL CHECK (v_major >= 0),
  v_minor       int NOT NULL CHECK (v_minor >= 0),
  v_patch       int NOT NULL CHECK (v_patch >= 0),

  channel       text NOT NULL DEFAULT 'stable'
                CHECK (channel IN ('stable', 'beta')),

  download_url  text NOT NULL,
  sha256        bytea NOT NULL CHECK (length(sha256) = 32),
  size_bytes    bigint NOT NULL CHECK (size_bytes > 0),

  -- סוכן ישן מדי לא יקפוץ ישירות. שדרוג מרחוק מדלג על שינויי מבנה
  -- שנעשו בדרך, וזה בדיוק מה שהופך מכשיר ללבנה.
  min_from_major int NOT NULL DEFAULT 0,
  min_from_minor int NOT NULL DEFAULT 0,
  min_from_patch int NOT NULL DEFAULT 0,

  -- הפצה מדורגת. עדכון פגום שמגיע לכל המכשירים בבת אחת הוא אירוע
  -- שאי אפשר להתאושש ממנו מרחוק, כי הכלי להתאוששות הוא הסוכן עצמו.
  rollout_percent int NOT NULL DEFAULT 0
                  CHECK (rollout_percent BETWEEN 0 AND 100),

  notes         text,
  published_at  timestamptz NOT NULL DEFAULT now(),
  published_by  uuid REFERENCES users(id) ON DELETE SET NULL,

  -- גרסה שהתגלתה כפגומה. אינה נמחקת — היא חלק מהיסטוריית ההפצה.
  revoked_at    timestamptz,
  revoked_reason text,

  CONSTRAINT release_revoked_has_reason CHECK (
    revoked_at IS NULL OR revoked_reason IS NOT NULL
  )
);

CREATE INDEX agent_releases_order_idx
  ON agent_releases (channel, v_major DESC, v_minor DESC, v_patch DESC)
  WHERE revoked_at IS NULL;

COMMENT ON TABLE agent_releases IS
  'גרסאות סוכן להפצה. כל שורה חתומה בזמן ההגשה במפתח העדכונים הנפרד.';

COMMENT ON COLUMN agent_releases.rollout_percent IS
  'אחוז המכשירים שיקבלו את הגרסה. הדלי נגזר מ-device_id ומהגרסה, ולכן יציב.';

-- ---------------------------------------------------------------- הדלי
--
-- אחוז ההפצה נקבע לכל צמד מכשיר-גרסה בנפרד, ובאופן דטרמיניסטי.
-- הגרלה בכל פעימה הייתה גורמת למכשיר להיכנס ולצאת מההפצה חליפות,
-- ולהתחיל הורדה שלא תושלם לעולם.

CREATE OR REPLACE FUNCTION app.rollout_bucket(p_device uuid, p_version text)
RETURNS int
LANGUAGE sql IMMUTABLE AS $$
  SELECT ('x' || substr(md5(p_device::text || ':' || p_version), 1, 8))::bit(32)::bigint % 100;
$$;

COMMENT ON FUNCTION app.rollout_bucket(uuid, text) IS
  'דלי יציב בטווח 0-99 לצמד מכשיר-גרסה. יציבות היא התכונה המהותית כאן.';

GRANT SELECT ON agent_releases TO safeme_app;

-- הטבלה אינה שייכת לדייר: הגרסאות משותפות לכל הלקוחות, וההגבלה
-- היחידה היא שמשתמש אינו רשאי לכתוב אליה. לכן אין RLS אלא היעדר
-- הרשאת כתיבה.
