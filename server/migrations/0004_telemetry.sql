-- ============================================================================
--  SafeMe · 0004 · טלמטריה
--
--  heartbeats היא הטבלה שתגדל הכי מהר: מכשיר אחד שולח כ-480 פעימות ביום.
--  10,000 מכשירים = כ-4.8 מיליון שורות ביום. לכן חלוקה לפי חודש מההתחלה,
--  כדי שמחיקת היסטוריה ישנה תהיה DROP של מחיצה ולא DELETE של מיליוני שורות.
-- ============================================================================

CREATE TABLE heartbeats (
  id           bigint GENERATED ALWAYS AS IDENTITY,
  device_id    uuid NOT NULL,
  tenant_id    uuid NOT NULL,
  received_at  timestamptz NOT NULL DEFAULT now(),
  sent_at      timestamptz,
  sequence     bigint NOT NULL,
  status       security_status NOT NULL,
  score        int CHECK (score BETWEEN 0 AND 100),
  policy_version int,
  lockout_active boolean NOT NULL DEFAULT false,
  payload      jsonb NOT NULL,

  -- מפתח ראשי בטבלה מחולקת חייב לכלול את מפתח החלוקה
  PRIMARY KEY (id, received_at)

  -- הערה: אין כאן מפתח זר אל devices, בשונה מ-events ומ-alerts.
  -- זו נקודת הכתיבה הכבדה ביותר במערכת, ובדיקת מפתח זר בכל פעימה
  -- מייקרת אותה. תקינות device_id נבדקת בנתיב הקליטה, שממילא
  -- מאמת את אסימון המכשיר לפני הכתיבה.
) PARTITION BY RANGE (received_at);

CREATE INDEX heartbeats_device_idx ON heartbeats (device_id, received_at DESC);
CREATE INDEX heartbeats_tenant_idx ON heartbeats (tenant_id, received_at DESC);

-- ---------------------------------------------------------------- ניהול מחיצות
--
-- יוצר מחיצה חודשית אם אינה קיימת. נקרא מ-BullMQ פעם ביום, וגם
-- בהתקנה הראשונית עבור החודש הנוכחי והבא.

CREATE OR REPLACE FUNCTION app.ensure_heartbeat_partition(target date)
RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
  start_at date := date_trunc('month', target)::date;
  end_at   date := (date_trunc('month', target) + interval '1 month')::date;
  part_name text := format('heartbeats_%s', to_char(start_at, 'YYYY_MM'));
BEGIN
  IF EXISTS (SELECT 1 FROM pg_class WHERE relname = part_name) THEN
    RETURN part_name;
  END IF;

  EXECUTE format(
    'CREATE TABLE %I PARTITION OF heartbeats FOR VALUES FROM (%L) TO (%L)',
    part_name, start_at, end_at);

  EXECUTE format('GRANT SELECT, INSERT ON %I TO safeme_app', part_name);

  -- RLS על טבלת האב חל על שאילתות שעוברות דרכה, אך לא על שאילתה
  -- שפונה ישירות למחיצה. לכן כל מחיצה מקבלת מדיניות משלה.
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', part_name);
  EXECUTE format($p$
    CREATE POLICY %1$I_isolation ON %1$I
      USING (app.is_platform() OR tenant_id = app.current_tenant())
      WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant())
  $p$, part_name);

  RETURN part_name;
END
$$;

-- מחיצה שתופסת כל מה שנפל מחוץ לטווח, כדי שפעימה לא תיכשל בגלל
-- מחיצה חסרה. קיום שורות כאן הוא סימן לתקלה בתזמון היצירה.
CREATE TABLE heartbeats_overflow PARTITION OF heartbeats DEFAULT;

GRANT SELECT, INSERT ON heartbeats_overflow TO safeme_app;
ALTER TABLE heartbeats_overflow ENABLE ROW LEVEL SECURITY;

CREATE POLICY heartbeats_overflow_isolation ON heartbeats_overflow
  USING (app.is_platform() OR tenant_id = app.current_tenant())
  WITH CHECK (app.is_platform() OR tenant_id = app.current_tenant());

SELECT app.ensure_heartbeat_partition(CURRENT_DATE);
SELECT app.ensure_heartbeat_partition((CURRENT_DATE + interval '1 month')::date);

-- ---------------------------------------------------------------- אירועים
--
-- נפח נמוך בהרבה מפעימות, ולכן ללא חלוקה. אלה אירועי חבלה ודיווחים חריגים.

CREATE TABLE events (
  id              bigserial PRIMARY KEY,
  device_id       uuid NOT NULL,
  tenant_id       uuid NOT NULL,
  kind            text NOT NULL,
  severity        text NOT NULL DEFAULT 'warning',
  detail          text,
  occurred_at     timestamptz NOT NULL,
  received_at     timestamptz NOT NULL DEFAULT now(),
  acknowledged_by uuid REFERENCES users(id) ON DELETE SET NULL,
  acknowledged_at timestamptz,

  FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX events_device_idx ON events (device_id, occurred_at DESC);
CREATE INDEX events_tenant_idx ON events (tenant_id, occurred_at DESC);
CREATE INDEX events_open_idx   ON events (severity, occurred_at DESC)
  WHERE acknowledged_at IS NULL;

-- ---------------------------------------------------------------- התראות
--
-- התראה אחת פתוחה לכל צירוף מכשיר וסוג, כדי שמכשיר שמנותק יומיים
-- לא ייצור 576 מיילים. ראה 8.1.

CREATE TABLE alerts (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id        uuid NOT NULL,
  tenant_id        uuid NOT NULL,
  kind             text NOT NULL,
  state            alert_state NOT NULL DEFAULT 'open',
  first_seen_at    timestamptz NOT NULL DEFAULT now(),
  last_notified_at timestamptz,
  notify_count     int NOT NULL DEFAULT 0,
  resolved_at      timestamptz,

  FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX alerts_open_unique_idx
  ON alerts (device_id, kind) WHERE state <> 'resolved';

CREATE INDEX alerts_tenant_idx ON alerts (tenant_id, state);

-- ---------------------------------------------------------------- חלון שקט
--
-- מכשיר שדיווח כיבוי מסודר לא ייחשב מנותק במשך 12 שעות. ראה 8.1.

CREATE TABLE quiet_windows (
  device_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  until     timestamptz NOT NULL,
  reason    text NOT NULL,

  FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE
);
