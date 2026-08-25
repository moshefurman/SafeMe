-- ============================================================================
--  SafeMe · 0005 · בקשות הסרה ויומן ביקורת
--
--  שתי הטבלאות הרגישות ביותר. uninstall_requests היא הנתיב היחיד לכיבוי
--  ההגנה, ו-audit_log הוא הראיה שהנתיב הזה לא נוצל לרעה.
-- ============================================================================

-- ---------------------------------------------------------------- בקשות הסרה

CREATE TABLE uninstall_requests (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id       uuid NOT NULL,
  tenant_id       uuid NOT NULL,

  challenge       text  NOT NULL,
  challenge_nonce bytea NOT NULL,
  challenge_issued_at timestamptz NOT NULL,

  -- אימות עיוור (7.1). נשמרות רק התוצאות, לא מה שהוקלד.
  id_verified          boolean NOT NULL DEFAULT false,
  card_verified        boolean NOT NULL DEFAULT false,
  verification_attempts int    NOT NULL DEFAULT 0,
  verification_locked   boolean NOT NULL DEFAULT false,

  operator_id     uuid REFERENCES users(id) ON DELETE RESTRICT,
  reason          text,

  -- חלון צינון (7.5): הקוד נמסר מיד אך נכנס לתוקף רק ב-effective_at.
  response_issued_at timestamptz,
  effective_at       timestamptz,
  expires_at         timestamptz,

  -- אסימון הביטול שנשלח בקישור במייל להורה. נשמר כ-hash בלבד.
  cancel_token_hash bytea,
  cancelled_at      timestamptz,
  cancelled_by      text,        -- 'tenant_owner' | 'platform' | 'system'

  confirmed_at    timestamptz,   -- המכשיר דיווח שההסרה בוצעה
  status          uninstall_status NOT NULL DEFAULT 'issued',
  created_at      timestamptz NOT NULL DEFAULT now(),

  UNIQUE (device_id, challenge_nonce),
  FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE,

  -- חלון הצינון אינו ניתן לקיצור. ראה 7.5.
  CONSTRAINT uninstall_cooldown_30m CHECK (
    effective_at IS NULL OR response_issued_at IS NULL OR
    effective_at >= response_issued_at + interval '30 minutes'
  ),

  -- קוד נמסר רק לאחר ששני האימותים עברו.
  CONSTRAINT uninstall_requires_verification CHECK (
    response_issued_at IS NULL OR (id_verified AND card_verified)
  ),

  CONSTRAINT uninstall_attempts_cap CHECK (verification_attempts <= 3)
);

CREATE INDEX uninstall_device_idx  ON uninstall_requests (device_id, created_at DESC);
CREATE INDEX uninstall_tenant_idx  ON uninstall_requests (tenant_id, created_at DESC);
CREATE INDEX uninstall_pending_idx ON uninstall_requests (status, effective_at)
  WHERE status = 'issued';

COMMENT ON COLUMN uninstall_requests.verification_attempts IS
  'שלושה ניסיונות לשיחה. מעבר לכך verification_locked והסלמה לאחראי משמרת.';

-- ---------------------------------------------------------------- יומן ביקורת
--
-- append-only. שתי שכבות הגנה: שלילת הרשאות מהאפליקציה, וטריגר שמסרב
-- לכל UPDATE או DELETE גם אם מישהו יקבל הרשאה בטעות. ראה 11.1.

CREATE TABLE audit_log (
  id          bigserial PRIMARY KEY,
  at          timestamptz NOT NULL DEFAULT now(),

  actor_type  actor_type NOT NULL,
  actor_id    uuid,
  actor_ip    inet,

  action      text NOT NULL,
  target_type text,
  target_id   uuid,
  tenant_id   uuid REFERENCES tenants(id) ON DELETE SET NULL,

  payload     jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX audit_log_at_idx     ON audit_log (at DESC);
CREATE INDEX audit_log_tenant_idx ON audit_log (tenant_id, at DESC);
CREATE INDEX audit_log_action_idx ON audit_log (action, at DESC);
CREATE INDEX audit_log_actor_idx  ON audit_log (actor_id, at DESC);

CREATE OR REPLACE FUNCTION app.audit_log_is_immutable()
RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_log הוא append-only: % נדחה', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END
$$;

CREATE TRIGGER audit_log_no_update
  BEFORE UPDATE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION app.audit_log_is_immutable();

CREATE TRIGGER audit_log_no_delete
  BEFORE DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION app.audit_log_is_immutable();

COMMENT ON TABLE audit_log IS
  'append-only. ניסיון UPDATE או DELETE נכשל בטריגר, גם עבור בעל הסכמה.';
