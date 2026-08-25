-- ============================================================================
--  SafeMe · 0003 · טבלאות הליבה
--
--  סטייה מודעת מפרק 4 באפיון: כל טבלה שתלויה בדייר נושאת tenant_id ישירות,
--  גם כשאפשר היה להסיק אותו דרך device_id. הסיבה כפולה — מדיניות RLS הופכת
--  להשוואה אחת בלי תת-שאילתה, וגם החלוקה לפי זמן נשארת יעילה.
--  המחיר: חובה לשמור על עקביות, ולכן יש מפתח זר מורכב (device_id, tenant_id).
-- ============================================================================

-- ---------------------------------------------------------------- דיירים

CREATE TABLE tenants (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  type          tenant_type   NOT NULL,
  name          text          NOT NULL,
  status        tenant_status NOT NULL DEFAULT 'active',
  contact_email citext,
  created_at    timestamptz   NOT NULL DEFAULT now(),
  updated_at    timestamptz   NOT NULL DEFAULT now()
);

CREATE TABLE licenses (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  key         text UNIQUE NOT NULL,
  tenant_id   uuid REFERENCES tenants(id) ON DELETE SET NULL,
  max_devices int  NOT NULL DEFAULT 1 CHECK (max_devices > 0),
  expires_at  timestamptz,
  status      text NOT NULL DEFAULT 'active',
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX licenses_tenant_idx ON licenses (tenant_id);

-- ---------------------------------------------------------------- משתמשים

CREATE TABLE users (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- NULL = משתמש פלטפורמה (צוות החברה). ראה 2.1 באפיון.
  tenant_id       uuid REFERENCES tenants(id) ON DELETE CASCADE,
  email           citext UNIQUE NOT NULL,
  password_hash   text NOT NULL,
  display_name    text,
  role            user_role   NOT NULL,
  status          user_status NOT NULL DEFAULT 'invited',
  mfa_secret      text,
  mfa_enrolled_at timestamptz,
  last_login_at   timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),

  -- תפקידי פלטפורמה אינם שייכים לדייר, ותפקידי דייר חייבים דייר.
  CONSTRAINT users_role_scope CHECK (
    (role IN ('platform_admin', 'support_operator') AND tenant_id IS NULL) OR
    (role IN ('tenant_owner', 'tenant_member')      AND tenant_id IS NOT NULL)
  ),

  -- 2FA אינו אופציונלי לצוות החברה. ראה 3.2.4.
  CONSTRAINT users_platform_requires_mfa CHECK (
    role NOT IN ('platform_admin', 'support_operator')
    OR status <> 'active'
    OR mfa_enrolled_at IS NOT NULL
  )
);

CREATE INDEX users_tenant_idx ON users (tenant_id);

-- ---------------------------------------------------------------- אימות זהות
--
-- הנתונים שמשמשים לאימות העיוור בעת הנפקת קוד הסרה (7.1).
--
-- אזהרה רגולטורית שמעוגנת כאן במבנה עצמו:
--   * אין ולא יהיה עמודה למספר כרטיס מלא (PAN) או ל-CVV.
--   * תעודת הזהות נשמרת כ-4 ספרות אחרונות בלבד, ורק כ-hash עם salt ייחודי.
-- מי שיוסיף כאן עמודת pan או id_number שובר את 7.2 ומכניס את המערכת
-- לתחולת PCI DSS ולחובות חוק הגנת הפרטיות.

CREATE TABLE verification_profiles (
  tenant_id     uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,

  id_last4_hash bytea,          -- sha256(salt || 4 ספרות אחרונות של ת"ז)
  id_salt       bytea,
  id_set_at     timestamptz,

  card_processor text,          -- cardcom | tranzila | stripe
  card_token     text,          -- טוקן מספק הסליקה. אינו מאפשר חיוב עצמאי.
  card_last4     char(4),
  card_set_at    timestamptz,

  updated_at    timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT verification_card_last4_digits CHECK (card_last4 ~ '^[0-9]{4}$'),
  CONSTRAINT verification_id_pair CHECK (
    (id_last4_hash IS NULL AND id_salt IS NULL) OR
    (id_last4_hash IS NOT NULL AND id_salt IS NOT NULL)
  )
);

COMMENT ON TABLE verification_profiles IS
  'אימות עיוור להנפקת קוד הסרה. אסור להוסיף כאן PAN, CVV או ת"ז מלאה.';

-- ---------------------------------------------------------------- אסימוני רישום

CREATE TABLE enroll_tokens (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  -- נשמר כ-hash בלבד. האסימון הגולמי מוצג פעם אחת ליוצר ואינו נשמר.
  token_hash       bytea UNIQUE NOT NULL,
  install_profile  install_profile  NOT NULL,
  enforcement_mode enforcement_mode NOT NULL,
  policy_floor     jsonb NOT NULL,
  max_uses         int NOT NULL DEFAULT 1 CHECK (max_uses > 0),
  uses             int NOT NULL DEFAULT 0 CHECK (uses >= 0),
  expires_at       timestamptz NOT NULL,
  created_by       uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  revoked_at       timestamptz,

  CONSTRAINT enroll_tokens_uses_within_limit CHECK (uses <= max_uses)
);

CREATE INDEX enroll_tokens_tenant_idx ON enroll_tokens (tenant_id);

-- ---------------------------------------------------------------- מכשירים

CREATE TABLE device_groups (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name       text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),

  UNIQUE (tenant_id, name)
);

CREATE TABLE devices (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  group_id         uuid REFERENCES device_groups(id) ON DELETE SET NULL,

  hwid             text NOT NULL,
  machine_name     text,
  display_name     text,
  os_version       text,
  agent_version    text,

  install_profile  install_profile  NOT NULL,
  -- ערך ראשוני מההתקנה. החמרה מרחוק מותרת, הקלה מתחת לרצפה אינה. ראה 3.2.
  enforcement_mode enforcement_mode NOT NULL,

  -- רצפת המדיניות שהמכשיר אוכף. נשלחת אליו חתומה והוא מאמת אותה בעצמו.
  policy_floor           jsonb NOT NULL,
  policy_floor_signature bytea,
  policy_floor_kid       text,

  status           device_status NOT NULL DEFAULT 'active',
  enrolled_at      timestamptz NOT NULL DEFAULT now(),
  uninstalled_at   timestamptz,

  UNIQUE (tenant_id, hwid),
  -- מאפשר מפתח זר מורכב מטבלאות הבת, כדי ש-tenant_id לא יוכל להתפצל
  UNIQUE (id, tenant_id)
);

CREATE INDEX devices_tenant_idx ON devices (tenant_id);
CREATE INDEX devices_hwid_idx   ON devices (hwid);
CREATE INDEX devices_group_idx  ON devices (group_id);

-- שורה אחת למכשיר. נכתבת בכל פעימה ומשמשת את הדשבורד ואת ה-Dead Man's Switch.
CREATE TABLE device_state (
  device_id         uuid PRIMARY KEY,
  tenant_id         uuid NOT NULL,

  last_seen_at      timestamptz,
  last_status       security_status NOT NULL DEFAULT 'unknown',
  last_score        int CHECK (last_score BETWEEN 0 AND 100),
  detected_provider text,
  public_ip         inet,
  wifi_ssid         text,

  lockout_active    boolean NOT NULL DEFAULT false,
  lockout_until     timestamptz,
  health            dead_man_state NOT NULL DEFAULT 'healthy',

  wfp_filter_count  int,
  policy_version    int,
  heartbeat_seq     bigint NOT NULL DEFAULT 0,
  updated_at        timestamptz NOT NULL DEFAULT now(),

  FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX device_state_tenant_idx ON device_state (tenant_id);
CREATE INDEX device_state_health_idx ON device_state (health, last_seen_at);

CREATE TABLE device_tokens (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id  uuid NOT NULL,
  tenant_id  uuid NOT NULL,
  jti        text UNIQUE NOT NULL,
  issued_at  timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,

  FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX device_tokens_device_idx ON device_tokens (device_id);
CREATE INDEX device_tokens_tenant_idx ON device_tokens (tenant_id);

-- ---------------------------------------------------------------- מפתחות חתימה
--
-- רק החלק הציבורי. המפתח הפרטי חי ב-KMS ואינו יוצא משם. ראה 11.1.

CREATE TABLE signing_keys (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kid        text UNIQUE NOT NULL,
  purpose    key_purpose NOT NULL,
  public_pem text NOT NULL,
  kms_key_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz
);

COMMENT ON TABLE signing_keys IS
  'חלק ציבורי בלבד. אין ולא תהיה כאן עמודה למפתח פרטי.';

-- מפתח פעיל אחד לכל ייעוד בכל רגע נתון
CREATE UNIQUE INDEX signing_keys_active_purpose_idx
  ON signing_keys (purpose) WHERE retired_at IS NULL;

-- ---------------------------------------------------------------- מדיניות

CREATE TABLE policies (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- NULL = תבנית גלובלית שאינה שייכת לאף דייר
  tenant_id    uuid REFERENCES tenants(id) ON DELETE CASCADE,
  version      int  NOT NULL,
  body         jsonb NOT NULL,

  -- הבתים המדויקים שנחתמו. הסוכן מאמת עליהם ואז מפרסר. ראה 5.2.
  signed_bytes bytea NOT NULL,
  signature    bytea NOT NULL,
  signing_kid  text  NOT NULL REFERENCES signing_keys(kid),
  etag         text  NOT NULL,

  published_at timestamptz NOT NULL DEFAULT now(),
  published_by uuid REFERENCES users(id) ON DELETE SET NULL
);

-- גרסה ייחודית לכל דייר. אינדקס חלקי כי NULL אינו שווה ל-NULL.
CREATE UNIQUE INDEX policies_tenant_version_idx
  ON policies (tenant_id, version) WHERE tenant_id IS NOT NULL;

CREATE UNIQUE INDEX policies_global_version_idx
  ON policies (version) WHERE tenant_id IS NULL;

CREATE TABLE device_policy_assignments (
  device_id   uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL,
  policy_id   uuid NOT NULL REFERENCES policies(id) ON DELETE RESTRICT,
  assigned_at timestamptz NOT NULL DEFAULT now(),

  FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX device_policy_tenant_idx ON device_policy_assignments (tenant_id);

-- ---------------------------------------------------------------- היתרי הקלה
--
-- ירידה מתחת לרצפה. היתר אחד לכל מכשיר, חד-פעמי, חלון זמן קצר. ראה 3.2.3.

CREATE TABLE loosening_grants (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id     uuid NOT NULL,
  tenant_id     uuid NOT NULL,

  nonce         bytea NOT NULL,
  from_floor    jsonb NOT NULL,
  to_floor      jsonb NOT NULL,
  reason        text  NOT NULL,

  approved_by   uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  mfa_verified_at timestamptz NOT NULL,

  signature     bytea NOT NULL,
  signing_kid   text  NOT NULL REFERENCES signing_keys(kid),

  issued_at     timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  consumed_at   timestamptz,

  UNIQUE (device_id, nonce),
  FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX loosening_grants_tenant_idx ON loosening_grants (tenant_id);
CREATE INDEX loosening_grants_issued_idx ON loosening_grants (issued_at DESC);

-- ---------------------------------------------------------------- ספקי סינון

CREATE TABLE providers (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  key          text UNIQUE NOT NULL,
  display_name text NOT NULL,
  trust_level  trust_level NOT NULL DEFAULT 'medium',
  enabled      boolean NOT NULL DEFAULT true,
  -- תעודות שורש, CIDR, ASN, תבניות rDNS וכותרות HTTP. ראה פרק 9.
  detection    jsonb NOT NULL DEFAULT '{}'::jsonb,
  sort_order   int NOT NULL DEFAULT 100,
  updated_by   uuid REFERENCES users(id) ON DELETE SET NULL,
  updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE provider_history (
  id          bigserial PRIMARY KEY,
  provider_id uuid NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
  detection   jsonb NOT NULL,
  trust_level trust_level NOT NULL,
  enabled     boolean NOT NULL,
  changed_by  uuid REFERENCES users(id) ON DELETE SET NULL,
  changed_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX provider_history_provider_idx ON provider_history (provider_id, changed_at DESC);
