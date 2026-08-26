import {
  bigint,
  bigserial,
  boolean,
  char,
  customType,
  index,
  integer,
  jsonb,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

/**
 * שיקוף מוטפס של הסכמה.
 *
 * מקור האמת הוא קובצי ה-SQL תחת migrations/. הקובץ הזה קיים כדי
 * לתת טיפוסים לשאילתות, ואינו מייצר DDL. כל שינוי במיגרציה מחייב
 * שינוי מקביל כאן, ולהפך.
 */

// ---------------------------------------------------------------- טיפוסים מותאמים

const bytea = customType<{ data: Buffer; driverData: Buffer }>({
  dataType: () => "bytea",
});

const citext = customType<{ data: string; driverData: string }>({
  dataType: () => "citext",
});

const inet = customType<{ data: string; driverData: string }>({
  dataType: () => "inet",
});

// ---------------------------------------------------------------- enums

export const tenantType = pgEnum("tenant_type", ["family", "organization", "individual"]);
export const tenantStatus = pgEnum("tenant_status", ["active", "suspended", "closed"]);

export const userRole = pgEnum("user_role", [
  "platform_admin",
  "support_operator",
  "tenant_owner",
  "tenant_member",
]);
export const userStatus = pgEnum("user_status", ["active", "disabled", "invited"]);

export const installProfile = pgEnum("install_profile", [
  "family_child",
  "individual",
  "organization",
]);
export const enforcementMode = pgEnum("enforcement_mode", ["monitor", "warn", "enforce"]);
export const redAction = pgEnum("red_action", ["none", "warn", "lockout"]);

export const deviceStatus = pgEnum("device_status", ["active", "uninstalled", "revoked"]);
export const securityStatus = pgEnum("security_status", [
  "unknown",
  "safe",
  "low_filter",
  "unfiltered",
  "blocked",
]);
export const deadManState = pgEnum("dead_man_state", [
  "healthy",
  "late",
  "missing",
  "offline",
  "tampered",
]);
export const trustLevel = pgEnum("trust_level", ["none", "low", "medium", "high"]);
export const uninstallStatus = pgEnum("uninstall_status", [
  "issued",
  "confirmed",
  "cancelled",
  "expired",
  "denied",
]);
export const alertState = pgEnum("alert_state", ["open", "notified", "resolved"]);
export const keyPurpose = pgEnum("key_purpose", ["policy", "uninstall", "loosening", "update"]);
export const actorType = pgEnum("actor_type", [
  "platform_user",
  "tenant_user",
  "device",
  "system",
]);

// ---------------------------------------------------------------- דיירים

export const tenants = pgTable("tenants", {
  id: uuid("id").primaryKey().defaultRandom(),
  type: tenantType("type").notNull(),
  name: text("name").notNull(),
  status: tenantStatus("status").notNull().default("active"),
  contactEmail: citext("contact_email"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const licenses = pgTable(
  "licenses",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    key: text("key").notNull().unique(),
    tenantId: uuid("tenant_id").references(() => tenants.id),
    maxDevices: integer("max_devices").notNull().default(1),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    status: text("status").notNull().default("active"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("licenses_tenant_idx").on(t.tenantId)],
);

// ---------------------------------------------------------------- משתמשים

export const users = pgTable(
  "users",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    /** null = משתמש פלטפורמה (צוות החברה) */
    tenantId: uuid("tenant_id").references(() => tenants.id, { onDelete: "cascade" }),
    email: citext("email").notNull().unique(),
    passwordHash: text("password_hash").notNull(),
    displayName: text("display_name"),
    role: userRole("role").notNull(),
    status: userStatus("status").notNull().default("invited"),
    mfaSecret: text("mfa_secret"),
    mfaEnrolledAt: timestamp("mfa_enrolled_at", { withTimezone: true }),
    lastLoginAt: timestamp("last_login_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("users_tenant_idx").on(t.tenantId)],
);

/** אימות עיוור. אין כאן PAN, אין CVV, אין ת"ז מלאה. ראה 7.2 באפיון. */
export const verificationProfiles = pgTable("verification_profiles", {
  tenantId: uuid("tenant_id")
    .primaryKey()
    .references(() => tenants.id, { onDelete: "cascade" }),
  idLast4Hash: bytea("id_last4_hash"),
  idSalt: bytea("id_salt"),
  idSetAt: timestamp("id_set_at", { withTimezone: true }),
  cardProcessor: text("card_processor"),
  cardToken: text("card_token"),
  cardLast4: char("card_last4", { length: 4 }),
  cardSetAt: timestamp("card_set_at", { withTimezone: true }),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

// ---------------------------------------------------------------- רישום מכשירים

export const enrollTokens = pgTable(
  "enroll_tokens",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    tokenHash: bytea("token_hash").notNull().unique(),
    installProfile: installProfile("install_profile").notNull(),
    enforcementMode: enforcementMode("enforcement_mode").notNull(),
    policyFloor: jsonb("policy_floor").notNull(),
    maxUses: integer("max_uses").notNull().default(1),
    uses: integer("uses").notNull().default(0),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    createdBy: uuid("created_by").references(() => users.id),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  },
  (t) => [index("enroll_tokens_tenant_idx").on(t.tenantId)],
);

export const deviceGroups = pgTable(
  "device_groups",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("device_groups_tenant_name_idx").on(t.tenantId, t.name)],
);

export const devices = pgTable(
  "devices",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    groupId: uuid("group_id").references(() => deviceGroups.id),
    hwid: text("hwid").notNull(),
    machineName: text("machine_name"),
    displayName: text("display_name"),
    osVersion: text("os_version"),
    agentVersion: text("agent_version"),
    installProfile: installProfile("install_profile").notNull(),
    enforcementMode: enforcementMode("enforcement_mode").notNull(),
    /** רצפת המדיניות שהמכשיר אוכף בעצמו. ראה 3.2.3. */
    policyFloor: jsonb("policy_floor").notNull(),
    policyFloorSignature: bytea("policy_floor_signature"),
    policyFloorKid: text("policy_floor_kid"),
    status: deviceStatus("status").notNull().default("active"),
    enrolledAt: timestamp("enrolled_at", { withTimezone: true }).notNull().defaultNow(),
    uninstalledAt: timestamp("uninstalled_at", { withTimezone: true }),
  },
  (t) => [
    uniqueIndex("devices_tenant_hwid_idx").on(t.tenantId, t.hwid),
    uniqueIndex("devices_id_tenant_idx").on(t.id, t.tenantId),
    index("devices_tenant_idx").on(t.tenantId),
    index("devices_hwid_idx").on(t.hwid),
  ],
);

export const deviceState = pgTable(
  "device_state",
  {
    deviceId: uuid("device_id").primaryKey(),
    tenantId: uuid("tenant_id").notNull(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }),
    lastStatus: securityStatus("last_status").notNull().default("unknown"),
    lastScore: integer("last_score"),
    detectedProvider: text("detected_provider"),
    publicIp: inet("public_ip"),
    wifiSsid: text("wifi_ssid"),
    lockoutActive: boolean("lockout_active").notNull().default(false),
    lockoutUntil: timestamp("lockout_until", { withTimezone: true }),
    health: deadManState("health").notNull().default("healthy"),
    wfpFilterCount: integer("wfp_filter_count"),
    policyVersion: integer("policy_version"),
    heartbeatSeq: bigint("heartbeat_seq", { mode: "number" }).notNull().default(0),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    index("device_state_tenant_idx").on(t.tenantId),
    index("device_state_health_idx").on(t.health, t.lastSeenAt),
  ],
);

export const deviceTokens = pgTable(
  "device_tokens",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    deviceId: uuid("device_id").notNull(),
    tenantId: uuid("tenant_id").notNull(),
    jti: text("jti").notNull().unique(),
    issuedAt: timestamp("issued_at", { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  },
  (t) => [
    index("device_tokens_device_idx").on(t.deviceId),
    index("device_tokens_tenant_idx").on(t.tenantId),
  ],
);

// ---------------------------------------------------------------- מפתחות ומדיניות

export const signingKeys = pgTable("signing_keys", {
  id: uuid("id").primaryKey().defaultRandom(),
  kid: text("kid").notNull().unique(),
  purpose: keyPurpose("purpose").notNull(),
  /** החלק הציבורי בלבד. הפרטי ב-KMS. */
  publicPem: text("public_pem").notNull(),
  kmsKeyId: text("kms_key_id").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  retiredAt: timestamp("retired_at", { withTimezone: true }),
});

export const policies = pgTable("policies", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").references(() => tenants.id, { onDelete: "cascade" }),
  version: integer("version").notNull(),
  body: jsonb("body").notNull(),
  /** הבתים המדויקים שנחתמו. הסוכן מאמת עליהם ואז מפרסר. ראה 5.2. */
  signedBytes: bytea("signed_bytes").notNull(),
  signature: bytea("signature").notNull(),
  signingKid: text("signing_kid").notNull(),
  etag: text("etag").notNull(),
  publishedAt: timestamp("published_at", { withTimezone: true }).notNull().defaultNow(),
  publishedBy: uuid("published_by").references(() => users.id),
});

export const devicePolicyAssignments = pgTable(
  "device_policy_assignments",
  {
    deviceId: uuid("device_id").primaryKey(),
    tenantId: uuid("tenant_id").notNull(),
    policyId: uuid("policy_id")
      .notNull()
      .references(() => policies.id),
    assignedAt: timestamp("assigned_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("device_policy_tenant_idx").on(t.tenantId)],
);

export const looseningGrants = pgTable(
  "loosening_grants",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    deviceId: uuid("device_id").notNull(),
    tenantId: uuid("tenant_id").notNull(),
    nonce: bytea("nonce").notNull(),
    fromFloor: jsonb("from_floor").notNull(),
    toFloor: jsonb("to_floor").notNull(),
    reason: text("reason").notNull(),
    approvedBy: uuid("approved_by")
      .notNull()
      .references(() => users.id),
    mfaVerifiedAt: timestamp("mfa_verified_at", { withTimezone: true }).notNull(),
    signature: bytea("signature").notNull(),
    signingKid: text("signing_kid").notNull(),
    issuedAt: timestamp("issued_at", { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    consumedAt: timestamp("consumed_at", { withTimezone: true }),
  },
  (t) => [
    uniqueIndex("loosening_grants_device_nonce_idx").on(t.deviceId, t.nonce),
    index("loosening_grants_tenant_idx").on(t.tenantId),
  ],
);

// ---------------------------------------------------------------- ספקי סינון

export const providers = pgTable("providers", {
  id: uuid("id").primaryKey().defaultRandom(),
  key: text("key").notNull().unique(),
  displayName: text("display_name").notNull(),
  trustLevel: trustLevel("trust_level").notNull().default("medium"),
  enabled: boolean("enabled").notNull().default(true),
  detection: jsonb("detection").notNull(),
  sortOrder: integer("sort_order").notNull().default(100),
  updatedBy: uuid("updated_by").references(() => users.id),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const providerHistory = pgTable(
  "provider_history",
  {
    id: bigserial("id", { mode: "number" }).primaryKey(),
    providerId: uuid("provider_id")
      .notNull()
      .references(() => providers.id, { onDelete: "cascade" }),
    detection: jsonb("detection").notNull(),
    trustLevel: trustLevel("trust_level").notNull(),
    enabled: boolean("enabled").notNull(),
    changedBy: uuid("changed_by").references(() => users.id),
    changedAt: timestamp("changed_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("provider_history_provider_idx").on(t.providerId, t.changedAt)],
);

// ---------------------------------------------------------------- טלמטריה

/** מחולקת לפי חודש ב-SQL. ראה 0004_telemetry.sql. */
export const heartbeats = pgTable(
  "heartbeats",
  {
    id: bigint("id", { mode: "number" }).notNull(),
    deviceId: uuid("device_id").notNull(),
    tenantId: uuid("tenant_id").notNull(),
    receivedAt: timestamp("received_at", { withTimezone: true }).notNull().defaultNow(),
    sentAt: timestamp("sent_at", { withTimezone: true }),
    sequence: bigint("sequence", { mode: "number" }).notNull(),
    status: securityStatus("status").notNull(),
    score: integer("score"),
    policyVersion: integer("policy_version"),
    lockoutActive: boolean("lockout_active").notNull().default(false),
    payload: jsonb("payload").notNull(),
  },
  (t) => [
    index("heartbeats_device_idx").on(t.deviceId, t.receivedAt),
    index("heartbeats_tenant_idx").on(t.tenantId, t.receivedAt),
  ],
);

export const events = pgTable(
  "events",
  {
    id: bigserial("id", { mode: "number" }).primaryKey(),
    deviceId: uuid("device_id").notNull(),
    tenantId: uuid("tenant_id").notNull(),
    kind: text("kind").notNull(),
    severity: text("severity").notNull().default("warning"),
    detail: text("detail"),
    occurredAt: timestamp("occurred_at", { withTimezone: true }).notNull(),
    receivedAt: timestamp("received_at", { withTimezone: true }).notNull().defaultNow(),
    acknowledgedBy: uuid("acknowledged_by").references(() => users.id),
    acknowledgedAt: timestamp("acknowledged_at", { withTimezone: true }),
  },
  (t) => [
    index("events_device_idx").on(t.deviceId, t.occurredAt),
    index("events_tenant_idx").on(t.tenantId, t.occurredAt),
  ],
);

export const alerts = pgTable(
  "alerts",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    deviceId: uuid("device_id").notNull(),
    tenantId: uuid("tenant_id").notNull(),
    kind: text("kind").notNull(),
    state: alertState("state").notNull().default("open"),
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull().defaultNow(),
    lastNotifiedAt: timestamp("last_notified_at", { withTimezone: true }),
    notifyCount: integer("notify_count").notNull().default(0),
    resolvedAt: timestamp("resolved_at", { withTimezone: true }),
  },
  (t) => [index("alerts_tenant_idx").on(t.tenantId, t.state)],
);

export const quietWindows = pgTable("quiet_windows", {
  deviceId: uuid("device_id").primaryKey(),
  tenantId: uuid("tenant_id").notNull(),
  until: timestamp("until", { withTimezone: true }).notNull(),
  reason: text("reason").notNull(),
});

// ---------------------------------------------------------------- הסרה וביקורת

export const uninstallRequests = pgTable(
  "uninstall_requests",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    deviceId: uuid("device_id").notNull(),
    tenantId: uuid("tenant_id").notNull(),
    challenge: text("challenge").notNull(),
    challengeNonce: bytea("challenge_nonce").notNull(),
    challengeIssuedAt: timestamp("challenge_issued_at", { withTimezone: true }).notNull(),
    idVerified: boolean("id_verified").notNull().default(false),
    cardVerified: boolean("card_verified").notNull().default(false),
    verificationAttempts: integer("verification_attempts").notNull().default(0),
    verificationLocked: boolean("verification_locked").notNull().default(false),
    operatorId: uuid("operator_id").references(() => users.id),
    reason: text("reason"),
    responseIssuedAt: timestamp("response_issued_at", { withTimezone: true }),
    /** חלון צינון: הקוד נכנס לתוקף רק כאן. ראה 7.5. */
    effectiveAt: timestamp("effective_at", { withTimezone: true }),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    cancelTokenHash: bytea("cancel_token_hash"),
    cancelledAt: timestamp("cancelled_at", { withTimezone: true }),
    cancelledBy: text("cancelled_by"),
    confirmedAt: timestamp("confirmed_at", { withTimezone: true }),
    status: uninstallStatus("status").notNull().default("issued"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex("uninstall_device_nonce_idx").on(t.deviceId, t.challengeNonce),
    index("uninstall_tenant_idx").on(t.tenantId, t.createdAt),
  ],
);

/** append-only. עדכון או מחיקה נדחים בטריגר. ראה 11.1. */
export const auditLog = pgTable(
  "audit_log",
  {
    id: bigserial("id", { mode: "number" }).primaryKey(),
    at: timestamp("at", { withTimezone: true }).notNull().defaultNow(),
    actorType: actorType("actor_type").notNull(),
    actorId: uuid("actor_id"),
    actorIp: inet("actor_ip"),
    action: text("action").notNull(),
    targetType: text("target_type"),
    targetId: uuid("target_id"),
    /** ללא מפתח זר במכוון: היומן שורד מחיקת דייר. ראה מיגרציה 0008. */
    tenantId: uuid("tenant_id"),
    payload: jsonb("payload").notNull(),
  },
  (t) => [
    index("audit_log_at_idx").on(t.at),
    index("audit_log_tenant_idx").on(t.tenantId, t.at),
    index("audit_log_action_idx").on(t.action, t.at),
  ],
);

// ---------------------------------------------------------------- הפעלות ואימות

export const sessions = pgTable(
  "sessions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    /** null עבור משתמשי פלטפורמה */
    tenantId: uuid("tenant_id").references(() => tenants.id, { onDelete: "cascade" }),
    /** ה-hash בלבד. האסימון עצמו לעולם אינו נשמר. */
    tokenHash: bytea("token_hash").notNull().unique(),
    csrfHash: bytea("csrf_hash").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    /** אימות שני טרי. פעולות רגישות דורשות אותו מחדש. ראה 3.2.4. */
    mfaVerifiedAt: timestamp("mfa_verified_at", { withTimezone: true }),
    ip: inet("ip"),
    userAgent: text("user_agent"),
  },
  (t) => [
    index("sessions_user_idx").on(t.userId, t.createdAt),
    index("sessions_tenant_idx").on(t.tenantId),
  ],
);

export const loginAttempts = pgTable(
  "login_attempts",
  {
    id: bigserial("id", { mode: "number" }).primaryKey(),
    email: citext("email").notNull(),
    ip: inet("ip"),
    at: timestamp("at", { withTimezone: true }).notNull().defaultNow(),
    success: boolean("success").notNull(),
    stage: text("stage").notNull().default("password"),
  },
  (t) => [
    index("login_attempts_email_idx").on(t.email, t.at),
    index("login_attempts_ip_idx").on(t.ip, t.at),
  ],
);
