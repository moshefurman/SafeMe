export type SecurityStatus = "unknown" | "safe" | "low_filter" | "unfiltered" | "blocked";

export type UserRole = "platform_admin" | "support_operator" | "tenant_owner" | "tenant_member";

export type TrialPhase =
  | "trial_active"
  | "trial_ending"
  | "grace"
  | "trial_expired"
  | "paid"
  | "canceled";

export interface TrialInfo {
  phase: TrialPhase;
  daysLeft: number;
  endsAt: string | null;
  headline: string;
  needsAttention: boolean;
}

export interface Me {
  userId: string;
  email: string;
  role: UserRole;
  tenantId: string | null;
  tenantName: string | null;
  displayName: string | null;
  mfaEnrolled: boolean;
  mfaVerifiedAt: string | null;
  trial: TrialInfo | null;
}

export interface DeviceRow {
  id: string;
  hwid: string;
  display_name: string | null;
  machine_name: string | null;
  install_profile: string;
  enforcement_mode: string;
  status: string;
  enrolled_at: string;
  tenant_id: string;
  tenant_name: string;
  last_seen_at: string | null;
  last_status: SecurityStatus | null;
  last_score: number | null;
  detected_provider: string | null;
  wifi_ssid: string | null;
  lockout_active: boolean | null;
  lockout_until: string | null;
  health: string | null;
  policy_version: number | null;
  wfp_filter_count: number | null;
  open_events: string;
}

export interface Summary {
  total: number;
  safe: number;
  lowFilter: number;
  unfiltered: number;
  blocked: number;
  offline: number;
}

export interface TimelineEntry {
  kind: "event" | "heartbeat" | "command";
  id: string;
  name: string;
  severity?: string;
  detail?: string | null;
  reason?: string | null;
  score?: number | null;
  at: string;
}

export interface Timeline {
  events: TimelineEntry[];
  heartbeats: TimelineEntry[];
  commands: TimelineEntry[];
}

export const STATUS_LABEL: Record<SecurityStatus, string> = {
  safe: "מוגן",
  low_filter: "סינון חלקי",
  unfiltered: "אינו מסונן",
  blocked: "חסום",
  unknown: "לא ידוע",
};

export const ROLE_LABEL: Record<UserRole, string> = {
  platform_admin: "מנהל מערכת",
  support_operator: "מוקד תמיכה",
  tenant_owner: "בעל חשבון",
  tenant_member: "צופה",
};

export const MODE_LABEL: Record<string, string> = {
  monitor: "ניטור בלבד",
  warn: "התראה בלבד",
  enforce: "אכיפה מלאה",
};

export const HEALTH_LABEL: Record<string, string> = {
  healthy: "תקין",
  late: "מאחר",
  missing: "לא מדווח",
  offline: "מנותק",
  tampered: "חשד לחבלה",
};

export const PROFILE_LABEL: Record<string, string> = {
  family_child: "מכשיר של ילד",
  individual: "אישי",
  organization: "ארגוני",
};

/** ניסוח יחסי בעברית, למשל "לפני 4 דקות". */
export function relativeTime(iso: string | null): string {
  if (!iso) return "מעולם לא";

  const seconds = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);

  if (seconds < 60) return "עכשיו";
  if (seconds < 3600) return `לפני ${Math.floor(seconds / 60)} דקות`;
  if (seconds < 86_400) return `לפני ${Math.floor(seconds / 3600)} שעות`;

  return `לפני ${Math.floor(seconds / 86_400)} ימים`;
}

export type NetworkApproval = "pending" | "approved" | "blocked";
export type NetworkPolicy = "strict" | "balanced" | "lenient";
export type HotspotConfidence = "none" | "possible" | "likely" | "certain";

export interface NetworkRow {
  id: string;
  ssid: string | null;
  gateway_ip: string | null;
  approval: NetworkApproval;
  detected_provider: string | null;
  hotspot_confidence: HotspotConfidence;
  hotspot_reasons: string[];
  first_seen_at: string;
  last_seen_at: string;
  note: string | null;
  session_count: string;
  total_seconds: string;
}

export interface NetworksResponse {
  networks: NetworkRow[];
  policy: NetworkPolicy;
}

export interface NetworkSessionRow {
  id: string;
  started_at: string;
  ended_at: string | null;
  outcome: string;
  ssid: string | null;
  approval: NetworkApproval;
  hotspot_confidence: HotspotConfidence;
}

export type EgressMode = "ispLevel" | "proxyEndpoint";

export interface EgressRule {
  enabled: boolean;
  mode: EgressMode;
  providerCidrs: string[];
  webPorts: number[];
  resolvers: string[];
  allowQuic: boolean;
  blockedPorts: { port: number; protocol: string; label: string }[];
  blockedCidrs: string[];
  blockedProcessNames: string[];
  blockInbound: boolean;
}

export interface EgressResponse {
  rule: EgressRule;
  version: number | null;
  description?: string;
}

export type BlockRuleKind = "ssid" | "gateway" | "category";

export interface BlockRuleRow {
  id: string;
  kind: BlockRuleKind;
  pattern: string;
  note: string | null;
  enabled: boolean;
  hit_count: number;
  last_hit_at: string | null;
  created_at: string;
}

export interface BlockRulesResponse {
  rules: BlockRuleRow[];
  categories: Record<string, string>;
}
