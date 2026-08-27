/**
 * מודל ההרשאות מפרק 3 באפיון, בקוד.
 *
 * המטריצה מוגדרת פעם אחת ונאכפת ברמת ה-API. ה-UI מסתיר כפתורים
 * לפי אותה מטריצה, אך ההסתרה אינה ההגנה — היא רק נימוס.
 */

export type UserRole = "platform_admin" | "support_operator" | "tenant_owner" | "tenant_member";

export type Permission =
  | "tenants.viewAll"
  | "devices.viewOwn"
  | "devices.lockout"
  | "devices.audit"
  | "enrollTokens.create"
  /* אישור רשת חדשה. הרשאה נפרדת מ-policy.tighten, כי היא מתירה
     ולא מחמירה — וכל מה שמתיר מקבל שער משלו. */
  | "networks.approve"
  | "policy.tighten"
  | "policy.loosenWithinSandbox"
  | "policy.lowerFloor"
  | "uninstall.issueCode"
  | "providers.manage"
  | "licenses.manage"
  | "auditLog.viewAll"
  | "auditLog.viewOwn";

const MATRIX: Record<UserRole, ReadonlySet<Permission>> = {
  platform_admin: new Set<Permission>([
    "tenants.viewAll",
    "devices.viewOwn",
    "devices.lockout",
    "devices.audit",
    "enrollTokens.create",
    "networks.approve",
    "policy.tighten",
    "policy.loosenWithinSandbox",
    "policy.lowerFloor",
    "uninstall.issueCode",
    "providers.manage",
    "licenses.manage",
    "auditLog.viewAll",
    "auditLog.viewOwn",
  ]),

  // המוקד רואה הכול ומנפיק קודי הסרה, אך אינו נוגע במדיניות.
  // הפרדה זו מצמצמת את הנזק מחשבון מוקדן שנפרץ.
  support_operator: new Set<Permission>([
    "tenants.viewAll",
    "devices.viewOwn",
    "devices.lockout",
    "devices.audit",
    "uninstall.issueCode",
    "auditLog.viewOwn",
  ]),

  tenant_owner: new Set<Permission>([
    "devices.viewOwn",
    "devices.lockout",
    "devices.audit",
    "enrollTokens.create",
    "networks.approve",
    "policy.tighten",
    "policy.loosenWithinSandbox",
    "auditLog.viewOwn",
  ]),

  tenant_member: new Set<Permission>(["devices.viewOwn", "auditLog.viewOwn"]),
};

/**
 * הרשאות שדורשות אימות שני טרי, ולא רק הפעלה שנפתחה עם MFA.
 *
 * ההיגיון: הנזק מהן בלתי הפיך או קרוב לכך, ולכן שווה את החיכוך
 * של הקלדת קוד נוסף גם למשתמש שכבר מחובר.
 */
const REQUIRES_FRESH_MFA = new Set<Permission>([
  "policy.lowerFloor",
  "uninstall.issueCode",
  "providers.manage",
]);

/** משך הזמן שבו אימות שני נחשב טרי. */
export const FRESH_MFA_WINDOW_MS = 5 * 60 * 1000;

export function isPlatformRole(role: UserRole): boolean {
  return role === "platform_admin" || role === "support_operator";
}

export function can(role: UserRole, permission: Permission): boolean {
  return MATRIX[role].has(permission);
}

export function requiresFreshMfa(permission: Permission): boolean {
  return REQUIRES_FRESH_MFA.has(permission);
}

export interface AuthorizationOutcome {
  allowed: boolean;
  /** true כשההרשאה קיימת אך נדרש אימות שני מחדש. */
  needsMfa: boolean;
  reason: string;
}

/**
 * ההכרעה המלאה: תפקיד, טריות האימות השני, ובידוד דיירים.
 *
 * שים לב לסדר: בדיקת השיוך לדייר קודמת לבדיקת ה-MFA. אחרת משתמש
 * היה לומד מהתשובה שהמשאב קיים אצל דייר אחר.
 */
export function authorize(input: {
  role: UserRole;
  permission: Permission;
  mfaVerifiedAt: Date | null;
  now?: Date;
  /** הדייר שהמשאב שייך לו, כשהפעולה מתייחסת למשאב מסוים. */
  resourceTenantId?: string | null;
  /** הדייר של המשתמש. null עבור משתמשי פלטפורמה. */
  userTenantId?: string | null;
}): AuthorizationOutcome {
  const deny = (reason: string): AuthorizationOutcome => ({
    allowed: false,
    needsMfa: false,
    reason,
  });

  if (!can(input.role, input.permission)) {
    return deny("אין הרשאה לפעולה זו.");
  }

  if (
    input.resourceTenantId !== undefined &&
    input.resourceTenantId !== null &&
    !isPlatformRole(input.role) &&
    input.resourceTenantId !== input.userTenantId
  ) {
    // אותה הודעה בדיוק כמו חוסר הרשאה, כדי לא לאשר קיום משאב
    return deny("אין הרשאה לפעולה זו.");
  }

  if (requiresFreshMfa(input.permission)) {
    const now = input.now ?? new Date();

    const fresh =
      input.mfaVerifiedAt !== null &&
      now.getTime() - input.mfaVerifiedAt.getTime() <= FRESH_MFA_WINDOW_MS;

    if (!fresh) {
      return {
        allowed: false,
        needsMfa: true,
        reason: "הפעולה דורשת אימות דו-שלבי מחדש.",
      };
    }
  }

  return { allowed: true, needsMfa: false, reason: "" };
}
