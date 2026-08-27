/**
 * כלל ה-default-deny, כפי שהשרת מנסח אותו.
 *
 * ההיפוך מול הגישה הקודמת: במקום לחסום את מה שידענו לזהות כרע
 * ולהתיר את השאר, מתירים את מה שדפדוף מסונן צריך וחוסמים את השאר.
 * רשימת כלי עקיפה תמיד מפגרת אחרי הכלי הבא — היא נכתבת רק אחרי
 * שהוא כבר בשימוש.
 *
 * מה שנכתב כאן חייב להתאים לְמה ש-EgressPlanner ב-C# מצפה לו.
 * ההתאמה נבדקת דרך shared/test-vectors.json, ולא בעין.
 */

export type ProviderEgressMode = "ispLevel" | "proxyEndpoint";

export interface PortBlock {
  port: number;
  protocol: "tcp" | "udp" | "any";
  label: string;
}

export interface EgressRule {
  enabled: boolean;
  mode: ProviderEgressMode;
  providerCidrs: string[];
  webPorts: number[];
  resolvers: string[];
  allowQuic: boolean;
  blockedPorts: PortBlock[];
  blockedCidrs: string[];
  blockedProcessNames: string[];
  blockInbound: boolean;
}

/**
 * שרתי DNS-over-HTTPS.
 *
 * הם הפרצה שקשה לראות: הדפדפן פונה אליהם ב-443 רגיל, ולכן חסימת
 * פורטים אינה נוגעת בהם. מי שמפעיל את ההגדרה הזו בדפדפן מפסיק
 * להשתמש בשרת השמות של הספק, וכל הסינון מבוסס-השמות נעלם.
 *
 * הרשימה כאן מכסה את הגדולים, שהם גם ברירות המחדל של הדפדפנים.
 */
const DOH_RESOLVERS: string[] = [
  // Cloudflare
  "1.1.1.1/32",
  "1.0.0.1/32",
  "2606:4700:4700::1111/128",
  "2606:4700:4700::1001/128",

  // Google
  "8.8.8.8/32",
  "8.8.4.4/32",
  "2001:4860:4860::8888/128",
  "2001:4860:4860::8844/128",

  // Quad9
  "9.9.9.9/32",
  "149.112.112.112/32",

  // AdGuard
  "94.140.14.14/32",
  "94.140.15.15/32",

  // OpenDNS
  "208.67.222.222/32",
  "208.67.220.220/32",
];

/**
 * הפורטים שנחסמים בשם.
 *
 * החסימה הכללית מכסה אותם ממילא. הם נרשמים בכל זאת כי הם גוברים
 * גם על היתר רחב שנוסף בטעות, וכי הם נותנים שם לחסימה ביומן —
 * "OpenVPN" ולא "פורט 1194".
 *
 * זהה ל-BaselineBlockedPorts ב-C#. הבדל בין השניים נתפס בווקטורים.
 */
export const BASELINE_BLOCKED_PORTS: PortBlock[] = [
  { port: 22, protocol: "tcp", label: "SSH — משמש למנהור" },
  { port: 500, protocol: "udp", label: "IPsec IKE" },
  { port: 853, protocol: "any", label: "DNS מוצפן (DoT)" },
  { port: 1194, protocol: "any", label: "OpenVPN" },
  { port: 1701, protocol: "any", label: "L2TP" },
  { port: 1723, protocol: "tcp", label: "PPTP" },
  { port: 3389, protocol: "any", label: "שולחן עבודה מרוחק" },
  { port: 4500, protocol: "udp", label: "IPsec NAT-T" },
  { port: 5900, protocol: "tcp", label: "VNC" },
  { port: 5938, protocol: "any", label: "TeamViewer" },
  { port: 9001, protocol: "tcp", label: "Tor" },
  { port: 9050, protocol: "tcp", label: "Tor SOCKS" },
  { port: 51820, protocol: "udp", label: "WireGuard" },
];

export interface EgressOptions {
  enabled?: boolean;
  mode?: ProviderEgressMode;
  providerCidrs?: string[];
  resolvers?: string[];
  allowQuic?: boolean;
  extraBlockedProcesses?: string[];
  extraBlockedCidrs?: string[];
}

/**
 * בונה את הכלל.
 *
 * QUIC סגור כברירת מחדל. הוא מוצפן כולל הכותרות, ולכן חלק
 * ממנגנוני הסינון אינם רואים לתוכו; כשהוא חסום הדפדפן נופל
 * אחורה ל-TCP, שהסינון כן קורא.
 */
export function buildEgressRule(options: EgressOptions = {}): EgressRule {
  return {
    enabled: options.enabled ?? false,
    mode: options.mode ?? "ispLevel",
    providerCidrs: [...(options.providerCidrs ?? [])],
    webPorts: [80, 443],
    resolvers: [...(options.resolvers ?? [])],
    allowQuic: options.allowQuic ?? false,
    blockedPorts: BASELINE_BLOCKED_PORTS.map((p) => ({ ...p })),
    blockedCidrs: [...DOH_RESOLVERS, ...(options.extraBlockedCidrs ?? [])],
    blockedProcessNames: [...(options.extraBlockedProcesses ?? [])],
    blockInbound: true,
  };
}

/**
 * מסביר מה הכלל עושה, בשפה שהורה קורא.
 *
 * מוצג בפורטל ליד ההגדרה. הגדרת אבטחה שאיש אינו מבין מה היא עושה
 * היא הגדרה שיכבו בפעם הראשונה שמשהו לא עובד.
 */
export function describeEgress(rule: EgressRule): string {
  if (!rule.enabled) return "כבוי. הסוכן חוסם רק כשמשהו חורג.";

  if (rule.mode === "proxyEndpoint") {
    return rule.providerCidrs.length === 0
      ? "מוגדר לשרתי ספק, אך לא הוזנו כתובות. המכשירים יינעלו."
      : `המחשב יוצא רק אל שרתי הספק (${rule.providerCidrs.length} טווחים). זו הצורה החזקה.`;
  }

  const quic = rule.allowQuic ? "" : " QUIC חסום כדי שהסינון יראה את התעבורה.";

  return (
    "מותרים גלישה רגילה ושרתי השמות של הספק בלבד. " +
    "VPN, שולחן עבודה מרוחק, ומנהרות — חסומים." +
    quic
  );
}
