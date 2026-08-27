import { createHash } from "node:crypto";

import {
  classifyHotspot,
  normalizeMac,
  type HotspotVerdict,
  type NetworkFingerprint,
} from "./hotspot.ts";

/**
 * מה לעשות עם הרשת שהמכשיר מחובר אליה.
 *
 * העיקרון זהה לשאר המוצר: רשת חדשה אינה מאושרת, ולהתיר צריך פעולה
 * מפורשת. מה שמייחד את הרשתות הוא דרגת ביניים שהגיונית — רשת חדשה
 * שכבר עוברת דרך ספק סינון מאושר אינה סיכון, וחסימתה רק מרגילה את
 * ההורה לאשר בלי לקרוא.
 */

export type NetworkPolicy = "strict" | "balanced" | "lenient";
export type NetworkApproval = "pending" | "approved" | "blocked";

export type NetworkAction = "allow" | "block" | "await_approval";

export interface NetworkDecision {
  action: NetworkAction;
  /** האם לרשום את הרשת כמאושרת אוטומטית. */
  autoApprove: boolean;
  /** האם ההורה צריך לקבל התראה. */
  notify: boolean;
  reason: string;
  hotspot: HotspotVerdict;
}

export interface NetworkContext extends NetworkFingerprint {
  policy: NetworkPolicy;
  /** מה שידוע על הרשת מקודם. null אם היא חדשה. */
  approval: NetworkApproval | null;
  /** ספק הסינון שזוהה, אם זוהה. */
  detectedProvider?: string | null;
}

/**
 * טביעת אצבע יציבה לרשת.
 *
 * כתובת החומרה של השער היא הבסיס: היא מזהה את הנתב הפיזי, ואינה
 * משתנה כשמישהו משנה את שם הרשת. כשהיא אינה זמינה — או כשהיא
 * מוגרלת ולכן חסרת ערך לזיהוי — נופלים לשם ולשער.
 *
 * הערך מגובב כדי שיהיה באורך קבוע ושלא יחשוף את מבנה הרשת בכתובת
 * או ביומן.
 */
export function fingerprintOf(network: NetworkFingerprint): string {
  const mac = network.gatewayMac ? normalizeMac(network.gatewayMac) : null;

  const material = mac !== null
    ? `mac:${mac}`
    : `net:${(network.ssid ?? "").trim().toLowerCase()}|${(network.gatewayIp ?? "").trim()}`;

  return createHash("sha256").update(material, "utf8").digest("hex").slice(0, 32);
}

/**
 * מכריע מה לעשות.
 *
 * סדר הבדיקות הוא הכלל: חסימה מפורשת גוברת על הכול, אחריה נקודה
 * חמה ודאית, ורק אז המדיניות. אישור קודם אינו מבטל זיהוי של נקודה
 * חמה — מכשיר שאושר פעם אחת כשהיה מחובר לנתב לא הופך כל רשת עתידית
 * עם אותה טביעה למותרת.
 */
export function decideNetwork(context: NetworkContext): NetworkDecision {
  const hotspot = classifyHotspot(context);

  // ---- 1. חסימה מפורשת ----
  //
  // ההורה חסם את הרשת הזו במפורש. שום שיקול אחר לא גובר על זה.
  if (context.approval === "blocked") {
    return {
      action: "block",
      autoApprove: false,
      notify: false,
      reason: "הרשת נחסמה על ידי מנהל החשבון.",
      hotspot,
    };
  }

  // ---- 2. נקודה חמה ודאית ----
  //
  // נחסמת בכל המדיניות, גם אם אושרה בעבר. שיתוף אינטרנט מטלפון
  // לעולם אינו מסונן, וזו דרך העקיפה השכיחה ביותר.
  if (hotspot.confidence === "certain") {
    return {
      action: "block",
      autoApprove: false,
      notify: true,
      reason: hotspot.summary,
      hotspot,
    };
  }

  // ---- 3. רשת מאושרת ----
  if (context.approval === "approved") {
    return {
      action: "allow",
      autoApprove: false,
      notify: false,
      reason: "רשת מאושרת.",
      hotspot,
    };
  }

  // ---- 4. רשת חדשה, לפי המדיניות ----

  const filtered = isFiltered(context.detectedProvider);

  if (context.policy === "lenient") {
    return {
      action: "allow",
      autoApprove: false,
      notify: true,
      reason: filtered
        ? `רשת חדשה, מסוננת דרך ${context.detectedProvider}. מותרת לפי ההגדרה.`
        : "רשת חדשה שאינה מסוננת. מותרת לפי ההגדרה, ונשלחה התראה.",
      hotspot,
    };
  }

  if (context.policy === "balanced" && filtered) {
    return {
      action: "allow",
      autoApprove: true,
      notify: true,
      reason: `רשת חדשה, מסוננת דרך ${context.detectedProvider}. אושרה אוטומטית.`,
      hotspot,
    };
  }

  // strict, או balanced עם רשת שאינה מסוננת
  return {
    action: "await_approval",
    autoApprove: false,
    notify: true,
    reason: filtered
      ? "רשת חדשה. ממתינה לאישור מנהל החשבון."
      : "רשת חדשה שאינה עוברת דרך ספק סינון מאושר. ממתינה לאישור.",
    hotspot,
  };
}

/**
 * האם הרשת עוברת דרך ספק סינון.
 *
 * הערך מגיע מהסוכן, שקבע אותו מארבעה וקטורי זיהוי בלתי תלויים.
 * ריק פירושו שלא זוהה ספק — ולא שאין ספק.
 */
function isFiltered(provider: string | null | undefined): boolean {
  return typeof provider === "string" && provider.trim() !== "";
}

/** נוסח לתצוגה ולהתראה. */
export function describeDecision(decision: NetworkDecision, ssid?: string | null): string {
  const name = ssid?.trim() ? `"${ssid.trim()}"` : "רשת ללא שם";

  switch (decision.action) {
    case "block":
      return `${name} נחסמה. ${decision.reason}`;

    case "await_approval":
      return `${name} ממתינה לאישורך. ${decision.reason}`;

    default:
      return `${name}: ${decision.reason}`;
  }
}
