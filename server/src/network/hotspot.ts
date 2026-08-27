/**
 * זיהוי נקודה חמה סלולרית.
 *
 * זו דרך העקיפה מספר אחת: מדליקים שיתוף אינטרנט בטלפון, מחברים את
 * המחשב, וגולשים דרך הסלולר בלי סינון. שלוש שניות, בלי שום ידע.
 *
 * הרשימה הלבנה חוסמת את זה ממילא — רשת חדשה אינה מאושרת. מה שהמודול
 * הזה מוסיף הוא **הסבר**: במקום "רשת לא מוכרת מבקשת אישור", ההורה
 * מקבל "נראית כמו שיתוף אינטרנט מטלפון". זה ההבדל בין אישור אוטומטי
 * מתוך עייפות לבין החלטה.
 *
 * המודול מחזיר ציון ביטחון ולא כן/לא, ובמכוון. אף סימן אינו מוחלט,
 * והצגת ניחוש כוודאות היא הדרך המהירה לאבד את אמון ההורה.
 */

export interface NetworkFingerprint {
  /** שם הרשת האלחוטית. */
  ssid?: string | null;
  /** כתובת השער. הסימן החזק ביותר. */
  gatewayIp?: string | null;
  /** כתובת החומרה של השער, אם ניתן היה לשלוף אותה. */
  gatewayMac?: string | null;
  /** הכתובת הציבורית שממנה המכשיר יוצא. */
  publicIp?: string | null;
}

export type HotspotConfidence = "none" | "possible" | "likely" | "certain";

export interface HotspotVerdict {
  confidence: HotspotConfidence;
  /** הסימנים שנמצאו, בשפה שאפשר להציג להורה. */
  reasons: string[];
  /** תיאור קצר לתצוגה. */
  summary: string;
}

/*
 * ─────────────────────────────────────────────── טווחי שער
 *
 * הסימן החזק והזול ביותר, ואינו דורש שום מאגר חיצוני.
 *
 * מערכות ההפעלה מקצות לשיתוף אינטרנט טווחי כתובות קבועים ומתועדים,
 * שנתבים ביתיים כמעט לעולם אינם משתמשים בהם. נתב ביתי יושב כמעט
 * תמיד על 192.168.0.1 או 192.168.1.1 או 10.0.0.138.
 */
const GATEWAY_SIGNATURES: Array<{ prefix: string; label: string; exact?: string }> = [
  // iOS מקצה תמיד 172.20.10.1 עם מסכת /28. התנהגות קבועה ומתועדת.
  { prefix: "172.20.10.", exact: "172.20.10.1", label: "שיתוף אינטרנט מ-iPhone" },

  // אנדרואיד, שיתוף קלאסי
  { prefix: "192.168.43.", exact: "192.168.43.1", label: "שיתוף אינטרנט מאנדרואיד" },

  // Windows Mobile Hotspot ו-Internet Connection Sharing
  { prefix: "192.168.137.", exact: "192.168.137.1", label: "שיתוף אינטרנט ממחשב Windows" },

  // אנדרואיד בגרסאות מסוימות, ומכשירים של יצרנים אחדים
  { prefix: "192.168.49.", exact: "192.168.49.1", label: "שיתוף אינטרנט מאנדרואיד" },
];

/*
 * ─────────────────────────────────────────────── תבניות שם
 *
 * ברירת המחדל של שם נקודה חמה כוללת את שם הדגם או את שם הבעלים.
 * המשתמש יכול לשנות, ולכן זה סימן תומך ולא מכריע.
 */
const SSID_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\biphone\b/i, label: "שם הרשת מזכיר iPhone" },
  { pattern: /\bipad\b/i, label: "שם הרשת מזכיר iPad" },
  { pattern: /\bgalaxy\b|\bsamsung\b/i, label: "שם הרשת מזכיר מכשיר Samsung" },
  { pattern: /\bandroidap\b/i, label: "שם ברירת המחדל של שיתוף אנדרואיד" },
  { pattern: /\bxiaomi\b|\bredmi\b|\bpoco\b/i, label: "שם הרשת מזכיר מכשיר Xiaomi" },
  { pattern: /\bhuawei\b|\bhonor\b/i, label: "שם הרשת מזכיר מכשיר Huawei" },
  { pattern: /\bpixel\b/i, label: "שם הרשת מזכיר מכשיר Pixel" },
  { pattern: /\boneplus\b/i, label: "שם הרשת מזכיר מכשיר OnePlus" },

  /*
   * "הטלפון של יוסי", "הנייד של דנה" — הצורה השכיחה בעברית.
   *
   * התבנית דורשת מילה שמציינת מכשיר לפני "של". הניסוח הקודם תפס
   * "של" לבדו, ולכן סימן גם "הרשת של הבית" — שם רשת ביתי רגיל
   * לחלוטין. בעברית "של" נפוץ מדי מכדי להיות סימן.
   */
  { pattern: /(הטלפון|הנייד|הסלולרי|האייפון|הפלאפון)\s+של/, label: "שם הרשת מזכיר טלפון אישי" },
];

/*
 * ─────────────────────────────────────────────── קידומות חומרה
 *
 * שלוש האוקטטות הראשונות ב-MAC מזהות את היצרן. הרשימה מכוונת
 * ליצרני טלפונים, וכוללת רק קידומות שהיצרן משתמש בהן במכשירים
 * ניידים.
 *
 * סימן תומך בלבד: מערכות מודרניות מגרילות כתובות חומרה, וגם נתבים
 * מיוצרים על ידי חלק מהחברות האלה.
 */
const PHONE_OUI: Record<string, string> = {
  "3C:2E:FF": "Apple",
  "A4:83:E7": "Apple",
  "F0:18:98": "Apple",
  "AC:BC:32": "Apple",
  "DC:2B:2A": "Apple",
  "5C:F9:38": "Apple",
  "E4:E0:A6": "Samsung",
  "F8:04:2E": "Samsung",
  "8C:77:12": "Samsung",
  "C0:BD:D1": "Samsung",
  "64:B0:A6": "Xiaomi",
  "F8:A2:D6": "Xiaomi",
  "50:8F:4C": "Xiaomi",
};

/** מנרמל כתובת חומרה לצורת השוואה: אותיות גדולות, מופרדת בנקודתיים. */
export function normalizeMac(mac: string): string | null {
  const hex = mac.replace(/[^0-9a-fA-F]/g, "").toUpperCase();

  if (hex.length !== 12) return null;

  return (hex.match(/.{2}/g) ?? []).join(":");
}

/**
 * האם הכתובת מנוהלת מקומית, כלומר מוגרלת.
 *
 * הביט השני מהסוף בבית הראשון מסמן זאת. כתובת כזו אינה שייכת לשום
 * יצרן, וחיפוש יצרן עליה יחזיר תשובה שגויה או ריקה.
 *
 * זה אינו מקרה קצה: נבדק על מכונת פיתוח אמיתית, והשער שם החזיר
 * DA:0F:1F — מוגרלת. מערכות מש ורשתות אורח משתמשות בזה דרך קבע.
 */
export function isLocallyAdministered(mac: string): boolean {
  const normalized = normalizeMac(mac);

  if (normalized === null) return false;

  return (parseInt(normalized.slice(0, 2), 16) & 0x02) !== 0;
}

function ouiOf(mac: string): string | null {
  const normalized = normalizeMac(mac);

  if (normalized === null) return null;

  // כתובת מוגרלת אינה נושאת מידע על יצרן
  if (isLocallyAdministered(normalized)) return null;

  return normalized.slice(0, 8);
}

/**
 * מסווג רשת.
 *
 * שער בטווח שיתוף ידוע הוא כמעט מכריע לבדו: נתב ביתי אינו יושב שם.
 * שאר הסימנים מחזקים אך אינם מספיקים לבדם, כי שם רשת ניתן לשנות
 * וכתובת חומרה ניתן להגריל.
 */
export function classifyHotspot(fingerprint: NetworkFingerprint): HotspotVerdict {
  const reasons: string[] = [];
  let score = 0;

  // ---- השער ----
  const gateway = fingerprint.gatewayIp?.trim();

  if (gateway) {
    for (const signature of GATEWAY_SIGNATURES) {
      if (!gateway.startsWith(signature.prefix)) continue;

      // התאמה מדויקת לכתובת השער היא חזקה יותר מהתאמה לטווח
      score += gateway === signature.exact ? 3 : 2;
      reasons.push(signature.label);
      break;
    }
  }

  // ---- שם הרשת ----
  const ssid = fingerprint.ssid?.trim();

  if (ssid) {
    for (const { pattern, label } of SSID_PATTERNS) {
      if (!pattern.test(ssid)) continue;

      score += 1;
      reasons.push(label);
      break;
    }
  }

  // ---- כתובת החומרה ----
  const mac = fingerprint.gatewayMac?.trim();

  if (mac) {
    const oui = ouiOf(mac);
    const vendor = oui === null ? undefined : PHONE_OUI[oui];

    if (vendor) {
      score += 1;
      reasons.push(`כתובת החומרה של השער שייכת ל-${vendor}`);
    }
  }

  const confidence: HotspotConfidence =
    score >= 4 ? "certain" : score >= 3 ? "likely" : score >= 1 ? "possible" : "none";

  return { confidence, reasons, summary: summarize(confidence, reasons) };
}

function summarize(confidence: HotspotConfidence, reasons: string[]): string {
  if (confidence === "none") return "לא זוהו סימנים לשיתוף אינטרנט מטלפון.";

  const opening =
    confidence === "certain"
      ? "הרשת היא שיתוף אינטרנט מטלפון."
      : confidence === "likely"
        ? "הרשת נראית כשיתוף אינטרנט מטלפון."
        : "ייתכן שהרשת היא שיתוף אינטרנט מטלפון.";

  return `${opening} ${reasons.join(". ")}.`;
}

/**
 * האם לחסום בלי לשאול.
 *
 * רק ודאות מצדיקה חסימה אוטומטית. בכל דרגה נמוכה יותר ההורה מחליט,
 * כי חסימה שגויה של רשת ביתית לגיטימית תלמד אותו לאשר הכול.
 */
export function shouldBlockOutright(verdict: HotspotVerdict): boolean {
  return verdict.confidence === "certain";
}
