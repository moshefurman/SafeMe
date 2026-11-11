/**
 * רשימה לבנה: המחשב גולש רק לאתרים שאושרו.
 *
 * הקובץ מחזיק את כל מה שאינו מסלול ואינו שאילתה: איך נראה שם מתחם
 * תקין, איך מקבצים שמות לפי האתר שהם שייכים לו, מה הסוכן מקבל,
 * ומה אסור לאשר לעולם.
 *
 * הטבלאות הן הכוונה של ההורה (מיגרציה 0040), והכלל שנבנה כאן הוא
 * מה שנחתם ונשלח. כמו בחלונות הזמן — תוצר, לא מקור אמת.
 */

import { domainToASCII } from "node:url";

import type pg from "pg";

// ---------------------------------------------------------------- קבועים

/**
 * השרתים שהסוכן פונה אליהם כדי לתרגם שמות במצב הזה.
 *
 * Cloudflare for Families: חוסם תוכן למבוגרים ואתרים מזיקים ברמת
 * ה-DNS. זו שכבה שנייה מתחת לרשימה — גם אתר שאושר בטעות, או
 * תת־מתחם של אתר מאושר, לא ייפתח אם הוא מסווג כך.
 *
 * קבוע בשרת ולא בסוכן, כדי שאפשר יהיה להחליף ספק בלי גרסת סוכן.
 */
export const WHITELIST_UPSTREAM_RESOLVERS: readonly string[] = ["1.1.1.3", "1.0.0.3"];

/**
 * שמות שנפתחים תמיד במצב רשימה לבנה, גם כשהרשימה ריקה.
 *
 * הרשימה קצרה ובכוונה. כל שם כאן הוא חור ברשימה של כל הורה, ולכן
 * נכנס רק מה שבלעדיו המחשב עצמו נשבר — לא מה שנוח:
 *
 *   · בדיקת החיבור של Windows. בלעדיה מופיע "אין אינטרנט" על סמל
 *     הרשת, ויישומים רבים מסרבים אפילו לנסות.
 *   · שעון. שעון שסוטה מכשיל TLS, וגם את בדיקת התוקף של המדיניות.
 *   · שרתי SafeMe עצמם: ה-API, הפורטל, ושרת העדכון של תוסף הדפדפן
 *     (api.safeme.win, ראה extension/update.xml). בלעדיהם המחשב אינו
 *     מקבל את המדיניות שמשחררת אותו, וההורה אינו מגיע מהמחשב הזה
 *     למסך שבו מאשרים אתרים. מארח הפורטל שבתצורה מתווסף בנוסף, לטובת
 *     התקנות שאינן יושבות תחת safeme.win — ראה setWhitelistServiceUrls.
 *
 * Windows Update, חנות היישומים ואימות תעודות אינם כאן. הם רחבים
 * (עשרות שמות, חלקם CDN משותף עם חצי אינטרנט), וההורה יכול ללמוד
 * ולאשר אותם כמו כל אתר אחר.
 */
export const WHITELIST_SYSTEM_DOMAINS: readonly string[] = [
  "msftconnecttest.com",
  "msftncsi.com",
  "time.windows.com",
  "safeme.win",
];

/** כמה אתרים מאושרים למחשב אחד. גבול שפוי, לא מגבלה עסקית. */
export const MAX_APPROVED_DOMAINS = 500;

/** כמה שמות נצפים נשמרים למחשב אחד. סוכן שמדווח בלי סוף לא ימלא את המסד. */
export const MAX_OBSERVED_DOMAINS = 5000;

/** אחרי סוף הלמידה הסוכן עוד רשאי לשלוח את מה שצבר. */
export const OBSERVED_GRACE_MS = 10 * 60 * 1000;

// ---------------------------------------------------------------- נרמול

const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

/** תווית של שם שנצפה. קו תחתון מותר: שמות כמו ‎_dmarc קיימים ב-DNS. */
const OBSERVED_LABEL = /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/;

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * מוציא שם מארח ממה שהוקלד או הודבק.
 *
 * הורה מדביק מה שיש לו בשורת הכתובת: "https://www.ynet.co.il/news?x=1".
 * דחייה של זה עם "שם מתחם לא תקין" הייתה נכונה ולא מועילה. מה שהוא
 * מתכוון אליו ברור, ולכן הסכימה, הנתיב, הפורט, פרטי ההתחברות וכוכבית
 * מובילה ("‎*.example.com") מוסרים.
 *
 * מחזיר null כשאין שם מארח שאפשר לחלץ.
 */
function extractHost(raw: string): string | null {
  let s = raw.trim().toLowerCase();

  if (s === "" || s.length > 2048) return null;

  // סכימה, אם יש. כל סכימה — גם ftp:// מודבק לפעמים.
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");

  // עד הנתיב, השאילתה או העוגן
  s = s.split(/[/?#]/)[0] ?? "";

  // פרטי התחברות: user:pass@host
  if (s.includes("@")) s = s.slice(s.lastIndexOf("@") + 1);

  // כתובת IPv6 בסוגריים אינה שם מתחם
  if (s.startsWith("[")) return null;

  // פורט
  s = s.replace(/:\d{1,5}$/, "");

  // כוכבית מובילה. הרשומה ממילא כוללת תת־מתחמים.
  while (s.startsWith("*.")) s = s.slice(2);

  // נקודה סופית של שם מלא
  s = s.replace(/\.+$/, "");

  if (s === "" || s.includes(":") || s.includes("*")) return null;

  /*
   * עברית ושאר אותיות שאינן ASCII עוברות ל-punycode.
   *
   * זו הצורה שה-DNS רואה, ולכן הצורה שהסוכן משווה מולה. שם שנשמר
   * בעברית היה נחתם למדיניות ולא מתאים לעולם לשום בקשה.
   */
  const ascii = domainToASCII(s);

  return ascii === "" ? null : ascii;
}

function validShape(host: string, label: RegExp): boolean {
  if (host.length > 253) return false;
  if (IPV4.test(host)) return false;

  const labels = host.split(".");

  // שם בן תווית אחת ("localhost", "router") אינו אתר באינטרנט
  if (labels.length < 2) return false;
  if (!labels.every((l) => label.test(l))) return false;

  // סיומת שכולה ספרות היא כתובת, לא שם
  return !/^\d+$/.test(labels[labels.length - 1]!);
}

export interface NormalizeOptions {
  /**
   * להסיר "www." מוביל.
   *
   * דולק לקלט ידני, כבוי למה שנצפה בלמידה.
   *
   * הורה שמדביק "https://www.ynet.co.il" מתכוון לאתר, לא למארח
   * אחד בתוכו. בלי ההסרה היה מאושר www.ynet.co.il בלבד: הכתובת
   * בלי ה-www — שאליה מפנים חצי מהקישורים — הייתה חסומה, וכך גם
   * images.ynet.co.il. התוצאה היא "אישרתי וזה לא עובד", בדיוק
   * המקרה שהמצב הזה צריך למנוע.
   *
   * בלמידה אין סיבה לנחש: שם שנצפה מאושר כפי שנצפה, והקיבוץ לפי
   * אתר כבר מראה להורה מה שייך למה.
   */
  stripWww?: boolean;
}

/**
 * שם מתחם לאישור, בצורתו האחת. null כשהקלט אינו שם מתחם.
 *
 * נדחים: כתובות IP (רשימה לבנה היא של שמות; כתובת עוקפת את בדיקת
 * התוכן כולה), שמות בני תווית אחת, ותווים שאינם חוקיים בשם מארח.
 */
export function normalizeDomain(raw: string, options: NormalizeOptions = {}): string | null {
  let host = extractHost(raw);

  if (host === null) return null;

  if (options.stripWww === true && host.startsWith("www.")) {
    const rest = host.slice(4);

    // "www.co" נשאר כמו שהוא: בלי ה-www לא נשאר שם מתחם
    if (rest.includes(".")) host = rest;
  }

  return validShape(host, LABEL) ? host : null;
}

/**
 * שם שהסוכן דיווח שנצפה. מקל מעט מהאישור — קו תחתון מותר — כי זה
 * מה שהמחשב ביקש בפועל, והתפקיד כאן הוא להציג, לא לאשר.
 */
export function normalizeObserved(raw: string): string | null {
  const host = raw.trim().toLowerCase().replace(/\.+$/, "");

  if (host === "" || /[^a-z0-9._-]/.test(host)) return null;

  return validShape(host, OBSERVED_LABEL) ? host : null;
}

/**
 * מפרק טקסט חופשי לרשומות: רווחים, פסיקים, נקודה־פסיק ושורות.
 *
 * תיבת ההוספה מקבלת הדבקה של רשימה שלמה, ואין סיבה שהורה יצטרך
 * לדעת איזה מפריד בחרנו.
 */
export function splitDomainInput(text: string): string[] {
  return text.split(/[\s,;]+/).map((s) => s.trim()).filter((s) => s !== "");
}

// ---------------------------------------------------------------- קיבוץ לפי אתר

/**
 * סיומות ציבוריות בנות שתי תוויות.
 *
 * אין כאן רשימת הסיומות הציבורית המלאה (PSL) ובכוונה: היא תלות של
 * אלפי שורות שמתעדכנת כל שבוע, והשימוש כאן הוא קיבוץ לתצוגה ובדיקת
 * האב — לא החלטת אבטחה שעומדת לבדה. טעות בקיבוץ מציגה שתי קבוצות
 * במקום אחת; היא אינה מאשרת דבר.
 *
 * הרשימה מכסה את ישראל במלואה ואת הנפוצות בעולם.
 */
const TWO_LEVEL_SUFFIXES = new Set([
  // ישראל
  "co.il", "org.il", "ac.il", "gov.il", "net.il", "muni.il", "k12.il", "idf.il",
  // בריטניה
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "nhs.uk",
  // אוסטרליה וניו זילנד
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
  "co.nz", "org.nz", "net.nz", "ac.nz", "govt.nz",
  // שאר העולם, לפי שכיחות
  "com.br", "net.br", "org.br", "gov.br",
  "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
  "co.kr", "or.kr", "go.kr",
  "com.cn", "net.cn", "org.cn", "gov.cn",
  "co.in", "net.in", "org.in", "ac.in", "gov.in",
  "co.za", "org.za", "ac.za", "gov.za",
  "com.tr", "org.tr", "gov.tr", "edu.tr",
  "com.mx", "org.mx", "gob.mx",
  "com.ar", "gob.ar",
  "com.ua", "org.ua",
  "com.sg", "com.hk", "com.tw", "com.my", "com.ph", "com.vn", "com.eg", "com.sa",
  "co.th", "co.id", "co.ke",
  "com.pl", "com.ru", "com.es", "com.pt", "com.gr", "com.cy",
]);

/**
 * המתחם שנרשם אצל רשם — "האתר" שהשם שייך לו.
 *
 * static.cdn.example.co.il ← example.co.il
 * www.example.com          ← example.com
 *
 * משמש לשני דברים: קיבוץ השמות שנצפו כך שההורה יראה אתרים ולא
 * רשימה שטוחה של מאות מארחים, ובדיקת התוכן של האב — כי שם תמים
 * למראה ("img-7.cdn-x.net") עשוי להיות של אתר שאינו כזה.
 */
export function registrableDomain(host: string): string {
  const labels = host.toLowerCase().replace(/\.+$/, "").split(".");

  if (labels.length <= 2) return labels.join(".");

  const lastTwo = labels.slice(-2).join(".");
  const take = TWO_LEVEL_SUFFIXES.has(lastTwo) ? 3 : 2;

  return labels.slice(-take).join(".");
}

// ---------------------------------------------------------------- הכלל שנחתם

/** הצורה שהסוכן מצפה לה ב-enforcement.whitelist. חוזה קבוע מול הסוכן. */
export interface WhitelistRule {
  enabled: boolean;
  domains: string[];
  systemDomains: string[];
  upstreamResolvers: string[];
  learnUntilUtc: string | null;
}

/**
 * שם המארח של כתובת, או null. לשרתי SafeMe שנכנסים ל-systemDomains.
 *
 * מארח מקומי וכתובת IP מדולגים: הם אינם שמות מתחם, והסוכן ממילא
 * מתיר את שרת ה-API שלו לפי התצורה שבידיו.
 */
function hostOf(url: string): string | null {
  try {
    return normalizeDomain(new URL(url).hostname);
  } catch {
    return null;
  }
}

let serviceHosts: string[] = [];

/**
 * רושם את כתובות השירות של ההתקנה הזו (PORTAL_URL), פעם אחת בעלייה.
 *
 * מצב ברמת המודול ולא פרמטר, ובכוונה. המדיניות של מחשב מורכבת
 * מכמה מקומות — מסלולי הפורטל, ההרכבה בעליית השרת, שינוי מדיניות
 * הרשתות — וכולם חייבים להפיק בדיוק אותה רשימה. פרמטר שעובר בחמש
 * חתימות הוא פרמטר שמישהו ישכח באחת מהן, ואז שני מרכיבים יפיקו
 * שני גופים שונים ויפרסמו זה על גבי זה בכל אתחול.
 */
export function setWhitelistServiceUrls(urls: readonly string[]): void {
  serviceHosts = urls.map(hostOf).filter((h): h is string => h !== null);
}

/**
 * השמות שנפתחים תמיד, כולל שרתי SafeMe של ההתקנה הזו.
 *
 * מיון וביטול כפילויות כדי ששתי בניות של אותה תצורה יפיקו בדיוק
 * אותו גוף — אחרת ההרכבה בעליית השרת הייתה מוצאת "שינוי" ומפרסמת
 * גרסה חדשה בכל אתחול. מארח שכבר מכוסה על ידי רשומה קבועה
 * (app.safeme.win תחת safeme.win) אינו נוסף שוב.
 */
export function whitelistSystemDomains(): string[] {
  const covered = (host: string): boolean =>
    WHITELIST_SYSTEM_DOMAINS.some((d) => host === d || host.endsWith(`.${d}`));

  return [...new Set([...WHITELIST_SYSTEM_DOMAINS, ...serviceHosts.filter((h) => !covered(h))])].sort();
}

/**
 * בונה את הכלל.
 *
 * חלון למידה שעבר נכתב כ-null ולא כזמן שבעבר. הסוכן משווה את הזמן
 * בעצמו ולכן שתי הצורות שקולות אצלו — אבל null אומר את האמת למי
 * שקורא את המדיניות, ואינו משאיר זמן ישן שנראה כמו תקלה.
 */
export function buildWhitelistRule(input: {
  enabled?: boolean;
  domains?: readonly string[];
  learningUntil?: Date | null;
  systemDomains?: readonly string[];
  now?: Date;
} = {}): WhitelistRule {
  const now = input.now ?? new Date();
  const until = input.learningUntil ?? null;
  const learning = until !== null && until.getTime() > now.getTime();

  return {
    enabled: input.enabled === true,
    domains: [...new Set(input.domains ?? [])].sort(),
    systemDomains: [...(input.systemDomains ?? whitelistSystemDomains())],
    upstreamResolvers: [...WHITELIST_UPSTREAM_RESOLVERS],
    learnUntilUtc: learning ? until.toISOString() : null,
  };
}

// ---------------------------------------------------------------- מה שבמסד

export interface WhitelistState {
  enabled: boolean;
  learningUntil: Date | null;
  domains: Array<{ id: string; domain: string; source: string; created_at: Date }>;
}

/** ההגדרה והאתרים המאושרים של מחשב אחד. מחשב בלי שורה הוא מחשב כבוי. */
export async function loadWhitelist(
  tx: { query: pg.ClientBase["query"] },
  deviceId: string,
): Promise<WhitelistState> {
  const settings = await tx.query<{ enabled: boolean; learning_until: Date | null }>(
    "SELECT enabled, learning_until FROM device_whitelist WHERE device_id = $1",
    [deviceId],
  );

  const domains = await tx.query<{ id: string; domain: string; source: string; created_at: Date }>(
    `SELECT id, domain, source, created_at
       FROM device_whitelist_domains
      WHERE device_id = $1
      ORDER BY domain`,
    [deviceId],
  );

  return {
    enabled: settings.rows[0]?.enabled ?? false,
    learningUntil: settings.rows[0]?.learning_until ?? null,
    domains: domains.rows,
  };
}

/** האם חלון הלמידה פתוח ברגע זה. */
export function learningActive(state: Pick<WhitelistState, "learningUntil">, now = new Date()): boolean {
  return state.learningUntil !== null && state.learningUntil.getTime() > now.getTime();
}

// ---------------------------------------------------------------- מה שאסור לאשר

/**
 * מילים שהופעתן בכל מקום בשם מסגירה את האתר.
 *
 * רק מחרוזות שאינן מופיעות במילים תמימות. "sex" ו-"xxx" אינן כאן:
 * הן יושבות בתוך essex, middlesex, sussex ובתוך מידות בגדים, ולכן
 * נבדקות כמילה שלמה בלבד — ראה WHOLE_WORDS.
 */
const SUBSTRINGS = [
  "porn", "xvideos", "xnxx", "xhamster", "redtube", "youporn", "onlyfans",
  "chaturbate", "stripchat", "livejasmin", "bongacams", "brazzers", "spankbang",
  "eporner", "hentai", "youjizz", "rule34", "fapello", "motherless", "hclips",
  "tnaflix", "nhentai", "camsoda", "myfreecams", "sexcam", "freesex", "sexvid",
];

/**
 * מילים שנבדקות רק כמילה שלמה: תווית שלמה, או חלק שמופרד במקף.
 *
 * "sex.com" ו-"free-sex.net" נתפסים; "essex.gov.uk" לא.
 */
const WHOLE_WORDS = new Set([
  "sex", "xxx", "porno", "nsfw", "nude", "nudes",
  "cam4", "tube8", "milf", "fap", "erotic", "erotica", "sexy", "xvideo",
]);

/** סיומות שכל ייעודן הוא התוכן הזה. */
const ADULT_TLDS = new Set(["xxx", "porn", "sex", "adult", "sexy"]);

/**
 * הבדיקה המקומית: האם השם עצמו מסגיר תוכן למבוגרים.
 *
 * מהירה, בלי רשת, ולכן רצה גם בתצוגה של מה שנצפה. היא השכבה
 * הראשונה בלבד: רוב האתרים האלה אינם נושאים את המילה בשמם, ואת
 * אלה תופסת הבדיקה החיה.
 */
export function looksAdult(domain: string): boolean {
  const host = domain.toLowerCase();
  const labels = host.split(".");

  if (ADULT_TLDS.has(labels[labels.length - 1] ?? "")) return true;
  if (SUBSTRINGS.some((s) => host.includes(s))) return true;

  return labels.some((label) => label.split("-").some((word) => WHOLE_WORDS.has(word)));
}

export type DomainVerdict =
  | { ok: true }
  | {
      ok: false;
      reason: string;
      /**
       * 'blocked' — האתר עצמו פסול, וזה לא ישתנה בניסיון חוזר.
       * 'unverified' — לא הצלחנו לבדוק. ניסיון חוזר עשוי להצליח.
       *
       * ההבחנה קובעת מה נשמר: פסילה נרשמת ומוצגת מעתה כחסומה,
       * וכשל בדיקה אינו נרשם — אחרת תקלת רשת של רגע הייתה מסמנת
       * אתר תמים לתמיד.
       */
      kind: "blocked" | "unverified";
    };

export const REASON_BLOCKED = "אתר זה אינו ניתן לאישור: הוא מסווג כתוכן למבוגרים או כאתר מזיק.";
export const REASON_UNVERIFIED = "לא ניתן לאמת את האתר כרגע, נסו שוב";

const FAMILY_DOH = "https://family.cloudflare-dns.com/dns-query";

export interface CheckOptions {
  /** מוחלף בבדיקות. ברירת המחדל היא fetch של Node. */
  fetch?: typeof fetch;
  timeoutMs?: number;
}

/**
 * שואל את Cloudflare for Families אם השם חסום אצלו.
 *
 * נמדד מול השירות החי (11.11.2026): שם חסום מקבל תשובה תקינה,
 * Status 0, עם רשומת A שערכה 0.0.0.0 (ו-AAAA שערכה ::) והערה
 * "EDE(17): Filtered". שם רגיל מקבל כתובות אמיתיות. שם שאינו קיים
 * מקבל Status 3 בלי תשובות.
 *
 * מחזיר true לחסום, false לנקי, וזורק כשאי אפשר לדעת.
 */
async function familyBlocks(name: string, options: CheckOptions): Promise<boolean> {
  const doFetch = options.fetch ?? fetch;

  const response = await doFetch(
    `${FAMILY_DOH}?name=${encodeURIComponent(name)}&type=A`,
    {
      headers: { accept: "application/dns-json" },
      signal: AbortSignal.timeout(options.timeoutMs ?? 4000),
    },
  );

  if (!response.ok) throw new Error(`בדיקת הסיווג החזירה ${response.status}`);

  const body = await response.json() as {
    Status?: unknown;
    Answer?: Array<{ data?: unknown }>;
    Comment?: unknown;
  };

  if (typeof body.Status !== "number") throw new Error("תשובת הסיווג אינה בצורה המוכרת");

  const answers = Array.isArray(body.Answer) ? body.Answer : [];

  if (answers.some((a) => a.data === "0.0.0.0" || a.data === "::")) return true;

  const comments = Array.isArray(body.Comment) ? body.Comment : [body.Comment];

  if (comments.some((c) => typeof c === "string" && c.includes("Filtered"))) return true;

  /*
   * 0 הוא תשובה, 3 הוא "אין שם כזה". שניהם אומרים שהשם אינו חסום.
   *
   * שם שאינו קיים מאושר ולא נדחה: הוא אינו מוביל לשום מקום, ושמות
   * של CDN נוטים להיות בלי רשומת A משלהם. כל קוד אחר — ובעיקר 2,
   * כשל בשרת — פירושו שלא קיבלנו הכרעה, וזה אינו "נקי".
   */
  if (body.Status === 0 || body.Status === 3) return false;

  throw new Error(`בדיקת הסיווג החזירה קוד DNS ${body.Status}`);
}

/**
 * האם מותר לאשר את השם.
 *
 * שתי שכבות. הראשונה מקומית ומיידית — השם עצמו. השנייה היא שאילתה
 * חיה לסיווג של Cloudflare, על השם ועל המתחם הרשום שמעליו: אישור
 * של "cdn.example.com" מתיר גם את תת־המתחמים שלו, והאב הוא מה
 * שמעיד על מי עומד מאחוריו.
 *
 * כשהבדיקה החיה נכשלת — האישור נדחה. זו הכרעה מודעת: הפונקציה
 * הזו היא השער היחיד שמונע אישור של אתר למבוגרים, ושער שנפתח
 * כשהרשת מקרטעת הוא שער שאפשר לפתוח בכוונה. ההורה מקבל הודעה
 * ברורה ויכול לנסות שוב.
 */
export async function checkDomainAllowed(
  domain: string,
  options: CheckOptions = {},
): Promise<DomainVerdict> {
  const host = domain.toLowerCase();
  const parent = registrableDomain(host);

  if (looksAdult(host)) return { ok: false, reason: REASON_BLOCKED, kind: "blocked" };

  const names = parent === host ? [host] : [host, parent];

  try {
    const results = await Promise.all(names.map((name) => familyBlocks(name, options)));

    if (results.some((blocked) => blocked)) {
      return { ok: false, reason: REASON_BLOCKED, kind: "blocked" };
    }
  } catch {
    return { ok: false, reason: REASON_UNVERIFIED, kind: "unverified" };
  }

  return { ok: true };
}

/**
 * מריץ בדיקות במקביל, עם תקרה.
 *
 * אישור של חמישים שמות בבת אחת הוא מאה שאילתות החוצה. בלי תקרה
 * הן יוצאות כולן יחד, ושירות שמגביל קצב היה עונה בשגיאות — שכאן
 * פירושן דחייה של אתרים תמימים.
 */
export async function checkDomainsAllowed(
  domains: readonly string[],
  options: CheckOptions = {},
  concurrency = 6,
): Promise<Map<string, DomainVerdict>> {
  const out = new Map<string, DomainVerdict>();
  const queue = [...new Set(domains)];

  async function worker(): Promise<void> {
    for (;;) {
      const next = queue.shift();

      if (next === undefined) return;

      out.set(next, await checkDomainAllowed(next, options));
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, queue.length) }, worker));

  return out;
}
