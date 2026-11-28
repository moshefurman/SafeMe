import type { SecurityStatus, TimelineEntry } from "./types";

/**
 * ציר הזמן בשתי שפות.
 *
 * הבעיה שהמודול הזה פותר: מה שהסוכן שולח נכתב למי שכתב אותו.
 * "coverage_gap", "wfp_filters_missing", ושישים שורות "פעימה · מוגן
 * · ציון 100" ברצף. הכול נכון, ואף אחד מזה אינו תשובה לשאלה שהורה
 * בא לשאול — "מה קרה למחשב של הילד שלי".
 *
 * ולכן שתי שפות ולא ניסוח אחד שמתפשר. ההורה מקבל משפטים; מי שבא
 * לאבחן מקבל את הגלם. אין כאן מידע שנמחק — יש בחירה מה מוצג
 * כברירת מחדל.
 */

/** מה שההורה רואה: כותרת, ולמה זה חשוב. */
export interface PlainEntry {
  id: string;
  at: string;
  /**
   * מתי המצב התחיל. שונה מ-at רק ברצף של בדיקות זהות, ואז שני
   * הזמנים יחד הם "מ-14:05 עד 17:20" ולא מונה של בדיקות.
   */
  since: string;
  tone: "good" | "warn" | "bad" | "info";
  title: string;
  why: string;
  /** כמה פעמים זה חזר ברצף. 1 פירושו פעם אחת. */
  repeats: number;
}

const STATUS_TONE: Record<string, PlainEntry["tone"]> = {
  safe: "good",
  low_filter: "warn",
  unfiltered: "bad",
  blocked: "warn",
  whitelist: "good",
  unknown: "info",
};

/**
 * החבלות, בשם שאומר מה קרה ולא איך קוראים לזה בקוד.
 *
 * הניסוח נצמד לעובדה. "השירות נעצר" הוא מה שידוע; "הילד ניסה לעקוף"
 * הוא ניחוש, ואם הוא יתברר כשגוי פעם אחת ההורה יפסיק להאמין לכל
 * ההתראות.
 */
const TAMPER: Record<string, { title: string; why: string; tone: PlainEntry["tone"] }> = {
  service_stop_attempt: {
    title: "מישהו ניסה לעצור את Filter+‎",
    why: "הניסיון נחסם והתוכנה המשיכה לפעול.",
    tone: "bad",
  },
  service_crash: {
    title: "Filter+‎ נעצר מעצמו וחזר",
    why: "תקלה בתוכנה, לא ניסיון עקיפה. אם זה חוזר — כדאי לדווח.",
    tone: "warn",
  },
  tray_app_killed: {
    title: "חלון המצב נסגר",
    why: "האכיפה עצמה נמשכה. החלון חזר מעצמו.",
    tone: "warn",
  },
  wfp_filters_missing: {
    title: "כללי החסימה נעלמו מהמחשב",
    why: "הם הוחזרו אוטומטית. מישהו ניסה להסיר אותם ידנית.",
    tone: "bad",
  },
  state_file_missing: {
    title: "קובץ ההגדרות נמחק",
    why: "התוכנה שחזרה אותו והמשיכה לפעול.",
    tone: "bad",
  },
  state_file_tampered: {
    title: "מישהו ערך את קובץ ההגדרות",
    why: "השינוי נדחה. ההגדרות חתומות, ועריכה ידנית אינה מתקבלת.",
    tone: "bad",
  },
  clock_rolled_back: {
    title: "השעון של המחשב הוזז אחורה",
    why: "דרך מוכרת לנסות לעקוף הגבלות זמן. ההזזה זוהתה.",
    tone: "bad",
  },
  policy_signature_invalid: {
    title: "התקבלו הגדרות שאינן חתומות כראוי",
    why: "הן נדחו. המחשב המשיך לפי ההגדרות הקודמות.",
    tone: "bad",
  },
  bfe_unavailable: {
    title: "שירות החומה של Windows כובה",
    why: "בלעדיו אי אפשר לחסום. Filter+‎ מנסה להפעיל אותו מחדש.",
    tone: "bad",
  },
  uninstall_brute_force: {
    title: "ניסיונות חוזרים לנחש את קוד ההסרה",
    why: "כל הניסיונות נדחו.",
    tone: "bad",
  },
  coverage_gap: {
    title: "המחשב היה דלוק ו-Filter+‎ לא פעל",
    why: "התגלה מיומן האירועים של Windows. זו התקופה היחידה שאינה מכוסה.",
    tone: "bad",
  },
  offline_expiry_near: {
    title: "המחשב מנותק מהשרת זמן רב",
    why: "ההגנה מתקרבת לפקיעה. כשהמחשב יתחבר לאינטרנט התוקף יתחדש מעצמו.",
    tone: "bad",
  },
};

const COMMAND: Record<string, string> = {
  lockout: "ביקשת לחסום את הגלישה במחשב",
  release_lockout: "ביקשת לבטל את החסימה",
  run_audit: "ביקשת בדיקה מיידית",
  refresh_policy: "ביקשת לרענן את ההגדרות",
};

const COMMAND_STATE: Record<string, string> = {
  pending: "ממתין שהמחשב יתחבר.",
  delivered: "הגיע למחשב.",
  acked: "המחשב ביצע.",
  expired: "לא הגיע בזמן ופג.",
  cancelled: "בוטל.",
};

/**
 * מתרגם ומכווץ.
 *
 * הכיווץ הוא העיקר. פעימה נשלחת כל כמה דקות, ולכן מחשב תקין מייצר
 * עשרות שורות זהות שקוברות את השורה האחת שכן קרה בה משהו. רצף של
 * אותו מצב הופך לשורה אחת עם מונה, והשינוי — שהוא המידע האמיתי —
 * חוזר להיות נראה.
 */
export function toPlain(entries: readonly TimelineEntry[]): PlainEntry[] {
  const out: PlainEntry[] = [];

  for (const entry of entries) {
    const plain = translate(entry);

    if (plain === null) continue;

    const previous = out[out.length - 1];

    // רק פעימות מתכווצות. אירוע שחזר פעמיים הוא שני אירועים.
    if (
      previous !== undefined
      && entry.kind === "heartbeat"
      && previous.title === plain.title
    ) {
      previous.repeats += 1;

      // הרשומות ממוינות מהחדש לישן, ולכן כל רשומה נוספת ברצף מוקדמת יותר
      previous.since = entry.at;
      continue;
    }

    out.push(plain);
  }

  return out;
}

function translate(entry: TimelineEntry): PlainEntry | null {
  const base = { id: `${entry.kind}-${entry.id}`, at: entry.at, since: entry.at, repeats: 1 };

  if (entry.kind === "heartbeat") {
    const status = (entry.name ?? "unknown") as SecurityStatus;

    return {
      ...base,
      tone: STATUS_TONE[status] ?? "info",
      title: HEARTBEAT_TITLE[status] ?? "מצב לא ידוע",
      why: HEARTBEAT_WHY[status] ?? "",
    };
  }

  if (entry.kind === "command") {
    return {
      ...base,
      tone: "info",
      title: COMMAND[entry.name] ?? entry.name,
      why: COMMAND_STATE[entry.detail ?? ""] ?? "",
    };
  }

  const known = TAMPER[entry.name];

  /*
   * אירוע שאין לו תרגום מוצג בכל זאת, בשמו הגולמי.
   *
   * הפיתוי היה להסתיר מה שלא מוכר, וזו בדיוק הטעות: אירוע חדש
   * שנוסף לסוכן היה נעלם מהמסך של ההורה עד שמישהו יזכור לתרגם
   * אותו — כלומר דווקא האירועים החדשים, שאיש עוד לא ראה.
   */
  return known === undefined
    ? { ...base, tone: "warn", title: entry.name, why: entry.detail ?? "" }
    : { ...base, tone: known.tone, title: known.title, why: known.why };
}

const HEARTBEAT_TITLE: Record<string, string> = {
  safe: "החיבור מסונן",
  low_filter: "הסינון חלקי",
  unfiltered: "החיבור אינו מסונן",
  blocked: "הגלישה במחשב חסומה",
  whitelist: "גלישה לאתרים מאושרים בלבד",
  unknown: "לא ניתן היה לבדוק",
};

const HEARTBEAT_WHY: Record<string, string> = {
  safe: "המחשב גלש דרך ספק סינון מאושר.",
  low_filter: "הספק זוהה, אבל לא בכל הבדיקות. ייתכן שהסינון הוחלש.",
  unfiltered: "לא זוהה ספק סינון מאושר.",
  blocked: "כל הגלישה חסומה, עד שהחיבור יחזור להיות מסונן או שהחסימה תבוטל.",
  whitelist: "המחשב במצב רשימה לבנה: נפתחים רק האתרים שאישרת.",
  unknown: "המחשב לא הצליח להשלים בדיקה. לרוב מפני שאין רשת.",
};
