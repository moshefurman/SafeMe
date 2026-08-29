/**
 * מצב תקופת הניסיון.
 *
 * 30 יום חינם, בלי אשראי ובלי מגע אנושי. הלוגיקה טהורה וניתנת
 * לבדיקה, כי היא קובעת מה הלקוח רואה ומה מותר לו — ואסור שתהיה
 * פזורה בין מסלולי ה-API.
 */

export const TRIAL_DAYS = 30;

/** ימי חסד אחרי סוף הניסיון. ההגנה ממשיכה לפעול לאורכם. */
export const GRACE_DAYS = 7;

/** מתי מתחילים להזכיר ללקוח שהניסיון נגמר. */
export const REMINDER_DAYS = [7, 3, 1] as const;

export type BillingPlan = "trial" | "paid" | "expired" | "canceled";

export type TrialPhase =
  /** בתוך הניסיון, רגוע */
  | "trial_active"
  /** בתוך הניסיון, נותרו ימים ספורים */
  | "trial_ending"
  /** הניסיון נגמר, בתוך שבוע החסד. הכול עדיין עובד. */
  | "grace"
  /** גם החסד נגמר */
  | "trial_expired"
  /** לקוח משלם */
  | "paid"
  /** הלקוח ביטל */
  | "canceled";

export interface TrialState {
  phase: TrialPhase;
  /** ימים שנותרו, מעוגל כלפי מעלה. אפס אחרי הסיום. */
  daysLeft: number;
  endsAt: Date | null;
  /** האם להציג באנר בפורטל */
  showBanner: boolean;
  /** נוסח קצר בעברית לתצוגה */
  headline: string;
  /** האם נדרשת פעולה מהלקוח */
  needsAttention: boolean;
}

export interface TenantBilling {
  plan: BillingPlan;
  trialEndsAt: Date | null;
  paidUntil: Date | null;
  graceDays?: number;
}

/*
 * חשוב: הפרמטר now חייב להגיע מאותו שעון שיצר את trialEndsAt, כלומר
 * מבסיס הנתונים. השרת ובסיס הנתונים הם מכונות שונות, וסטייה של שניות
 * ספורות ביניהן הופכת ל-31 ימים במקום 30 — כי החישוב מעגל כלפי מעלה.
 *
 * זה התגלה בפועל: הקונטיינר המקומי הקדים את המארח ב-31 שניות.
 */

/**
 * ימים שנותרו, כלפי מעלה.
 *
 * cap חוסם את התוצאה מלמעלה, וזה נחוץ בגלל תכונה של Math.ceil:
 * הפרש של שנייה אחת מעבר לגבול מוסיף יום שלם. תאריך הסיום נקבע
 * בבסיס הנתונים, והשוואה מולו מניחה שהשעון לא זז אחורה בין
 * הכתיבה לקריאה — הנחה שאינה תמיד נכונה. סנכרון NTP מושך שעונים
 * אחורה, וקונטיינר שחוזר משינה מקבל תיקון של שניות ואף דקות.
 *
 * החוק שכן תמיד נכון: לניסיון לא יכולים להיוותר יותר ימים ממשך
 * הניסיון עצמו. במקום לרדוף אחרי השעון, אוכפים אותו.
 */
function daysBetween(from: Date, to: Date, cap?: number): number {
  const days = Math.ceil((to.getTime() - from.getTime()) / 86_400_000);

  return cap === undefined ? days : Math.min(days, cap);
}

/**
 * מעריך את מצב הניסיון.
 *
 * הפרמטר now חובה ואין לו ברירת מחדל, ובמכוון.
 *
 * תאריך סיום הניסיון נקבע בבסיס הנתונים, ולכן חישוב מולו חייב
 * להשתמש באותו שעון. ברירת מחדל של new Date() הייתה מסתירה סטייה
 * בין השרת לבסיס הנתונים: הפרש של שניות ספורות מזיז את התוצאה של
 * Math.ceil ביום שלם, וניסיון בן 30 יום מוצג כ-31.
 *
 * זו אינה שאלה תיאורטית. הסטייה בין המארח לקונטיינר בפיתוח היא
 * עשרות שניות, ובענן היא קיימת תמיד. בלי החובה הזו הבאג חוזר בכל
 * פעם שמישהו מוסיף מסלול חדש ושוכח.
 */
export function evaluateTrial(tenant: TenantBilling, now: Date): TrialState {
  if (tenant.plan === "canceled") {
    return {
      phase: "canceled",
      daysLeft: 0,
      endsAt: tenant.trialEndsAt,
      showBanner: true,
      headline: "המנוי בוטל",
      needsAttention: true,
    };
  }

  if (tenant.plan === "paid") {
    // מנוי בתשלום שפג הוא מקרה של תשלום שנכשל, ולא של ניסיון שנגמר.
    // ההבחנה חשובה: הנוסח ללקוח שונה לגמרי.
    const expired = tenant.paidUntil !== null && tenant.paidUntil <= now;

    return {
      phase: expired ? "trial_expired" : "paid",
      daysLeft: tenant.paidUntil ? Math.max(0, daysBetween(now, tenant.paidUntil)) : 0,
      endsAt: tenant.paidUntil,
      showBanner: expired,
      headline: expired ? "התשלום לא עבר" : "מנוי פעיל",
      needsAttention: expired,
    };
  }

  if (tenant.trialEndsAt === null) {
    // מצב שלא אמור לקרות: יש CHECK בבסיס הנתונים. מטופל כפג תוקף
    // ולא כתקין, כדי שתקלה לא תיתן ניסיון אינסופי.
    return {
      phase: "trial_expired",
      daysLeft: 0,
      endsAt: null,
      showBanner: true,
      headline: "תקופת הניסיון אינה מוגדרת",
      needsAttention: true,
    };
  }

  const left = daysBetween(now, tenant.trialEndsAt, TRIAL_DAYS);

  if (left <= 0) {
    // שבוע חסד: מי ששכח לשלם אינו נופל מצוק. ההגנה על המחשבים
    // ממשיכה לפעול לאורך כל התקופה, גם אחרי שהחסד נגמר.
    const graceDays = tenant.graceDays ?? GRACE_DAYS;
    const graceEnds = new Date(tenant.trialEndsAt.getTime() + graceDays * 86_400_000);
    const graceLeft = daysBetween(now, graceEnds, graceDays);

    if (graceLeft > 0) {
      return {
        phase: "grace",
        daysLeft: graceLeft,
        endsAt: graceEnds,
        showBanner: true,
        headline:
          graceLeft === 1
            ? "יום אחרון לחידוש. ההגנה ממשיכה לפעול"
            : `תקופת הניסיון הסתיימה. נותרו ${graceLeft} ימים לחידוש`,
        needsAttention: true,
      };
    }

    return {
      phase: "trial_expired",
      daysLeft: 0,
      endsAt: graceEnds,
      showBanner: true,
      headline: "תקופת הניסיון הסתיימה",
      needsAttention: true,
    };
  }

  const ending = left <= REMINDER_DAYS[0];

  return {
    phase: ending ? "trial_ending" : "trial_active",
    daysLeft: left,
    endsAt: tenant.trialEndsAt,
    showBanner: true,
    headline:
      left === 1
        ? "יום אחרון בתקופת הניסיון"
        : `נותרו ${left} ימים בתקופת הניסיון`,
    needsAttention: ending,
  };
}

/** האם מותר לרשום מחשב נוסף במצב הנוכחי. */
export function canEnrollDevice(state: TrialState): boolean {
  return state.phase !== "canceled" && state.phase !== "trial_expired";
}

/**
 * האם ההגנה על המחשבים ממשיכה לפעול.
 *
 * התשובה היא כן בכל מצב, וזו החלטת מוצר מכוונת: הגנה שנעלמת בשקט
 * כשתשלום נכשל היא גרועה משתי סיבות. הורה ששכח לשלם מאבד הגנה בלי
 * לדעת, וילד שמבין את המנגנון פשוט ממתין שהניסיון ייגמר.
 *
 * מה שכן משתנה אחרי החסד: הפורטל נעול לפעולות, ונתיב ההסרה נפתח.
 */
export function enforcementContinues(_state: TrialState): boolean {
  return true;
}

/** האם הפורטל מוגבל לצפייה ולחידוש בלבד. */
export function portalReadOnly(state: TrialState): boolean {
  return state.phase === "trial_expired" || state.phase === "canceled";
}

/**
 * האם יש נתוני אימות לצורך הנפקת קוד הסרה.
 *
 * בניסיון ללא אשראי אין למה להשוות, ולכן המוקד חייב נתיב אחר.
 * ראה 7.2 באפיון השרת.
 */
export type VerificationMethod = "none" | "id_only" | "id_and_card";

export function verificationStrength(method: VerificationMethod): {
  usable: boolean;
  note: string;
} {
  switch (method) {
    case "id_and_card":
      return { usable: true, note: "תעודת זהות ואשראי" };
    case "id_only":
      return { usable: true, note: "תעודת זהות בלבד — אימות חלש יותר" };
    default:
      return {
        usable: false,
        note: "אין נתוני אימות. חשבון ניסיון ללא אשראי.",
      };
  }
}
