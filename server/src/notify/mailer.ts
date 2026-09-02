/**
 * שליחת הודעות לבעל החשבון.
 *
 * גילוי בלי הודעה שווה מעט: הורה לא ייכנס לפורטל כל יום, ואם ההגנה
 * הופסקה אתמול בלילה הוא צריך לדעת הבוקר.
 *
 * המנשק מופרד מהספק בכוונה. הבחירה בספק היא החלטה עסקית שטרם
 * התקבלה, וכל השאר — מתי שולחים, למי, ומה כתוב — נבנה ונבדק בלעדיה.
 * כשהספק ייבחר, הוא קובץ אחד.
 */

export interface Message {
  to: string;
  subject: string;
  /** גוף ההודעה כטקסט. HTML נוסף כשיהיה ספק אמיתי. */
  body: string;
}

export interface Mailer {
  readonly name: string;
  send(message: Message): Promise<void>;
}

/**
 * לא שולח כלום.
 *
 * ברירת המחדל כשאין ספק מוגדר. הוא מצליח בשקט ובמכוון: התראה
 * שנפתחה חשובה יותר מהודעה שנשלחה, ואין להפיל את הסריקה בגלל
 * הודעה שלא יצאה.
 */
export class NullMailer implements Mailer {
  readonly name = "none";

  private readonly sent: Message[] = [];

  send(message: Message): Promise<void> {
    this.sent.push(message);
    return Promise.resolve();
  }

  /** מה שהיה נשלח. משמש בבדיקות. */
  get outbox(): readonly Message[] {
    return this.sent;
  }
}

/** מדפיס ליומן במקום לשלוח. לפיתוח. */
export class ConsoleMailer implements Mailer {
  readonly name = "console";

  send(message: Message): Promise<void> {
    console.log(`\n── הודעה ל-${message.to} ──`);
    console.log(message.subject);
    console.log("");
    console.log(message.body);
    console.log("──\n");

    return Promise.resolve();
  }
}

/**
 * ספק שנבחר אך חסר לו מפתח.
 *
 * נכשל במפורש ולא בשקט: הודעה שלא נשלחה בלי שאיש יידע גרועה
 * מכישלון גלוי, כי היא יוצרת ביטחון שאינו קיים.
 */
export class UnconfiguredMailer implements Mailer {
  readonly name: string;

  private readonly why: string;

  constructor(provider: string, why: string) {
    this.name = provider;
    this.why = why;
  }

  send(): Promise<void> {
    return Promise.reject(new Error(this.why));
  }
}

/**
 * Resend.
 *
 * נבחר כי הוא ה-API הפשוט ביותר שעושה את העבודה: בקשה אחת, בלי
 * SDK ובלי תלות נוספת. אם יוחלף מחר, זה הקובץ היחיד שישתנה.
 *
 * מה שהמחלקה הזו **אינה** עושה: ניסיון חוזר. שליחה שנכשלה נרשמת
 * ונגמרת. התראה שתגיע פעמיים גרועה כמעט כמו התראה שלא הגיעה,
 * והניסיון החוזר שייך לשכבה שיודעת מה נשלח כבר.
 */
export class ResendMailer implements Mailer {
  readonly name = "resend";

  private readonly apiKey: string;
  private readonly from: string;
  private readonly replyTo: string | null;

  constructor(input: { apiKey: string; from: string; replyTo?: string | null }) {
    this.apiKey = input.apiKey;
    this.from = input.from;
    this.replyTo = input.replyTo ?? null;
  }

  async send(message: Message): Promise<void> {
    const controller = new AbortController();

    // הודעה שלא יצאה תוך עשר שניות לא תצא. החזקת הסורק אינה עוזרת.
    const timer = setTimeout(() => controller.abort(), 10_000);

    try {
      const response = await fetch("https://api.resend.com/emails", {
        method: "POST",
        signal: controller.signal,
        headers: {
          authorization: `Bearer ${this.apiKey}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          from: this.from,
          to: [message.to],
          subject: message.subject,
          text: message.body,
          ...(this.replyTo === null ? {} : { reply_to: this.replyTo }),
        }),
      });

      if (!response.ok) {
        /*
         * גוף השגיאה נכנס להודעה, אך חתוך.
         *
         * הוא מכיל את הסיבה האמיתית — דומיין שלא אומת, כתובת שנדחתה —
         * וזה בדיוק מה שצריך כדי לתקן. הוא **אינו** מכיל את המפתח,
         * שנשלח בכותרת בלבד.
         */
        const detail = (await response.text().catch(() => "")).slice(0, 300);

        throw new Error(`Resend החזיר ${response.status}. ${detail}`);
      }
    } finally {
      clearTimeout(timer);
    }
  }
}

export interface MailChoice {
  provider: "none" | "console" | "resend";
  apiKey?: string | undefined;
  from?: string | undefined;
  replyTo?: string | null | undefined;
}

/**
 * בונה את הדוור מהבחירה הפעילה.
 *
 * מחזיר ספק שנכשל במפורש — ולא NullMailer — כשהבחירה היא ספק אמיתי
 * שחסר לו משהו. השקט הוא הכשל שאסור כאן: מנהל שבחר Resend ושכח
 * מפתח היה מקבל מערכת שנראית עובדת ואינה שולחת דבר.
 */
export function createMailer(choice: MailChoice): Mailer {
  switch (choice.provider) {
    case "console":
      return new ConsoleMailer();

    case "resend": {
      if (!choice.apiKey) {
        return new UnconfiguredMailer(
          "resend",
          "חסר מפתח API ל-Resend. יש להגדיר את RESEND_API_KEY בסביבת השרת.",
        );
      }

      if (!choice.from) {
        return new UnconfiguredMailer(
          "resend",
          "לא הוגדרה כתובת שולח. יש לקבוע אותה במסך הדואר היוצא.",
        );
      }

      return new ResendMailer({
        apiKey: choice.apiKey,
        from: choice.from,
        replyTo: choice.replyTo ?? null,
      });
    }

    default:
      return new NullMailer();
  }
}

// ---------------------------------------------------------------- נוסחים

/**
 * ההודעה על מחשב ששתק.
 *
 * הנוסח אומר את מה שידוע ולא יותר. "המחשב לא מדווח" הוא עובדה;
 * "הילד ניתק את התוכנה" הוא ניחוש, ואם הוא יתברר כשגוי פעם אחת,
 * ההורה יפסיק להאמין לכל ההתראות.
 */
export function silentDeviceMessage(input: {
  to: string;
  deviceName: string;
  silenceText: string;
  portalUrl: string;
}): Message {
  return {
    to: input.to,
    subject: `SafeMe · ${input.deviceName} הפסיק לדווח`,
    body: [
      `שלום,`,
      ``,
      `${input.silenceText}`,
      ``,
      `מחשב שאינו מדווח עשוי להיות כבוי — או שההגנה עליו הופסקה.`,
      `כשהוא יחזור לדווח, SafeMe יבדוק ביומן האירועים של Windows אם`,
      `המחשב היה דלוק בזמן הזה, ויציג את התשובה במרכז הניהול.`,
      ``,
      `מרכז הניהול: ${input.portalUrl}`,
      ``,
      `— SafeMe`,
    ].join("\n"),
  };
}

/**
 * ההודעה על בקשה להחליף את כתובת ההתראות.
 *
 * יוצאת לשתי הכתובות — הישנה והחדשה — ובזה כל העניין. מי שהשיג
 * גישה לחשבון שולט במה שרואים בפורטל, אך לא בתיבה של ההורה.
 *
 * הכתובת הישנה מקבלת אזהרה עם קישור לעצירה. החדשה מקבלת הודעה
 * עניינית, כי היא עשויה להיות של אדם שלא ביקש דבר.
 */
export function emailChangeMessage(input: {
  to: string;
  audience: "current" | "new";
  fromEmail: string;
  newEmail: string;
  effectiveAt: Date;
  cancelUrl: string;
  portalUrl: string;
}): Message {
  const when = input.effectiveAt.toLocaleString("he-IL", {
    dateStyle: "short",
    timeStyle: "short",
  });

  if (input.audience === "new") {
    return {
      to: input.to,
      subject: "SafeMe · התבקשה העברת התראות לכתובת הזו",
      body: [
        "שלום,",
        "",
        `התקבלה בקשה להעביר את התראות SafeMe מהכתובת ${input.fromEmail}`,
        `לכתובת הזו. השינוי ייכנס לתוקף ב-${when}.`,
        "",
        "אם אינך מכיר את הבקשה, אין צורך לעשות דבר — בעל הכתובת",
        "הקודמת קיבל הודעה ויכול לעצור אותה.",
        "",
        "— SafeMe",
      ].join("\n"),
    };
  }

  return {
    to: input.to,
    subject: "SafeMe · מישהו מבקש להעביר את ההתראות שלך",
    body: [
      "שלום,",
      "",
      `התקבלה בקשה להעביר את התראות SafeMe לכתובת ${input.newEmail}.`,
      `אם לא תעצור אותה, היא תיכנס לתוקף ב-${when} — ומאותו רגע`,
      "ההתראות על המחשבים שלך יגיעו לשם ולא לכאן.",
      "",
      "אם לא ביקשת את זה, עצור עכשיו:",
      input.cancelUrl,
      "",
      "העצירה אינה דורשת כניסה לחשבון. זה מכוון: אם מישהו הגיע",
      "לחשבון שלך, הקישור הזה הוא מה שהוא אינו שולט בו.",
      "",
      `מרכז הניהול: ${input.portalUrl}`,
      "",
      "— SafeMe",
    ].join("\n"),
  };
}

/**
 * אימות כתובת נוספת.
 *
 * הכתובת אינה מקבלת דבר עד שבעליה לחץ. בלי זה, הוספת כתובת הייתה
 * דרך שקטה להזרים את ההתראות למי שרוצה לדעת מתי אפשר לפעול.
 */
export function verifyRecipientMessage(input: {
  to: string;
  tenantName: string;
  verifyUrl: string;
}): Message {
  return {
    to: input.to,
    subject: "SafeMe · אישור קבלת התראות",
    body: [
      "שלום,",
      "",
      `הכתובת הזו נוספה לקבלת התראות SafeMe של ${input.tenantName}.`,
      "כדי להתחיל לקבל אותן, אשר כאן:",
      input.verifyUrl,
      "",
      "אם אינך מכיר את הבקשה, התעלם מההודעה. בלי האישור הזה",
      "לא יישלח לכאן דבר.",
      "",
      "— SafeMe",
    ].join("\n"),
  };
}

/**
 * קישור לאיפוס סיסמה.
 *
 * הנוסח אינו מאשר שהחשבון קיים ואינו מזכיר את הכתובת, כי אותה
 * הודעה עלולה להגיע למי שלא ביקש — מישהו הקליד את כתובתו בטעות,
 * או ניסה לגלות אם היא רשומה.
 *
 * ומה שהוא כן אומר במפורש: שהתעלמות אינה משנה דבר. משתמש שקיבל
 * הודעה שלא ביקש צריך לדעת שאין לו מה לעשות, אחרת הוא ילחץ.
 */
export function passwordResetMessage(input: {
  to: string;
  resetUrl: string;
  minutes: number;
}): Message {
  return {
    to: input.to,
    subject: "SafeMe · איפוס סיסמה",
    body: [
      "שלום,",
      "",
      "התקבלה בקשה לאיפוס הסיסמה במרכז הניהול של SafeMe.",
      "לקביעת סיסמה חדשה:",
      input.resetUrl,
      "",
      `הקישור תקף ${input.minutes} דקות, ולשימוש אחד בלבד.`,
      "",
      "אם לא ביקשת, אין צורך לעשות דבר — הסיסמה הנוכחית נשארת",
      "בתוקף, והקישור יפוג מעצמו.",
      "",
      "— SafeMe",
    ].join("\n"),
  };
}
