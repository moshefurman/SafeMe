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
 * ספק אמיתי. טרם מומש.
 *
 * נכשל במפורש ולא בשקט: הודעה שלא נשלחה בלי שאיש יידע גרועה
 * מכישלון גלוי, כי היא יוצרת ביטחון שאינו קיים.
 */
export class UnconfiguredMailer implements Mailer {
  readonly name: string;

  constructor(provider: string) {
    this.name = provider;
  }

  send(): Promise<void> {
    return Promise.reject(
      new Error(
        `ספק ההודעות ${this.name} טרם מומש. יש להגדיר MAIL_PROVIDER=none ` +
          "או לממש את הספק.",
      ),
    );
  }
}

export function createMailer(config: {
  MAIL_PROVIDER: "none" | "console" | "resend";
}): Mailer {
  switch (config.MAIL_PROVIDER) {
    case "console":
      return new ConsoleMailer();

    case "resend":
      return new UnconfiguredMailer("resend");

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
