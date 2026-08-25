import { z } from "zod";

/**
 * תצורת השרת. נטענת פעם אחת בעלייה, ונכשלת מיד אם חסר משהו —
 * עדיף שהשרת לא יעלה מאשר שיעלה בלי מפתח חתימה ויגלה זאת בבקשה הראשונה.
 */

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(3000),
  HOST: z.string().default("127.0.0.1"),

  DATABASE_URL_APP: z.string().min(1, "חסרה מחרוזת חיבור של האפליקציה"),

  /** סוד לחתימת אסימוני מכשיר. אינו קשור למפתח חתימת המדיניות. */
  DEVICE_TOKEN_SECRET: z.string().min(32, "DEVICE_TOKEN_SECRET חייב להיות באורך 32 תווים לפחות"),
  DEVICE_TOKEN_TTL_DAYS: z.coerce.number().int().positive().default(7),

  /**
   * ספק החתימה.
   *   local — מפתח בקובץ. לפיתוח ולבדיקות בלבד.
   *   aws   — AWS KMS
   *   gcp   — Google Cloud KMS
   *   azure — Azure Key Vault
   */
  SIGNER: z.enum(["local", "aws", "gcp", "azure"]).default("local"),
  SIGNER_LOCAL_KEY_PATH: z.string().optional(),
  SIGNER_KID: z.string().default("dev-policy-0"),
  SIGNER_KMS_KEY_ID: z.string().optional(),

  /**
   * מפתח היתרי ההקלה — נפרד ובמכוון.
   *
   * זו כל ההגנה מאחורי "להחמיר כן, להסיר לא": הסוכן מקבל הקלה מתחת
   * לרצפה רק אם היא חתומה במפתח שאינו זה שחותם על מדיניות רגילה.
   * מפתח אחד לשניהם היה הופך כל פרסום מדיניות ליכולת להקל, ומבטל
   * את ההפרדה בלי שום סימן חיצוני.
   */
  SIGNER_LOOSENING_KID: z.string().default("dev-loosening-0"),
  SIGNER_LOOSENING_KMS_KEY_ID: z.string().optional(),

  /**
   * מפתח קודי ההסרה — נפרד משני האחרים.
   *
   * הדרישה היא שהסרה תעבור תמיד דרך החברה. כל עוד קוד ההסרה מאומת
   * במפתח המדיניות, מי שמשיג את היכולת לחתום מדיניות מקבל גם את
   * היכולת להסיר כל מכשיר בשטח — ושתי הסמכויות האלה לא אמורות
   * לנסוע יחד.
   */
  SIGNER_UNINSTALL_KID: z.string().default("dev-uninstall-0"),
  SIGNER_UNINSTALL_KMS_KEY_ID: z.string().optional(),
});

export type Config = z.infer<typeof schema>;

/**
 * מנקה את הסביבה לפני האימות.
 *
 * שני תיקונים שמונעים פריסה כושלת מסיבה חסרת עניין:
 *
 * רווחים — הדבקת נתיב מפתח ארוך לממשק של ספק אירוח גוררת לעיתים
 * רווח או שורה בסוף. נתיב כזה נראה נכון לחלוטין בעין ונדחה על ידי
 * KMS בהודעה שלא מרמזת על הסיבה.
 *
 * רישיות ב-SIGNER — הספקים נקראים AWS ו-GCP, וזה מה שמקלידים.
 * קפדנות כאן לא מוסיפה שום ביטחון.
 */
function normalize(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const cleaned: NodeJS.ProcessEnv = { ...env };

  for (const key of Object.keys(schema.shape)) {
    const value = cleaned[key];
    if (typeof value === "string") cleaned[key] = value.trim();
  }

  if (typeof cleaned["SIGNER"] === "string") {
    cleaned["SIGNER"] = cleaned["SIGNER"].toLowerCase();
  }

  return cleaned;
}

export function loadConfig(rawEnv: NodeJS.ProcessEnv = process.env): Config {
  const env = normalize(rawEnv);
  const parsed = schema.safeParse(env);

  if (!parsed.success) {
    const details = parsed.error.issues
      .map((i) => `  ${i.path.join(".")}: ${i.message}`)
      .join("\n");

    throw new Error(`תצורה לא תקינה:\n${details}`);
  }

  const config = parsed.data;

  // חתימה מקומית בייצור פירושה מפתח פרטי על שרת האפליקציה,
  // וזו בדיוק ההנחה ש-11.1 באפיון אוסר.
  if (config.NODE_ENV === "production" && config.SIGNER === "local") {
    throw new Error(
      "SIGNER=local אסור בייצור. המפתח הפרטי חייב לחיות ב-KMS ולא על שרת האפליקציה.",
    );
  }

  // ---- הפרדת שלושת המפתחות ----
  //
  // כל מפתח הוא סמכות אחת: לחתום מדיניות, להקל אותה, או להסיר
  // מכשיר. שיתוף מפתח בין שתיים מהן פירושו שמי שהשיג אחת קיבל גם
  // את השנייה, בלי שום סימן חיצוני.
  //
  // כאן מושווים המזהים בלבד. את המקרה שבו שני מזהים שונים מצביעים
  // לאותו מפתח אפשר לתפוס רק מול המפתחות עצמם, וזה קורה ב-buildApp.

  const kids = [
    ["SIGNER_KID", config.SIGNER_KID],
    ["SIGNER_LOOSENING_KID", config.SIGNER_LOOSENING_KID],
    ["SIGNER_UNINSTALL_KID", config.SIGNER_UNINSTALL_KID],
  ] as const;

  for (let i = 0; i < kids.length; i++) {
    for (let j = i + 1; j < kids.length; j++) {
      if (kids[i]![1] === kids[j]![1]) {
        throw new Error(
          `${kids[i]![0]} ו-${kids[j]![0]} זהים. הסוכן בוחר מפתח אימות לפי ה-kid, ` +
            "ולכן שני מזהים זהים פירושם שהוא לא יבדיל ביניהם.",
        );
      }
    }
  }

  if (config.SIGNER !== "local") {
    const keys = [
      ["SIGNER_KMS_KEY_ID", config.SIGNER_KMS_KEY_ID, "מדיניות"],
      ["SIGNER_LOOSENING_KMS_KEY_ID", config.SIGNER_LOOSENING_KMS_KEY_ID, "היתרי הקלה"],
      ["SIGNER_UNINSTALL_KMS_KEY_ID", config.SIGNER_UNINSTALL_KMS_KEY_ID, "קודי הסרה"],
    ] as const;

    for (const [name, value, purpose] of keys) {
      if (!value) {
        throw new Error(`${name} נדרש. ${purpose} מחייבים מפתח נפרד משלהם.`);
      }
    }

    for (let i = 0; i < keys.length; i++) {
      for (let j = i + 1; j < keys.length; j++) {
        if (keys[i]![1] === keys[j]![1]) {
          throw new Error(
            `${keys[i]![0]} ו-${keys[j]![0]} מצביעים לאותו מפתח. ` +
              "כל סמכות חייבת מפתח משלה.",
          );
        }
      }
    }
  }

  // אישורי GCP: להיכשל בעלייה ולא בחתימה הראשונה. שגיאת הרשאה
  // מ-KMS נראית כמו בעיית מפתח, ומחפשים אותה במקום הלא נכון.
  if (config.SIGNER === "gcp" && config.NODE_ENV === "production") {
    const hasInline = (env["GOOGLE_APPLICATION_CREDENTIALS_JSON"] ?? "").trim() !== "";
    const hasPath = (env["GOOGLE_APPLICATION_CREDENTIALS"] ?? "").trim() !== "";

    if (!hasInline && !hasPath) {
      throw new Error(
        "SIGNER=gcp דורש אישורי חשבון שירות: GOOGLE_APPLICATION_CREDENTIALS_JSON " +
          "עם תוכן הקובץ, או GOOGLE_APPLICATION_CREDENTIALS עם נתיב אליו.",
      );
    }
  }

  return config;
}
