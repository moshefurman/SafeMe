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
   *   azure — Azure Key Vault
   */
  SIGNER: z.enum(["local", "aws", "azure"]).default("local"),
  SIGNER_LOCAL_KEY_PATH: z.string().optional(),
  SIGNER_KID: z.string().default("dev-policy-0"),
  SIGNER_KMS_KEY_ID: z.string().optional(),
});

export type Config = z.infer<typeof schema>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
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

  return config;
}
