import { createHmac } from "node:crypto";

import { inlineGcpCredentials } from "./signing.ts";

/**
 * סוד ההסרה של מחשב, נגזר ולא נשמר.
 *
 * קוד ההסרה נחתם היום ב-RSA, והחתימה היא כשש מאות תווים בבסיס 64.
 * זה עובד כשמדביקים, ואי אפשר להכתיב את זה בטלפון — כלומר מסלול
 * המוקד אינו שמיש בדיוק במצב שבשבילו הוא קיים: מחשב חסום, בלי
 * אינטרנט, והורה שמחייג.
 *
 * הסוכן כבר יודע לאמת קוד קצר: HMAC קטוע ל-15 בתים, מקודד Base32
 * Crockford, עשרים וארבעה תווים בארבע קבוצות. המנגנון היה בנוי
 * ומעולם לא נבחר, כי בצד השרת לא היה מי שיפיק אותו.
 *
 * ---
 *
 * HMAC מחייב סוד משותף: הסוכן חייב להחזיק אותו, כי הוא מאמת בלי
 * אינטרנט. אין דרך לעקוף את זה, וזה מקובל — חילוץ הסוד ממחשב אחד
 * פותח את אותו מחשב בלבד.
 *
 * מה שאינו מקובל הוא שהשרת ישמור סוד לכל מחשב. דליפת מסד הייתה
 * פותחת את כל הצי בבת אחת, וזה בדיוק מה שהמפתח ב-KMS נועד למנוע
 * במסלול ה-RSA.
 *
 * לכן הסוד נגזר ואינו נשמר:
 *
 *     deviceSecret = HMAC(master, "filterplus:uninstall:v1|" + hwid)
 *
 * השרת מחשב אותו בעת הצורך ושוכח. מה שנשמר הוא רק המפתח הראשי,
 * ובייצור הוא יושב ב-KMS ואינו יוצא ממנו.
 */

/** הפרדת מרחב, כדי שאותו מפתח ראשי לא ייתן את אותו סוד לשימוש אחר. */
const CONTEXT = "filterplus:uninstall:v1|";

/**
 * מקור המפתח הראשי.
 *
 * שתי מימושים: אחד מקומי לפיתוח, ואחד שמעביר את החישוב ל-KMS.
 * הממשק זהה כדי שהקוד שמשתמש בו לא ידע במה מדובר — וכדי שמעבר
 * בין השניים לא ידרוש שינוי בקריאה.
 */
export interface DeviceSecretDeriver {
  derive(hwid: string): Promise<Buffer>;
}

/**
 * גזירה מקומית ממפתח בסביבה.
 *
 * לפיתוח, ולפריסות שאין בהן KMS. loadConfig חוסם מפתח ברירת מחדל
 * בייצור, בדיוק כפי שהוא חוסם חתימה מקומית.
 */
export class LocalDeviceSecretDeriver implements DeviceSecretDeriver {
  readonly #master: Buffer;

  constructor(masterKey: string) {
    if (masterKey.trim().length < 32) {
      throw new Error("מפתח גזירת סודות חייב להיות באורך 32 תווים לפחות.");
    }

    this.#master = Buffer.from(masterKey, "utf8");
  }

  derive(hwid: string): Promise<Buffer> {
    return Promise.resolve(
      createHmac("sha256", this.#master).update(CONTEXT + hwid, "utf8").digest(),
    );
  }
}

/**
 * גזירה ב-KMS.
 *
 * המפתח הוא מסוג MAC, והחישוב מתבצע אצל הספק. השרת שולח את הקלט
 * ומקבל את התוצאה; המפתח עצמו אינו נחשף לו, ולכן דליפה של השרת
 * אינה מאפשרת לחשב סודות של מחשבים אחרים — היא מאפשרת רק לבקש
 * חישוב, וזה נרשם ומוגבל בהרשאות.
 */
/** מה שנדרש מלקוח KMS לצורך גזירה. מצומצם בכוונה, כדי שאפשר יהיה להחליף. */
export interface KmsMacClient {
  macSign(request: { name: string; data: Buffer }): Promise<[{ mac?: Uint8Array | null }]>;
}

export class KmsDeviceSecretDeriver implements DeviceSecretDeriver {
  readonly #keyName: string;
  readonly #client: KmsMacClient;

  constructor(keyName: string, client: KmsMacClient) {
    this.#keyName = keyName;
    this.#client = client;
  }

  async derive(hwid: string): Promise<Buffer> {
    const [result] = await this.#client.macSign({
      name: this.#keyName,
      data: Buffer.from(CONTEXT + hwid, "utf8"),
    });

    if (!result.mac) throw new Error("KMS לא החזיר MAC עבור גזירת סוד המחשב.");

    return Buffer.from(result.mac);
  }
}

/*
 * הפקת הקוד עצמו אינה כאן.
 *
 * generateHmacResponse ב-challenge.ts כבר עושה בדיוק את זה, ובאותו
 * קידוד שהסוכן מצפה לו. מימוש שני היה נראה זהה היום ומתפצל מחר —
 * וכשקוד הסרה מפסיק להתאים, איש לא יחשוד בשתי פונקציות שנכתבו
 * להיות אותו דבר.
 */

/**
 * לקוח KMS, נטען עצלנית.
 *
 * החבילה של Google כבדה ואינה נחוצה בפריסה מקומית, ולכן היא
 * מיובאת רק כשבאמת הוגדר מפתח — בדיוק כפי ש-signing.ts עושה
 * עבור החתימה.
 */
export async function createKmsMacClient(): Promise<KmsMacClient> {
  const { KeyManagementServiceClient } = await import("@google-cloud/kms");

  /*
   * אותם אישורים כמו לקוח החתימה, ומאותו מקור.
   *
   * לקוח בלי אישורים מפורשים פונה לשרת המטא-דאטה של הספק, ו-Render
   * אינה אחת — הקריאה נכשלת ב-MetadataLookupWarning ואיתה כל גזירה.
   * זה נראה בלוג הפריסה עוד לפני שהקוד הזה נכנס, ולכן היה ברור
   * שלקוח שני חייב לקבל את אותו טיפול.
   *
   * inlineGcpCredentials ולא העתקה של הלוגיקה: שני מקומות שקוראים
   * אישורים בנפרד מתפצלים בסוף, ואז חתימה עובדת וגזירה לא.
   */
  const credentials = inlineGcpCredentials(process.env);

  const client = new KeyManagementServiceClient(credentials ? { credentials } : {});

  return {
    async macSign(request) {
      const [result] = await client.macSign(request);

      /*
       * KMS מחזיר גם מחרוזת, לפי הקידוד שהלקוח בחר.
       *
       * המרה מפורשת ולא הנחה: mac שחוזר כמחרוזת ומטופל כבתים היה
       * מייצר סוד אחר לגמרי, וקוד הסרה שלא מתאים — בלי שום שגיאה
       * בדרך.
       */
      const mac = result.mac;

      return [{
        mac: mac === null || mac === undefined
          ? null
          : typeof mac === "string"
            ? new Uint8Array(Buffer.from(mac, "base64"))
            : new Uint8Array(mac),
      }];
    },
  };
}
