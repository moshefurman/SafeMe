import {
  constants,
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
import { readFileSync } from "node:fs";

/**
 * חתימת מדיניות והיתרי הקלה.
 *
 * הפורמט חייב להתאים בדיוק לצד ה-C# בסוכן:
 *   אלגוריתם  RSASSA-PSS
 *   גיבוב     SHA-256
 *   אורך salt = אורך הגיבוב (32 בתים) — זו ברירת המחדל של
 *              RSASignaturePadding.Pss ב-.NET
 *
 * כל סטייה כאן פירושה שכל המכשירים בשטח ידחו כל מדיניות.
 */

export const ALG = "RSASSA-PSS-SHA256";

const PSS_OPTIONS = {
  padding: constants.RSA_PKCS1_PSS_PADDING,
  saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
} as const;

/**
 * ספק חתימה. המימוש בייצור מעביר את הבקשה ל-KMS ולעולם אינו
 * מחזיק את המפתח הפרטי בזיכרון התהליך.
 */
export interface Signer {
  readonly kid: string;
  sign(data: Uint8Array): Promise<Buffer>;
  publicKeyPem(): Promise<string>;
}

/**
 * חתימה מקומית. לפיתוח ולבדיקות בלבד — loadConfig חוסם אותה בייצור.
 */
export class LocalSigner implements Signer {
  readonly kid: string;

  readonly #privatePem: string;

  constructor(options: { kid: string; privateKeyPem: string }) {
    this.kid = options.kid;
    this.#privatePem = options.privateKeyPem;
  }

  static fromFile(kid: string, path: string): LocalSigner {
    return new LocalSigner({ kid, privateKeyPem: readFileSync(path, "utf8") });
  }

  /** מייצר זוג מפתחות זמני. משמש בבדיקות כדי לא לשמור מפתח במאגר. */
  static ephemeral(kid = "dev-policy-0"): LocalSigner {
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });

    return new LocalSigner({
      kid,
      privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    });
  }

  sign(data: Uint8Array): Promise<Buffer> {
    const key = createPrivateKey(this.#privatePem);
    return Promise.resolve(sign("sha256", data, { key, ...PSS_OPTIONS }));
  }

  publicKeyPem(): Promise<string> {
    const pub = createPublicKey(createPrivateKey(this.#privatePem));
    return Promise.resolve(pub.export({ type: "spki", format: "pem" }).toString());
  }
}

/**
 * הלקוח המינימלי שהחותם צריך מ-KMS.
 *
 * מוגדר כאן ולא נלקח מה-SDK כדי שאפשר יהיה להזריק כפיל בבדיקות:
 * את הדברים שקל לטעות בהם — סוג ההודעה, שם האלגוריתם, המרת
 * המפתח — אי אפשר לאמת מול AWS אמיתי בכל הרצת בדיקות.
 */
export interface KmsClientLike {
  send(command: unknown): Promise<{
    Signature?: Uint8Array;
    PublicKey?: Uint8Array;
    SigningAlgorithms?: string[];
    KeySpec?: string;
    KeyUsage?: string;
  }>;
}

/** האלגוריתם היחיד שתואם את הסוכן. ראה ההערה בראש הקובץ. */
export const KMS_ALGORITHM = "RSASSA_PSS_SHA_256";

/** מפרט המפתח היחיד הנתמך. */
export const KMS_KEY_SPEC = "RSA_2048";

/**
 * המרת מפתח ציבורי מ-DER ל-PEM.
 *
 * KMS מחזיר SPKI גולמי, ובבסיס הנתונים נשמר PEM. ההמרה חייבת
 * לייצר בדיוק את אותו טקסט ש-LocalSigner מייצר, אחרת registerSigningKey
 * יראה שני מפתחות שונים ויסרב להתחיל.
 */
export function derToPem(der: Uint8Array): string {
  const body = Buffer.from(der).toString("base64");
  const lines = body.match(/.{1,64}/g) ?? [];

  const NEWLINE = "\n";

  return [
    "-----BEGIN PUBLIC KEY-----",
    ...lines,
    "-----END PUBLIC KEY-----",
    "",
  ].join(NEWLINE);
}

/**
 * חתימה ב-AWS KMS. המפתח הפרטי אינו יוצא משם, ולכן פריצה לשרת
 * מאפשרת לבקש חתימות בזמן הפריצה אך לא לגנוב את המפתח.
 *
 * ההודעה נשלחת כ-DIGEST ולא כ-RAW משתי סיבות: KMS מגביל הודעה
 * גולמית ל-4096 בתים, ומעטפת מדיניות עשויה לחרוג; ומעבר לכך, שליחת
 * גיבוב מקומי חוסכת העברת התוכן עצמו ל-AWS.
 */
export class AwsKmsSigner implements Signer {
  readonly kid: string;

  readonly #keyId: string;

  readonly #client: KmsClientLike;

  /** המפתח הציבורי אינו משתנה, ואין טעם לשלם עליו קריאה בכל פעם. */
  #cachedPem: string | null = null;

  constructor(options: { kid: string; keyId: string; client: KmsClientLike }) {
    this.kid = options.kid;
    this.#keyId = options.keyId;
    this.#client = options.client;
  }

  async sign(data: Uint8Array): Promise<Buffer> {
    const { SignCommand } = await import("@aws-sdk/client-kms");

    const digest = createHash("sha256").update(data).digest();

    const result = await this.#client.send(
      new SignCommand({
        KeyId: this.#keyId,
        Message: digest,
        MessageType: "DIGEST",
        SigningAlgorithm: KMS_ALGORITHM,
      }),
    );

    if (!result.Signature) {
      throw new Error(`KMS לא החזיר חתימה עבור ${this.#keyId}`);
    }

    return Buffer.from(result.Signature);
  }

  async publicKeyPem(): Promise<string> {
    if (this.#cachedPem !== null) return this.#cachedPem;

    const { GetPublicKeyCommand } = await import("@aws-sdk/client-kms");

    const result = await this.#client.send(
      new GetPublicKeyCommand({ KeyId: this.#keyId }),
    );

    if (!result.PublicKey) {
      throw new Error(`KMS לא החזיר מפתח ציבורי עבור ${this.#keyId}`);
    }

    // אימות בעלייה, לא בזמן החתימה. מפתח עם מפרט שגוי ייצור חתימות
    // שכל מכשיר בשטח ידחה, וזו תקלה שחייבת להתגלות לפני הפריסה
    // ולא בפעם הראשונה שמפיצים מדיניות.
    if (result.KeySpec && result.KeySpec !== KMS_KEY_SPEC) {
      throw new Error(
        `מפתח ${this.#keyId} הוא ${result.KeySpec}, ונדרש ${KMS_KEY_SPEC}. ` +
          "הסוכן ידחה כל חתימה אחרת.",
      );
    }

    if (result.KeyUsage && result.KeyUsage !== "SIGN_VERIFY") {
      throw new Error(
        `מפתח ${this.#keyId} מוגדר ${result.KeyUsage}, ונדרש SIGN_VERIFY.`,
      );
    }

    if (result.SigningAlgorithms && !result.SigningAlgorithms.includes(KMS_ALGORITHM)) {
      throw new Error(
        `מפתח ${this.#keyId} אינו תומך ב-${KMS_ALGORITHM}. ` +
          `נתמכים: ${result.SigningAlgorithms.join(", ")}`,
      );
    }

    this.#cachedPem = derToPem(result.PublicKey);
    return this.#cachedPem;
  }
}

// ---------------------------------------------------------------- מעטפה

/**
 * המעטפה החתומה שנשלחת למכשיר.
 *
 * הרעיון כולו: הסוכן מאמת חתימה על **הבתים שהגיעו**, ולא על JSON
 * שהוא בנה מחדש בעצמו. כך אין תלות בסדר מפתחות, בבריחת תווים עבריים
 * או בייצוג מספרים — ההבדלים שבין System.Text.Json ל-JSON.stringify.
 */
export interface SignedEnvelope {
  alg: string;
  kid: string;
  /** base64url של הבתים המדויקים שנחתמו */
  payload: string;
  signature: string;
}

export function toBase64Url(data: Uint8Array): string {
  return Buffer.from(data).toString("base64url");
}

export function fromBase64Url(text: string): Buffer {
  return Buffer.from(text, "base64url");
}

/** מסדרת אובייקט לבתים, חותמת עליהם, ומחזירה גם את הבתים לשמירה. */
export async function buildEnvelope(
  signer: Signer,
  value: unknown,
): Promise<{ envelope: SignedEnvelope; bytes: Buffer; signature: Buffer }> {
  const bytes = Buffer.from(JSON.stringify(value), "utf8");
  const signature = await signer.sign(bytes);

  return {
    envelope: {
      alg: ALG,
      kid: signer.kid,
      payload: toBase64Url(bytes),
      signature: toBase64Url(signature),
    },
    bytes,
    signature,
  };
}

/** בונה מעטפה מבתים וחתימה ששמורים כבר במאגר, בלי לחתום מחדש. */
export function envelopeFromStored(
  kid: string,
  bytes: Buffer,
  signature: Buffer,
): SignedEnvelope {
  return { alg: ALG, kid, payload: toBase64Url(bytes), signature: toBase64Url(signature) };
}

/**
 * אימות מעטפה. זהו בדיוק מה שהסוכן עושה בצד השני, ולכן הוא משמש
 * בבדיקות כדי להוכיח שהחתימה שהשרת מייצר אכן ניתנת לאימות.
 */
export function verifyEnvelope(envelope: SignedEnvelope, publicKeyPem: string): boolean {
  if (envelope.alg !== ALG) return false;

  try {
    return verify(
      "sha256",
      fromBase64Url(envelope.payload),
      { key: createPublicKey(publicKeyPem), ...PSS_OPTIONS },
      fromBase64Url(envelope.signature),
    );
  } catch {
    return false;
  }
}

/** מפענח את גוף המעטפה לאחר אימות. לעולם לא לפני. */
export function decodeEnvelope<T>(envelope: SignedEnvelope): T {
  return JSON.parse(fromBase64Url(envelope.payload).toString("utf8")) as T;
}

export function createSigner(
  config: {
    SIGNER: "local" | "aws" | "azure";
    SIGNER_KID: string;
    SIGNER_LOCAL_KEY_PATH?: string | undefined;
    SIGNER_KMS_KEY_ID?: string | undefined;
  },
  options?: { client?: KmsClientLike },
): Signer {
  if (config.SIGNER === "local") {
    return config.SIGNER_LOCAL_KEY_PATH
      ? LocalSigner.fromFile(config.SIGNER_KID, config.SIGNER_LOCAL_KEY_PATH)
      : LocalSigner.ephemeral(config.SIGNER_KID);
  }

  if (!config.SIGNER_KMS_KEY_ID) {
    throw new Error("SIGNER_KMS_KEY_ID נדרש כאשר SIGNER אינו local");
  }

  if (config.SIGNER === "azure") {
    throw new Error(
      "חתימה ב-Azure Key Vault טרם מומשה. יש להשתמש ב-SIGNER=aws, " +
        "או לממש ספק לפי אותו מנשק — RSA-2048, PSS, SHA-256.",
    );
  }

  return new AwsKmsSigner({
    kid: config.SIGNER_KID,
    keyId: config.SIGNER_KMS_KEY_ID,
    client: options?.client ?? new LazyKmsClient(),
  });
}

/**
 * החותם של היתרי ההקלה. מפתח נפרד, ובמכוון.
 *
 * נבנה מאותה תצורה אך עם המפתח וה-kid של ההיתרים. ההפרדה נאכפת
 * בשלושה מקומות: config בודק שהמזהים שונים, כאן נבנה מפתח נפרד,
 * ו-buildApp משווה את המפתחות הציבוריים עצמם — כי שני כינויים
 * ב-KMS יכולים להצביע לאותו מפתח, ואת זה רק ההשוואה הזו תופסת.
 */
export function createLooseningSigner(
  config: {
    SIGNER: "local" | "aws" | "azure";
    SIGNER_LOOSENING_KID: string;
    SIGNER_LOOSENING_KMS_KEY_ID?: string | undefined;
  },
  options?: { client?: KmsClientLike },
): Signer {
  return createSigner(
    {
      SIGNER: config.SIGNER,
      SIGNER_KID: config.SIGNER_LOOSENING_KID,
      // מפתח מקומי מקובץ אינו נתמך להיתרים: קובץ אחד היה משמש את
      // שניהם, וזה בדיוק מה שההפרדה באה למנוע. בפיתוח נוצר מפתח
      // זמני נפרד.
      SIGNER_KMS_KEY_ID: config.SIGNER_LOOSENING_KMS_KEY_ID,
    },
    options,
  );
}

/**
 * עוטף את לקוח ה-KMS כך שהוא נוצר בקריאה הראשונה בלבד.
 *
 * createSigner נקרא בעליית התהליך, וטעינת ה-SDK שם הייתה מוסיפה
 * זמן עלייה גם להרצות שאינן חותמות דבר.
 */
class LazyKmsClient implements KmsClientLike {
  #client: KmsClientLike | null = null;

  async send(command: unknown): Promise<Awaited<ReturnType<KmsClientLike["send"]>>> {
    if (this.#client === null) {
      const { KMSClient } = await import("@aws-sdk/client-kms");
      this.#client = new KMSClient({}) as unknown as KmsClientLike;
    }

    return this.#client.send(command);
  }
}
