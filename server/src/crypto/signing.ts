import { constants, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
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
 * חתימה ב-KMS. המפתח הפרטי אינו יוצא משם, ולכן פריצה לשרת
 * מאפשרת לבקש חתימות בזמן הפריצה אך לא לגנוב את המפתח.
 *
 * המימוש דורש את ה-SDK של הספק ולכן נשאר פתוח עד לבחירת הענן.
 * הוא נכשל במפורש ולא מחזיר חתימה שגויה בשקט.
 */
export class KmsSigner implements Signer {
  readonly kid: string;

  readonly #keyId: string;

  readonly #provider: "aws" | "azure";

  constructor(options: { kid: string; keyId: string; provider: "aws" | "azure" }) {
    this.kid = options.kid;
    this.#keyId = options.keyId;
    this.#provider = options.provider;
  }

  sign(_data: Uint8Array): Promise<Buffer> {
    throw new Error(
      `חתימת ${this.#provider} KMS עבור ${this.#keyId} טרם מומשה. ` +
        "נדרש להתקין את ה-SDK של הספק ולוודא שהמפתח מוגדר RSA-2048 עם PSS/SHA-256.",
    );
  }

  publicKeyPem(): Promise<string> {
    throw new Error(`שליפת מפתח ציבורי מ-${this.#provider} KMS טרם מומשה.`);
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

export function createSigner(config: {
  SIGNER: "local" | "aws" | "azure";
  SIGNER_KID: string;
  SIGNER_LOCAL_KEY_PATH?: string | undefined;
  SIGNER_KMS_KEY_ID?: string | undefined;
}): Signer {
  if (config.SIGNER === "local") {
    return config.SIGNER_LOCAL_KEY_PATH
      ? LocalSigner.fromFile(config.SIGNER_KID, config.SIGNER_LOCAL_KEY_PATH)
      : LocalSigner.ephemeral(config.SIGNER_KID);
  }

  if (!config.SIGNER_KMS_KEY_ID) {
    throw new Error("SIGNER_KMS_KEY_ID נדרש כאשר SIGNER אינו local");
  }

  return new KmsSigner({
    kid: config.SIGNER_KID,
    keyId: config.SIGNER_KMS_KEY_ID,
    provider: config.SIGNER,
  });
}
