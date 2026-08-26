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
    SIGNER: "local" | "aws" | "gcp" | "azure";
    SIGNER_KID: string;
    SIGNER_LOCAL_KEY_PATH?: string | undefined;
    SIGNER_KMS_KEY_ID?: string | undefined;
  },
  options?: { client?: KmsClientLike; gcpClient?: GcpKmsClientLike },
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
      "חתימה ב-Azure Key Vault טרם מומשה. יש להשתמש ב-SIGNER=aws או ב-SIGNER=gcp, " +
        "או לממש ספק לפי אותו מנשק — RSA-2048, PSS, SHA-256.",
    );
  }

  if (config.SIGNER === "gcp") {
    return new GcpKmsSigner({
      kid: config.SIGNER_KID,
      keyName: config.SIGNER_KMS_KEY_ID,
      client: options?.gcpClient ?? new LazyGcpClient(),
    });
  }

  return new AwsKmsSigner({
    kid: config.SIGNER_KID,
    keyId: config.SIGNER_KMS_KEY_ID,
    client: options?.client ?? new LazyKmsClient(),
  });
}

// ---------------------------------------------------------------- GCP

/**
 * טבלת CRC-32C (Castagnoli). נבנית פעם אחת בטעינת המודול.
 *
 * Google ממליצה לשלוח סיכום ביקורת עם כל בקשת חתימה, והשירות מחזיר
 * אם הוא התאים. חתימה על גיבוב שהשתבש בדרך תיראה תקינה לחלוטין —
 * היא פשוט תהיה חתימה על משהו אחר — ואת זה אי אפשר לגלות אחר כך.
 */
const CRC32C_TABLE: Uint32Array = (() => {
  const table = new Uint32Array(256);

  for (let i = 0; i < 256; i++) {
    let crc = i;
    for (let bit = 0; bit < 8; bit++) {
      crc = crc & 1 ? (crc >>> 1) ^ 0x82f63b78 : crc >>> 1;
    }
    table[i] = crc >>> 0;
  }

  return table;
})();

/** CRC-32C של מערך בתים. הבדיקה: "123456789" נותן 0xE3069283. */
export function crc32c(data: Uint8Array): number {
  let crc = 0xffffffff;

  for (const byte of data) {
    crc = (crc >>> 8) ^ CRC32C_TABLE[(crc ^ byte) & 0xff]!;
  }

  return (crc ^ 0xffffffff) >>> 0;
}

/** האלגוריתם היחיד ב-GCP שתואם את הסוכן. */
export const GCP_ALGORITHM = "RSA_SIGN_PSS_2048_SHA256";

export interface GcpKmsClientLike {
  asymmetricSign(request: {
    name: string;
    digest: { sha256: Uint8Array };
    digestCrc32c: { value: number };
  }): Promise<[{
    signature?: Uint8Array | string | null;
    verifiedDigestCrc32c?: boolean | null;
    signatureCrc32c?: { value?: number | string | null } | null;
    name?: string | null;
  }]>;

  getPublicKey(request: { name: string }): Promise<[{
    pem?: string | null;
    algorithm?: string | number | null;
  }]>;
}

/**
 * תבנית שם המשאב של גרסת מפתח ב-GCP, כפי שהשירות עצמו אוכף אותה.
 *
 * הבדיקה כאן חייבת להיות מלאה ולא רק על הסיומת. בדיקת סיומת בלבד
 * עוברת גם על נתיב שבו הוחלף שם הטבעת בשם המפתח והושמט מקטע
 * cryptoKeys — טעות טבעית, כי שני השמות דומים — והתקלה מתגלה רק
 * כשגיאת gRPC בת מאה שורות בפריסה.
 */
const GCP_KEY_VERSION_PATTERN =
  /^projects\/[^/]{1,100}\/locations\/[a-zA-Z0-9_-]{1,63}\/keyRings\/[a-zA-Z0-9_-]{1,63}\/cryptoKeys\/[a-zA-Z0-9_-]{1,63}\/cryptoKeyVersions\/[a-zA-Z0-9_-]{1,63}$/;

/** מסביר מה חסר בנתיב, או null אם הוא תקין. */
export function explainGcpKeyName(name: string): string | null {
  if (GCP_KEY_VERSION_PATTERN.test(name)) return null;

  const parts = name.split("/");
  const expected = ["projects", "locations", "keyRings", "cryptoKeys", "cryptoKeyVersions"];
  const missing = expected.filter((segment) => !parts.includes(segment));

  const detail = missing.length > 0
    ? `חסרים המקטעים: ${missing.join(", ")}`
    : "המבנה אינו תקין";

  return (
    `מזהה המפתח ב-GCP אינו תקין. ${detail}.\n` +
    "התקבל:  " + name + "\n" +
    "נדרש:   projects/<פרויקט>/locations/<אזור>/keyRings/<טבעת>" +
    "/cryptoKeys/<מפתח>/cryptoKeyVersions/<מספר>\n" +
    "העתק דרך Versions ← שלוש נקודות ← Copy resource name."
  );
}

/**
 * חתימה ב-Google Cloud KMS.
 *
 * שני הבדלים לטובה מול AWS: המפתח הציבורי מוחזר כ-PEM ולא כ-DER,
 * ולכן אין המרה; ויש סיכום ביקורת דו-כיווני על הבקשה ועל התשובה.
 *
 * הבדל אחד לרעה: המזהה חייב להצביע על **גרסת מפתח** ולא על המפתח
 * עצמו. זו הטעות השכיחה, והיא נבדקת כאן בעלייה.
 */
export class GcpKmsSigner implements Signer {
  readonly kid: string;

  readonly #name: string;

  readonly #client: GcpKmsClientLike;

  #cachedPem: string | null = null;

  constructor(options: { kid: string; keyName: string; client: GcpKmsClientLike }) {
    const problem = explainGcpKeyName(options.keyName);

    if (problem !== null) throw new Error(problem);

    this.kid = options.kid;
    this.#name = options.keyName;
    this.#client = options.client;
  }

  async sign(data: Uint8Array): Promise<Buffer> {
    const digest = createHash("sha256").update(data).digest();

    const [result] = await this.#client.asymmetricSign({
      name: this.#name,
      digest: { sha256: digest },
      digestCrc32c: { value: crc32c(digest) },
    });

    // השירות מאשר שהגיבוב הגיע שלם. false פירושו שהוא חתם על משהו
    // אחר ממה ששלחנו, וחתימה כזו תיראה תקינה לגמרי במכשיר.
    if (result.verifiedDigestCrc32c !== true) {
      throw new Error("GCP KMS לא אישר את שלמות הגיבוב. החתימה נזרקת.");
    }

    if (!result.signature) {
      throw new Error(`GCP KMS לא החזיר חתימה עבור ${this.#name}`);
    }

    const signature =
      typeof result.signature === "string"
        ? Buffer.from(result.signature, "base64")
        : Buffer.from(result.signature);

    // ואותה בדיקה בכיוון ההפוך, על התשובה
    const expected = result.signatureCrc32c?.value;

    if (expected !== null && expected !== undefined) {
      if (crc32c(signature) !== Number(expected)) {
        throw new Error("חתימת GCP KMS השתבשה בהעברה. החתימה נזרקת.");
      }
    }

    return signature;
  }

  async publicKeyPem(): Promise<string> {
    if (this.#cachedPem !== null) return this.#cachedPem;

    const [result] = await this.#client.getPublicKey({ name: this.#name });

    if (!result.pem) {
      throw new Error(`GCP KMS לא החזיר מפתח ציבורי עבור ${this.#name}`);
    }

    // אימות בעלייה. מפתח באלגוריתם אחר ייצור חתימות שכל מכשיר בשטח
    // ידחה, וזו תקלה שחייבת להתגלות לפני הפריסה.
    if (result.algorithm !== null && result.algorithm !== undefined) {
      const name = typeof result.algorithm === "string" ? result.algorithm : null;

      if (name !== null && name !== GCP_ALGORITHM) {
        throw new Error(
          `מפתח ${this.#name} הוא ${name}, ונדרש ${GCP_ALGORITHM}. ` +
            "הסוכן ידחה כל חתימה אחרת.",
        );
      }
    }

    this.#cachedPem = result.pem;
    return this.#cachedPem;
  }
}

/**
 * קורא את פרטי חשבון השירות מתוך משתנה סביבה.
 *
 * ה-SDK של Google מכיר רק את GOOGLE_APPLICATION_CREDENTIALS, שהוא
 * **נתיב לקובץ**. בפריסה לקונטיינר לרוב אין קובץ אלא רק ערך, ולכן
 * נתמך כאן גם GOOGLE_APPLICATION_CREDENTIALS_JSON שמכיל את התוכן
 * עצמו — כ-JSON או כ-base64, כי חלק מהפלטפורמות מקצצות שורות חדשות
 * והמפתח הפרטי בקובץ מכיל אותן.
 *
 * אם המשתנה אינו מוגדר, נופלים לזיהוי הרגיל של Google: הקובץ שבנתיב,
 * או זהות מנוהלת כשרצים בתוך GCP.
 */
function inlineGcpCredentials(env: NodeJS.ProcessEnv): Record<string, unknown> | null {
  const raw = env["GOOGLE_APPLICATION_CREDENTIALS_JSON"];

  if (!raw || raw.trim() === "") return null;

  const text = raw.trim().startsWith("{")
    ? raw
    : Buffer.from(raw, "base64").toString("utf8");

  let parsed: unknown;

  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(
      "GOOGLE_APPLICATION_CREDENTIALS_JSON אינו JSON תקין. " +
        "יש להדביק את תוכן הקובץ במלואו, או את אותו תוכן מקודד base64.",
    );
  }

  const credentials = parsed as { client_email?: unknown; private_key?: unknown };

  // שדה חסר כאן מתגלה אחרת רק בחתימה הראשונה, כשגיאת הרשאה מבלבלת
  if (typeof credentials.client_email !== "string" || typeof credentials.private_key !== "string") {
    throw new Error(
      "GOOGLE_APPLICATION_CREDENTIALS_JSON חסר client_email או private_key. " +
        "ודא שזה קובץ חשבון שירות ולא קובץ אחר.",
    );
  }

  return credentials as Record<string, unknown>;
}

export { inlineGcpCredentials };

/** נוצר בקריאה הראשונה בלבד, כדי לא להאט את עליית התהליך. */
class LazyGcpClient implements GcpKmsClientLike {
  #client: GcpKmsClientLike | null = null;

  async #get(): Promise<GcpKmsClientLike> {
    if (this.#client === null) {
      const { KeyManagementServiceClient } = await import("@google-cloud/kms");
      const credentials = inlineGcpCredentials(process.env);

      this.#client = new KeyManagementServiceClient(
        credentials ? { credentials } : {},
      ) as unknown as GcpKmsClientLike;
    }

    return this.#client;
  }

  async asymmetricSign(
    request: Parameters<GcpKmsClientLike["asymmetricSign"]>[0],
  ): ReturnType<GcpKmsClientLike["asymmetricSign"]> {
    return (await this.#get()).asymmetricSign(request);
  }

  async getPublicKey(
    request: Parameters<GcpKmsClientLike["getPublicKey"]>[0],
  ): ReturnType<GcpKmsClientLike["getPublicKey"]> {
    return (await this.#get()).getPublicKey(request);
  }
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
    SIGNER: "local" | "aws" | "gcp" | "azure";
    SIGNER_LOOSENING_KID: string;
    SIGNER_LOOSENING_KMS_KEY_ID?: string | undefined;
  },
  options?: { client?: KmsClientLike; gcpClient?: GcpKmsClientLike },
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
 * החותם של קודי ההסרה. מפתח שלישי ונפרד.
 *
 * ההסרה חייבת לעבור דרך החברה, וזו הדרישה שהמפתח הזה מגן עליה:
 * שרת שנפרץ ומסוגל לחתום מדיניות אינו מסוגל בכך גם להנפיק קוד
 * הסרה למכשיר כלשהו.
 */
export function createUninstallSigner(
  config: {
    SIGNER: "local" | "aws" | "gcp" | "azure";
    SIGNER_UNINSTALL_KID: string;
    SIGNER_UNINSTALL_KMS_KEY_ID?: string | undefined;
  },
  options?: { client?: KmsClientLike; gcpClient?: GcpKmsClientLike },
): Signer {
  return createSigner(
    {
      SIGNER: config.SIGNER,
      SIGNER_KID: config.SIGNER_UNINSTALL_KID,
      SIGNER_KMS_KEY_ID: config.SIGNER_UNINSTALL_KMS_KEY_ID,
    },
    options,
  );
}

/**
 * החותם של עדכוני הסוכן. מפתח רביעי ונפרד.
 *
 * זהו המפתח החזק במערכת: חתימה בו מורה למחשב מוגן להוריד קוד
 * ולהריץ אותו כ-SYSTEM. הוא מוגן בדיוק כמו האחרים, ובנפרד מהם.
 */
export function createUpdateSigner(
  config: {
    SIGNER: "local" | "aws" | "gcp" | "azure";
    SIGNER_UPDATE_KID: string;
    SIGNER_UPDATE_KMS_KEY_ID?: string | undefined;
  },
  options?: { client?: KmsClientLike; gcpClient?: GcpKmsClientLike },
): Signer {
  return createSigner(
    {
      SIGNER: config.SIGNER,
      SIGNER_KID: config.SIGNER_UPDATE_KID,
      SIGNER_KMS_KEY_ID: config.SIGNER_UPDATE_KMS_KEY_ID,
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
