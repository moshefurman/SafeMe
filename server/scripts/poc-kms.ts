/**
 * חתימה ב-AWS KMS.
 *
 * מול KMS אמיתי אי אפשר לבדוק בכל הרצה, ולכן נבדק כאן מול כפיל
 * שמחקה את הסמנטיקה: הוא מקבל גיבוב, חותם ב-PSS/SHA-256 ומחזיר
 * SPKI גולמי — בדיוק כמו השירות.
 *
 * מה שנבדק הוא בדיוק מה שקל לטעות בו ואי אפשר לגלות בלי לפרוס:
 * סוג ההודעה, שם האלגוריתם, והמרת המפתח ל-PEM.
 */

import {
  constants,
  createHash,
  createPublicKey,
  generateKeyPairSync,
  privateEncrypt,
  randomBytes,
} from "node:crypto";

import {
  AwsKmsSigner,
  KMS_ALGORITHM,
  KMS_KEY_SPEC,
  buildEnvelope,
  createSigner,
  derToPem,
  verifyEnvelope,
  type KmsClientLike,
} from "../src/crypto/signing.ts";

let passed = 0;
let failed = 0;

function check(ok: boolean, name: string, detail = "") {
  if (ok) {
    passed++;
    console.log(`  ✓ ${name}${detail ? `\n      ${detail}` : ""}`);
  } else {
    failed++;
    console.log(`  ✗ ${name}${detail ? `\n      ${detail}` : ""}`);
  }
}

async function throws(fn: () => Promise<unknown>): Promise<string | null> {
  try {
    await fn();
    return null;
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
}

// ------------------------------------------------------- הכפיל

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const publicDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;

/**
 * חתימה על גיבוב מוכן, כפי ש-KMS עושה עם MessageType=DIGEST.
 *
 * ה-API הגבוה של Node אינו יודע לעשות זאת: crypto.sign(null, digest)
 * עם PSS נופל ל-MGF1 אחר, ומייצר חתימה שמאמת PSS/SHA-256 תקני דוחה.
 * לכן הקידוד כתוב כאן במפורש לפי RFC 8017 §9.1.1 — וכך הכפיל מדמה
 * את KMS ולא הנחה על KMS.
 */
function mgf1(seed: Buffer, length: number): Buffer {
  const blocks: Buffer[] = [];
  let produced = 0;

  for (let counter = 0; produced < length; counter++) {
    const c = Buffer.alloc(4);
    c.writeUInt32BE(counter);

    const block = createHash("sha256").update(seed).update(c).digest();
    blocks.push(block);
    produced += block.length;
  }

  return Buffer.concat(blocks).subarray(0, length);
}

function signDigest(mHash: Buffer): Buffer {
  const hLen = 32;
  const sLen = 32;
  const emBits = 2047; // modBits - 1, עבור מפתח 2048
  const emLen = Math.ceil(emBits / 8);

  const salt = randomBytes(sLen);
  const mPrime = Buffer.concat([Buffer.alloc(8), mHash, salt]);
  const H = createHash("sha256").update(mPrime).digest();

  const psLen = emLen - sLen - hLen - 2;
  const db = Buffer.concat([Buffer.alloc(psLen), Buffer.from([0x01]), salt]);

  const maskedDb = Buffer.from(db);
  const mask = mgf1(H, emLen - hLen - 1);
  for (let i = 0; i < maskedDb.length; i++) maskedDb[i]! ^= mask[i]!;

  // איפוס הביטים העודפים משמאל
  maskedDb[0]! &= 0xff >> (8 * emLen - emBits);

  const em = Buffer.concat([maskedDb, H, Buffer.from([0xbc])]);

  return privateEncrypt({ key: privatePem, padding: constants.RSA_NO_PADDING }, em);
}

interface FakeOptions {
  keySpec?: string;
  keyUsage?: string;
  algorithms?: string[];
}

/** מה שהכפיל ראה בפועל — כדי לאמת את הבקשה ולא רק את התוצאה. */
const seen: { messageType?: string; algorithm?: string; message?: Buffer } = {};

function fakeKms(options: FakeOptions = {}): KmsClientLike {
  return {
    async send(command: unknown) {
      const name = (command as { constructor: { name: string } }).constructor.name;
      const input = (command as { input: Record<string, unknown> }).input;

      if (name === "GetPublicKeyCommand") {
        return {
          PublicKey: new Uint8Array(publicDer),
          KeySpec: options.keySpec ?? KMS_KEY_SPEC,
          KeyUsage: options.keyUsage ?? "SIGN_VERIFY",
          SigningAlgorithms: options.algorithms ?? [KMS_ALGORITHM],
        };
      }

      if (name === "SignCommand") {
        seen.messageType = input["MessageType"] as string;
        seen.algorithm = input["SigningAlgorithm"] as string;
        seen.message = Buffer.from(input["Message"] as Uint8Array);

        return { Signature: new Uint8Array(signDigest(seen.message)) };
      }

      throw new Error(`הכפיל אינו מכיר את ${name}`);
    },
  };
}

// ------------------------------------------------------- המרת המפתח

console.log("\n── המרת מפתח ציבורי ──\n");

const fromNode = publicKey.export({ type: "spki", format: "pem" }).toString();
const fromKms = derToPem(new Uint8Array(publicDer));

check(
  fromKms === fromNode,
  "derToPem מייצר בדיוק את אותו PEM ש-Node מייצר",
  fromKms === fromNode
    ? `${fromKms.split("\n").length - 1} שורות, זהה תו בתו`
    : `שונה:\n${JSON.stringify(fromKms.slice(0, 80))}\n${JSON.stringify(fromNode.slice(0, 80))}`,
);

// זו ההשוואה שבאמת מתבצעת בעלייה, ב-registerSigningKey
check(
  createPublicKey(fromKms).export({ type: "spki", format: "der" }).equals(publicDer),
  "ה-PEM נטען חזרה למפתח זהה",
);

// ------------------------------------------------------- החתימה

console.log("\n── החתימה ──\n");

const signer = new AwsKmsSigner({ kid: "kms-policy-1", keyId: "arn:fake", client: fakeKms() });

const pem = await signer.publicKeyPem();
check(pem === fromNode, "publicKeyPem מחזיר PEM תקין");

const payload = { version: 42, note: "מדיניות עם עברית ותווים מיוחדים: \" \ ✓" };
const built = await buildEnvelope(signer, payload);
const envelope = built.envelope;

check(
  verifyEnvelope(envelope, pem),
  "מעטפה שנחתמה ב-KMS עוברת אימות באותו מסלול כמו מקומית",
);

check(seen.messageType === "DIGEST", "ההודעה נשלחה כ-DIGEST", `נשלח ${seen.messageType}`);
check(seen.algorithm === KMS_ALGORITHM, "האלגוריתם נכון", `נשלח ${seen.algorithm}`);

// הגיבוב שנשלח חייב להיות של הבתים שנחתמו, לא של משהו אחר
const payloadBytes = Buffer.from(envelope.payload, "base64url");
check(
  seen.message!.equals(createHash("sha256").update(payloadBytes).digest()),
  "הגיבוב שנשלח הוא של המטען עצמו",
  `${seen.message!.length} בתים`,
);

// שינוי בתוכן חייב לפסול את החתימה
const tampered = { ...envelope, payload: Buffer.from('{"version":43}').toString("base64url") };
check(!verifyEnvelope(tampered, pem), "מטען שהוחלף נפסל");

// מפתח אחר חייב לפסול
const other = generateKeyPairSync("rsa", { modulusLength: 2048 });
check(
  !verifyEnvelope(envelope, other.publicKey.export({ type: "spki", format: "pem" }).toString()),
  "מפתח אחר אינו מאמת",
);

// ------------------------------------------------------- שמירות

console.log("\n── סירוב על מפתח לא מתאים ──\n");

const wrongSpec = new AwsKmsSigner({
  kid: "k", keyId: "arn:wrong-spec", client: fakeKms({ keySpec: "RSA_4096" }),
});
const specError = await throws(() => wrongSpec.publicKeyPem());
check(
  specError !== null && specError.includes("RSA_4096"),
  "מפתח RSA_4096 נדחה בעלייה",
  specError ?? "לא נזרקה שגיאה",
);

const wrongUsage = new AwsKmsSigner({
  kid: "k", keyId: "arn:wrong-usage", client: fakeKms({ keyUsage: "ENCRYPT_DECRYPT" }),
});
const usageError = await throws(() => wrongUsage.publicKeyPem());
check(
  usageError !== null && usageError.includes("SIGN_VERIFY"),
  "מפתח להצפנה נדחה",
  usageError ?? "לא נזרקה שגיאה",
);

const wrongAlg = new AwsKmsSigner({
  kid: "k", keyId: "arn:wrong-alg", client: fakeKms({ algorithms: ["RSASSA_PKCS1_V1_5_SHA_256"] }),
});
const algError = await throws(() => wrongAlg.publicKeyPem());
check(
  algError !== null && algError.includes(KMS_ALGORITHM),
  "מפתח בלי תמיכה ב-PSS נדחה",
  algError ?? "לא נזרקה שגיאה",
);

// ------------------------------------------------------- createSigner

console.log("\n── בחירת הספק ──\n");

const viaFactory = createSigner(
  { SIGNER: "aws", SIGNER_KID: "kms-1", SIGNER_KMS_KEY_ID: "arn:fake" },
  { client: fakeKms() },
);
check(viaFactory instanceof AwsKmsSigner, "SIGNER=aws מייצר חותם KMS");

const noKey = await throws(async () =>
  createSigner({ SIGNER: "aws", SIGNER_KID: "k" }),
);
check(
  noKey !== null && noKey.includes("SIGNER_KMS_KEY_ID"),
  "SIGNER=aws בלי מזהה מפתח נדחה",
);

const azure = await throws(async () =>
  createSigner({ SIGNER: "azure", SIGNER_KID: "k", SIGNER_KMS_KEY_ID: "x" }),
);
check(
  azure !== null && azure.includes("Azure"),
  "Azure נכשל במפורש ולא בשקט",
  azure ?? "",
);

console.log(`\n${failed === 0 ? "✓" : "✗"} ${passed} עברו, ${failed} נכשלו\n`);
process.exit(failed === 0 ? 0 : 1);
