import { tokenFromFileName } from "../src/installer/filename.ts";
import { constants, createHash, createPrivateKey, sign } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  base32Decode,
  base32Encode,
  base32Group,
  buildChallengeBytes,
  crc16,
  generateHmacResponse,
  generateRsaResponse,
  normalizeHwidComponent,
  parseChallenge,
  verifyRsaResponse,
} from "../src/crypto/challenge.ts";

/**
 * מאמת שהמימוש ב-TypeScript זהה למימוש ב-C#.
 *
 * הווקטורים נוצרים בצד ה-C# (`dotnet run --project tools/FilterPlus.CodeGen -- vectors`),
 * והסקריפט הזה חייב לעבור את כולם. כישלון כאן משמעו שהשרת והסוכן
 * כבר לא מדברים באותו פרוטוקול — וזה ייראה בשטח כקוד הסרה שלא עובד.
 *
 * בסיום נכתבת בחזרה חתימת RSA שנוצרה כאן, כדי שבדיקת ה-C#
 * תאמת גם את הכיוון ההפוך: שרת חותם, סוכן מאמת.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const VECTORS_PATH = join(HERE, "..", "..", "shared", "test-vectors.json");

interface Vectors {
  version: number;
  generatedBy: string;
  context: string;
  base32: Array<{ hex: string; text: string; grouped: string }>;
  crc16: Array<{ hex: string; crc: number }>;
  challenges: Array<{
    hwid: string;
    hwidHashHex: string;
    flags: number;
    issuedUnixMinutes: number;
    nonceHex: string;
    bytesHex: string;
    signedPayloadHex: string;
    display: string;
    mode: string;
    offlineEmergency: boolean;
  }>;
  hmac: Array<{ secretHex: string; challengeDisplay: string; response: string }>;
  rsa: {
    publicKeyPem: string;
    privateKeyPem: string;
    challengeDisplay: string;
    signedInputHex: string;
    signatureFromCSharp: string;
    signatureFromTypeScript?: string;
    saltLength: number;
  };
  hwid: Array<{ components: Array<string | null>; id: string }>;
  installerNames: Array<{ fileName: string; token?: string | null }>;
  policyEnvelopeFromTypeScript?: {
    alg: string;
    kid: string;
    payload: string;
    signature: string;
    expectedVersion: number;
    expectedProviderName: string;
  };
}

let passed = 0;
let failed = 0;

function check(condition: boolean, title: string, detail = ""): void {
  if (condition) {
    passed += 1;
    console.log(`  ✓ ${title}${detail ? ` — ${detail}` : ""}`);
  } else {
    failed += 1;
    console.log(`  ✗ ${title}${detail ? ` — ${detail}` : ""}`);
  }
}

function section(title: string): void {
  console.log(`\n${title}`);
  console.log("─".repeat(64));
}

/** מזהה חומרה: SHA-256 על הרכיבים המנורמלים, מקודד Base32, 26 תווים. */
function buildHwid(components: Array<string | null>): string {
  const normalized = components
    .map(normalizeHwidComponent)
    .filter((v): v is string => v !== null);

  if (normalized.length === 0) throw new Error("אין רכיב חומרה יציב");

  const hash = createHash("sha256").update(normalized.join("|"), "utf8").digest();

  return base32Encode(hash).slice(0, 26);
}

async function main(): Promise<void> {
  const raw = await readFile(VECTORS_PATH, "utf8");
  const v = JSON.parse(raw) as Vectors;

  console.log(`וקטורי בדיקה גרסה ${v.version}, נוצרו על ידי ${v.generatedBy}`);

  // ─────────────────────────────────────────────── Base32
  section("Base32-Crockford");

  for (const item of v.base32) {
    const bytes = Buffer.from(item.hex, "hex");
    const encoded = base32Encode(bytes);

    check(encoded === item.text, `קידוד ${item.hex || "(ריק)"}`, encoded || "(ריק)");
    check(base32Group(encoded) === item.grouped, `קיבוץ ${item.hex || "(ריק)"}`);

    // הפענוח חייב להחזיר את הבתים המקוריים
    const back = base32Decode(item.text).subarray(0, bytes.length);
    check(back.equals(bytes), `פענוח חוזר ${item.hex || "(ריק)"}`);
  }

  check(
    base32Decode("I1L1O0").equals(base32Decode("111100")),
    "תווים מבלבלים ממופים כמו ב-C#",
    "I ו-L הם 1, O הוא 0",
  );

  // ─────────────────────────────────────────────── CRC16
  section("CRC-16/CCITT-FALSE");

  for (const item of v.crc16) {
    const actual = crc16(Buffer.from(item.hex, "hex"));
    check(actual === item.crc, `CRC של ${item.hex || "(ריק)"}`, `${actual} מול ${item.crc}`);
  }

  // ─────────────────────────────────────────────── אתגרים
  section("מבנה האתגר");

  for (const item of v.challenges) {
    const built = buildChallengeBytes({
      flags: item.flags,
      hwidHash: Buffer.from(item.hwidHashHex, "hex"),
      issuedUnixMinutes: item.issuedUnixMinutes,
      nonce: Buffer.from(item.nonceHex, "hex"),
    });

    check(
      built.toString("hex").toUpperCase() === item.bytesHex,
      `בניית 22 הבתים עבור ${item.hwid.slice(0, 12)}`,
      built.toString("hex").toUpperCase().slice(0, 24) + "...",
    );

    check(
      base32Group(base32Encode(built)) === item.display,
      "ייצוג התצוגה זהה",
      item.display,
    );

    const parsed = parseChallenge(item.display);

    check(parsed.flags === item.flags, "דגלים");
    check(parsed.issuedUnixMinutes === item.issuedUnixMinutes, "חותמת זמן");
    check(parsed.nonce.toString("hex").toUpperCase() === item.nonceHex, "nonce");
    check(parsed.mode === item.mode, `מצב אימות ${parsed.mode}`);
    check(parsed.offlineEmergency === item.offlineEmergency, "דגל חירום אופליין");

    check(
      Buffer.concat([parsed.bytes.subarray(0, 20)]).toString("hex").toUpperCase() ===
        item.signedPayloadHex,
      "מטען החתימה (20 בתים)",
    );
  }

  // שגיאת הקלדה חייבת להיתפס
  const typo = v.challenges[0]!.display.split("");
  const idx = typo.findIndex((c, i) => i > 20 && c !== "-");
  typo[idx] = typo[idx] === "A" ? "B" : "A";

  let caught = false;
  try {
    parseChallenge(typo.join(""));
  } catch {
    caught = true;
  }

  check(caught, "שגיאת הקלדה נתפסת ב-CRC");

  // ─────────────────────────────────────────────── HMAC
  section("תגובת HMAC-SHA256");

  for (const item of v.hmac) {
    const challenge = parseChallenge(item.challengeDisplay);
    const response = generateHmacResponse(challenge, Buffer.from(item.secretHex, "hex"));

    check(
      response === item.response,
      "קוד HMAC זהה לזה של C#",
      `${response} מול ${item.response}`,
    );
  }

  // ─────────────────────────────────────────────── RSA
  section("חתימת RSA-PSS");

  const rsaChallenge = parseChallenge(v.rsa.challengeDisplay);

  // הכיוון הקריטי: הסוכן ב-C# חייב לאמת חתימה שהשרת ב-TypeScript ייצר.
  // כאן נבדק הכיוון ההפוך תחילה, כדי לוודא שהפרמטרים זהים.
  check(
    verifyRsaResponse(rsaChallenge, v.rsa.signatureFromCSharp, v.rsa.publicKeyPem),
    "TypeScript מאמת חתימה שנוצרה ב-C#",
    `PSS · SHA-256 · salt ${v.rsa.saltLength}`,
  );

  const tsSignature = generateRsaResponse(rsaChallenge, v.rsa.privateKeyPem);

  check(
    verifyRsaResponse(rsaChallenge, tsSignature, v.rsa.publicKeyPem),
    "החתימה שנוצרה כאן מאמתת את עצמה",
    `${tsSignature.length} תווים`,
  );

  // חתימה על אתגר אחר חייבת להיכשל
  const otherChallenge = parseChallenge(v.challenges[1]!.display);

  check(
    !verifyRsaResponse(otherChallenge, tsSignature, v.rsa.publicKeyPem),
    "חתימה של אתגר אחד אינה תקפה לאתגר אחר",
  );

  // ─────────────────────────────────────────────── HWID
  section("מזהה חומרה");

  for (const item of v.hwid) {
    const id = buildHwid(item.components);
    check(id === item.id, "מזהה זהה ל-C#", `${id.slice(0, 14)}...`);
  }

  // ─────────────────────────────────────────────── שם קובץ המתקין
  section("אסימון בשם קובץ המתקין");

  // שני הצדדים חייבים להסכים על כל שם: השרת בונה אותו, והמתקין
  // קורא אותו בחזרה. סטייה כאן פירושה מתקין שלא יודע לאיזה חשבון
  // להתחבר — או גרוע מכך, מתקין שיודע ושרת שלא.
  for (const item of v.installerNames) {
    const got = tokenFromFileName(item.fileName);

    // מסדר ה-JSON ב-C# משמיט שדות null, ולכן "אין אסימון" מגיע
    // כ-undefined. שני הייצוגים אומרים אותו דבר.
    const expected = item.token ?? null;

    check(
      got === expected,
      item.fileName === "" ? "שם ריק" : `${item.fileName.slice(0, 46)}`,
      got === expected ? (got ?? "אין אסימון") : `TS: ${got} · C#: ${expected}`,
    );
  }

  // ─────────────────────────────────────────────── מעטפת מדיניות
  section("מעטפת מדיניות חתומה");

  // מדיניות לדוגמה עם עברית, בדיוק כפי שהשרת יחתום עליה בייצור.
  // הצד ב-C# יאמת את המעטפה הזו ויוודא שהתוכן שרד ללא שינוי.
  const samplePolicy = {
    version: 7,
    issuedUtc: "2026-08-25T09:00:00+00:00",
    ttlMinutes: 240,
    graceMinutes: 720,
    providers: [{ id: "netfree", displayName: "נטפרי", trustLevel: "high" }],
    enforcement: {
      mode: "enforce",
      minScoreForGreen: 85,
      minScoreForYellow: 60,
      onRedAction: "lockout",
    },
  };

  const policyBytes = Buffer.from(JSON.stringify(samplePolicy), "utf8");

  const policySignature = sign("sha256", policyBytes, {
    key: createPrivateKey(v.rsa.privateKeyPem),
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
  });

  check(
    policyBytes.includes(Buffer.from("נטפרי", "utf8")),
    "הבתים החתומים מכילים עברית גולמית",
    `${policyBytes.length} בתים`,
  );

  v.policyEnvelopeFromTypeScript = {
    alg: "RSASSA-PSS-SHA256",
    kid: "vectors-policy",
    payload: policyBytes.toString("base64url"),
    signature: policySignature.toString("base64url"),
    expectedVersion: samplePolicy.version,
    expectedProviderName: samplePolicy.providers[0]!.displayName,
  };

  check(true, "מעטפת מדיניות נחתמה ונכתבה לקובץ", "בדיקת ה-C# תאמת אותה");

  // ─────────────────────────────────────────────── כתיבה חזרה
  v.rsa.signatureFromTypeScript = tsSignature;

  await writeFile(VECTORS_PATH, `${JSON.stringify(v, null, 2)}\n`, "utf8");

  console.log("\n" + "═".repeat(64));
  console.log(`עברו ${passed} · נכשלו ${failed}`);
  console.log("החתימה מ-TypeScript נכתבה לקובץ. בדיקת ה-C# תאמת אותה.");
  console.log("═".repeat(64));

  if (failed > 0) process.exitCode = 1;
}

main().catch((error: unknown) => {
  console.error("\nבדיקת הווקטורים נכשלה:", error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
