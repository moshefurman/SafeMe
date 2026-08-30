/**
 * הנפקת קוד הסרה, מקצה לקצה.
 *
 * זו הפעולה הרגישה ביותר במוצר: קוד הסרה מפרק את ההגנה על מחשב.
 * כל שאר המנגנון — המחגר, השמירה ההדדית, ההרשאות המוקשחות — נשען
 * על כך שאי אפשר להשיג אותו בלי לעבור במסלול הזה.
 *
 * מה שנבדק כאן הוא לא רק שהמסלול עונה, אלא ששני צדדים שנכתבו
 * בשפות שונות מסכימים: אתגר שנוצר בסוכן מפוענח נכון בשרת, והקוד
 * שהשרת מנפיק מתקבל בסוכן. שני מימושים של אותו פרוטוקול נוטים
 * להיפרד בשקט, ובמקרה הזה ההיפרדות פירושה מוקד שאינו יכול לשחרר
 * אף מחשב.
 */

import { generateKeyPairSync } from "node:crypto";

import {
  base32Encode,
  base32Group,
  buildChallengeBytes,
  buildSigningInput,
  generateRsaResponse,
  hwidHashHex,
  parseChallenge,
  verifyRsaResponse,
  CHALLENGE_TOTAL_LENGTH,
  FLAG_RSA,
} from "../src/crypto/challenge.ts";

let passed = 0;
let failed = 0;

function check(ok: boolean, title: string, detail = ""): void {
  if (ok) passed += 1;
  else failed += 1;

  console.log(`  ${ok ? "OK" : "!!"} ${title}${detail ? ` -- ${detail}` : ""}`);
}

function section(title: string): void {
  console.log("");
  console.log(title);
  console.log("-".repeat(64));
}

const HWID = "TESTHWID0123456789ABCDEF";

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

// ─────────────────────────────────────────── האתגר

section("1 · האתגר");

const bytes = buildChallengeBytes({
  flags: FLAG_RSA,
  hwidHash: Buffer.from(hwidHashHex(HWID), "hex"),
  issuedUnixMinutes: Math.floor(Date.now() / 60_000),
  nonce: Buffer.from("0102030405060708090a0b", "hex").subarray(0, 6),
});

check(bytes.length === CHALLENGE_TOTAL_LENGTH, "האתגר הוא 22 בתים", `${bytes.length}`);

const display = base32Group(base32Encode(bytes));

check(display.includes("-"), "מוצג בקבוצות, לקריאה בטלפון", display);

const parsed = parseChallenge(display);

check(
  parsed.hwidHash.toString("hex") === hwidHashHex(HWID).toLowerCase(),
  "הפענוח מחזיר את גיבוב מזהה החומרה",
  "זה מה שמאפשר למוקד לדעת של מי המחשב",
);

check(parsed.mode === "Rsa", "מזהה את מצב החתימה");

/*
 * תו שגוי אחד. הורה מקריא 36 תווים בטלפון, וזה יקרה.
 */
section("2 · שגיאת הקלדה");

const broken = display.replace(/[A-Z]/, (c) => (c === "A" ? "B" : "A"));

let rejected = false;

try {
  parseChallenge(broken);
} catch {
  rejected = true;
}

check(rejected, "תו שגוי נדחה ואינו מפוענח כאתגר אחר", "ה-CRC תופס אותו לפני השיחה עם המוקד");

// ─────────────────────────────────────────── ההנפקה

section("3 · הקוד שהמוקד מנפיק");

const code = generateRsaResponse(parsed, privateKey);

check(code.length > 100, "הקוד מונפק", `${code.length} תווים`);

check(
  verifyRsaResponse(parsed, code, publicKey),
  "והוא מתקבל מול המפתח הציבורי",
  "זה מה שהסוכן עושה במחשב",
);

/*
 * הקוד קשור לאתגר, ולכן לא לאתגר אחר.
 *
 * בלי זה, קוד אחד שדלף היה משחרר כל מחשב — וכל המנגנון היה חסר
 * ערך. זו הבדיקה שמצדיקה את המבנה כולו.
 */
const other = parseChallenge(base32Group(base32Encode(buildChallengeBytes({
  flags: FLAG_RSA,
  hwidHash: Buffer.from(hwidHashHex("SOMEONE-ELSE"), "hex"),
  issuedUnixMinutes: Math.floor(Date.now() / 60_000),
  nonce: Buffer.from("0b0a090807060504030201", "hex").subarray(0, 6),
}))));

check(
  !verifyRsaResponse(other, code, publicKey),
  "קוד של מחשב אחד אינו משחרר מחשב אחר",
  "בלי זה קוד שדלף היה פותח את כולם",
);

// ─────────────────────────────────────────── החתימה

section("4 · מה נחתם");

const signed = buildSigningInput(parsed);

check(
  !signed.equals(parsed.bytes),
  "החתימה אינה על 22 הבתים כמו שהם",
  "ה-CRC הוא בדיקת הקלדה ואינו חלק מהחתימה",
);

const { publicKey: strangerKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

check(
  !verifyRsaResponse(parsed, code, strangerKey),
  "מפתח אחר אינו מאמת",
  "מפתח ההסרות נפרד ממפתח המדיניות במכוון",
);

console.log("");
console.log("=".repeat(64));
console.log(`עברו ${passed} · נכשלו ${failed}`);
console.log("=".repeat(64));

process.exit(failed === 0 ? 0 : 1);
