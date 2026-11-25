import { constants, createHash, createHmac, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";

/**
 * מימוש TypeScript של פרוטוקול האתגר והתגובה.
 *
 * זהו תאום של FilterPlus.Core/Security ב-C#. השרת מייצר כאן קודי הסרה,
 * והסוכן מאמת אותם שם. שני מימושים נפרדים של אותו פרוטוקול נוטים
 * להיפרד בשקט, ולכן shared/test-vectors.json מקבע את שניהם:
 * הרצת `npm run check:vectors` נכשלת ברגע שמשהו כאן סוטה.
 *
 * אין לשנות דבר בקובץ הזה בלי לעדכן את הצד ב-C# ואת הווקטורים.
 */

// ---------------------------------------------------------------- Base32

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const REVERSE = (() => {
  const table = new Int8Array(128).fill(-1);

  for (let i = 0; i < ALPHABET.length; i += 1) {
    table[ALPHABET.charCodeAt(i)] = i;
    table[ALPHABET.toLowerCase().charCodeAt(i)] = i;
  }

  // תווים מבלבלים בהקראה בטלפון. U נשאר פסול במכוון.
  for (const [ch, value] of [["I", 1], ["L", 1], ["O", 0]] as const) {
    table[ch.charCodeAt(0)] = value;
    table[ch.toLowerCase().charCodeAt(0)] = value;
  }

  return table;
})();

export function base32Encode(data: Uint8Array): string {
  let out = "";
  let buffer = 0;
  let bits = 0;

  for (const byte of data) {
    buffer = (buffer << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(buffer >> bits) & 0x1f];
    }
  }

  if (bits > 0) out += ALPHABET[(buffer << (5 - bits)) & 0x1f];

  return out;
}

export function base32Decode(text: string): Buffer {
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;

  for (const ch of text) {
    if (ch === "-" || ch === " " || ch === "\t" || ch === "\r" || ch === "\n") continue;

    const code = ch.charCodeAt(0);
    const value = code < 128 ? REVERSE[code]! : -1;

    if (value < 0) throw new Error(`תו לא חוקי בקוד: '${ch}'`);

    buffer = (buffer << 5) | value;
    bits += 5;

    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }

  return Buffer.from(out);
}

export function base32Group(code: string, groupSize = 6): string {
  if (groupSize <= 0 || code.length <= groupSize) return code;

  const parts: string[] = [];
  for (let i = 0; i < code.length; i += groupSize) parts.push(code.slice(i, i + groupSize));

  return parts.join("-");
}

export function base32Normalize(input: string): string {
  return [...input].filter((c) => !/\s/.test(c) && c !== "-").join("").toUpperCase();
}

// ---------------------------------------------------------------- CRC16

const CRC_TABLE = (() => {
  const table = new Uint16Array(256);

  for (let i = 0; i < 256; i += 1) {
    let crc = (i << 8) & 0xffff;

    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc & 0x8000) !== 0 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }

    table[i] = crc;
  }

  return table;
})();

/** CRC-16/CCITT-FALSE. בדיקת שגיאות הקלדה, לא מנגנון אבטחה. */
export function crc16(data: Uint8Array): number {
  let crc = 0xffff;

  for (const byte of data) {
    crc = ((crc << 8) ^ CRC_TABLE[((crc >> 8) ^ byte) & 0xff]!) & 0xffff;
  }

  return crc;
}

// ---------------------------------------------------------------- אתגר

export const CHALLENGE_PAYLOAD_LENGTH = 20;
export const CHALLENGE_TOTAL_LENGTH = 22;
export const CHALLENGE_VERSION = 1;

export const FLAG_RSA = 0b0000_0001;
export const FLAG_OFFLINE_EMERGENCY = 0b0000_0010;

export interface UninstallChallenge {
  version: number;
  flags: number;
  hwidHash: Buffer;
  issuedUnixMinutes: number;
  issuedUtc: Date;
  nonce: Buffer;
  bytes: Buffer;
  display: string;
  mode: "Rsa" | "Hmac";
  offlineEmergency: boolean;
}

export function buildChallengeBytes(input: {
  version?: number;
  flags: number;
  hwidHash: Uint8Array;
  issuedUnixMinutes: number;
  nonce: Uint8Array;
}): Buffer {
  const bytes = Buffer.alloc(CHALLENGE_TOTAL_LENGTH);

  bytes[0] = input.version ?? CHALLENGE_VERSION;
  bytes[1] = input.flags;
  Buffer.from(input.hwidHash).copy(bytes, 2, 0, 8);
  bytes.writeUInt32LE(input.issuedUnixMinutes, 10);
  Buffer.from(input.nonce).copy(bytes, 14, 0, 6);
  bytes.writeUInt16LE(crc16(bytes.subarray(0, CHALLENGE_PAYLOAD_LENGTH)), 20);

  return bytes;
}

export function parseChallenge(text: string): UninstallChallenge {
  const decoded = base32Decode(base32Normalize(text));

  if (decoded.length < CHALLENGE_TOTAL_LENGTH) {
    throw new Error("קוד האתגר קצר מדי או חסר.");
  }

  // Base32 עלול להוסיף בית ריפוד אחד בסוף
  const bytes = decoded.subarray(0, CHALLENGE_TOTAL_LENGTH);

  if (bytes[0] !== CHALLENGE_VERSION) {
    throw new Error(`גרסת אתגר לא נתמכת (${bytes[0]}).`);
  }

  const expected = crc16(bytes.subarray(0, CHALLENGE_PAYLOAD_LENGTH));

  if (expected !== bytes.readUInt16LE(20)) {
    throw new Error("שגיאת הקלדה בקוד האתגר.");
  }

  const minutes = bytes.readUInt32LE(10);
  const flags = bytes[1]!;

  return {
    version: bytes[0]!,
    flags,
    hwidHash: Buffer.from(bytes.subarray(2, 10)),
    issuedUnixMinutes: minutes,
    issuedUtc: new Date(minutes * 60_000),
    nonce: Buffer.from(bytes.subarray(14, 20)),
    bytes: Buffer.from(bytes),
    display: base32Group(base32Encode(bytes)),
    mode: (flags & FLAG_RSA) !== 0 ? "Rsa" : "Hmac",
    offlineEmergency: (flags & FLAG_OFFLINE_EMERGENCY) !== 0,
  };
}

export function challengeSignedPayload(challenge: UninstallChallenge): Buffer {
  return challenge.bytes.subarray(0, CHALLENGE_PAYLOAD_LENGTH);
}

// ---------------------------------------------------------------- תגובה

/** הפרדת תחום. חייב להיות זהה בדיוק לצד ה-C#. */
export const UNINSTALL_CONTEXT = Buffer.from("FilterPlus/uninstall/v1", "utf8");

/** 15 בתים = 120 ביט = 24 תווי Base32 בדיוק, בלי ריפוד. */
export const HMAC_RESPONSE_BYTES = 15;

const PSS_OPTIONS = {
  padding: constants.RSA_PKCS1_PSS_PADDING,
  saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
} as const;

export function buildSigningInput(challenge: UninstallChallenge): Buffer {
  return Buffer.concat([UNINSTALL_CONTEXT, challengeSignedPayload(challenge)]);
}

export function generateHmacResponse(challenge: UninstallChallenge, secret: Uint8Array): string {
  const mac = createHmac("sha256", Buffer.from(secret)).update(buildSigningInput(challenge)).digest();

  return base32Group(base32Encode(mac.subarray(0, HMAC_RESPONSE_BYTES)));
}

export function generateRsaResponse(challenge: UninstallChallenge, privateKeyPem: string): string {
  const signature = sign("sha256", buildSigningInput(challenge), {
    key: createPrivateKey(privateKeyPem),
    ...PSS_OPTIONS,
  });

  return signature.toString("base64");
}

export function verifyRsaResponse(
  challenge: UninstallChallenge,
  response: string,
  publicKeyPem: string,
): boolean {
  try {
    return verify(
      "sha256",
      buildSigningInput(challenge),
      { key: createPublicKey(publicKeyPem), ...PSS_OPTIONS },
      Buffer.from(response.trim().replace(/\s+/g, ""), "base64"),
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------- HWID

const PLACEHOLDERS = new Set([
  "to be filled by o.e.m.",
  "system serial number",
  "default string",
  "none",
  "n/a",
  "not specified",
  "00000000-0000-0000-0000-000000000000",
  "ffffffff-ffff-ffff-ffff-ffffffffffff",
]);

/** מנרמל רכיב חומרה. מחזיר null אם הערך חסר משמעות. */
export function normalizeHwidComponent(value: string | null | undefined): string | null {
  if (value === null || value === undefined) return null;

  const trimmed = value.trim();

  if (trimmed.length === 0) return null;
  if (PLACEHOLDERS.has(trimmed.toLowerCase())) return null;
  if ([...trimmed].every((c) => c === "0" || c === "-" || c === " ")) return null;
  if (trimmed.length < 4) return null;

  return trimmed.toUpperCase();
}

/**
 * שמונת הבתים הראשונים של SHA-256 על מזהה החומרה, כמחרוזת הקסדצימלית.
 *
 * מראה מדויקת של UninstallChallenge.ComputeHwidHash בצד ה-C#, כולל
 * הנרמול: קיצוץ רווחים והמרה לאותיות גדולות. סטייה כאן פירושה
 * שכל קשירה למחשב תיכשל, ובשקט.
 */
export function hwidHashHex(hwid: string): string {
  const full = createHash("sha256").update(hwid.trim().toUpperCase(), "utf8").digest();
  return full.subarray(0, 8).toString("hex").toUpperCase();
}
