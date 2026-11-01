/**
 * אורז את תוסף הדפדפן כ-CRX3 ומייצר update.xml.
 *
 * ללא תלויות חיצוניות — ZIP ו-protobuf בנויים ידנית.
 *
 *   node scripts/pack-extension.mjs
 *
 * הפלט:
 *   server/extension/safeme-audio.crx
 *   server/extension/update.xml
 *
 * מפתח החתימה נוצר פעם אחת ב-server/extension-key.pem.
 * הקובץ ב-.gitignore ונשמר רק אצל מי שבונה את ה-CRX.
 */

import {
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  createSign,
  createHash,
} from "node:crypto";
import {
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  statSync,
} from "node:fs";
import { join } from "node:path";
import { crc32 } from "node:zlib";

const ROOT = join(import.meta.dirname, "..");
const EXT_DIR = join(ROOT, "..", "src", "SafeMe.BrowserExtension");
const OUT_DIR = join(ROOT, "extension");
const KEY_PATH = join(ROOT, "extension-key.pem");
const BASE_URL = "https://api.safeme.win";

// ── 1. מפתח RSA ─────────────────────────────────────────────

let privateKey;

if (existsSync(KEY_PATH)) {
  privateKey = createPrivateKey(readFileSync(KEY_PATH));
  console.log("Loaded existing key:", KEY_PATH);
} else {
  const { privateKey: pem } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  writeFileSync(KEY_PATH, pem, { mode: 0o600 });
  privateKey = createPrivateKey(pem);
  console.log("Generated new key:", KEY_PATH);
}

const publicKeyDer = createPublicKey(privateKey).export({ type: "spki", format: "der" });

// ── 2. Extension ID ──────────────────────────────────────────

const pubKeyHash = createHash("sha256").update(publicKeyDer).digest();
const crxId = pubKeyHash.subarray(0, 16);

const extensionId = Array.from(crxId)
  .flatMap((b) => [b >> 4, b & 0xf])
  .map((n) => String.fromCharCode(0x61 + n))
  .join("");

// ── 3. קבצי התוסף ────────────────────────────────────────────

function collectFiles(dir, base = "") {
  const result = [];
  for (const entry of readdirSync(dir).sort()) {
    // Chrome מייצר את _metadata כשטוענים את התוסף ידנית; זה עותק ישן של הכללים.
    if (!base && entry === "_metadata") continue;
    const full = join(dir, entry);
    const rel = base ? `${base}/${entry}` : entry;
    if (statSync(full).isDirectory()) {
      result.push(...collectFiles(full, rel));
    } else {
      result.push({ path: rel, data: readFileSync(full) });
    }
  }
  return result;
}

const files = collectFiles(EXT_DIR);

// ── 4. ZIP (stored, ללא דחיסה) ───────────────────────────────

function createZip(entries) {
  const locals = [];
  const index = [];
  let offset = 0;

  for (const file of entries) {
    const nameBytes = Buffer.from(file.path, "utf8");
    const checksum = crc32(file.data);

    const local = Buffer.alloc(30 + nameBytes.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt16LE(0, 10);
    local.writeUInt16LE(0, 12);
    local.writeUInt32LE(checksum, 14);
    local.writeUInt32LE(file.data.length, 18);
    local.writeUInt32LE(file.data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28);
    nameBytes.copy(local, 30);

    index.push({ offset, checksum, size: file.data.length, nameBytes });
    locals.push(local, file.data);
    offset += local.length + file.data.length;
  }

  const cdStart = offset;
  const centrals = [];

  for (const entry of index) {
    const cd = Buffer.alloc(46 + entry.nameBytes.length);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt16LE(0, 8);
    cd.writeUInt16LE(0, 10);
    cd.writeUInt16LE(0, 12);
    cd.writeUInt16LE(0, 14);
    cd.writeUInt32LE(entry.checksum, 16);
    cd.writeUInt32LE(entry.size, 20);
    cd.writeUInt32LE(entry.size, 24);
    cd.writeUInt16LE(entry.nameBytes.length, 28);
    cd.writeUInt16LE(0, 30);
    cd.writeUInt16LE(0, 32);
    cd.writeUInt16LE(0, 34);
    cd.writeUInt16LE(0, 36);
    cd.writeUInt32LE(0, 38);
    cd.writeUInt32LE(entry.offset, 42);
    entry.nameBytes.copy(cd, 46);
    centrals.push(cd);
    offset += cd.length;
  }

  const cdSize = offset - cdStart;

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(index.length, 8);
  eocd.writeUInt16LE(index.length, 10);
  eocd.writeUInt32LE(cdSize, 12);
  eocd.writeUInt32LE(cdStart, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...locals, ...centrals, eocd]);
}

const zip = createZip(files);

// ── 5. CRX3 ──────────────────────────────────────────────────

function varint(n) {
  const bytes = [];
  do {
    let byte = n & 0x7f;
    n >>>= 7;
    if (n > 0) byte |= 0x80;
    bytes.push(byte);
  } while (n > 0);
  return Buffer.from(bytes);
}

function pbBytes(field, data) {
  const tag = varint((field << 3) | 2);
  const len = varint(data.length);
  return Buffer.concat([tag, len, data]);
}

const signedHeaderData = pbBytes(1, crxId);

const prefix = Buffer.from("CRX3 SignedData\x00");
const lenBuf = Buffer.alloc(4);
lenBuf.writeUInt32LE(signedHeaderData.length);
const signedContent = Buffer.concat([prefix, lenBuf, signedHeaderData, zip]);

const sign = createSign("SHA256");
sign.update(signedContent);
const signature = sign.sign(privateKey);

const keyProof = Buffer.concat([
  pbBytes(1, publicKeyDer),
  pbBytes(2, signature),
]);

const header = Buffer.concat([
  pbBytes(2, keyProof),
  pbBytes(10000, signedHeaderData),
]);

const magic = Buffer.from("Cr24");
const ver = Buffer.alloc(4);
ver.writeUInt32LE(3);
const hdrLen = Buffer.alloc(4);
hdrLen.writeUInt32LE(header.length);

const crx = Buffer.concat([magic, ver, hdrLen, header, zip]);

// ── 6. כתיבה ─────────────────────────────────────────────────

mkdirSync(OUT_DIR, { recursive: true });
writeFileSync(join(OUT_DIR, "safeme-audio.crx"), crx);

const version = JSON.parse(readFileSync(join(EXT_DIR, "manifest.json"), "utf8")).version;

const updateXml = `<?xml version="1.0" encoding="UTF-8"?>
<gupdate xmlns="http://www.google.com/update2/response" protocol="2.0">
  <app appid="${extensionId}">
    <updatecheck codebase="${BASE_URL}/extension/safeme-audio.crx" version="${version}" />
  </app>
</gupdate>
`;

writeFileSync(join(OUT_DIR, "update.xml"), updateXml);

console.log();
console.log("Extension ID:", extensionId);
console.log("Version:     ", version);
console.log("CRX:         ", join(OUT_DIR, "safeme-audio.crx"));
console.log("update.xml:  ", join(OUT_DIR, "update.xml"));
