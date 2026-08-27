/**
 * המסלול המלא, כפי שלקוח אמיתי עובר אותו.
 *
 * פותח חשבון, מקבל קישור הורדה, מוריד את המתקין דרך השרת, מחלץ את
 * האסימון משם הקובץ כפי שהמתקין עושה, רושם מכשיר ושולח פעימה — עד
 * שהמחשב מופיע במרכז הניהול.
 *
 * מה שאינו נבדק כאן הוא רישום השירות ב-Windows עצמו. זו הפעולה
 * היחידה בשרשרת שמשנה את המערכת, ואין דרך לבדוק אותה בלי לבצע
 * אותה. כל השאר — קישור, הורדה, חילוץ, רישום, פעימה, תצוגה — נבדק
 * מקצה לקצה עם הקובץ האמיתי.
 */

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createReadStream, statSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import pg from "pg";

import { buildApp } from "../src/app.ts";
import { createPool, sslFor, withPlatform } from "../src/db/client.ts";
import { LocalSigner } from "../src/crypto/signing.ts";
import { tokenFromFileName } from "../src/installer/filename.ts";
import { loadConfig } from "../src/config.ts";

let passed = 0;
let failed = 0;

function check(ok: boolean, name: string, detail = ""): void {
  if (ok) {
    passed++;
    console.log(`  ✓ ${name}${detail ? `\n      ${detail}` : ""}`);
  } else {
    failed++;
    console.log(`  ✗ ${name}${detail ? `\n      ${detail}` : ""}`);
  }
}

function step(n: number, title: string): void {
  console.log(`\n${n} · ${title}`);
  console.log("─".repeat(64));
}

const SYSTEM = { userId: "00000000-0000-0000-0000-000000000000", reason: "הרצת POC" };

/** מגיש קובץ יחיד, במקום המאגר הציבורי שאינו נגיש מסביבת הבדיקה. */
function serveFile(path: string): Promise<{ url: string; close: () => Promise<void> }> {
  return new Promise((resolve) => {
    const server: Server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/octet-stream" });
      createReadStream(path).pipe(res);
    });

    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;

      resolve({
        url: `http://127.0.0.1:${port}/SafeMe-Setup.exe`,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

async function main(): Promise<void> {
  const installerPath = process.argv[2]
    ?? "C:/Users/Moshe/Documents/Project/SafeMe/artifacts/release/SafeMe-Setup.exe";

  let size: number;

  try {
    size = statSync(installerPath).size;
  } catch {
    console.error(`\n  לא נמצא מתקין: ${installerPath}`);
    console.error("  יש להריץ קודם: powershell -File build/pack.ps1\n");
    process.exit(1);
  }

  const config = loadConfig({
    ...process.env,
    NODE_ENV: "test",
    DEVICE_TOKEN_SECRET: process.env["DEVICE_TOKEN_SECRET"] ?? randomBytes(32).toString("hex"),
  });

  const pool = createPool({ connectionString: config.DATABASE_URL_APP });
  const u = () => randomUUID().slice(0, 8);

  const app = await buildApp({
    config,
    pool,
    signer: LocalSigner.ephemeral(`e2e-policy-${u()}`),
    looseningSigner: LocalSigner.ephemeral(`e2e-loosening-${u()}`),
    uninstallSigner: LocalSigner.ephemeral(`e2e-uninstall-${u()}`),
    updateSigner: LocalSigner.ephemeral(`e2e-update-${u()}`),
    logger: false,
  });

  const host = await serveFile(installerPath);

  // פרסום גרסה הוא פעולת פלטפורמה ולכן נעשה כבעל הסכמה
  const adminUrl = process.env["DATABASE_URL"];

  if (!adminUrl) {
    console.error("\n  חסר DATABASE_URL.\n");
    process.exit(1);
  }

  const admin = new pg.Client({ connectionString: adminUrl, ssl: sslFor(adminUrl) });
  await admin.connect();

  const sha = createHash("sha256");

  await new Promise<void>((done, fail) => {
    const s = createReadStream(installerPath);
    s.on("data", (c) => sha.update(c));
    s.on("end", () => done());
    s.on("error", fail);
  });

  const digest = sha.digest("hex");

  await admin.query("DELETE FROM agent_releases");
  await admin.query(
    `INSERT INTO agent_releases
       (version, v_major, v_minor, v_patch, download_url, sha256, size_bytes, rollout_percent)
     VALUES ('1.0.0', 1, 0, 0, $1, decode($2, 'hex'), $3, 0)`,
    [host.url, digest, size],
  );

  console.log("");
  console.log(`  מתקין: ${installerPath}`);
  console.log(`  גודל : ${(size / 1024 / 1024).toFixed(1)} מגה`);
  console.log(`  SHA256: ${digest.slice(0, 24)}…`);

  // ─────────────────────────────────────────── 1
  step(1, "פתיחת חשבון באתר");

  const suffix = u();

  const signup = await app.fastify.inject({
    method: "POST",
    url: "/api/portal/v1/signup",
    payload: {
      email: `haim-${suffix}@example.test`,
      password: "Sisma-Chazaka-2026!",
      displayName: "חיים",
      accountName: "משפחת חיים",
      accountType: "family",
      idLast4: "4821",
    },
  });

  const account = signup.json<{
    trial: { daysLeft: number };
    enrollToken: string;
    installerFileName: string;
  }>();

  check(signup.statusCode === 200, "החשבון נפתח", `סטטוס ${signup.statusCode}`);
  check(account.trial.daysLeft === 30, "ניסיון 30 יום", "בלי כרטיס אשראי");

  const cookie = String(signup.headers["set-cookie"]).split(";")[0]!;

  // ─────────────────────────────────────────── 2
  step(2, "קישור ההורדה");

  console.log(`      /d/${account.installerFileName}`);
  console.log("");

  check(
    account.installerFileName.includes(account.enrollToken),
    "שם הקובץ נושא את אסימון החשבון",
    "זה מה שיקשר את המחשב לחשבון הזה ולא לאחר",
  );

  // ─────────────────────────────────────────── 3
  step(3, "ההורדה");

  const download = await app.fastify.inject({
    method: "GET",
    url: `/d/${account.installerFileName}`,
  });

  check(download.statusCode === 200, "הקובץ הוגש", `סטטוס ${download.statusCode}`);

  check(
    download.rawPayload.length === size,
    "כל הבתים הגיעו",
    `${(download.rawPayload.length / 1024 / 1024).toFixed(1)} מגה`,
  );

  check(
    createHash("sha256").update(download.rawPayload).digest("hex") === digest,
    "סכום הביקורת תואם למקור",
    "הקובץ לא השתנה בדרך",
  );

  const disposition = String(download.headers["content-disposition"]);

  check(
    disposition === `attachment; filename="${account.installerFileName}"`,
    "הדפדפן יישמור אותו בשם הנכון",
    disposition,
  );

  // ─────────────────────────────────────────── 4
  step(4, "המתקין קורא את שמו");

  // בדיוק מה ש-InstallerToken.FromFileName עושה בצד ה-C#
  const saved = `C:\\Users\\Haim\\Downloads\\${account.installerFileName}`;
  const recovered = tokenFromFileName(saved);

  console.log(`      ${saved}`);
  console.log("");

  check(recovered === account.enrollToken, "האסימון חולץ", recovered ?? "לא חולץ");

  check(
    tokenFromFileName(saved.replace(".exe", " (1).exe")) === account.enrollToken,
    "וגם אחרי שהדפדפן הוסיף סיומת כפילות",
    "הורדה חוזרת אינה שוברת את הקישור לחשבון",
  );

  // ─────────────────────────────────────────── 5
  step(5, "רישום המכשיר");

  const hwid = `HWID${randomBytes(10).toString("hex").toUpperCase()}`;

  const enroll = await app.fastify.inject({
    method: "POST",
    url: "/api/v1/enroll",
    payload: {
      enrollToken: recovered,
      hwid,
      machineName: "המחשב-של-חיים",
      osVersion: "10.0.26200",
      agentVersion: "1.0.0",
    },
  });

  const device = enroll.json<{
    deviceId: string;
    deviceToken: string;
    enforcementMode: string;
    serverPublicKeyPem: string;
    looseningPublicKeyPem: string;
    uninstallPublicKeyPem: string;
    updatePublicKeyPem: string;
  }>();

  check(enroll.statusCode === 200, "המכשיר נרשם", `סטטוס ${enroll.statusCode}`);
  check(device.enforcementMode === "enforce", "מצב האכיפה נקבע", device.enforcementMode);

  check(
    new Set([
      device.serverPublicKeyPem,
      device.looseningPublicKeyPem,
      device.uninstallPublicKeyPem,
      device.updatePublicKeyPem,
    ]).size === 4,
    "המכשיר קיבל ארבעה מפתחות שונים",
    "מדיניות · היתרי הקלה · קודי הסרה · עדכונים",
  );

  // ─────────────────────────────────────────── 6
  step(6, "הפעימה הראשונה");

  const beat = await app.fastify.inject({
    method: "POST",
    url: "/api/v1/heartbeat",
    // גם מזהה החומרה בכותרת: אסימון גנוב שיוצג ממכשיר אחר נדחה
    headers: {
      authorization: `Bearer ${device.deviceToken}`,
      "x-safeme-hwid": hwid,
    },
    payload: {
      hwid,
      agentVersion: "1.0.0",
      sequence: 1,
      status: "safe",
      score: 96,
      activeAdapters: [{ name: "Wi-Fi", ssid: "BAYIT-NETFREE", gateway: "192.168.1.1" }],
      detectedProvider: "netfree",
      publicIp: "185.32.10.4",
      failedProbes: [],
      tamperEvents: [],
      lockoutActive: false,
    },
  });

  check(beat.statusCode === 200, "הפעימה התקבלה", `סטטוס ${beat.statusCode}`);

  // ─────────────────────────────────────────── 7
  step(7, "המחשב במרכז הניהול");

  const list = await app.fastify.inject({
    method: "GET",
    url: "/api/portal/v1/devices",
    headers: { cookie },
  });

  const devices = list.json<{
    devices: Array<{
      machine_name: string;
      last_status: string;
      last_score: number;
      detected_provider: string | null;
      wifi_ssid: string | null;
    }>;
  }>();

  check(devices.devices.length === 1, "מכשיר אחד מופיע", `${devices.devices.length} מכשירים`);

  const shown = devices.devices[0];

  if (shown) {
    console.log("");
    console.log(`      ${shown.machine_name}`);
    console.log(
      `      מצב: ${shown.last_status} · ציון: ${shown.last_score} · ` +
        `ספק: ${shown.detected_provider} · רשת: ${shown.wifi_ssid}`,
    );
    console.log("");

    check(shown.machine_name === "המחשב-של-חיים", "השם נכון");
    check(shown.last_status === "safe", "המצב מוגן");
    check(shown.last_score === 96, "הציון עבר");
    check(shown.detected_provider === "netfree", "הספק זוהה");
    check(shown.wifi_ssid === "BAYIT-NETFREE", "שם הרשת נקלט");
  }

  await host.close();
  await admin.end();
  await app.close();
  await pool.end();

  console.log("═".repeat(64));
  console.log(`עברו ${passed} · נכשלו ${failed}`);
  console.log("═".repeat(64));

  if (failed === 0) {
    console.log("");
    console.log("  מהרשמה ועד מכשיר מוגן בדשבורד, עם הקובץ האמיתי.");
    console.log("  מה שלא נבדק כאן: רישום השירות ב-Windows עצמו.");
    console.log("");
  }

  process.exit(failed === 0 ? 0 : 1);
}

await main();
