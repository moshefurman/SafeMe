/**
 * הפרדת מפתח ההיתרים ממפתח המדיניות.
 *
 * ההפרדה נאכפת בשלוש שכבות, ולכל אחת יש מה שרק היא תופסת:
 *   config   — מזהים זהים, הטעות המפורשת
 *   buildApp — מפתחות ציבוריים זהים, כלומר שני כינויים ב-KMS
 *              שמצביעים לאותו מפתח. המזהים שונים, ההפרדה לא קיימת.
 *   הסוכן    — מסרב להיתר שנחתם במפתח המדיניות, גם אם השרת שלח כך
 *              (נבדק ב-C#, KeySeparationTests)
 */

import { randomBytes, randomUUID } from "node:crypto";
import { buildApp } from "../src/app.ts";
import { assertAppRole, createPool, sslFor, withPlatform } from "../src/db/client.ts";
import { LocalSigner } from "../src/crypto/signing.ts";
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

function section(title: string): void {
  console.log(`\n${title}`);
  console.log("─".repeat(64));
}

async function throws(fn: () => Promise<unknown> | unknown): Promise<string | null> {
  try {
    await fn();
    return null;
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
}

const SYSTEM = { userId: "00000000-0000-0000-0000-000000000000", reason: "הרצת POC" };

const BASE = {
  DATABASE_URL_APP: "postgres://x/y",
  DEVICE_TOKEN_SECRET: "a".repeat(32),
};

async function main(): Promise<void> {
  // ───────────────────────────────────────────── שכבה 1: התצורה
  section("1 · התצורה תופסת מזהים זהים");

  const sameKeyId = await throws(() =>
    loadConfig({
      ...BASE,
      NODE_ENV: "production",
      SIGNER: "aws",
      SIGNER_KMS_KEY_ID: "alias/safeme",
      SIGNER_LOOSENING_KMS_KEY_ID: "alias/safeme",
      SIGNER_UNINSTALL_KMS_KEY_ID: "alias/other",
      SIGNER_UPDATE_KMS_KEY_ID: "alias/update",
    } as NodeJS.ProcessEnv),
  );
  check(
    sameKeyId !== null && sameKeyId.includes("מצביעים לאותו מפתח"),
    "אותו מזהה מפתח בשני השדות נדחה",
    sameKeyId ?? "לא נזרקה שגיאה",
  );

  const sameKid = await throws(() =>
    loadConfig({
      ...BASE,
      SIGNER_KID: "k1",
      SIGNER_LOOSENING_KID: "k1",
    } as NodeJS.ProcessEnv),
  );
  check(
    sameKid !== null && sameKid.includes("kid"),
    "אותו kid בשני השדות נדחה",
    sameKid ?? "לא נזרקה שגיאה",
  );

  const missing = await throws(() =>
    loadConfig({
      ...BASE,
      NODE_ENV: "production",
      SIGNER: "aws",
      SIGNER_KMS_KEY_ID: "alias/policy",
      SIGNER_LOOSENING_KMS_KEY_ID: "alias/loosening",
      SIGNER_UNINSTALL_KMS_KEY_ID: "alias/uninstall",
    } as NodeJS.ProcessEnv),
  );
  check(
    missing !== null && missing.includes("SIGNER_UPDATE_KMS_KEY_ID"),
    "בייצור חובה להגדיר גם מפתח עדכונים",
    missing ?? "לא נזרקה שגיאה",
  );

  const good = await throws(() =>
    loadConfig({
      ...BASE,
      NODE_ENV: "production",
      SIGNER: "aws",
      SIGNER_KID: "policy-1",
      SIGNER_LOOSENING_KID: "loosening-1",
      SIGNER_UNINSTALL_KID: "uninstall-1",
      SIGNER_UPDATE_KID: "update-1",
      SIGNER_KMS_KEY_ID: "alias/policy",
      SIGNER_LOOSENING_KMS_KEY_ID: "alias/loosening",
      SIGNER_UNINSTALL_KMS_KEY_ID: "alias/uninstall",
      SIGNER_UPDATE_KMS_KEY_ID: "alias/update",
    } as NodeJS.ProcessEnv),
  );
  check(good === null, "תצורה תקינה עוברת", good ?? "");

  // כל צירוף של שניים מתוך שלושה חייב להיתפס, ולא רק הראשון
  const uninstallCollides = await throws(() =>
    loadConfig({
      ...BASE,
      NODE_ENV: "production",
      SIGNER: "aws",
      SIGNER_KID: "p",
      SIGNER_LOOSENING_KID: "l",
      SIGNER_UNINSTALL_KID: "u",
      SIGNER_UPDATE_KID: "d",
      SIGNER_KMS_KEY_ID: "alias/policy",
      SIGNER_LOOSENING_KMS_KEY_ID: "alias/loosening",
      SIGNER_UNINSTALL_KMS_KEY_ID: "alias/loosening",
      SIGNER_UPDATE_KMS_KEY_ID: "alias/update",
    } as NodeJS.ProcessEnv),
  );
  check(
    uninstallCollides !== null && uninstallCollides.includes("UNINSTALL"),
    "התנגשות בין מפתח ההסרה למפתח ההיתרים נתפסת",
    uninstallCollides ?? "לא נזרקה שגיאה",
  );

  // ───────────────────────────────────────── שכבה 2: המפתחות עצמם
  section("2 · העלייה תופסת שני כינויים לאותו מפתח");

  const config = loadConfig({
    ...process.env,
    NODE_ENV: "test",
    DEVICE_TOKEN_SECRET: process.env["DEVICE_TOKEN_SECRET"] ?? randomBytes(32).toString("hex"),
  });

  const pool = createPool({ connectionString: config.DATABASE_URL_APP });

  // אותו מפתח פרטי בדיוק, תחת שני מזהים שונים — בדיוק מה שקורה
  // כששני כינויים ב-KMS מצביעים לאותו מפתח
  const twinId = randomUUID().slice(0, 8);
  const shared = LocalSigner.ephemeral(`shared-${twinId}-a`);
  const sharedPem = await shared.publicKeyPem();

  const aliasCollision = await throws(() =>
    buildApp({
      config,
      pool,
      signer: shared,
      // ספק שני שמחזיר את אותו מפתח ציבורי, עם kid אחר
      looseningSigner: {
        kid: `shared-${twinId}-b`,
        sign: (d: Uint8Array) => shared.sign(d),
        publicKeyPem: () => Promise.resolve(sharedPem),
      },
      logger: false,
    }),
  );

  check(
    aliasCollision !== null && aliasCollision.includes("אותו מפתח בפועל"),
    "שני מזהים שונים לאותו מפתח ציבורי נדחים בעלייה",
    aliasCollision ?? "לא נזרקה שגיאה — ההפרדה לא הייתה נאכפת",
  );

  // ───────────────────────────────────── שכבה 3: רישום והפצה
  section("3 · ארבעת המפתחות נרשמים ומופצים");

  const policySigner = LocalSigner.ephemeral(`poc-policy-${randomUUID().slice(0, 8)}`);
  const grantSigner = LocalSigner.ephemeral(`poc-loosening-${randomUUID().slice(0, 8)}`);
  const removeSigner = LocalSigner.ephemeral(`poc-uninstall-${randomUUID().slice(0, 8)}`);
  const patchSigner  = LocalSigner.ephemeral(`poc-update-${randomUUID().slice(0, 8)}`);

  const app = await buildApp({
    config,
    pool,
    signer: policySigner,
    looseningSigner: grantSigner,
    uninstallSigner: removeSigner,
    updateSigner: patchSigner,
    logger: false,
  });

  const registered = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ kid: string; purpose: string; public_pem: string }>(
      "SELECT kid, purpose::text AS purpose, public_pem FROM signing_keys WHERE kid = ANY($1)",
      [[policySigner.kid, grantSigner.kid, removeSigner.kid, patchSigner.kid]],
    );
    return r.rows;
  });

  check(registered.length === 4, "ארבעת המפתחות נרשמו", `${registered.length} רשומות`);

  const purposes = registered.map((r) => r.purpose).sort();
  check(
    purposes.join(",") === "loosening,policy,uninstall,update",
    "כל מפתח נרשם בייעוד הנכון",
    purposes.join(" · "),
  );

  check(
    new Set(registered.map((r) => r.public_pem)).size === 4,
    "ארבעת המפתחות הציבוריים שונים זה מזה",
  );

  // ───────────────────────────────────── שכבה 4: מה שהסוכן מקבל
  section("4 · המחשב מקבל את ארבעת המפתחות");

  const enrollTokenRaw = `ENR-${randomUUID().toUpperCase()}`;

  await withPlatform(pool, SYSTEM, async (tx) => {
    const t = await tx.query<{ id: string }>(
      `INSERT INTO tenants (type, name, trial_started_at, trial_ends_at)
       VALUES ('family', 'משפחת מפתחות', now(), now() + interval '30 days')
       RETURNING id`,
    );
    const id = t.rows[0]!.id;

    const { hashEnrollToken } = await import("../src/auth/device-token.ts");

    await tx.query(
      `INSERT INTO enroll_tokens
         (tenant_id, token_hash, install_profile, enforcement_mode, policy_floor,
          max_uses, expires_at)
       VALUES ($1, $2, 'family_child', 'enforce', $3, 5, now() + interval '7 days')`,
      [
        id,
        hashEnrollToken(enrollTokenRaw),
        JSON.stringify({ mode: "enforce", onRedAction: "lockout", minScoreForGreen: 85 }),
      ],
    );

    return id;
  });


  const enrolled = await app.fastify.inject({
    method: "POST",
    url: "/api/v1/enroll",
    payload: {
      enrollToken: enrollTokenRaw,
      hwid: `HWID${randomUUID().replace(/-/g, "").slice(0, 20).toUpperCase()}`,
      hostname: "בדיקת-מפתחות",
      osVersion: "10.0.26200",
      agentVersion: "1.0.0",
    },
  });

  const body = enrolled.json() as {
    serverPublicKeyPem?: string;
    looseningPublicKeyPem?: string;
    uninstallPublicKeyPem?: string;
    updatePublicKeyPem?: string;
  };

  check(enrolled.statusCode === 200, "רישום הצליח", `סטטוס ${enrolled.statusCode}`);

  check(
    typeof body.looseningPublicKeyPem === "string" && body.looseningPublicKeyPem.length > 0,
    "המחשב מקבל מפתח היתרים",
  );

  check(
    body.serverPublicKeyPem !== body.looseningPublicKeyPem,
    "שני המפתחות שהמחשב קיבל שונים זה מזה",
  );

  check(
    body.looseningPublicKeyPem === (await grantSigner.publicKeyPem()),
    "המפתח שהתקבל הוא אכן מפתח ההיתרים",
  );

  check(
    body.uninstallPublicKeyPem === (await removeSigner.publicKeyPem()),
    "המחשב מקבל את מפתח ההסרה הנכון",
  );

  check(
    new Set([
      body.serverPublicKeyPem,
      body.looseningPublicKeyPem,
      body.uninstallPublicKeyPem,
      body.updatePublicKeyPem,
    ]).size === 4,
    "ארבעת המפתחות שהמחשב קיבל שונים זה מזה",
  );

  // ─────────────────────────────────────────── ניקוי הסביבה

  section("5 · הסביבה מנוקה לפני האימות");

  const PROD = {
    ...BASE,
    NODE_ENV: "production",
    SIGNER_KID: "p",
    SIGNER_LOOSENING_KID: "l",
    SIGNER_UNINSTALL_KID: "u",
    SIGNER_UPDATE_KID: "d",
    SIGNER_KMS_KEY_ID: "alias/policy",
    SIGNER_LOOSENING_KMS_KEY_ID: "alias/loosening",
    SIGNER_UNINSTALL_KMS_KEY_ID: "alias/uninstall",
    SIGNER_UPDATE_KMS_KEY_ID: "alias/update",
    GOOGLE_APPLICATION_CREDENTIALS: "/etc/secrets/gcp.json",
  };

  // כך קוראים לספקים, וכך מקלידים אותם
  for (const written of ["GCP", "Gcp", " gcp "]) {
    const cfg = loadConfig({ ...PROD, SIGNER: written } as NodeJS.ProcessEnv);
    check(cfg.SIGNER === "gcp", `SIGNER=${JSON.stringify(written)} מתקבל`);
  }

  check(
    loadConfig({ ...PROD, SIGNER: "AWS" } as NodeJS.ProcessEnv).SIGNER === "aws",
    'SIGNER="AWS" מתקבל',
  );

  // נתיב עם שורה בסוף נראה תקין בעין ונדחה על ידי KMS
  const padded = loadConfig({
    ...PROD,
    SIGNER: "gcp",
    SIGNER_KMS_KEY_ID: "  alias/policy\n",
  } as NodeJS.ProcessEnv);
  check(padded.SIGNER_KMS_KEY_ID === "alias/policy", "רווחים ושורות מקוצצים מנתיב המפתח");

  // ─────────────────────────────────── מי רשאי להתחבר לבסיס הנתונים

  section("6 · רק safeme_app רשאי להתחבר");

  function roleError(user: string): string | null {
    try {
      assertAppRole(`postgres://${user}:pw@db.internal:5432/safeme`);
      return null;
    } catch (e) {
      return e instanceof Error ? e.message : String(e);
    }
  }

  check(roleError("safeme_app") === null, "safeme_app מתקבל");

  for (const owner of ["safeme_owner", "postgres"]) {
    check(roleError(owner) !== null, `${owner} נדחה`);
  }

  // המקרה שרשימת חסימה הייתה מחמיצה: ספק מנוהל שמייצר בעל סכמה
  // בשם משלו. זה מה ש-Render עושה בפועל.
  for (const owner of ["safeme_user", "filterplus", "render_admin", "root"]) {
    const err = roleError(owner);
    check(
      err !== null && err.includes("safeme_app"),
      `${owner} נדחה — שם שספק מנוהל עשוי לייצר`,
    );
  }


  // ─────────────────────────────────────────────── TLS

  section("7 · הצפנת החיבור לבסיס הנתונים");

  const LOCAL = "postgres://safeme_app:pw@localhost:55432/safeme";
  const REMOTE = "postgres://safeme_app:pw@dpg-abc.frankfurt-postgres.render.com/safeme";

  check(sslFor(LOCAL, {}) === undefined, "לולאה מקומית — בלי TLS");
  check(sslFor("postgres://safeme_app:pw@127.0.0.1/safeme", {}) === undefined, "גם 127.0.0.1");

  const remote = sslFor(REMOTE, {});
  check(remote?.rejectUnauthorized === true, "מארח מרוחק — TLS עם אימות תעודה");

  // אימות תעודה דלוק כברירת מחדל: מחרוזת החיבור נושאת סיסמה,
  // והצפנה בלי אימות מגנה מהאזנה אך לא מהתחזות
  check(
    sslFor(REMOTE, { DATABASE_SSL_INSECURE: "false" })?.rejectUnauthorized === true,
    "ערך אחר מ-true אינו מכבה את האימות",
  );
  check(
    sslFor(REMOTE, { DATABASE_SSL_INSECURE: "true" })?.rejectUnauthorized === false,
    "כיבוי האימות דורש הצהרה מפורשת",
  );

  const withCa = sslFor(REMOTE, { DATABASE_CA_CERT: "-----BEGIN CERTIFICATE-----" });
  check(
    withCa?.ca === "-----BEGIN CERTIFICATE-----" && withCa.rejectUnauthorized === true,
    "רשות תעודות מותאמת נטענת, והאימות נשאר דלוק",
  );

  // כפיית TLS גם מקומית, ולהפך
  check(
    sslFor(LOCAL, { PGSSLMODE: "require" })?.rejectUnauthorized === true,
    "PGSSLMODE=require כופה TLS גם מקומית",
  );
  check(
    sslFor("postgres://u:p@remote.example.com/db?sslmode=disable", {}) === undefined,
    "sslmode=disable במחרוזת מכבה",
  );

  check(sslFor("לא מחרוזת חיבור", {}) === undefined, "מחרוזת פגומה אינה מפילה");


  await app.close();
  await pool.end();

  console.log(`\n${"═".repeat(64)}`);
  console.log(`עברו ${passed} · נכשלו ${failed}`);
  console.log("═".repeat(64));

  process.exit(failed === 0 ? 0 : 1);
}

await main();
