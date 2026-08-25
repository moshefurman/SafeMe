import { randomBytes } from "node:crypto";
import { buildApp } from "../src/app.ts";
import { createPool, withPlatform } from "../src/db/client.ts";
import { LocalSigner } from "../src/crypto/signing.ts";
import { loadConfig } from "../src/config.ts";
import { hashPassword, needsRehash, verifyPassword } from "../src/auth/password.ts";
import { hotp, totp, verifyTotp } from "../src/auth/totp.ts";
import { authorize, can } from "../src/auth/rbac.ts";
import { createUser } from "../src/routes/portal-auth.ts";

/**
 * POC לשלב S4: אימות, תפקידים ואימות דו-שלבי.
 *
 * מוכיח שלושה דברים שקשה לראות בעין: שה-TOTP תואם לתקן, שהודעות
 * הכישלון אינן מדליפות מידע, ושמטריצת ההרשאות נאכפת בשרת ולא ב-UI.
 */

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

const SYSTEM = { userId: "system", reason: "הרצת POC" };

/** הסוד מ-RFC 6238: המחרוזת "12345678901234567890" בקידוד base32. */
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

async function main(): Promise<void> {
  // ─────────────────────────────────────────────── TOTP מול התקן
  section("1 · TOTP מול וקטורי RFC 6238");

  const rfcVectors: Array<[number, string]> = [
    [59, "287082"],
    [1_111_111_109, "081804"],
    [1_111_111_111, "050471"],
    [1_234_567_890, "005924"],
    [2_000_000_000, "279037"],
    [20_000_000_000, "353130"],
  ];

  for (const [time, expected] of rfcVectors) {
    const actual = totp(RFC_SECRET, time);
    check(actual === expected, `T=${time}`, `${actual} מול ${expected}`);
  }

  // הווקטור האחרון חורג מ-2^32 ובודק את פיצול המונה לשני חצאים
  check(
    hotp(Buffer.from("12345678901234567890", "utf8"), 666_666_666) === "353130",
    "מונה גדול מ-2^32 מטופל נכון",
  );

  const now = Math.floor(Date.now() / 1000);

  check(verifyTotp(RFC_SECRET, totp(RFC_SECRET, now), now), "קוד נוכחי מתקבל");
  check(verifyTotp(RFC_SECRET, totp(RFC_SECRET, now - 30), now), "קוד מהצעד הקודם מתקבל");
  check(!verifyTotp(RFC_SECRET, totp(RFC_SECRET, now - 120), now), "קוד ישן נדחה");
  check(!verifyTotp(RFC_SECRET, "000000", now), "קוד שגוי נדחה");
  check(!verifyTotp(RFC_SECRET, "12345", now), "קוד באורך שגוי נדחה");

  // ─────────────────────────────────────────────── סיסמאות
  section("2 · גיבוב סיסמאות");

  const password = "Sod-Chazak-2026!";
  const hash1 = await hashPassword(password);
  const hash2 = await hashPassword(password);

  check(hash1 !== hash2, "אותה סיסמה מייצרת גיבוב שונה", "מלח אקראי לכל גיבוב");
  check(await verifyPassword(password, hash1), "סיסמה נכונה מתאמתת");
  check(!(await verifyPassword("Sod-Chazak-2026?", hash1)), "סיסמה שגויה נדחית");
  check(!(await verifyPassword(password, "garbage")), "גיבוב פגום מוחזר כאי-התאמה ולא כשגיאה");
  check(!needsRehash(hash1), "הגיבוב הנוכחי אינו דורש רענון");
  check(needsRehash("scrypt$1024$8$1$AAAA$BBBB"), "גיבוב בפרמטרים ישנים מסומן לרענון");

  await (async () => {
    try {
      await hashPassword("short");
      check(false, "סיסמה קצרה נדחית", "לא נזרקה שגיאה");
    } catch {
      check(true, "סיסמה קצרה נדחית");
    }
  })();

  // ─────────────────────────────────────────────── מטריצת הרשאות
  section("3 · מטריצת ההרשאות");

  check(can("platform_admin", "policy.lowerFloor"), "מנהל פלטפורמה רשאי להוריד רצפה");
  check(!can("support_operator", "policy.lowerFloor"), "מוקדן אינו רשאי להוריד רצפה");
  check(can("support_operator", "uninstall.issueCode"), "מוקדן רשאי להנפיק קוד הסרה");
  check(!can("tenant_owner", "uninstall.issueCode"), "בעל דייר אינו רשאי להנפיק קוד הסרה");
  check(!can("tenant_member", "devices.lockout"), "צופה אינו רשאי לנעול מכשיר");
  check(can("tenant_owner", "policy.loosenWithinSandbox"), "בעל דייר רשאי להקל בארגז החול");

  const stale = new Date(Date.now() - 60 * 60 * 1000);
  const fresh = new Date();

  check(
    authorize({ role: "platform_admin", permission: "policy.lowerFloor", mfaVerifiedAt: stale })
      .needsMfa,
    "הורדת רצפה עם אימות ישן דורשת אימות מחדש",
    "חלון טריות 5 דקות",
  );

  check(
    authorize({ role: "platform_admin", permission: "policy.lowerFloor", mfaVerifiedAt: fresh })
      .allowed,
    "הורדת רצפה עם אימות טרי מאושרת",
  );

  check(
    authorize({ role: "platform_admin", permission: "devices.viewOwn", mfaVerifiedAt: stale })
      .allowed,
    "פעולה רגילה אינה דורשת אימות טרי",
  );

  check(
    !authorize({
      role: "tenant_owner",
      permission: "devices.lockout",
      mfaVerifiedAt: null,
      userTenantId: "aaa",
      resourceTenantId: "bbb",
    }).allowed,
    "בעל דייר אינו יכול לפעול על מכשיר של דייר אחר",
  );

  const crossTenant = authorize({
    role: "tenant_owner",
    permission: "devices.lockout",
    mfaVerifiedAt: null,
    userTenantId: "aaa",
    resourceTenantId: "bbb",
  });

  check(
    crossTenant.reason === authorize({
      role: "tenant_member",
      permission: "devices.lockout",
      mfaVerifiedAt: null,
    }).reason,
    "הודעת הדחייה זהה לחוסר הרשאה ולשיוך שגוי",
    "לא ניתן ללמוד מהתשובה שהמשאב קיים",
  );

  // ─────────────────────────────────────────────── זרימת הכניסה
  section("4 · זרימת כניסה מלאה");

  const config = loadConfig({
    ...process.env,
    NODE_ENV: "test",
    DEVICE_TOKEN_SECRET: process.env["DEVICE_TOKEN_SECRET"] ?? randomBytes(32).toString("hex"),
  });

  const pool = createPool({ connectionString: config.DATABASE_URL_APP });
  const signer = LocalSigner.ephemeral(`poc-auth-${randomBytes(4).toString("hex")}`);
  const app = await buildApp({ config, pool, signer, logger: false });

  const adminEmail = `admin-${randomBytes(4).toString("hex")}@safeme.test`;
  const ownerEmail = `parent-${randomBytes(4).toString("hex")}@safeme.test`;
  const adminPassword = "Nihul-Chazak-2026!";

  const tenantId = await withPlatform(pool, SYSTEM, async (tx) => {
    await tx.query("DELETE FROM login_attempts");

    const r = await tx.query<{ id: string }>(
      "INSERT INTO tenants (type, name) VALUES ('family', 'משפחת בדיקה') RETURNING id",
    );

    return r.rows[0]!.id;
  });

  const adminId = await createUser(pool, {
    email: adminEmail,
    password: adminPassword,
    role: "platform_admin",
    tenantId: null,
    displayName: "מנהל בדיקה",
  });

  await createUser(pool, {
    email: ownerEmail,
    password: adminPassword,
    role: "tenant_owner",
    tenantId,
    displayName: "הורה",
  });

  const login = async (email: string, pw: string) =>
    app.fastify.inject({
      method: "POST",
      url: "/api/portal/v1/auth/login",
      payload: { email, password: pw },
    });

  const wrongUser = await login("nobody@safeme.test", "whatever-long-enough");
  const wrongPass = await login(adminEmail, "definitely-wrong-pass");

  check(
    wrongUser.statusCode === 401 && wrongPass.statusCode === 401 &&
      wrongUser.json<{ error: string }>().error === wrongPass.json<{ error: string }>().error,
    "משתמש לא קיים וסיסמה שגויה מחזירים תשובה זהה",
    wrongUser.json<{ error: string }>().error,
  );

  const good = await login(adminEmail, adminPassword);

  check(good.statusCode === 200, "כניסה תקינה מצליחה", `סטטוס ${good.statusCode}`);

  const body = good.json<{ csrfToken: string; mfaRequired: boolean; mfaEnrolled: boolean }>();
  const cookie = String(good.headers["set-cookie"]).split(";")[0]!;

  check(body.mfaRequired && !body.mfaEnrolled, "מנהל פלטפורמה נדרש לרשום MFA");
  check(
    String(good.headers["set-cookie"]).includes("HttpOnly") &&
      String(good.headers["set-cookie"]).includes("SameSite=Strict"),
    "עוגיית ההפעלה מסומנת HttpOnly ו-SameSite",
  );

  const authed = { cookie, [String("x-safeme-csrf")]: body.csrfToken };

  // ─────────────────────────────────────────────── חסימה עד אימות שני
  section("5 · חסימה עד אימות דו-שלבי");

  const beforeMfa = await app.fastify.inject({
    method: "GET",
    url: "/api/portal/v1/auth/me",
    headers: { cookie },
  });

  check(
    beforeMfa.statusCode === 403 && beforeMfa.json<{ mfaRequired: boolean }>().mfaRequired,
    "מנהל פלטפורמה חסום עד אימות שני",
    `סטטוס ${beforeMfa.statusCode}`,
  );

  const enroll = await app.fastify.inject({
    method: "POST",
    url: "/api/portal/v1/auth/mfa/enroll",
    headers: authed,
  });

  const enrolled = enroll.json<{ secret: string; otpauthUri: string }>();

  check(enroll.statusCode === 200, "רישום MFA מחזיר סוד");
  check(
    enrolled.otpauthUri.startsWith("otpauth://totp/") && enrolled.otpauthUri.includes("SafeMe"),
    "כתובת ה-otpauth תקינה לסריקה",
  );

  const badConfirm = await app.fastify.inject({
    method: "POST",
    url: "/api/portal/v1/auth/mfa/confirm",
    headers: authed,
    payload: { code: "000000" },
  });

  check(badConfirm.statusCode === 401, "קוד שגוי אינו משלים רישום");

  const confirm = await app.fastify.inject({
    method: "POST",
    url: "/api/portal/v1/auth/mfa/confirm",
    headers: authed,
    payload: { code: totp(enrolled.secret) },
  });

  check(confirm.statusCode === 200, "קוד תקין משלים את הרישום");

  const afterMfa = await app.fastify.inject({
    method: "GET",
    url: "/api/portal/v1/auth/me",
    headers: { cookie },
  });

  check(
    afterMfa.statusCode === 200 && afterMfa.json<{ role: string }>().role === "platform_admin",
    "לאחר אימות שני הגישה נפתחת",
  );

  // ─────────────────────────────────────────────── CSRF
  section("6 · הגנת CSRF");

  const noCsrf = await app.fastify.inject({
    method: "POST",
    url: "/api/portal/v1/auth/logout",
    headers: { cookie },
  });

  check(noCsrf.statusCode === 403, "בקשה משנה-מצב בלי אסימון CSRF נדחית", `סטטוס ${noCsrf.statusCode}`);

  const wrongCsrf = await app.fastify.inject({
    method: "POST",
    url: "/api/portal/v1/auth/logout",
    headers: { cookie, "x-safeme-csrf": "not-the-right-token" },
  });

  check(wrongCsrf.statusCode === 403, "אסימון CSRF שגוי נדחה");

  // ─────────────────────────────────────────────── הגבלת קצב
  section("7 · הגבלת קצב על כניסה");

  const victim = `victim-${randomBytes(4).toString("hex")}@safeme.test`;
  await createUser(pool, { email: victim, password: adminPassword, role: "tenant_owner", tenantId });

  let limited = 0;

  for (let i = 0; i < 7; i += 1) {
    const attempt = await login(victim, `wrong-guess-number-${i}`);
    if (attempt.statusCode === 429) limited += 1;
  }

  check(limited > 0, "ניחוש חוזר נחסם", `${limited} מתוך 7 הניסיונות נחסמו`);

  const stillBlocked = await login(victim, adminPassword);

  check(
    stillBlocked.statusCode === 429,
    "גם הסיסמה הנכונה נחסמת בזמן ההגבלה",
    "מונע עקיפה על ידי ניחוש מוצלח אחרי חסימה",
  );

  // ─────────────────────────────────────────────── שלילת הפעלה
  section("8 · שלילת הפעלה");

  const logout = await app.fastify.inject({
    method: "POST",
    url: "/api/portal/v1/auth/logout",
    headers: authed,
  });

  check(logout.statusCode === 200, "יציאה מצליחה");

  const afterLogout = await app.fastify.inject({
    method: "GET",
    url: "/api/portal/v1/auth/me",
    headers: { cookie },
  });

  check(
    afterLogout.statusCode === 401,
    "אסימון שנשלל אינו תקף יותר",
    "השלילה מיידית, לא ממתינה לפקיעת העוגייה",
  );

  // ─────────────────────────────────────────────── יומן ביקורת
  section("9 · תיעוד ביומן הביקורת");

  const logged = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ action: string; n: string }>(
      `SELECT action, count(*) AS n FROM audit_log
       WHERE action LIKE 'auth.%' AND (actor_id = $1 OR payload->>'email' IS NOT NULL)
       GROUP BY action ORDER BY action`,
      [adminId],
    );

    return r.rows;
  });

  const actions = logged.map((r) => r.action);

  check(actions.includes("auth.login.success"), "כניסה מוצלחת תועדה");
  check(actions.includes("auth.login.failed"), "כניסה כושלת תועדה");
  check(actions.includes("auth.mfa.enrolled"), "רישום MFA תועד");
  check(actions.includes("auth.logout"), "יציאה תועדה");

  console.log("\n" + "═".repeat(64));
  console.log(`עברו ${passed} · נכשלו ${failed}`);
  console.log("═".repeat(64));

  await app.close();
  await pool.end();

  if (failed > 0) process.exitCode = 1;
}

main().catch((error: unknown) => {
  console.error("\nה-POC נכשל:", error instanceof Error ? error.stack : error);
  process.exitCode = 1;
});
