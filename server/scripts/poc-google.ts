/**
 * כניסה דרך Google.
 *
 * הבדיקות מתמקדות במה שמונע השתלטות על חשבון: אימות התביעות
 * ב-id_token, והכרטיס החתום שמחזיק זהות מאומתת עד שהטופס יושלם.
 *
 * החלפת הקוד מול Google עצמו אינה נבדקת כאן — היא קריאת רשת לשירות
 * חיצוני. מה שנבדק הוא כל מה שקורה עם התשובה אחריה, וזה המקום שבו
 * טעות הופכת לפרצה.
 */

import { createHmac } from "node:crypto";

import {
  openPending,
  readIdToken,
  sealPending,
  FLOW_TTL_SECONDS,
  authorizeUrl,
  beginFlow,
} from "../src/auth/google.ts";

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

/** בונה id_token מדומה. החתימה אינה נבדקת, ולכן היא שרירותית. */
function token(claims: Record<string, unknown>): string {
  const part = (value: unknown) =>
    Buffer.from(JSON.stringify(value), "utf8").toString("base64url");

  return `${part({ alg: "RS256" })}.${part(claims)}.signature`;
}

const CLIENT = "1234.apps.googleusercontent.com";
const NONCE = "nonce-abc";
const NOW = new Date("2026-08-27T12:00:00Z");

function claims(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: "https://accounts.google.com",
    aud: CLIENT,
    sub: "google-user-1",
    email: "Parent@Example.com",
    email_verified: true,
    name: "משה",
    exp: Math.floor(NOW.getTime() / 1000) + 600,
    nonce: NONCE,
    ...over,
  };
}

function rejects(over: Record<string, unknown>, name: string): void {
  try {
    readIdToken(token(claims(over)), CLIENT, NONCE, NOW);
    check(false, name, "התקבל, ולא היה אמור");
  } catch (error) {
    check(true, name, error instanceof Error ? error.message : "");
  }
}

console.log("═".repeat(64));
console.log("  SafeMe · כניסה דרך Google");
console.log("═".repeat(64));

// ─────────────────────────────────────────────── id_token

section("1 · אימות id_token");

{
  const identity = readIdToken(token(claims()), CLIENT, NONCE, NOW);

  check(identity.sub === "google-user-1", "המזהה נקרא");
  check(identity.email === "parent@example.com", "המייל מנורמל לאותיות קטנות", identity.email);
  check(identity.emailVerified, "email_verified נקרא");
  check(identity.name === "משה", "השם נקרא");
}

rejects({ aud: "other.apps.googleusercontent.com" }, "אסימון שהונפק ליישום אחר נדחה");
rejects({ iss: "https://evil.example.com" }, "מנפיק שאינו Google נדחה");
rejects({ exp: Math.floor(NOW.getTime() / 1000) - 1 }, "אסימון שפג נדחה");
rejects({ nonce: "אחר" }, "nonce שאינו תואם נדחה");
rejects({ sub: "" }, "אסימון בלי מזהה נדחה");
rejects({ email: undefined }, "אסימון בלי מייל נדחה");

{
  // email_verified חוזר לעיתים כמחרוזת. אי-טיפול בזה היה הופך
  // חשבון מאומת ללא מאומת, וחוסם קישור לגיטימי.
  const asText = readIdToken(token(claims({ email_verified: "true" })), CLIENT, NONCE, NOW);

  check(asText.emailVerified, "email_verified כמחרוזת מזוהה");

  const missing = readIdToken(token(claims({ email_verified: undefined })), CLIENT, NONCE, NOW);

  check(!missing.emailVerified, "בהיעדרו, הכתובת אינה נחשבת מאומתת");
}

// ─────────────────────────────────────────────── הכרטיס

section("2 · הכרטיס החתום");

{
  const SECRET = "secret-for-tests";
  const pending = { sub: "g-1", email: "a@b.test", name: "שם", issuedAt: NOW.getTime() };
  const sealed = sealPending(pending, SECRET);

  const opened = openPending(sealed, SECRET, NOW);

  check(opened?.email === "a@b.test", "כרטיס תקין נפתח");

  check(
    openPending(sealed, "secret-אחר", NOW) === null,
    "כרטיס שנחתם בסוד אחר נדחה",
    "בלי זה, מי שמייצר כרטיס משלו פותח חשבון על כל כתובת",
  );

  const tampered = sealed.replace(/^./, (c) => (c === "a" ? "b" : "a"));

  check(openPending(tampered, SECRET, NOW) === null, "כרטיס ששונה נדחה");

  const late = new Date(NOW.getTime() + (FLOW_TTL_SECONDS + 1) * 1000);

  check(openPending(sealed, SECRET, late) === null, "כרטיס שפג נדחה");

  // כרטיס "מהעתיד" פירושו שעון שזז, ואין סיבה לקבלו רק כי החתימה תקינה
  const early = new Date(NOW.getTime() - 60_000);

  check(openPending(sealed, SECRET, early) === null, "כרטיס עם חותמת עתידית נדחה");

  check(openPending("לא-כרטיס", SECRET, NOW) === null, "מחרוזת שאינה כרטיס נדחית");
  check(openPending("", SECRET, NOW) === null, "מחרוזת ריקה נדחית");

  /*
   * המפתח נגזר עם תווית ייעודית, ולא משתמש בסוד הגולמי. אותו
   * עיקרון שמפריד בין ארבעת מפתחות החתימה: סוד משותף פירושו
   * שמי שהשיג חתימה מאחד יכול לזייף בשני.
   */
  const raw = createHmac("sha256", SECRET).update(sealed.split(".")[0]!).digest("base64url");

  check(
    !sealed.endsWith(raw),
    "החתימה אינה HMAC ישיר על הסוד",
    "המפתח נגזר עם תווית ייעודית",
  );
}

// ─────────────────────────────────────────────── כתובת ההפניה

section("3 · כתובת ההפניה");

{
  const secrets = beginFlow();
  const url = new URL(authorizeUrl(CLIENT, "https://portal.test/cb", secrets));
  const q = url.searchParams;

  check(q.get("client_id") === CLIENT, "מזהה היישום נשלח");
  check(q.get("code_challenge_method") === "S256", "PKCE בשיטת S256");
  check(q.get("code_challenge") !== secrets.codeVerifier, "נשלח האתגר ולא המפתח");
  check(q.get("state") === secrets.state, "state נשלח");
  check(q.get("nonce") === secrets.nonce, "nonce נשלח");
  check(q.get("scope") === "openid email profile", "רק ההרשאות הנחוצות", String(q.get("scope")));
  check(q.get("prompt") === "select_account", "בחירת חשבון מפורשת");

  const again = beginFlow();

  check(again.state !== secrets.state, "כל סיבוב מקבל state חדש");
}

console.log("\n" + "═".repeat(64));
console.log(`עברו ${passed} · נכשלו ${failed}`);
console.log("═".repeat(64));

process.exit(failed === 0 ? 0 : 1);
