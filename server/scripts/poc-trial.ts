import { randomBytes, randomUUID } from "node:crypto";
import { buildApp } from "../src/app.ts";
import { createPool, withPlatform } from "../src/db/client.ts";
import { LocalSigner } from "../src/crypto/signing.ts";
import { loadConfig } from "../src/config.ts";
import {
  TRIAL_DAYS,
  canEnrollDevice,
  enforcementContinues,
  evaluateTrial,
  portalReadOnly,
  verificationStrength,
} from "../src/billing/trial.ts";
import { hashIdLast4, verifyIdLast4 } from "../src/billing/identity.ts";

/**
 * POC לרישום עצמי ולתקופת ניסיון.
 *
 * מוכיח את המסלול המלא: אדם נרשם בלי אשראי, מקבל 30 יום ואסימון
 * התקנה, ומצליח לרשום מכשיר מוגן — הכול בלי מגע אנושי.
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
const day = 86_400_000;

async function main(): Promise<void> {
  // ─────────────────────────────────────────────── לוגיקה טהורה
  section("1 · חישוב מצב הניסיון");

  const now = new Date("2026-03-01T10:00:00Z");
  const trialOf = (daysFromNow: number) =>
    evaluateTrial(
      { plan: "trial", trialEndsAt: new Date(now.getTime() + daysFromNow * day), paidUntil: null },
      now,
    );

  check(trialOf(30).phase === "trial_active", "יום ראשון: ניסיון פעיל", `${trialOf(30).daysLeft} ימים`);
  check(trialOf(20).phase === "trial_active", "20 ימים לפני הסוף: רגוע");
  check(trialOf(7).phase === "trial_ending", "שבוע לפני הסוף: מתחיל להזכיר");
  check(trialOf(1).headline === "יום אחרון בתקופת הניסיון", "יום אחרון מנוסח ביחיד");
  // מרגע סיום הניסיון מתחיל שבוע החסד, ולא נפילה מיידית
  check(trialOf(0).phase === "grace", "יום הסיום עצמו: נכנס לחסד");
  check(trialOf(-5).phase === "grace", "חמישה ימים אחרי: עדיין בחסד");
  check(trialOf(-10).phase === "trial_expired", "עשרה ימים אחרי: מעבר לחסד");

  check(
    evaluateTrial({ plan: "paid", trialEndsAt: null, paidUntil: new Date(now.getTime() + 40 * day) }, now)
      .phase === "paid",
    "לקוח משלם אינו רואה באנר ניסיון",
  );

  check(
    evaluateTrial({ plan: "paid", trialEndsAt: null, paidUntil: new Date(now.getTime() - day) }, now)
      .headline === "התשלום לא עבר",
    "תשלום שנכשל מנוסח אחרת מניסיון שנגמר",
    "ההבחנה חשובה ללקוח משלם",
  );

  check(
    evaluateTrial({ plan: "trial", trialEndsAt: null, paidUntil: null }, now).phase === "trial_expired",
    "ניסיון בלי תאריך סיום נחשב פג ולא תקין",
    "תקלה לא תיתן ניסיון אינסופי",
  );

  const graceOf = (daysAfterEnd: number) =>
    evaluateTrial(
      {
        plan: "trial",
        trialEndsAt: new Date(now.getTime() - daysAfterEnd * day),
        paidUntil: null,
        graceDays: 7,
      },
      now,
    );

  check(graceOf(1).phase === "grace", "יום אחרי הסוף: תקופת חסד", graceOf(1).headline);
  check(graceOf(6).phase === "grace", "יום שישי לחסד: עדיין חסד");
  check(graceOf(8).phase === "trial_expired", "אחרי שבוע החסד: פג סופית");

  check(
    enforcementContinues(graceOf(30)),
    "ההגנה ממשיכה לפעול גם חודש אחרי שהחסד נגמר",
    "הגנה שנעלמת בשקט גרועה משתי סיבות",
  );

  check(!portalReadOnly(graceOf(3)), "בחסד הפורטל עדיין פעיל");
  check(portalReadOnly(graceOf(20)), "אחרי החסד הפורטל מוגבל");
  check(!canEnrollDevice(graceOf(20)), "אחרי החסד אי אפשר להוסיף מכשירים");
  check(canEnrollDevice(graceOf(3)), "בחסד עדיין אפשר להוסיף מכשיר");

  const identity = hashIdLast4("4821");

  check(verifyIdLast4("4821", identity), "ארבע ספרות נכונות מתאמתות");
  check(!verifyIdLast4("4822", identity), "ספרה אחת שונה נדחית");
  check(!verifyIdLast4("482", identity), "אורך שגוי נדחה");
  check(
    !hashIdLast4("4821").hash.equals(identity.hash),
    "אותן ספרות מייצרות hash שונה בכל לקוח",
    "salt ייחודי — מרחב של 10,000 ערכים היה נשבר בטבלת קשת",
  );

  check(!verificationStrength("none").usable, "ניסיון ללא אשראי אינו ניתן לאימות בהסרה");
  check(verificationStrength("id_and_card").usable, "ת\"ז ואשראי כן ניתנים לאימות");

  // ─────────────────────────────────────────────── רישום עצמי
  section("2 · רישום עצמי מקצה לקצה");

  const config = loadConfig({
    ...process.env,
    NODE_ENV: "test",
    DEVICE_TOKEN_SECRET: process.env["DEVICE_TOKEN_SECRET"] ?? randomBytes(32).toString("hex"),
  });

  const pool = createPool({ connectionString: config.DATABASE_URL_APP });
  const signer = LocalSigner.ephemeral(`poc-trial-${randomBytes(4).toString("hex")}`);
  // חותם ההיתרים חייב מזהה ייחודי להרצה מאותה סיבה כמו חותם
  // המדיניות: מפתח זמני מתחלף בכל הרצה, ורישום מפתח אחר תחת
  // אותו kid נדחה — ובצדק.
  const looseningSigner = LocalSigner.ephemeral(`poc-loosening-${randomUUID().slice(0, 8)}`);

  const app = await buildApp({ config, pool, signer, looseningSigner, logger: false });

  const suffix = randomBytes(4).toString("hex");
  const email = `newuser-${suffix}@example.test`;

  await withPlatform(pool, SYSTEM, async (tx) => {
    await tx.query("DELETE FROM signup_attempts");
  });

  const signup = await app.fastify.inject({
    method: "POST",
    url: "/api/portal/v1/signup",
    payload: {
      email,
      password: "Nisayon-Chinam-2026!",
      displayName: "משה לוי",
      accountName: "משפחת לוי",
      accountType: "family",
      idLast4: "4821",
    },
  });

  check(signup.statusCode === 200, "רישום ללא אשראי מצליח", `סטטוס ${signup.statusCode}`);

  const created = signup.json<{
    csrfToken: string;
    tenantId: string;
    trial: { phase: string; daysLeft: number };
    enrollToken: string;
  }>();

  check(
    created.trial.phase === "trial_active" && created.trial.daysLeft === TRIAL_DAYS,
    "התקבלו 30 יום ניסיון",
    `${created.trial.daysLeft} ימים`,
  );

  check(
    created.enrollToken.startsWith("ENR-"),
    "התקבל אסימון התקנה מיד",
    "המסלול מהרשמה עד מכשיר מוגן רצוף",
  );

  const cookie = String(signup.headers["set-cookie"]).split(";")[0]!;

  const me = await app.fastify.inject({
    method: "GET",
    url: "/api/portal/v1/auth/me",
    headers: { cookie },
  });

  const profile = me.json<{
    role: string;
    tenantName: string;
    trial: { daysLeft: number; headline: string };
  }>();

  check(
    me.statusCode === 200 && profile.role === "tenant_owner",
    "המשתמש מחובר מיד אחרי הרישום",
    "בלי מסך כניסה נוסף",
  );

  check(profile.tenantName === "משפחת לוי", "שם החשבון נשמר", profile.tenantName);
  check(profile.trial.daysLeft === TRIAL_DAYS, "מצב הניסיון מוחזר ב-me", profile.trial.headline);

  // ─────────────────────────────────────────────── התקנה בפועל
  section("3 · התקנת מכשיר עם האסימון מהרישום");

  const hwid = `TRIAL${suffix.toUpperCase()}${"0".repeat(21 - suffix.length)}`;

  const enrolled = await app.fastify.inject({
    method: "POST",
    url: "/api/v1/enroll",
    payload: { enrollToken: created.enrollToken, hwid, machineName: "PC-LEVI" },
  });

  check(enrolled.statusCode === 200, "המכשיר נרשם", `סטטוס ${enrolled.statusCode}`);

  const device = enrolled.json<{ enforcementMode: string; policyFloor: { alg: string } }>();

  check(
    device.enforcementMode === "enforce",
    "אכיפה מלאה כבר בניסיון",
    "לא גרסה מוגבלת",
  );

  check(
    device.policyFloor.alg === "RSASSA-PSS-SHA256",
    "רצפת המדיניות חתומה גם בניסיון",
  );

  // ─────────────────────────────────────────────── כפילויות והגבלה
  section("4 · הגנות על הדלת הפתוחה");

  const duplicate = await app.fastify.inject({
    method: "POST",
    url: "/api/portal/v1/signup",
    payload: {
      email,
      password: "Nisayon-Chinam-2026!",
      displayName: "מתחזה",
      accountName: "ניסיון כפול",
      idLast4: "1234",
    },
  });

  check(duplicate.statusCode === 409, "כתובת מייל שכבר רשומה נדחית");

  const weak = await app.fastify.inject({
    method: "POST",
    url: "/api/portal/v1/signup",
    payload: {
      email: `weak-${suffix}@example.test`,
      password: "short",
      displayName: "בדיקה",
      accountName: "בדיקה",
      idLast4: "1234",
    },
  });

  check(weak.statusCode === 400, "סיסמה קצרה נדחית ברישום");

  let limited = 0;

  for (let i = 0; i < 6; i += 1) {
    const attempt = await app.fastify.inject({
      method: "POST",
      url: "/api/portal/v1/signup",
      payload: {
        email: `flood-${suffix}-${i}@example.test`,
        password: "Nisayon-Chinam-2026!",
        displayName: "מציף",
        accountName: `הצפה ${i}`,
        idLast4: "1234",
      },
    });

    if (attempt.statusCode === 429) limited += 1;
  }

  check(limited > 0, "פתיחת חשבונות המונית נחסמת", `${limited} מתוך 6 נחסמו`);

  // ─────────────────────────────────────────────── ניסיון חוזר
  section("5 · ניסיון נפתח פעם אחת");

  const reopened = await withPlatform(pool, SYSTEM, async (tx) => {
    const before = await tx.query<{ trial_ends_at: Date }>(
      "SELECT trial_ends_at FROM tenants WHERE id = $1",
      [created.tenantId],
    );

    // ניסיון "לאפס" את הניסיון על ידי קריאה חוזרת לפונקציה
    await tx.query("SELECT app.start_trial($1, 30)", [created.tenantId]);

    const after = await tx.query<{ trial_ends_at: Date }>(
      "SELECT trial_ends_at FROM tenants WHERE id = $1",
      [created.tenantId],
    );

    return {
      before: before.rows[0]!.trial_ends_at.getTime(),
      after: after.rows[0]!.trial_ends_at.getTime(),
    };
  });

  check(
    reopened.before === reopened.after,
    "קריאה חוזרת אינה מאריכה את הניסיון",
    "סגירה ופתיחה מחדש אינה דרך ל-30 יום נוספים",
  );

  // ─────────────────────────────────────────────── אימות מייל
  section("6 · אימות כתובת מייל");

  const verifyToken = signup.json<{ verifyToken?: string }>().verifyToken;

  check(typeof verifyToken === "string", "אסימון אימות נוצר בהרשמה");

  const verified = await app.fastify.inject({
    method: "POST",
    url: "/api/portal/v1/verify-email",
    payload: { token: verifyToken },
  });

  check(verified.statusCode === 200, "אימות המייל מצליח");

  const reused = await app.fastify.inject({
    method: "POST",
    url: "/api/portal/v1/verify-email",
    payload: { token: verifyToken },
  });

  check(reused.statusCode === 400, "אסימון אימות אינו ניתן לשימוש חוזר");

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
