import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * כניסה דרך Google, בזרימת authorization code.
 *
 * מה שנאכף כאן, ולמה:
 *
 * **state** מונע CSRF. בלי אימותו, תוקף יכול לגרום לדפדפן של הקורבן
 * להשלים כניסה עם קוד שהוא עצמו קיבל — והקורבן מוצא את עצמו מחובר
 * לחשבון של התוקף בלי לדעת.
 *
 * **PKCE** מגן על הקוד עצמו. הוא מיותר לכאורה כשיש client secret,
 * ונשמר כי הוא זול והוא מבטל שכבה שלמה של תקיפות שנשענות על גניבת
 * הקוד מהכתובת — היסטוריית דפדפן, לוגים של פרוקסי, Referer.
 *
 * **email_verified** הוא התנאי לקישור לחשבון קיים. בלעדיו, מי
 * שמשיג כתובת שכבר בשימוש היה יכול להשתלט על חשבון.
 */

const AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const ISSUERS = ["https://accounts.google.com", "accounts.google.com"];

/** חלון החיים של סיבוב הכניסה. קצר: זה הזמן שבין לחיצה לחזרה. */
export const FLOW_TTL_SECONDS = 15 * 60;

export interface GoogleIdentity {
  /** המזהה היציב אצל Google. אינו משתנה כשהמייל משתנה. */
  sub: string;
  email: string;
  emailVerified: boolean;
  name: string | null;
}

export interface FlowSecrets {
  state: string;
  codeVerifier: string;
  nonce: string;
}

/** פותח סיבוב חדש. הערכים נשמרים בעוגייה חתומה עד החזרה. */
export function beginFlow(): FlowSecrets {
  return {
    state: randomBytes(24).toString("base64url"),
    codeVerifier: randomBytes(32).toString("base64url"),
    nonce: randomBytes(16).toString("base64url"),
  };
}

/** כתובת ההפניה ל-Google. */
export function authorizeUrl(
  clientId: string,
  redirectUri: string,
  secrets: FlowSecrets,
): string {
  const challenge = createHash("sha256").update(secrets.codeVerifier).digest("base64url");

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",

    // רק מה שנחוץ. כל scope נוסף הוא הרשאה שהמשתמש נשאל עליה
    // ושצריך להצדיק, ואנחנו לא צריכים דבר מעבר לזהות.
    scope: "openid email profile",

    state: secrets.state,
    nonce: secrets.nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",

    // מונע בחירה אוטומטית של חשבון כשיש כמה מחוברים בדפדפן.
    // הורה שמתקין על מחשב משפחתי צריך לראות באיזה חשבון הוא נכנס.
    prompt: "select_account",
  });

  return `${AUTH_ENDPOINT}?${params.toString()}`;
}

/**
 * מחליף קוד בזהות.
 *
 * ה-id_token מגיע ישירות מ-Google בערוץ TLS מאומת, ולכן החתימה
 * עליו אינה נבדקת — כך גם קובע OpenID Connect בסעיף 3.1.3.7 עבור
 * אסימון שמתקבל מנקודת הקצה עצמה. מה שכן נבדק הוא התביעות, וכל
 * אחת מהן מונעת משהו: aud מונע אסימון שהונפק ליישום אחר, iss
 * מונע מנפיק אחר, exp מונע אסימון שנשמר ונעשה בו שימוש חוזר,
 * ו-nonce קושר את התשובה לבקשה שיצאה מכאן.
 */
export async function exchangeCode(input: {
  code: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  codeVerifier: string;
  nonce: string;
  now?: Date;
}): Promise<GoogleIdentity> {
  const response = await fetch(TOKEN_ENDPOINT, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code: input.code,
      client_id: input.clientId,
      client_secret: input.clientSecret,
      redirect_uri: input.redirectUri,
      grant_type: "authorization_code",
      code_verifier: input.codeVerifier,
    }),
  });

  if (!response.ok) {
    // גוף התשובה מ-Google עלול להכיל את הקוד עצמו. נרשם הסטטוס בלבד.
    throw new Error(`החלפת הקוד מול Google נכשלה (${response.status}).`);
  }

  const body = (await response.json()) as { id_token?: unknown };

  if (typeof body.id_token !== "string") {
    throw new Error("התשובה מ-Google אינה מכילה id_token.");
  }

  return readIdToken(body.id_token, input.clientId, input.nonce, input.now ?? new Date());
}

/** מפענח ומאמת את התביעות. מיוצא לבדיקות. */
export function readIdToken(
  idToken: string,
  clientId: string,
  nonce: string,
  now: Date,
): GoogleIdentity {
  const parts = idToken.split(".");

  if (parts.length !== 3) throw new Error("id_token פגום.");

  let claims: Record<string, unknown>;

  try {
    claims = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8")) as Record<
      string,
      unknown
    >;
  } catch {
    throw new Error("id_token אינו קריא.");
  }

  const aud = claims["aud"];

  // השוואה בזמן קבוע: המזהה אינו סוד, אבל ההרגל של השוואת ערכי
  // אימות בזמן משתנה הוא מה שמייצר את התקלה במקום שבו כן חשוב.
  if (typeof aud !== "string" || !constantEquals(aud, clientId)) {
    throw new Error("id_token הונפק ליישום אחר.");
  }

  const iss = claims["iss"];

  if (typeof iss !== "string" || !ISSUERS.includes(iss)) {
    throw new Error("id_token הונפק על ידי מנפיק שאינו Google.");
  }

  const exp = claims["exp"];

  if (typeof exp !== "number" || exp * 1000 <= now.getTime()) {
    throw new Error("תוקף id_token פג.");
  }

  const gotNonce = claims["nonce"];

  if (typeof gotNonce !== "string" || !constantEquals(gotNonce, nonce)) {
    throw new Error("id_token אינו תואם לבקשה שנפתחה מכאן.");
  }

  const sub = claims["sub"];
  const email = claims["email"];

  if (typeof sub !== "string" || sub === "") throw new Error("id_token בלי מזהה משתמש.");
  if (typeof email !== "string" || email === "") throw new Error("id_token בלי כתובת מייל.");

  const name = claims["name"];

  return {
    sub,
    email: email.trim().toLowerCase(),
    // Google מחזיר את השדה כבוליאני, אך גם כמחרוזת בגרסאות מסוימות
    emailVerified: claims["email_verified"] === true || claims["email_verified"] === "true",
    name: typeof name === "string" && name.trim() !== "" ? name.trim() : null,
  };
}

// ---------------------------------------------------------------- כרטיס ההרשמה

/**
 * זהות מאומתת שעדיין אין לה חשבון.
 *
 * Google נותן מייל ושם. המוצר צריך גם סוג חשבון וארבע ספרות של
 * תעודת זהות — העוגן היחיד לאימות הסרה בתקופת הניסיון, כי אין
 * כרטיס אשראי. אלה דברים ש-Google אינו יודע, וצריך לשאול.
 *
 * הזהות נשמרת עד שהטופס יושלם. בעוגייה חתומה ולא בטבלה: מי שנוטש
 * את הטופס לא אמור להשאיר שורה במאגר.
 */
export interface PendingSignup {
  sub: string;
  email: string;
  name: string | null;
  issuedAt: number;
}

export function sealPending(pending: PendingSignup, secret: string): string {
  const payload = Buffer.from(JSON.stringify(pending), "utf8").toString("base64url");

  return `${payload}.${mac(payload, secret)}`;
}

/** מחזיר null על כל פגם — חתימה, מבנה, או תוקף. */
export function openPending(
  sealed: string,
  secret: string,
  now: Date = new Date(),
): PendingSignup | null {
  const [payload, signature] = sealed.split(".");

  if (!payload || !signature) return null;
  if (!constantEquals(signature, mac(payload, secret))) return null;

  let pending: PendingSignup;

  try {
    pending = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as PendingSignup;
  } catch {
    return null;
  }

  if (typeof pending.sub !== "string" || typeof pending.email !== "string") return null;

  const age = now.getTime() - pending.issuedAt;

  // גם שלילי נדחה: כרטיס שנחתם "בעתיד" פירושו שעון שזז, ואין סיבה
  // לקבל אותו רק משום שהחתימה תקינה.
  if (age < 0 || age > FLOW_TTL_SECONDS * 1000) return null;

  return pending;
}

/**
 * מפתח נפרד לכל שימוש.
 *
 * אותו עיקרון שמפריד בין ארבעת מפתחות החתימה: סוד אחד ששני מנגנונים
 * חולקים פירושו שמי שהשיג חתימה מאחד יכול לזייף בשני.
 */
function mac(payload: string, secret: string): string {
  return createHmac("sha256", `safeme.google.pending ${secret}`)
    .update(payload)
    .digest("base64url");
}

function constantEquals(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");

  // אורכים שונים מסגירים את עצמם בכל מקרה דרך גודל הבאפר
  if (left.length !== right.length) return false;

  return timingSafeEqual(left, right);
}
