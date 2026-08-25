/**
 * לקוח ה-API של הפורטל.
 *
 * שני דברים שהוא מטפל בהם בשביל כל שאר האפליקציה:
 * צירוף אסימון ה-CSRF לכל בקשה משנה-מצב, וזיהוי המצב שבו השרת
 * דורש אימות דו-שלבי — שהוא תשובה תקינה ולא שגיאה.
 */

const CSRF_HEADER = "x-safeme-csrf";

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;

  try {
    if (token) sessionStorage.setItem("safeme.csrf", token);
    else sessionStorage.removeItem("safeme.csrf");
  } catch {
    // מצב פרטי או אחסון חסום. האסימון עדיין עובד לסשן הנוכחי.
  }
}

export function restoreCsrfToken(): void {
  try {
    csrfToken = sessionStorage.getItem("safeme.csrf");
  } catch {
    csrfToken = null;
  }
}

/** נדרש אימות דו-שלבי. נזרק כדי שה-UI יעבור למסך הקוד. */
export class MfaRequiredError extends Error {
  readonly enrolled: boolean;

  constructor(enrolled: boolean) {
    super("נדרש אימות דו-שלבי");
    this.name = "MfaRequiredError";
    this.enrolled = enrolled;
  }
}

export class UnauthorizedError extends Error {
  constructor() {
    super("נדרשת התחברות");
    this.name = "UnauthorizedError";
  }
}

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};

  if (body !== undefined) headers["content-type"] = "application/json";
  if (method !== "GET" && csrfToken) headers[CSRF_HEADER] = csrfToken;

  const response = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });

  if (response.status === 204) return undefined as T;

  const text = await response.text();
  const payload = text ? (JSON.parse(text) as Record<string, unknown>) : {};

  if (response.ok) return payload as T;

  if (response.status === 401) throw new UnauthorizedError();

  if (response.status === 403 && payload["mfaRequired"] === true) {
    throw new MfaRequiredError(payload["mfaEnrolled"] === true);
  }

  throw new ApiError(response.status, String(payload["error"] ?? "הפעולה נכשלה"));
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body ?? {}),
};
