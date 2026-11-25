/**
 * לקוח ה-API של הפורטל.
 *
 * שני דברים שהוא מטפל בהם בשביל כל שאר האפליקציה:
 * צירוף אסימון ה-CSRF לכל בקשה משנה-מצב, וזיהוי המצב שבו השרת
 * דורש אימות דו-שלבי — שהוא תשובה תקינה ולא שגיאה.
 */

const CSRF_HEADER = "x-filterplus-csrf";

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;

  try {
    if (token) sessionStorage.setItem("filterplus.csrf", token);
    else sessionStorage.removeItem("filterplus.csrf");
  } catch {
    // מצב פרטי או אחסון חסום. האסימון עדיין עובד לסשן הנוכחי.
  }
}

/**
 * מוצא את האסימון אחרי רענון או פתיחת לשונית.
 *
 * העוגייה היא המקור, ו-sessionStorage רק גיבוי לסביבה שחוסמת
 * עוגיות צד-ראשון קריאות. הסדר הזה חשוב: sessionStorage נמחק
 * בסגירת הלשונית בעוד שהעוגייה שורדת, ולכן לשונית חדשה מוצאת
 * אסימון רק דרכה.
 *
 * לפני שהעוגייה נוספה, לשונית בלי אסימון גרמה לשרת לייצר חדש —
 * מה שהרג את האסימון של כל לשונית אחרת, וכל פעולה בה נדחתה
 * ב-403 בלי סימן. היציאה נראתה כמו כפתור שבור.
 */
export function restoreCsrfToken(): void {
  csrfToken = readCsrfCookie();

  if (csrfToken !== null) return;

  try {
    csrfToken = sessionStorage.getItem("filterplus.csrf");
  } catch {
    csrfToken = null;
  }
}

function readCsrfCookie(): string | null {
  const prefix = "filterplus_csrf=";

  for (const part of document.cookie.split(";")) {
    const item = part.trim();

    if (!item.startsWith(prefix)) continue;

    const value = decodeURIComponent(item.slice(prefix.length));

    return value === "" ? null : value;
  }

  return null;
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

/**
 * 401 מהשרת.
 *
 * שני מצבים שונים לגמרי חולקים את הקוד הזה: פעילות שפגה, וניסיון
 * התחברות שנכשל. הראשון מטופל גלובלית — חוזרים למסך הכניסה —
 * ובשני המשתמש כבר שם, וההודעה היא כל מה שיש לו.
 *
 * לכן ההודעה נשמרת. היא נזרקה קודם: השרת החזיר "אימייל או סיסמה
 * שגויים", המחלקה החליפה אותה ב"נדרשת התחברות", ומסך הכניסה — שלא
 * מזהה את הטיפוס הזה — הציג "ההתחברות נכשלה". שלוש שכבות, וכל אחת
 * מהן איבדה עוד מהמידע.
 */
export class UnauthorizedError extends Error {
  constructor(message?: string) {
    super(message && message.trim().length > 0 ? message : "נדרשת התחברות");
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

/**
 * מה לעשות כשהשרת מבקש אימות שני באמצע העבודה.
 *
 * נרשם על ידי המעטפת של האפליקציה, כי רק לה יש מסך להציג בו. מוחזר
 * true כשהמשתמש אימת בהצלחה, ואז הבקשה המקורית נשלחת שוב.
 */
type StepUp = () => Promise<boolean>;

let stepUp: StepUp | null = null;

export function setStepUpHandler(handler: StepUp | null): void {
  stepUp = handler;
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  retried = false,
): Promise<T> {
  const headers: Record<string, string> = {};

  if (body !== undefined) headers["content-type"] = "application/json";
  /*
   * האסימון נשלח גם ב-GET.
   *
   * מסלול /auth/me משתמש בו כדי לדעת אם ללקוח יש אסימון תקף: כשאין,
   * הוא מנפיק חדש. בלי השליחה הזו הוא היה מסובב בכל טעינה ופוסל
   * בקשת כתיבה שיצאה במקביל.
   */
  const token = csrfToken ?? readCsrfCookie();

  if (token) headers[CSRF_HEADER] = token;

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

  if (response.status === 401) {
    throw new UnauthorizedError(
      typeof payload["error"] === "string" ? payload["error"] : undefined);
  }

  if (response.status === 403 && payload["mfaRequired"] === true) {
    /*
     * אימות שני שנדרש באמצע העבודה, ולא בכניסה.
     *
     * פעולות רגישות דורשות אימות מהחמש דקות האחרונות. הדרישה
     * נכונה — מי שהשאיר מחשב פתוח לא אמור לשנות דרכה הגדרות —
     * אבל הפורטל טיפל בה רק בטעינה הראשונה, ולכן המשתמש קיבל
     * שגיאה בלי שום דרך לספק את מה שהיא מבקשת.
     *
     * זה נצפה בשטח: שמירת הגדרות דואר נכשלה שוב ושוב, והדרך
     * היחידה הייתה לצאת ולהיכנס מחדש.
     *
     * כשיש מטפל רשום, הוא מבקש קוד והבקשה נשלחת שוב — פעם אחת
     * בלבד. ניסיון חוזר אינסופי על דרישה שלא נענתה הוא לולאה,
     * לא התאוששות.
     */
    if (stepUp !== null && !retried) {
      const verified = await stepUp();

      if (verified) return request<T>(method, path, body, true);
    }

    throw new MfaRequiredError(payload["mfaEnrolled"] === true);
  }

  throw new ApiError(response.status, String(payload["error"] ?? "הפעולה נכשלה"));
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body ?? {}),
  patch: <T>(path: string, body?: unknown) => request<T>("PATCH", path, body ?? {}),
  put: <T>(path: string, body?: unknown) => request<T>("PUT", path, body ?? {}),
  del: <T>(path: string) => request<T>("DELETE", path),
};
