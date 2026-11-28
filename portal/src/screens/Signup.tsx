import { useState } from "react";
import { AccountTypePicker } from "../components/AccountTypePicker";
import { ApiError, api, setCsrfToken } from "../api";
import { Logo } from "../components/Logo";
import { Shield } from "../components/Shield";
import { GoogleButton } from "../components/GoogleButton";

/**
 * פתיחת חשבון חדש.
 *
 * 30 יום ניסיון, בלי אשראי ובלי שיחה עם מוקד. בסיום ההרשמה המשתמש
 * כבר מחובר ומחזיק אסימון התקנה — כדי שהמסלול מהרשמה עד מחשב מוגן
 * יהיה רצוף ולא ייעצר בהמתנה למייל.
 */

type Stage = "form" | "done";

interface SignupResult {
  csrfToken: string;
  trial: { daysLeft: number; endsAt: string };
  enrollToken: string;
  /** שם הקובץ שנושא את האסימון. הקישור נבנה ממנו יחסית למקור. */
  installerFileName: string;
}


export function Signup({
  onSignedIn,
  onBackToLogin,
  onBackToSite,
}: {
  onSignedIn: () => void;
  onBackToLogin: () => void;
  onBackToSite: () => void;
}) {
  const [stage, setStage] = useState<Stage>("form");
  const [accountType, setAccountType] = useState<string>("organization");
  const [displayName, setDisplayName] = useState("");
  const [accountName, setAccountName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [idLast4, setIdLast4] = useState("");
  const [result, setResult] = useState<SignupResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);

    try {
      const created = await api.post<SignupResult>("/api/portal/v1/signup", {
        email,
        password,
        displayName,
        accountName,
        accountType,
        idLast4,
      });

      setCsrfToken(created.csrfToken);
      setResult(created);
      setStage("done");
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "פתיחת החשבון נכשלה");
    } finally {
      setBusy(false);
    }
  }

  async function copyToken() {
    if (!result) return;

    try {
      await navigator.clipboard.writeText(result.enrollToken);
      setCopied(true);
    } catch {
      // לוח ההעתקה עשוי להיות חסום. המשתמש יסמן ידנית.
      setCopied(false);
    }
  }

  if (stage === "done" && result) {
    return (
      <div className="auth-wrap" id="main" role="main" tabIndex={-1}>
        <div className="auth-card" style={{ maxWidth: 440 }}>
          <Shield status="safe" size={40} />

          <h1>החשבון נפתח</h1>
          <p className="sub">
            {result.trial.daysLeft} ימי ניסיון, בלי אשראי ובלי התחייבות.
          </p>

          <div className="notice">
            ההורדה כבר מקושרת לחשבון שלך. אין מה להקליד — הרץ את הקובץ
            על המחשב שברצונך להגן עליו, וזהו.
          </div>

          {/*
            * הורדה ולא העתקת קוד.
            *
            * האסימון נוסע בשם הקובץ, ולכן המתקין יודע לבד לאיזה חשבון
            * להתחבר. הקוד עצמו נשאר זמין למי שמתקין ממחשב אחר או
            * מעדיף להקליד — אבל הוא כבר לא הדרך הראשית.
            */}
          <a
            className="btn primary download"
            href={`/d/${result.installerFileName}`}
            download={result.installerFileName}
          >
            הורדת המתקין ל-Windows
          </a>

          <details className="manual">
            <summary>מתקין ממחשב אחר?</summary>

            <p>
              הורד את המתקין שם, והקלד את הקוד הזה כשתתבקש. הוא מוצג
              פעם אחת ואינו ניתן לשחזור.
            </p>

            <div className="secret">{result.enrollToken}</div>

            <button onClick={() => void copyToken()}>
              {copied ? "הועתק" : "העתק קוד"}
            </button>
          </details>

          <button className="primary" onClick={onSignedIn} style={{ width: "100%" }}>
            המשך למרכז הניהול
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="auth-wrap" id="main" role="main" tabIndex={-1}>
      <div className="auth-card" style={{ maxWidth: 440 }}>
        {/*
          יציאה בראש הכרטיס, ולא רק בתחתיתו.
          הטופס ארוך, והקישור התחתון נמצא מתחת לקו הקיפול — כלומר
          מי שרוצה לצאת אינו רואה שאפשר.
        */}
        <button className="auth-back" onClick={onBackToSite}>
          ← חזרה לאתר
        </button>

        <Logo size={40} />

        {/*
          הסלוגן, זהה לזה שבדף הנחיתה.
          מי שהגיע לכאן מהאתר צריך לזהות שהוא באותו מקום.
        */}
        <p className="auth-slogan">
          סינון אינטרנט למשרד, <em>בלי לגעת באבטחת המידע.</em>
        </p>

        <h1>פתיחת חשבון</h1>
        <p className="sub">30 יום ניסיון חינם. אין צורך בכרטיס אשראי.</p>

        {error && <div className="error">{error}</div>}

        <GoogleButton label="הרשמה עם Google" />

        <form onSubmit={submit}>
          <div className="field">
            <label>סוג החשבון</label>

            <AccountTypePicker value={accountType} onChange={setAccountType} />
          </div>

          <div className="field">
            <label htmlFor="accountName">
              {accountType === "organization" ? "שם הארגון" : "שם החשבון"}
            </label>
            <input
              id="accountName"
              value={accountName}
              onChange={(e) => setAccountName(e.target.value)}
              placeholder={accountType === "family" ? "משפחת כהן" : ""}
              required
            />
          </div>

          <div className="field">
            <label htmlFor="displayName">שמך</label>
            <input
              id="displayName"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              required
            />
          </div>

          <div className="field">
            <label htmlFor="email">כתובת אימייל</label>
            <input
              id="email"
              type="email"
              dir="ltr"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="username"
              required
            />
          </div>

          <div className="field">
            <label htmlFor="password">סיסמה</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="new-password"
              minLength={12}
              required
            />
            <div style={{ fontSize: 12, color: "var(--muted)", marginTop: 5 }}>
              לפחות 12 תווים
            </div>
          </div>

          <div className="field">
            <label htmlFor="idLast4">4 ספרות אחרונות של תעודת הזהות</label>
            <input
              id="idLast4"
              inputMode="numeric"
              maxLength={4}
              dir="ltr"
              style={{ fontFamily: "var(--mono)", letterSpacing: "0.3em", textAlign: "center" }}
              value={idLast4}
              onChange={(e) => setIdLast4(e.target.value.replace(/\D/g, ""))}
              placeholder="0000"
              required
            />
            <div style={{ fontSize: 12, color: "var(--muted)", marginTop: 5, lineHeight: 1.5 }}>
              נדרש כדי לאמת בקשת הסרה בעתיד. נשמר מוצפן, ואנחנו לא
              שומרים את מספר הזהות המלא.
            </div>
          </div>

          <button
            className="primary"
            type="submit"
            disabled={busy || idLast4.length !== 4}
            style={{ width: "100%" }}
          >
            {busy ? "פותח חשבון..." : "התחל 30 יום ניסיון"}
          </button>

          <p className="auth-consent">
            בפתיחת החשבון אתם מאשרים את{" "}
            <a href="/terms.html" target="_blank" rel="noopener">תנאי השימוש</a> ואת{" "}
            <a href="/privacy.html" target="_blank" rel="noopener">מדיניות הפרטיות</a>.
          </p>
        </form>

        <div className="auth-foot">
          <button className="link" onClick={onBackToLogin}>
            כבר יש לך חשבון? התחברות
          </button>

          {/*
            יציאה מהטופס בלי הדפדפן.

            מי שנכנס לטופס וגילה שהוא רוצה לקרוא עוד נשאר תקוע:
            כפתור "אחורה" של הדפדפן אינו עובד כאן, כי הניווט הוא
            במצב מקומי ולא בכתובת.
          */}
          <button className="link muted-link" onClick={onBackToSite}>
            ← חזרה לאתר
          </button>
        </div>
      </div>
    </div>
  );
}
