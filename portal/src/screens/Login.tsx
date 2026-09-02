import { useState } from "react";
import { ApiError, UnauthorizedError, api, setCsrfToken } from "../api";
import { Shield } from "../components/Shield";
import { SupportLink } from "../components/SupportLink";
import { GoogleButton } from "../components/GoogleButton";

/**
 * מסך הכניסה, כולל שני שלבי האימות הדו-שלבי.
 *
 * שלושה מצבים: סיסמה, רישום ראשוני של אפליקציית האימות, והקלדת קוד.
 * משתמש פלטפורמה עובר את כולם בהכרח; בעל חשבון רגיל נכנס בשלב אחד.
 */

type Stage = "password" | "enroll" | "code";

interface LoginResult {
  csrfToken: string;
  role: string;
  mfaRequired: boolean;
  mfaEnrolled: boolean;
}

export function Login({
  onSignedIn,
  onSignup,
  onBackToSite,
  onForgot,
}: {
  onSignedIn: () => void;
  onSignup: () => void;
  onBackToSite: () => void;
  onForgot: () => void;
}) {
  const [stage, setStage] = useState<Stage>("password");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [secret, setSecret] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submitPassword(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);

    try {
      const result = await api.post<LoginResult>("/api/portal/v1/auth/login", {
        email,
        password,
      });

      setCsrfToken(result.csrfToken);

      if (!result.mfaRequired) {
        onSignedIn();
        return;
      }

      if (result.mfaEnrolled) {
        setStage("code");
        return;
      }

      // משתמש פלטפורמה חדש חייב לרשום אפליקציית אימות לפני כל פעולה
      const enrolled = await api.post<{ secret: string }>("/api/portal/v1/auth/mfa/enroll");

      setSecret(enrolled.secret);
      setStage("enroll");
    } catch (caught) {
      /*
       * 401 הוא המקרה הרגיל כאן, ולא חריג.
       *
       * הוא נזרק כ-UnauthorizedError ולא כ-ApiError, ולכן התנאי
       * הישן פספס אותו והציג "ההתחברות נכשלה" על כל כשל — כולל
       * חשבון מושעה, שההודעה שלו אומרת בדיוק מה לעשות.
       */
      setError(
        caught instanceof ApiError || caught instanceof UnauthorizedError
          ? caught.message
          : "ההתחברות נכשלה");
    } finally {
      setBusy(false);
    }
  }

  async function submitCode(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);

    const path = stage === "enroll"
      ? "/api/portal/v1/auth/mfa/confirm"
      : "/api/portal/v1/auth/mfa/verify";

    try {
      await api.post(path, { code });
      onSignedIn();
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "הקוד שגוי");
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-wrap">
      <div className="auth-card">
        {/*
          יציאה בראש הכרטיס, ולא רק בתחתיתו.
          הטופס ארוך, והקישור התחתון נמצא מתחת לקו הקיפול — כלומר
          מי שרוצה לצאת אינו רואה שאפשר.
        */}
        <button className="auth-back" onClick={onBackToSite}>
          ← חזרה לאתר
        </button>

        <Shield color="#4d94d1" size={40} />

        {/*
          הסלוגן, זהה לזה שבדף הנחיתה.
          מי שהגיע לכאן מהאתר צריך לזהות שהוא באותו מקום.
        */}
        <p className="auth-slogan">
          החלטתם לסנן. SafeMe דואג <em>שזה יישאר כך.</em>
        </p>

        {stage === "password" && (
          <>
            <h1>מרכז הניהול</h1>
            <p className="sub">התחברות לניהול מחשבי SafeMe</p>

            {error && <div className="error">{error}</div>}

            <GoogleButton label="התחברות עם Google" />

            <form onSubmit={submitPassword}>
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
                  autoComplete="current-password"
                  required
                />
              </div>

              <button className="primary" type="submit" disabled={busy} style={{ width: "100%" }}>
                {busy ? "מתחבר..." : "התחברות"}
              </button>
            </form>

            <div className="auth-foot">
              {/*
                איפוס סיסמה ראשון ברשימה, ומעל ההרשמה.

                מי שמגיע לכאן ואינו מצליח להיכנס מחפש בדיוק את זה,
                והקישור שהיה חסר שלח אותו למוקד. פתיחת חשבון חדש
                אינה מה שהוא צריך.
              */}
              <button className="link" onClick={onForgot}>
                שכחת סיסמה?
              </button>

              <button className="link" onClick={onSignup}>
                אין לך חשבון? 30 יום ניסיון חינם
              </button>

              <button className="link muted-link" onClick={onBackToSite}>
                ← חזרה לאתר
              </button>

              {/*
                כאן היא נדרשת דווקא למי שאינו מחובר: חשבון מושעה,
                סיסמה שלא עובדת, או אימות דו-שלבי שאבד.
              */}
              <SupportLink />
            </div>
          </>
        )}

        {stage === "enroll" && (
          <>
            <h1>הגדרת אימות דו-שלבי</h1>
            <p className="sub">
              הוסף את המפתח באפליקציית אימות, והקלד את הקוד שהיא מציגה.
            </p>

            <div className="secret">{secret}</div>

            {error && <div className="error">{error}</div>}

            <form onSubmit={submitCode}>
              <div className="field">
                <input
                  className="code-input"
                  inputMode="numeric"
                  maxLength={6}
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                  placeholder="000000"
                  autoFocus
                  required
                />
              </div>

              <button
                className="primary"
                type="submit"
                disabled={busy || code.length !== 6}
                style={{ width: "100%" }}
              >
                אישור והשלמת הגדרה
              </button>
            </form>
          </>
        )}

        {stage === "code" && (
          <>
            <h1>אימות דו-שלבי</h1>
            <p className="sub">הקלד את הקוד מאפליקציית האימות שלך.</p>

            {error && <div className="error">{error}</div>}

            <form onSubmit={submitCode}>
              <div className="field">
                <input
                  className="code-input"
                  inputMode="numeric"
                  maxLength={6}
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                  placeholder="000000"
                  autoFocus
                  required
                />
              </div>

              <button
                className="primary"
                type="submit"
                disabled={busy || code.length !== 6}
                style={{ width: "100%" }}
              >
                {busy ? "בודק..." : "אישור"}
              </button>
            </form>
          </>
        )}
      </div>
    </div>
  );
}
