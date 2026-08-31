import { useCallback, useEffect, useState } from "react";
import { MfaRequiredError, UnauthorizedError, api, restoreCsrfToken, setCsrfToken } from "./api";
import { Shield } from "./components/Shield";
import { Landing } from "./screens/Landing";
import { Login } from "./screens/Login";
import { Signup } from "./screens/Signup";
import { Dashboard } from "./screens/Dashboard";
import { DeviceDetail } from "./screens/DeviceDetail";
import { Networks } from "./screens/Networks";
import { Egress } from "./screens/Egress";
import { GoogleComplete } from "./screens/GoogleComplete";
import { Providers } from "./screens/Providers";
import { Notifications } from "./screens/Notifications";
import { Mail } from "./screens/Mail";
import { UninstallDesk } from "./screens/UninstallDesk";
import { TrialBanner } from "./components/TrialBanner";
import { ROLE_LABEL, type Me } from "./types";

/**
 * שורש הפורטל.
 *
 * הניווט מנוהל במצב מקומי ולא בספריית ניתוב: יש שני מסכים בלבד,
 * וספרייה נוספת כאן הייתה תלות בלי תמורה.
 */
export function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [checking, setChecking] = useState(true);
  const [deviceId, setDeviceId] = useState<string | null>(null);
  const [view, setView] = useState<"devices" | "networks" | "egress" | "notifications" | "providers" | "mail" | "uninstall">("devices");
  /**
   * מבקר שאינו מחובר רואה קודם את דף הנחיתה, ולא טופס התחברות.
   * הרוב המכריע של מי שמגיע לכתובת הזו עדיין לא לקוח.
   */
  const [gate, setGate] = useState<"landing" | "login" | "signup" | "google">("landing");
  const [googleError, setGoogleError] = useState<string | null>(null);

  const loadMe = useCallback(async () => {
    try {
      const profile = await api.get<Me>("/api/portal/v1/auth/me");

      // השרת מנפיק אסימון חדש כשהוא רואה שאין לנו. בלי השורה הזו
      // המשתמש נשאר מחובר וכל פעולת כתיבה שלו נדחית.
      if (profile.csrfToken) setCsrfToken(profile.csrfToken);

      setMe(profile);
    } catch (caught) {
      // שתי התשובות האלה משמעותן "עדיין לא מחובר", ולא תקלה
      if (caught instanceof UnauthorizedError || caught instanceof MfaRequiredError) {
        setMe(null);
      } else {
        setMe(null);
      }
    } finally {
      setChecking(false);
    }
  }, []);

  useEffect(() => {
    restoreCsrfToken();

    /*
     * חזרה מ-Google.
     *
     * התוצאה מגיעה בכתובת, כי זו הפניה ולא בקשת רקע. הכתובת מנוקה
     * מיד: אסימון ה-CSRF אינו אמור להישאר בהיסטוריה, וגם רענון של
     * הדף לא צריך לחזור על הטיפול.
     */
    const params = new URLSearchParams(window.location.search);
    const outcome = params.get("google");

    if (outcome !== null) {
      const csrf = params.get("csrf");

      if (outcome === "ok" && csrf !== null) setCsrfToken(csrf);
      if (outcome === "complete") setGate("google");

      if (outcome === "failed") setGoogleError("הכניסה דרך Google נכשלה. נסה שוב.");
      if (outcome === "expired") {
        setGoogleError("הכניסה ארכה זמן רב מדי. נסה שוב.");
      }

      window.history.replaceState({}, "", window.location.pathname);
    }

    void loadMe();
  }, [loadMe]);

  async function signOut() {
    try {
      await api.post("/api/portal/v1/auth/logout");
    } catch {
      // גם אם הבקשה נכשלה, מנקים את המצב המקומי
    }

    setCsrfToken(null);
    setMe(null);
    setDeviceId(null);
    setGate("landing");
  }

  if (checking) {
    return (
      <div className="auth-wrap">
        <Shield color="#4d94d1" size={40} />
      </div>
    );
  }

  if (!me) {
    if (gate === "google") {
      return (
        <GoogleComplete
          onDone={() => void loadMe()}
          onCancel={() => setGate("landing")}
        />
      );
    }

    if (gate === "landing") {
      return (
        <>
          {googleError !== null && <p className="banner-error">{googleError}</p>}

          <Landing
            onStart={() => setGate("signup")}
            onLogin={() => setGate("login")}
          />
        </>
      );
    }

    if (gate === "signup") {
      return (
        <Signup
          onSignedIn={() => void loadMe()}
          onBackToLogin={() => setGate("login")}
          onBackToSite={() => setGate("landing")}
        />
      );
    }

    return (
      <Login
        onSignedIn={() => void loadMe()}
        onSignup={() => setGate("signup")}
        onBackToSite={() => setGate("landing")}
      />
    );
  }

  return (
    <>
      <header className="topbar">
        <div className="topbar-inner">
          <div className="brand">
            <Shield color="#4d94d1" size={26} />
            SafeMe
          </div>

          <nav className="tabs">
            <button
              className={view === "devices" && deviceId === null ? "tab on" : "tab"}
              onClick={() => {
                setView("devices");
                setDeviceId(null);
              }}
            >
              מחשבים
            </button>
            <button
              className={view === "networks" ? "tab on" : "tab"}
              onClick={() => {
                setView("networks");
                setDeviceId(null);
              }}
            >
              רשתות
            </button>
            <button
              className={view === "egress" ? "tab on" : "tab"}
              onClick={() => {
                setView("egress");
                setDeviceId(null);
              }}
            >
              חסימת VPN
            </button>
            <button
              className={view === "notifications" ? "tab on" : "tab"}
              onClick={() => {
                setView("notifications");
                setDeviceId(null);
              }}
            >
              התראות
            </button>



            {/*
              ספקי הסינון הם הגדרה גלובלית, ולכן רק מנהל פלטפורמה.
              דייר שיכול להגדיר מה נחשב "מסונן" יכול לאשר לעצמו כל
              חיבור, ובכך לבטל את המוצר מבפנים.
            */}
            {me.role === "platform_admin" && (
              <button
                className={view === "providers" ? "tab on" : "tab"}
                onClick={() => {
                  setView("providers");
                  setDeviceId(null);
                }}
              >
                ספקי סינון
              </button>
            )}

            {me.role === "platform_admin" && (
              <button
                className={view === "mail" ? "tab on" : "tab"}
                onClick={() => {
                  setView("mail");
                  setDeviceId(null);
                }}
              >
                דואר יוצא
              </button>
            )}

            {me.role === "platform_admin" && (
              <button
                className={view === "uninstall" ? "tab on" : "tab"}
                onClick={() => {
                  setView("uninstall");
                  setDeviceId(null);
                }}
              >
                קוד הסרה
              </button>
            )}
          </nav>

          <div className="spacer" />

          <div className="who">
            <b>{me.displayName ?? me.email}</b>
            {ROLE_LABEL[me.role]}
          </div>

          <button onClick={() => void signOut()}>יציאה</button>
        </div>
      </header>

      {me.trial && (
        <div className="shell" style={{ paddingBottom: 0 }}>
          <TrialBanner trial={me.trial} />
        </div>
      )}

      {deviceId !== null ? (
        <DeviceDetail id={deviceId} onBack={() => setDeviceId(null)} />
      ) : view === "networks" ? (
        <main className="shell">
          <Networks />
        </main>
      ) : view === "egress" ? (
        <main className="shell">
          <Egress />
        </main>
      ) : view === "notifications" ? (
        <main className="shell">
          <Notifications />
        </main>

      ) : view === "uninstall" ? (
        <main className="shell">
          <UninstallDesk />
        </main>
      ) : view === "mail" ? (
        <main className="shell">
          <Mail />
        </main>
      ) : view === "providers" ? (
        <main className="shell">
          <Providers />
        </main>
      ) : (
        <Dashboard onOpenDevice={setDeviceId} />
      )}
    </>
  );
}
