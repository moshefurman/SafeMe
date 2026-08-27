import { useCallback, useEffect, useState } from "react";
import { MfaRequiredError, UnauthorizedError, api, restoreCsrfToken, setCsrfToken } from "./api";
import { Shield } from "./components/Shield";
import { Landing } from "./screens/Landing";
import { Login } from "./screens/Login";
import { Signup } from "./screens/Signup";
import { Dashboard } from "./screens/Dashboard";
import { DeviceDetail } from "./screens/DeviceDetail";
import { Networks } from "./screens/Networks";
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
  const [view, setView] = useState<"devices" | "networks">("devices");
  /**
   * מבקר שאינו מחובר רואה קודם את דף הנחיתה, ולא טופס התחברות.
   * הרוב המכריע של מי שמגיע לכתובת הזו עדיין לא לקוח.
   */
  const [gate, setGate] = useState<"landing" | "login" | "signup">("landing");

  const loadMe = useCallback(async () => {
    try {
      setMe(await api.get<Me>("/api/portal/v1/auth/me"));
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
    if (gate === "landing") {
      return (
        <Landing
          onStart={() => setGate("signup")}
          onLogin={() => setGate("login")}
        />
      );
    }

    if (gate === "signup") {
      return (
        <Signup
          onSignedIn={() => void loadMe()}
          onBackToLogin={() => setGate("login")}
        />
      );
    }

    return (
      <Login onSignedIn={() => void loadMe()} onSignup={() => setGate("signup")} />
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
              מכשירים
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
      ) : (
        <Dashboard onOpenDevice={setDeviceId} />
      )}
    </>
  );
}
