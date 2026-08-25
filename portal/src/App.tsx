import { useCallback, useEffect, useState } from "react";
import { MfaRequiredError, UnauthorizedError, api, restoreCsrfToken, setCsrfToken } from "./api";
import { Shield } from "./components/Shield";
import { Login } from "./screens/Login";
import { Signup } from "./screens/Signup";
import { Dashboard } from "./screens/Dashboard";
import { DeviceDetail } from "./screens/DeviceDetail";
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
  const [showSignup, setShowSignup] = useState(false);

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
  }

  if (checking) {
    return (
      <div className="auth-wrap">
        <Shield color="#4d94d1" size={40} />
      </div>
    );
  }

  if (!me) {
    return showSignup ? (
      <Signup
        onSignedIn={() => {
          setShowSignup(false);
          void loadMe();
        }}
        onBackToLogin={() => setShowSignup(false)}
      />
    ) : (
      <Login onSignedIn={() => void loadMe()} onSignup={() => setShowSignup(true)} />
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

      {deviceId ? (
        <DeviceDetail id={deviceId} onBack={() => setDeviceId(null)} />
      ) : (
        <Dashboard onOpenDevice={setDeviceId} />
      )}
    </>
  );
}
