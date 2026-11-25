import { useCallback, useEffect, useState } from "react";
import { MfaRequiredError, UnauthorizedError, api, restoreCsrfToken, setCsrfToken } from "./api";
import { Logo } from "./components/Logo";
import { Landing } from "./screens/Landing";
import { Login } from "./screens/Login";
import { PasswordReset } from "./screens/PasswordReset";
import { Signup } from "./screens/Signup";
import { Dashboard } from "./screens/Dashboard";
import { DeviceDetail } from "./screens/DeviceDetail";
import { Groups } from "./screens/Groups";
import { GroupDetail } from "./screens/GroupDetail";
import { Networks } from "./screens/Networks";
import { Egress } from "./screens/Egress";
import { GoogleComplete } from "./screens/GoogleComplete";
import { Customers } from "./screens/Customers";
import { Security } from "./screens/Security";
import { Subscription } from "./screens/Subscription";
import { Plans } from "./screens/Plans";
import { StepUpMfa } from "./components/StepUpMfa";
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
  const [groupId, setGroupId] = useState<string | null>(null);
  const [view, setView] = useState<"devices" | "groups" | "networks" | "egress" | "notifications" | "security" | "subscription" | "plans" | "customers" | "providers" | "mail" | "uninstall">("devices");
  /**
   * מבקר שאינו מחובר רואה קודם את דף הנחיתה, ולא טופס התחברות.
   * הרוב המכריע של מי שמגיע לכתובת הזו עדיין לא לקוח.
   */
  const [gate, setGate] = useState<"landing" | "login" | "signup" | "google" | "reset">("landing");

  /*
   * האסימון מהקישור במייל.
   *
   * נקרא פעם אחת ומנוקה מהכתובת מיד, כמו אסימון ה-CSRF של Google:
   * הוא שווה ערך לסיסמה עד שנוצל, ואין סיבה שיישאר בהיסטוריית
   * הדפדפן או בכותרת Referer של הבקשה הבאה.
   */
  const [resetToken, setResetToken] = useState<string | null>(null);
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

    /*
     * קישור איפוס סיסמה.
     *
     * הנתיב הוא /reset והאסימון בשאילתה. שניהם מנוקים מיד אחרי
     * הקריאה, מאותה סיבה בדיוק.
     */
    const token = params.get("token");

    if (token !== null && window.location.pathname.startsWith("/reset")) {
      setResetToken(token);
      setGate("reset");

      window.history.replaceState({}, "", "/");
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
        <Logo size={40} />
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

    if (gate === "reset") {
      return (
        <PasswordReset
          token={resetToken}
          onDone={() => {
            setResetToken(null);
            setGate("login");
          }}
        />
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
        onForgot={() => { setResetToken(null); setGate("reset"); }}
      />
    );
  }

  return (
    <>
      <header className="topbar">
        <div className="topbar-inner">
          <div className="brand">
            <Logo size={26} />
            Filter+‎
          </div>

          <nav className="tabs">
            <button
              className={view === "devices" && deviceId === null ? "tab on" : "tab"}
              onClick={() => {
                setView("devices");
                setDeviceId(null);
                setGroupId(null);
              }}
            >
              מחשבים
            </button>
            <button
              className={view === "groups" ? "tab on" : "tab"}
              onClick={() => {
                setView("groups");
                setDeviceId(null);
                setGroupId(null);
              }}
            >
              קבוצות
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
              הגבלות גלישה
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
            {/*
              מנוי, לכל משתמש עם דייר.

              מנהל פלטפורמה אינו שייך לדייר ואין לו מנוי, ולשונית
              שמובילה למסך ריק היא בדיוק מה שמלמד להתעלם מהתפריט.
            */}
            {me.tenantId !== null && (
              <button
                className={view === "subscription" ? "tab on" : "tab"}
                onClick={() => {
                  setView("subscription");
                  setDeviceId(null);
                }}
              >
                מנוי
              </button>
            )}

            {/*
              אבטחה זמינה לכל משתמש, ולא רק לצוות החברה.

              החשבון של ההורה שולט על ההגנה של כל מחשבי הבית —
              אישור רשתות, הקלת מדיניות, והנפקת קוד הסרה. אין סיבה
              שדווקא הוא יישאר בלי אימות דו-שלבי.
            */}
            <button
              className={view === "security" ? "tab on" : "tab"}
              onClick={() => {
                setView("security");
                setDeviceId(null);
              }}
            >
              אבטחה
            </button>

            {/*
              לקוחות לפני ספקים, וזה סדר ולא קישוט.

              זה המסך שנפתח כשרוצים לדעת מה מצב העסק, והוא אמור
              להיות הראשון שהיד מגיעה אליו.
            */}
            {me.role === "platform_admin" && (
              <button
                className={view === "customers" ? "tab on" : "tab"}
                onClick={() => {
                  setView("customers");
                  setDeviceId(null);
                }}
              >
                לקוחות
              </button>
            )}

            {me.role === "platform_admin" && (
              <button
                className={view === "plans" ? "tab on" : "tab"}
                onClick={() => {
                  setView("plans");
                  setDeviceId(null);
                }}
              >
                מחירון
              </button>
            )}

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

      {/*
        מסך האימות החוזר יושב במעטפת, כי כל בקשה עשויה לדרוש אותו.
      */}
      <StepUpMfa />

      {deviceId !== null ? (
        <DeviceDetail id={deviceId} onBack={() => setDeviceId(null)} />
      ) : groupId !== null ? (
        <GroupDetail
          id={groupId}
          onBack={() => setGroupId(null)}
          onOpenDevice={(did) => { setGroupId(null); setView("devices"); setDeviceId(did); }}
        />
      ) : view === "groups" ? (
        <main className="shell">
          <Groups onOpen={(gid) => setGroupId(gid)} />
        </main>
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

      ) : view === "subscription" ? (
        <Subscription />
      ) : view === "plans" ? (
        <Plans />
      ) : view === "security" ? (
        <Security />
      ) : view === "customers" ? (
        <Customers />
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
