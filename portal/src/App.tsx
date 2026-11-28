import { useCallback, useEffect, useState } from "react";
import { MfaRequiredError, UnauthorizedError, api, restoreCsrfToken, setCsrfToken } from "./api";
import { Logo } from "./components/Logo";
import { Landing } from "./screens/Landing";
import { Login } from "./screens/Login";
import { PasswordReset } from "./screens/PasswordReset";
import { Signup } from "./screens/Signup";
import { Dashboard } from "./screens/Dashboard";
import { DeviceDetail } from "./screens/DeviceDetail";
import { GroupDetail } from "./screens/GroupDetail";
import { Browsing, type BrowsingTopic } from "./screens/Browsing";
import { History } from "./screens/History";
import { Settings, type SettingsTopic } from "./screens/Settings";
import { TrusteeLink } from "./screens/TrusteeLink";
import { AdminPortal } from "./screens/AdminPortal";
import { GoogleComplete } from "./screens/GoogleComplete";
import { Subscription } from "./screens/Subscription";
import { StepUpMfa } from "./components/StepUpMfa";
import { TrialBanner } from "./components/TrialBanner";
import { useFleet, type Scope } from "./fleet";
import { ROLE_LABEL, type Me } from "./types";

/*
 * פורטל הניהול יושב בכתובת משלו, admin.filterplus.co.il.
 *
 * אותו קוד ואותו שרת, אבל כתובת אחרת פירושה עוגיית הפעלה אחרת:
 * מי שמחובר כלקוח באתר הרגיל אינו מחובר לניהול, ולהפך. בכתובת
 * הזו אין דף בית שיווקי, אין הרשמה ואין כניסה דרך Google.
 */
const ADMIN_HOST = window.location.hostname.startsWith("admin.");

/**
 * שורש הפורטל.
 *
 * הניווט מנוהל במצב מקומי ולא בספריית ניתוב: יש שני מסכים בלבד,
 * וספרייה נוספת כאן הייתה תלות בלי תמורה.
 */
export function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [checking, setChecking] = useState(true);
  /**
   * מבקר שאינו מחובר רואה קודם את דף הנחיתה, ולא טופס התחברות.
   * הרוב המכריע של מי שמגיע לכתובת הזו עדיין לא לקוח.
   */
  const [gate, setGate] = useState<"landing" | "login" | "signup" | "google" | "reset">(
    ADMIN_HOST ? "login" : "landing");

  /*
   * האסימון מהקישור במייל.
   *
   * נקרא פעם אחת ומנוקה מהכתובת מיד, כמו אסימון ה-CSRF של Google:
   * הוא שווה ערך לסיסמה עד שנוצל, ואין סיבה שיישאר בהיסטוריית
   * הדפדפן או בכותרת Referer של הבקשה הבאה.
   */
  const [resetToken, setResetToken] = useState<string | null>(null);
  const [googleError, setGoogleError] = useState<string | null>(null);

  /*
   * קישור של נאמן.
   *
   * הנאמן אינו משתמש במערכת, ולכן הדף שלו מוצג בלי קשר לשאלה אם
   * מישהו מחובר בדפדפן הזה. האסימון נשאר בזיכרון בלבד ומנוקה
   * מהכתובת, כמו אסימון איפוס הסיסמה.
   */
  const [trustee, setTrustee] = useState<{ token: string; by: string | null } | null>(null);

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

    if (token !== null && window.location.pathname.startsWith("/trustee")) {
      setTrustee({ token, by: params.get("by") });

      window.history.replaceState({}, "", "/");
    }

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
    setGate(ADMIN_HOST ? "login" : "landing");
  }

  if (trustee !== null) {
    return (
      <TrusteeLink
        token={trustee.token}
        by={trustee.by}
        onHome={() => setTrustee(null)}
      />
    );
  }

  if (checking) {
    return (
      <div className="auth-wrap" id="main" role="main" tabIndex={-1}>
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
        staff={ADMIN_HOST}
        onSignedIn={() => void loadMe()}
        onSignup={() => setGate("signup")}
        onBackToSite={() => setGate("landing")}
        onForgot={() => { setResetToken(null); setGate("reset"); }}
      />
    );
  }

  const staff = me.role === "platform_admin" || me.role === "support_operator";

  /*
   * איש צוות מקבל את פורטל הניהול בכל כתובת שממנה נכנס.
   *
   * עד שהכתובת הנפרדת מחוברת, זו הדרך היחידה להגיע לניהול. לקוח
   * אינו רואה ממנו דבר בשום כתובת.
   */
  if (staff) return <AdminPortal me={me} onSignOut={() => void signOut()} />;

  // לקוח שהגיע לכתובת של הצוות: אין לו כאן מה לעשות
  if (ADMIN_HOST) {
    return (
      <div className="auth-wrap" id="main" role="main" tabIndex={-1}>
        <div className="auth-card">
          <Logo size={40} />
          <h1>הכתובת הזו מיועדת לצוות</h1>
          <p className="sub">
            מרכז הניהול של החשבון שלך נמצא בכתובת{" "}
            <a className="link" href="https://www.filterplus.co.il" dir="ltr">www.filterplus.co.il</a>.
          </p>
          <button onClick={() => void signOut()}>יציאה</button>
        </div>
      </div>
    );
  }

  return <Portal me={me} onSignOut={() => void signOut()} onAccountChanged={() => void loadMe()} />;
}

type View = "computers" | "browsing" | "history" | "billing" | "settings";

/**
 * מרכז הניהול, אחרי כניסה.
 *
 * חמש לשוניות, אחת לכל נושא: המחשבים, מה מותר להם לגלוש, מה קרה
 * בהם, המנוי, והגדרות החשבון. עד עכשיו כל הגדרה ישבה בתוך המסך של
 * המחשב שהיא חלה עליו, וכדי למצוא אותה היה צריך לדעת מראש שהיא שם.
 *
 * הבחירה במחשב או בקבוצה משותפת לכל הלשוניות. מי שפתח את לוח
 * הבקרה של מחשב ולחץ "שנה" ליד זמני הגלישה מגיע ללשונית ההגדרות
 * כשאותו מחשב כבר נבחר.
 */
function Portal({
  me,
  onSignOut,
  onAccountChanged,
}: {
  me: Me;
  onSignOut: () => void;
  /** פרטי החשבון השתנו, ויש לטעון אותם מחדש. */
  onAccountChanged: () => void;
}) {
  const [view, setView] = useState<View>("computers");
  const [deviceId, setDeviceId] = useState<string | null>(null);
  const [groupId, setGroupId] = useState<string | null>(null);
  const [setupId, setSetupId] = useState<string | null>(null);
  const [scope, setScope] = useState<Scope>({ kind: "account" });
  const [browsing, setBrowsing] = useState<BrowsingTopic>("whitelist");
  const [settings, setSettings] = useState<SettingsTopic>("notifications");

  const fleet = useFleet();
  const { reload } = fleet;

  // מעבר בין לשוניות מרענן את הרשימה: כינוי ששונה במסך אחד צריך להופיע בבורר של הבא
  useEffect(() => { void reload(); }, [view, reload]);

  function go(next: View) {
    setView(next);
    setDeviceId(null);
    setGroupId(null);
    setSetupId(null);
    window.scrollTo({ top: 0 });
  }

  const tabs: Array<{ key: View; label: string; show: boolean }> = [
    { key: "computers", label: "ראשי", show: true },
    { key: "browsing", label: "הגדרות גלישה", show: true },
    { key: "history", label: "היסטוריה והתראות", show: true },
    { key: "billing", label: "מנוי ותשלומים", show: me.tenantId !== null },
    { key: "settings", label: "הגדרות", show: true },
  ];

  const focusDevice = scope.kind === "device" ? scope.id : null;

  return (
    <>
      {/*
        הסרגל נשאר בראש המסך בזמן גלילה. הלשוניות הן הדרך היחידה
        לעבור בין נושאים, ומסך ארוך לא אמור להעלים אותן.
      */}
      <header className="topbar">
        <div className="topbar-inner">
          <div className="brand">
            <Logo size={26} />
            Filter+‎
          </div>

          <nav className="tabs" aria-label="ניווט ראשי">
            {tabs.filter((t) => t.show).map((t) => (
              <button
                key={t.key}
                className={view === t.key ? "tab on" : "tab"}
                aria-current={view === t.key ? "page" : undefined}
                onClick={() => go(t.key)}
              >
                {t.label}
              </button>
            ))}
          </nav>

          <div className="spacer" />

          <div className="who">
            <b>{me.displayName ?? me.email}</b>
            {ROLE_LABEL[me.role]}
          </div>

          <button onClick={onSignOut}>יציאה</button>
        </div>
      </header>

      {me.trial && (
        <div className="shell" style={{ paddingBottom: 0 }}>
          <TrialBanner trial={me.trial} />
        </div>
      )}

      {/* מסך האימות החוזר יושב במעטפת, כי כל בקשה עשויה לדרוש אותו. */}
      <StepUpMfa />

      {view === "billing" ? (
        <Subscription />
      ) : (
        <main className="shell" id="main" tabIndex={-1}>
          {view === "computers" && deviceId !== null && (
            <DeviceDetail
              id={deviceId}
              onBack={() => setDeviceId(null)}
              onSetup={() => { setSetupId(deviceId); setDeviceId(null); window.scrollTo({ top: 0 }); }}
              onBrowse={(topic) => {
                setScope({ kind: "device", id: deviceId });
                setBrowsing(topic);
                go("browsing");
              }}
              onHistory={() => {
                setScope({ kind: "device", id: deviceId });
                go("history");
              }}
              onSettings={(topic) => {
                setScope({ kind: "device", id: deviceId });
                setSettings(topic);
                go("settings");
              }}
            />
          )}

          {view === "computers" && deviceId === null && groupId !== null && (
            <GroupDetail
              id={groupId}
              onBack={() => setGroupId(null)}
              onOpenDevice={(did) => { setGroupId(null); setDeviceId(did); }}
              onSettings={(topic) => {
                setScope({ kind: "group", id: groupId });
                setBrowsing(topic);
                go("browsing");
              }}
            />
          )}

          {view === "computers" && deviceId === null && groupId === null && (
            <Dashboard
              accountType={me.tenantType ?? null}
              setupId={setupId}
              onSetup={(id) => { setSetupId(id); window.scrollTo({ top: 0 }); }}
              onOpenDevice={(id) => { setDeviceId(id); window.scrollTo({ top: 0 }); }}
              onOpenGroup={(id) => { setGroupId(id); window.scrollTo({ top: 0 }); }}
            />
          )}

          {view === "browsing" && (
            <Browsing
              fleet={fleet}
              topic={browsing}
              onTopic={setBrowsing}
              scope={scope}
              onScope={setScope}
            />
          )}

          {view === "history" && (
            <History
              fleet={fleet}
              deviceId={focusDevice}
              onDevice={(id) => setScope({ kind: "device", id })}
            />
          )}

          {view === "settings" && (
            <Settings
              me={me}
              onAccountChanged={onAccountChanged}
              fleet={fleet}
              topic={settings}
              onTopic={setSettings}
              deviceId={focusDevice}
              onDevice={(id) => setScope({ kind: "device", id })}
            />
          )}

        </main>
      )}
    </>
  );
}
