import { useState } from "react";

import { Logo } from "../components/Logo";
import { StepUpMfa } from "../components/StepUpMfa";
import { ROLE_LABEL, type Me } from "../types";
import { CustomerCard } from "./CustomerCard";
import { Customers } from "./Customers";
import { Mail } from "./Mail";
import { Plans } from "./Plans";
import { Providers } from "./Providers";
import { Security } from "./Security";
import { UninstallDesk } from "./UninstallDesk";

/**
 * פורטל הניהול של הצוות.
 *
 * נפרד מהפורטל של הלקוחות, ולא חמש לשוניות נוספות בתוכו. מי
 * שמנהל את כל הלקוחות אינו לקוח: אין לו מחשבים, אין לו מנוי,
 * והלשוניות "ראשי" ו"הגדרות גלישה" היו מציגות לו מסכים ריקים.
 * ומהצד השני, לקוח אינו אמור לראות אפילו את קיומו של הניהול.
 *
 * מה שמוצג נגזר מהתפקיד, אבל ההסתרה כאן היא נימוס ולא הגנה: השרת
 * בודק כל בקשה מול ההרשאה, בלי קשר למה שהמסך הציג.
 */

type View = "customers" | "plans" | "providers" | "mail" | "uninstall" | "security";

export function AdminPortal({ me, onSignOut }: { me: Me; onSignOut: () => void }): JSX.Element {
  const admin = me.role === "platform_admin";
  const [view, setView] = useState<View>("customers");
  const [tenantId, setTenantId] = useState<string | null>(null);

  const tabs: Array<{ key: View; label: string; show: boolean }> = [
    // לקוחות ראשונים: זה המסך שנפתח כשרוצים לדעת מה מצב העסק
    { key: "customers", label: "לקוחות", show: true },
    { key: "uninstall", label: "קוד הסרה", show: true },
    { key: "plans", label: "מחירון", show: admin },
    { key: "providers", label: "ספקי סינון", show: admin },
    { key: "mail", label: "דואר יוצא", show: admin },
    { key: "security", label: "האבטחה שלי", show: true },
  ];

  return (
    <>
      <header className="topbar admin-bar">
        <div className="topbar-inner">
          <div className="brand">
            <Logo size={26} />
            Filter+‎
            <span className="admin-mark">ניהול</span>
          </div>

          <nav className="tabs" aria-label="ניווט ראשי">
            {tabs.filter((t) => t.show).map((t) => (
              <button
                key={t.key}
                className={view === t.key ? "tab on" : "tab"}
                aria-current={view === t.key ? "page" : undefined}
                onClick={() => { setView(t.key); setTenantId(null); window.scrollTo({ top: 0 }); }}
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

      {/* מסך האימות החוזר יושב במעטפת, כי כל בקשה עשויה לדרוש אותו. */}
      <StepUpMfa />

      {view === "customers" && tenantId !== null ? (
        <CustomerCard id={tenantId} onBack={() => setTenantId(null)} />
      ) : view === "customers" ? (
        <Customers onOpen={(id) => { setTenantId(id); window.scrollTo({ top: 0 }); }} />
      ) : view === "plans" ? (
        <Plans />
      ) : (
        <main className="shell" id="main" tabIndex={-1}>
          {view === "uninstall" && <UninstallDesk />}
          {view === "mail" && <Mail />}
          {view === "providers" && <Providers />}

          {view === "security" && (
            <>
              <div className="page-head"><h1>האבטחה שלי</h1></div>
              <Security />
            </>
          )}
        </main>
      )}
    </>
  );
}
