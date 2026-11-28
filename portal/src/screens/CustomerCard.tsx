import { useCallback, useEffect, useState } from "react";

import { ApiError, api } from "../api";
import { StatusChip } from "../components/StatusChip";
import {
  HEALTH_LABEL,
  ROLE_LABEL,
  relativeTime,
  type SecurityStatus,
  type UserRole,
} from "../types";

/**
 * כרטיס לקוח.
 *
 * כשלקוח פונה למוקד, השאלה הראשונה היא "מה המצב אצלו". עד עכשיו
 * התשובה הייתה שורה אחת בטבלת הלקוחות. הכרטיס מציג במסך אחד את
 * מה שמי שעונה לפנייה צריך: מי המשתמשים, אילו מחשבים, מי הנאמנים
 * ומה ממתין להם, ומה קרה לאחרונה.
 *
 * פעולות התמיכה יושבות ליד מה שהן נוגעות בו. פעולה שמקלה על
 * ההגנה מבקשת סיבה לפני הביצוע, והסיבה נרשמת ביומן.
 */

interface Card {
  tenant: {
    id: string;
    name: string;
    type: string;
    status: string;
    plan: string;
    contact_email: string | null;
    created_at: string;
    trial_ends_at: string | null;
    paid_until: string | null;
    network_policy: string;
    network_policy_floor: string;
    uninstall_policy: string;
    credit: number;
  };
  users: Array<{
    id: string;
    email: string;
    display_name: string | null;
    role: UserRole;
    status: string;
    mfa_enrolled_at: string | null;
    last_login_at: string | null;
    google: boolean;
  }>;
  devices: Array<{
    id: string;
    display_name: string | null;
    machine_name: string | null;
    status: string;
    agent_version: string | null;
    os_version: string | null;
    group_name: string | null;
    last_seen_at: string | null;
    last_status: SecurityStatus | null;
    detected_provider: string | null;
    health: string | null;
    lockout_active: boolean | null;
  }>;
  audit: Array<{
    at: string;
    actor_type: string;
    action: string;
    payload: Record<string, unknown>;
    actor_email: string | null;
  }>;
  trustees: {
    mode: string | null;
    list: Array<{
      id: string;
      name: string;
      email: string;
      verified_at: string | null;
      removal_effective_at: string | null;
    }>;
    requests: Array<{
      id: string;
      summary: string;
      status: string;
      created_at: string;
      decided_at: string | null;
      decided_by: string | null;
    }>;
  };
}

const TYPE: Record<string, string> = { organization: "ארגון", family: "משפחה", individual: "אישי" };
const PLAN: Record<string, string> = { trial: "ניסיון", paid: "בתשלום", expired: "פג", canceled: "בוטל" };
const TENANT_STATUS: Record<string, string> = { active: "פעיל", suspended: "מושעה", closed: "סגור" };
const USER_STATUS: Record<string, string> = { active: "פעיל", invited: "טרם אימת דוא\"ל", suspended: "מושעה", disabled: "מושבת" };
const NETWORK: Record<string, string> = { strict: "מחמיר", balanced: "מאוזן", lenient: "מקל" };
const REQUEST: Record<string, string> = {
  pending: "ממתינה לנאמן", approved: "אושרה", denied: "נדחתה", cancelled: "בוטלה", executed: "בוצעה",
};

/** פעולות היומן, בעברית. פעולה שאינה ברשימה מוצגת בשמה הגולמי, ולא מוסתרת. */
const ACTION: Record<string, string> = {
  "auth.login": "כניסה לחשבון",
  "auth.password.changed": "החלפת סיסמה",
  "auth.password.resetRequested": "בקשת איפוס סיסמה",
  "account.type_changed": "שינוי סוג החשבון",
  "trustee.invited": "הזמנת נאמן",
  "trustee.accepted": "נאמן קיבל את התפקיד",
  "trustee.declined": "נאמן סירב לתפקיד",
  "trustee.mode_changed": "שינוי תפקיד הנאמן",
  "trustee.removal_requested": "בקשה להסיר נאמן",
  "trustee.removal_approved": "נאמן אישר את הסרתו",
  "trustee.removal_stopped": "נאמן עצר את הסרתו",
  "trustee.request.created": "בקשה לנאמן",
  "trustee.request.approved": "נאמן אישר בקשה",
  "trustee.request.denied": "נאמן דחה בקשה",
  "support.password_reset_sent": "המוקד שלח קישור איפוס",
  "support.mfa_reset": "המוקד ביטל אימות דו-שלבי",
  "support.trustee_request_released": "המוקד שחרר בקשה לנאמן",
  "support.trustee_removed": "המוקד הסיר נאמן",
  "device.settings_reset": "איפוס הגדרות מחשב",
  "settings.egress.enabled": "שמירת הגדרות סינון",
  "settings.egress.disabled": "כיבוי חסימת עקיפות",
};

const ACTOR: Record<string, string> = {
  platform_user: "צוות", tenant_user: "הלקוח", system: "המערכת", device: "מחשב",
};

const when = (iso: string | null): string =>
  iso === null
    ? "—"
    : new Date(iso).toLocaleString("he-IL", { dateStyle: "short", timeStyle: "short" });

const day = (iso: string | null): string =>
  iso === null ? "—" : new Date(iso).toLocaleDateString("he-IL");

export function CustomerCard({ id, onBack }: { id: string; onBack: () => void }): JSX.Element {
  const [card, setCard] = useState<Card | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setCard(await api.get<Card>(`/api/portal/v1/platform/tenants/${id}/card`));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "טעינת הכרטיס נכשלה");
    }
  }, [id]);

  useEffect(() => { void load(); }, [load]);

  /**
   * פעולת תמיכה.
   *
   * כשהפעולה מקלה על ההגנה, נשאלת סיבה לפני הביצוע. בלי סיבה אין
   * פעולה: מה שנרשם ביומן הוא מה שיאפשר להבין בעוד חודש למה זה
   * נעשה.
   */
  async function act(path: string, askReason: string | null) {
    let body: unknown = {};

    if (askReason !== null) {
      const reason = window.prompt(askReason);

      if (reason === null) return;

      body = { reason };
    }

    setBusy(true);
    setError(null);
    setNote(null);

    try {
      const r = await api.post<{ note: string }>(path, body);

      setNote(r.note);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "הפעולה נכשלה");
    } finally {
      setBusy(false);
      await load();
    }
  }

  if (card === null) {
    return (
      <main className="shell" id="main" tabIndex={-1}>
        <button className="link" onClick={onBack}>→ חזרה ללקוחות</button>
        {error !== null ? <p className="error">{error}</p> : <p className="muted">טוען…</p>}
      </main>
    );
  }

  const t = card.tenant;
  const active = card.devices.filter((d) => d.status !== "uninstalled");
  const removed = card.devices.length - active.length;
  const openRequests = card.trustees.requests.filter((r) => r.status === "pending");

  return (
    <main className="shell" id="main" tabIndex={-1}>
      <button className="link" onClick={onBack}>→ חזרה ללקוחות</button>

      <div className="page-head" style={{ marginTop: 10 }}>
        <h1>{t.name}</h1>
        <span className={t.status === "active" ? "tag ok" : "tag warn"}>
          {TENANT_STATUS[t.status] ?? t.status}
        </span>
        <div className="spacer" />
        <button disabled={busy} onClick={() => void load()}>רענן</button>
      </div>

      {error !== null && <p className="error">{error}</p>}
      {note !== null && <p className="ok-note">{note}</p>}

      <div className="detail-grid">
        <div>
          {/* ─────────────────────────────── משתמשים */}

          <div className="panel" style={{ marginBottom: 18 }}>
            <div className="panel-head"><h2>משתמשים</h2></div>

            {card.users.length === 0 ? (
              <p className="panel-body muted">אין משתמשים בחשבון.</p>
            ) : (
              <ul className="settings-list">
                {card.users.map((u) => (
                  <li key={u.id}>
                    <div>
                      <b>{u.display_name ?? u.email}</b>
                      <span>
                        <bdi dir="ltr">{u.email}</bdi>
                        {" · "}{ROLE_LABEL[u.role] ?? u.role}
                        {" · "}{USER_STATUS[u.status] ?? u.status}
                        {u.google ? " · כניסה דרך Google" : ""}
                      </span>
                      <span>
                        אימות דו-שלבי: {u.mfa_enrolled_at !== null ? "פעיל" : "כבוי"}
                        {" · "}כניסה אחרונה: {u.last_login_at !== null ? relativeTime(u.last_login_at) : "מעולם לא"}
                      </span>
                    </div>

                    <button
                      disabled={busy}
                      onClick={() => void act(`/api/portal/v1/platform/users/${u.id}/send-reset`, null)}
                    >
                      שלח קישור איפוס
                    </button>

                    {u.mfa_enrolled_at !== null && (
                      <button
                        className="danger"
                        disabled={busy}
                        onClick={() => void act(
                          `/api/portal/v1/platform/users/${u.id}/reset-mfa`,
                          `לבטל את האימות הדו-שלבי של ${u.email}? הוא ייכנס עם סיסמה בלבד, וכל ההפעלות שלו ינותקו.\n\nסיבה (תירשם ביומן):`,
                        )}
                      >
                        בטל אימות דו-שלבי
                      </button>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>

          {/* ─────────────────────────────── מחשבים */}

          <div className="panel" style={{ marginBottom: 18 }}>
            <div className="panel-head">
              <h2>מחשבים</h2>
              <div className="spacer" />
              <span className="device-sub">
                {active.length} פעילים{removed > 0 ? ` · ${removed} הוסרו` : ""}
              </span>
            </div>

            {active.length === 0 ? (
              <p className="panel-body muted">אין מחשבים פעילים בחשבון.</p>
            ) : (
              <div className="scroller">
                <table>
                  <thead>
                    <tr>
                      <th>מחשב</th>
                      <th>מצב</th>
                      <th>קבוצה</th>
                      <th>ספק סינון</th>
                      <th>גרסה</th>
                      <th>דיווח אחרון</th>
                    </tr>
                  </thead>
                  <tbody>
                    {active.map((d) => (
                      <tr key={d.id} style={{ cursor: "default" }}>
                        <td>
                          <div className="device-name">
                            {d.display_name?.trim() || d.machine_name || "מחשב ללא כינוי"}
                          </div>
                          {d.display_name && d.machine_name && (
                            <div className="device-sub">{d.machine_name}</div>
                          )}
                        </td>
                        <td>
                          <StatusChip status={d.lockout_active ? "blocked" : d.last_status} />
                          {d.health && d.health !== "healthy" && (
                            <span className={`health ${d.health}`} style={{ marginInlineStart: 6 }}>
                              {HEALTH_LABEL[d.health] ?? d.health}
                            </span>
                          )}
                        </td>
                        <td>{d.group_name ?? <span className="muted">—</span>}</td>
                        <td>{d.detected_provider ?? <span className="muted">לא זוהה</span>}</td>
                        <td className="num">{d.agent_version ?? "—"}</td>
                        <td style={{ color: "var(--muted)", fontSize: 13 }}>{relativeTime(d.last_seen_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* ─────────────────────────────── נאמנים */}

          <div className="panel" style={{ marginBottom: 18 }}>
            <div className="panel-head">
              <h2>נאמנים</h2>
              <div className="spacer" />
              {card.trustees.list.length > 0 && (
                <span className="device-sub">
                  {card.trustees.mode === "inform" ? "הנאמן רק מקבל הודעות" : "הנאמן מאשר הקלות והסרה"}
                </span>
              )}
            </div>

            {card.trustees.list.length === 0 ? (
              <p className="panel-body muted">לא מונה נאמן. בעל החשבון מאשר לעצמו.</p>
            ) : (
              <ul className="settings-list">
                {card.trustees.list.map((tr) => (
                  <li key={tr.id}>
                    <div>
                      <b>{tr.name}</b>
                      <span>
                        <bdi dir="ltr">{tr.email}</bdi>
                        {" · "}
                        {tr.verified_at === null
                          ? "הוזמן, ועוד לא אישר"
                          : tr.removal_effective_at !== null
                            ? `בהסרה, תיכנס לתוקף ב-${when(tr.removal_effective_at)}`
                            : "פעיל"}
                      </span>
                    </div>

                    <button
                      className="danger"
                      disabled={busy}
                      onClick={() => void act(
                        `/api/portal/v1/platform/trustees/${tr.id}/remove`,
                        `להסיר את ${tr.name} מתפקיד הנאמן, מיד ובלי אישורו? אחרי ההסרה בעל החשבון יוכל להקל בלי נאמן.\n\nסיבה (תירשם ביומן):`,
                      )}
                    >
                      הסר נאמן
                    </button>
                  </li>
                ))}
              </ul>
            )}

            {card.trustees.requests.length > 0 && (
              <>
                <div className="panel-head" style={{ borderTop: "1px solid var(--line)" }}>
                  <h2>בקשות לנאמן</h2>
                  <div className="spacer" />
                  <span className="device-sub">{openRequests.length} ממתינות</span>
                </div>

                <ul className="settings-list">
                  {card.trustees.requests.map((r) => (
                    <li key={r.id}>
                      <div>
                        <b>{r.summary}</b>
                        <span>
                          {REQUEST[r.status] ?? r.status}
                          {" · "}נשלחה {when(r.created_at)}
                          {r.decided_by ? ` · ${r.decided_by}` : ""}
                        </span>
                      </div>

                      {r.status === "pending" && (
                        <button
                          className="danger"
                          disabled={busy}
                          onClick={() => void act(
                            `/api/portal/v1/platform/trustee-requests/${r.id}/release`,
                            `לאשר את הבקשה הזו במקום הנאמן?\n\n${r.summary}\n\nסיבה (תירשם ביומן):`,
                          )}
                        >
                          אשר במקום הנאמן
                        </button>
                      )}
                    </li>
                  ))}
                </ul>
              </>
            )}
          </div>

          {/* ─────────────────────────────── יומן */}

          <div className="panel">
            <div className="panel-head">
              <h2>מה קרה בחשבון</h2>
              <div className="spacer" />
              <span className="device-sub">60 הפעולות האחרונות</span>
            </div>

            {card.audit.length === 0 ? (
              <p className="panel-body muted">עוד לא נרשמו פעולות.</p>
            ) : (
              <div className="scroller">
                <table>
                  <thead>
                    <tr>
                      <th>מתי</th>
                      <th>מי</th>
                      <th>מה</th>
                      <th>פרטים</th>
                    </tr>
                  </thead>
                  <tbody>
                    {card.audit.map((a, i) => (
                      <tr key={i} style={{ cursor: "default" }}>
                        <td style={{ whiteSpace: "nowrap", color: "var(--muted)", fontSize: 13 }}>{when(a.at)}</td>
                        <td style={{ fontSize: 13 }}>
                          {ACTOR[a.actor_type] ?? a.actor_type}
                          {a.actor_email && <div className="device-sub" dir="ltr">{a.actor_email}</div>}
                        </td>
                        <td>{ACTION[a.action] ?? <code dir="ltr">{a.action}</code>}</td>
                        <td className="muted small">{describe(a.payload)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        {/* ─────────────────────────────── פרטי החשבון */}

        <div>
          <div className="panel">
            <div className="panel-head"><h2>החשבון</h2></div>

            <dl className="kv">
              <dt>סוג</dt>
              <dd>{TYPE[t.type] ?? t.type}</dd>

              <dt>מנוי</dt>
              <dd>{PLAN[t.plan] ?? t.plan}</dd>

              {t.plan === "trial" && (
                <>
                  <dt>סוף הניסיון</dt>
                  <dd>{day(t.trial_ends_at)}</dd>
                </>
              )}

              {t.paid_until !== null && (
                <>
                  <dt>שולם עד</dt>
                  <dd>{day(t.paid_until)}</dd>
                </>
              )}

              <dt>קרדיט</dt>
              <dd className="num">{t.credit}</dd>

              <dt>נרשם</dt>
              <dd>{day(t.created_at)}</dd>

              <dt>דוא"ל קשר</dt>
              <dd dir="ltr" style={{ textAlign: "right" }}>{t.contact_email ?? "—"}</dd>

              <dt>רשתות חדשות</dt>
              <dd>{NETWORK[t.network_policy] ?? t.network_policy}</dd>

              <dt>רצפת רשתות</dt>
              <dd>{NETWORK[t.network_policy_floor] ?? t.network_policy_floor}</dd>

              <dt>הסרת התוכנה</dt>
              <dd>{t.uninstall_policy === "support_only" ? "רק דרך המוקד" : "בעל החשבון מנפיק קוד"}</dd>
            </dl>

            <p className="panel-body muted small">
              השעיה, הארכת ניסיון, סימון תשלום וקרדיט נעשים בטבלת הלקוחות.
            </p>
          </div>
        </div>
      </div>
    </main>
  );
}

/** פרטי פעולה מהיומן, בשורה אחת. שדות ריקים אינם מוצגים. */
function describe(payload: Record<string, unknown>): string {
  return Object.entries(payload ?? {})
    .filter(([, v]) => v !== null && v !== "" && typeof v !== "object")
    .map(([k, v]) => `${LABEL[k] ?? k}: ${String(v)}`)
    .join(" · ");
}

const LABEL: Record<string, string> = {
  reason: "סיבה",
  summary: "בקשה",
  user: "משתמש",
  email: "דוא\"ל",
  trustee: "נאמן",
  mode: "מצב",
  accountType: "סוג",
  sent: "נשלח",
  method: "שיטה",
  path: "נתיב",
  version: "גרסה",
};
