import { useCallback, useEffect, useState } from "react";

import { api, ApiError } from "../api";

/**
 * מסך הלקוחות של מנהל הפלטפורמה.
 *
 * עד כה היה אפשר לראות מחשבים ולא לקוחות. מחשבים הם מה שהמערכת
 * מודדת; לקוחות הם מה שמחליט אם היא מתקיימת. עם אלפי התקנות אין
 * דרך לדעת מהמסך הישן כמה לקוחות יש, מי מהם ננטש, ואצל מי כל
 * המחשבים הפסיקו לדווח — וזה בדיוק הלקוח שעומד לעזוב.
 *
 * המספר שהמסך בנוי סביבו הוא "לקוחות בלי אף מחשב מדווח". סכום של
 * מחשבים מסתיר אותו לגמרי: לקוח אחד עם עשרים מחשבים מכסה על עשרה
 * לקוחות נטושים, והממוצע נראה מצוין עד שהם מבטלים.
 */

interface Tenant {
  id: string;
  name: string;
  type: string;
  status: string;
  plan: string;
  contactEmail: string | null;
  createdAt: string;
  trialEndsAt: string | null;
  devices: number;
  reporting: number;
  silent: number;
  neverReported: number;
  lastSeenAt: string | null;
  paidUntil?: string | null;
  credit: number;
  networkFloor: string;
  uninstallPolicy: string;
}

interface Summary {
  tenants: number;
  active: number;
  suspended: number;
  devices: number;
  reporting: number;
  silent: number;
  neverReported: number;
  withoutReporting: number;
}

const PLAN_LABEL: Record<string, string> = {
  trial: "ניסיון",
  paid: "משלם",
  expired: "פג",
  canceled: "בוטל",
};

const TYPE_LABEL: Record<string, string> = {
  family: "משפחה",
  organization: "ארגון",
  individual: "יחיד",
};

function days(from: string | null): number | null {
  if (from === null) return null;

  return Math.round((new Date(from).getTime() - Date.now()) / 86_400_000);
}

export function Customers(): JSX.Element {
  const [tenants, setTenants] = useState<Tenant[] | null>(null);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const r = await api.get<{ tenants: Tenant[]; summary: Summary }>(
        "/api/portal/v1/platform/tenants");

      setTenants(r.tenants);
      setSummary(r.summary);
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "טעינת הלקוחות נכשלה");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function setStatus(t: Tenant, status: "active" | "suspended") {
    setBusy(t.id);
    setError(null);
    setNote(null);

    try {
      const r = await api.post<{ note: string }>(
        `/api/portal/v1/platform/tenants/${t.id}/status`, { status });

      setNote(r.note);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "השינוי נכשל");
    } finally {
      setBusy(null);
    }
  }

  /*
   * סימון תשלום ידני.
   *
   * גבייה ידנית היא הדרך הנכונה לעשרות הלקוחות הראשונים: סליקה
   * עולה זמן וכסף קבוע, ולא תלמד דבר שאי אפשר ללמוד מעשרה לקוחות
   * ומהעברה בנקאית.
   *
   * שנה כברירת מחדל, כי זה מה שרוב הלקוחות ישלמו — וחודש הוא
   * לחיצה אחת נוספת ולא ברירת מחדל.
   */
  async function markPaid(t: Tenant, days: number) {
    setBusy(t.id);
    setError(null);
    setNote(null);

    try {
      const r = await api.post<{ note: string }>(
        `/api/portal/v1/platform/tenants/${t.id}/paid`, { days });

      setNote(r.note);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "הסימון נכשל");
    } finally {
      setBusy(null);
    }
  }

  /*
   * שינוי אופן ההסרה, דרך המוקד.
   *
   * ההורה בחר בהתקנה וטריגר במסד נועל את הבחירה. הטריגר מתיר
   * לפלטפורמה, וזה המסלול היחיד שדרכו אפשר לשנות — כלומר ההבטחה
   * "שינוי דרך המוקד" מקבלת כאן מימוש.
   *
   * מעבר להסרה עצמית צורך קרדיט, כי הוא מקל: ההורה מוותר על
   * החיכוך שהוא עצמו ביקש. חזרה למוקד חינם.
   */
  async function setUninstallPolicy(t: Tenant, policy: "self_service" | "support_only") {
    setBusy(t.id);
    setError(null);
    setNote(null);

    try {
      const r = await api.post<{ note: string }>(
        `/api/portal/v1/platform/tenants/${t.id}/uninstall-policy`, { policy });

      setNote(r.note);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "השינוי נכשל");
    } finally {
      setBusy(null);
    }
  }

  async function addCredit(t: Tenant) {
    setBusy(t.id);
    setError(null);
    setNote(null);

    try {
      const r = await api.post<{ note: string }>(
        `/api/portal/v1/platform/tenants/${t.id}/credit`, { amount: 5 });

      setNote(r.note);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "הטעינה נכשלה");
    } finally {
      setBusy(null);
    }
  }

  async function extendTrial(t: Tenant) {
    setBusy(t.id);
    setError(null);
    setNote(null);

    try {
      const r = await api.post<{ note: string }>(
        `/api/portal/v1/platform/tenants/${t.id}/trial`, { days: 14 });

      setNote(r.note);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "ההארכה נכשלה");
    } finally {
      setBusy(null);
    }
  }

  if (error !== null && tenants === null) return <p className="error">{error}</p>;
  if (tenants === null) return <p className="muted">טוען…</p>;

  return (
    <main className="shell">
      <h2>לקוחות</h2>

      {/*
        אותן אריחים כמו בלוח המחוונים, ולא מחלקות חדשות.

        מסך שנראה כמו חלק אחר של אותו מוצר אינו העדפה אסתטית: מי
        שלמד לקרוא צבע אחד במסך אחד קורא אותו נכון גם כאן, ומסך
        שממציא שפה משלו מלמד מחדש.
      */}
      {summary && (
        <div className="tiles">
          <div className="tile">
            <div className="n">{summary.tenants}</div>
            <div className="l">לקוחות</div>
          </div>

          <div className="tile">
            <div className="n">{summary.devices}</div>
            <div className="l">מחשבים</div>
          </div>

          <div className={summary.reporting > 0 ? "tile safe" : "tile"}>
            <div className="n">{summary.reporting}</div>
            <div className="l">מדווחים</div>
          </div>

          {/*
            שני סוגי שתיקה, ולא אחד. מחשב שדיווח והפסיק הוא מחשב
            שכובה או נותק; מחשב שמעולם לא דיווח הוא התקנה שלא עלתה.
            מספר אחד לשניהם אינו אומר במה לטפל.
          */}
          <div className={summary.silent > 0 ? "tile low" : "tile"}>
            <div className="n">{summary.silent}</div>
            <div className="l">שותקים</div>
          </div>

          <div className={summary.neverReported > 0 ? "tile low" : "tile"}>
            <div className="n">{summary.neverReported}</div>
            <div className="l">לא דיווחו מעולם</div>
          </div>

          <div className={summary.withoutReporting > 0 ? "tile bad" : "tile"}>
            <div className="n">{summary.withoutReporting}</div>
            <div className="l">לקוחות בלי כיסוי</div>
          </div>
        </div>
      )}

      {note  !== null && <p className="muted">{note}</p>}
      {error !== null && <p className="error">{error}</p>}

      <div className="panel">
        <div className="panel-head">
          <h3>{tenants.length} רשומים</h3>
        </div>

        <table className="rows">
          <thead>
            <tr>
              <th>לקוח</th>
              <th>סוג</th>
              <th>מנוי</th>
              <th>מחשבים</th>
              <th>כיסוי</th>
              <th>קרדיט</th>
              <th>פעילות אחרונה</th>
              <th>פעולות</th>
            </tr>
          </thead>

          <tbody>
            {tenants.map((t) => {
              const trialLeft = t.plan === "trial" ? days(t.trialEndsAt) : null;
              const suspended = t.status === "suspended";
              const uncovered = !suspended && t.devices > 0 && t.reporting === 0;

              return (
                <tr key={t.id} style={suspended ? { opacity: 0.55 } : undefined}>
                  <td>
                    <b>{t.name}</b>
                    {t.contactEmail && (
                      <div className="muted small" dir="ltr">{t.contactEmail}</div>
                    )}
                  </td>

                  <td>{TYPE_LABEL[t.type] ?? t.type}</td>

                  <td>
                    {PLAN_LABEL[t.plan] ?? t.plan}

                    {/*
                      הימים שנותרו, ובאדום כשהם נגמרו. תאריך לבדו
                      מחייב את הקורא לחשב, ובדיוק ברגע שבו הוא צריך
                      להחליט אם להאריך.
                    */}
                    {trialLeft !== null && (
                      <div className={trialLeft < 0 ? "error small" : "muted small"}>
                        {trialLeft < 0 ? `פג לפני ${-trialLeft} ימים` : `${trialLeft} ימים`}
                      </div>
                    )}

                    {suspended && <div className="error small">מושעה</div>}
                  </td>

                  <td style={{ fontVariantNumeric: "tabular-nums" }}>{t.devices}</td>

                  <td style={{ fontVariantNumeric: "tabular-nums" }}>
                    <span className={uncovered ? "error" : undefined}>
                      {t.reporting} / {t.devices}
                    </span>

                    {t.neverReported > 0 && (
                      <div className="muted small">{t.neverReported} לא דיווחו מעולם</div>
                    )}
                  </td>

                  {/*
                    קרדיט לשינויים, לא כסף.

                    הוא מכסה פעולות שדורשות אדם מהמוקד, כדי שטעות
                    קטנה לא תהפוך לשיחת טלפון משלמת.
                  */}
                  <td style={{ fontVariantNumeric: "tabular-nums" }}>
                    <span className={t.credit === 0 ? "muted" : undefined}>{t.credit}</span>
                  </td>

                  <td className="muted small">
                    {t.lastSeenAt
                      ? new Date(t.lastSeenAt).toLocaleString("he-IL")
                      : "מעולם"}
                  </td>

                  <td>
                    <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                      {t.plan === "trial" && (
                        <button
                          className="ghost"
                          disabled={busy === t.id}
                          onClick={() => void extendTrial(t)}
                        >
                          הארך ניסיון
                        </button>
                      )}

                      <button
                        className="ghost"
                        disabled={busy === t.id}
                        onClick={() => void markPaid(t, 365)}
                      >
                        שולם · שנה
                      </button>

                      <button
                        className="ghost"
                        disabled={busy === t.id}
                        onClick={() => void markPaid(t, 30)}
                      >
                        שולם · חודש
                      </button>

                      <button
                        className="ghost"
                        disabled={busy === t.id}
                        onClick={() => void addCredit(t)}
                      >
                        ‎+5 קרדיט
                      </button>

                      {/*
                        אופן ההסרה, עם המצב הנוכחי בכפתור.

                        "שנה אופן הסרה" בלי לומר לְמה היה מחייב את
                        המוקד לזכור מה המצב, ובשיחה זה בדיוק מה
                        שנשכח.
                      */}
                      <button
                        className="ghost"
                        disabled={busy === t.id}
                        onClick={() => void setUninstallPolicy(
                          t,
                          t.uninstallPolicy === "self_service" ? "support_only" : "self_service",
                        )}
                      >
                        {t.uninstallPolicy === "self_service"
                          ? "הסרה → מוקד"
                          : "הסרה → עצמית"}
                      </button>

                      {suspended ? (
                        <button
                          className="ghost"
                          disabled={busy === t.id}
                          onClick={() => void setStatus(t, "active")}
                        >
                          החזר לפעולה
                        </button>
                      ) : (
                        <button
                          className="danger"
                          disabled={busy === t.id}
                          onClick={() => void setStatus(t, "suspended")}
                        >
                          השעה
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/*
        מה שהשעיה עושה, ומה שאינה עושה.

        בלי המשפט הזה מי שמשעה לקוח שלא שילם יניח שהפסיק להגן עליו,
        וזה לא נכון — וגם לא רצוי. שרת שיכול לפרק הגנה מרחוק הופך
        פריצה אליו לכיבוי כל הצי בבת אחת.
      */}
      <p className="muted small">
        השעיה חוסמת כניסה לפורטל ורישום מחשבים חדשים. מחשבים שכבר מוגנים ממשיכים
        לאכוף לפי המדיניות שיש להם — השרת אינו מפרק הגנה מרחוק, בכוונה.
      </p>
    </main>
  );
}
