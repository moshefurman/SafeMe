import { useCallback, useEffect, useState } from "react";

import { api, ApiError } from "../api";

/**
 * המחירון, למנהל הפלטפורמה.
 *
 * המחירים יושבים במסד ולא בקוד, כי שינוי מחיר הוא החלטה עסקית
 * ופריסה חדשה לכל שינוי היא מתכון לטעות ברגע לחוץ.
 *
 * מה שהמסך אומר במפורש: שההנחה השנתית מחושבת ואינה נקבעת. מנהל
 * שמקליד "20% הנחה" מצפה שמשהו יקרה, ומסך שמראה לו את האחוז
 * שנגזר מהסכומים מלמד אותו איך זה באמת עובד.
 */

interface Plan {
  id: string;
  code: string;
  name: string;
  deviceLimit: number;
  monthly: number;
  yearly: number;
  yearlyDiscountPercent: number;
  active: boolean;
  priceMissing: boolean;
}

const shekel = (n: number): string =>
  n.toLocaleString("he-IL", { style: "currency", currency: "ILS", maximumFractionDigits: 2 });

export function Plans(): JSX.Element {
  const [plans, setPlans] = useState<Plan[] | null>(null);
  const [draft, setDraft] = useState<Plan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const r = await api.get<{ plans: Plan[] }>("/api/portal/v1/plans");

      setPlans(r.plans);
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "טעינת המחירון נכשלה");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function save() {
    if (draft === null) return;

    setBusy(true);
    setError(null);
    setNote(null);

    try {
      await api.put(`/api/portal/v1/plans/${draft.id}`, {
        name: draft.name,
        deviceLimit: draft.deviceLimit,
        monthly: draft.monthly,
        yearly: draft.yearly,
        active: draft.active,
      });

      setNote("המחירון עודכן. מנויים קיימים ממשיכים במחיר שבו נמכרו.");
      setDraft(null);

      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "השמירה נכשלה");
    } finally {
      setBusy(false);
    }
  }

  if (plans === null) return <main className="shell"><p className="muted">טוען…</p></main>;

  /*
   * ההנחה מחושבת גם בטיוטה, ולא רק במה ששמור.
   *
   * מנהל שמקליד מחיר שנתי צריך לראות מיד מה הוא הבטיח. חישוב
   * שמתעדכן רק אחרי שמירה הופך כל התאמה לניחוש.
   */
  const draftDiscount = draft === null || draft.monthly <= 0
    ? 0
    : Math.max(0, Math.round(((draft.monthly * 12 - draft.yearly) / (draft.monthly * 12)) * 100));

  return (
    <main className="shell">
      <h2>מחירון</h2>

      {note !== null && <p className="muted">{note}</p>}
      {error !== null && <p className="error">{error}</p>}

      <div className="panel">
        <div className="panel-head">
          <h3>{plans.length} תוכניות</h3>
        </div>

        <table className="rows">
          <thead>
            <tr>
              <th>תוכנית</th>
              <th>מחשבים</th>
              <th>חודשי</th>
              <th>שנתי</th>
              <th>הנחה</th>
              <th>מצב</th>
              <th />
            </tr>
          </thead>

          <tbody>
            {plans.map((p) => (
              <tr key={p.id}>
                <td>
                  <b>{p.name}</b>
                  <div className="muted small" dir="ltr">{p.code}</div>
                </td>

                <td style={{ fontVariantNumeric: "tabular-nums" }}>{p.deviceLimit}</td>

                {/*
                  מחיר אפס מוצג כחסר ולא כ"חינם".

                  התוכנית נזרעת כך בכוונה, כדי לאלץ החלטה. מסך
                  שמציג ‎₪0.00 נראה כמו מוצר חינמי, וזה בדיוק
                  הבלבול שאנחנו רוצים למנוע.
                */}
                <td>{p.priceMissing ? <span className="error">לא נקבע</span> : shekel(p.monthly)}</td>
                <td>{p.priceMissing ? <span className="error">לא נקבע</span> : shekel(p.yearly)}</td>

                <td>
                  {p.yearlyDiscountPercent > 0
                    ? <span className="tag">{p.yearlyDiscountPercent}%</span>
                    : <span className="muted small">—</span>}
                </td>

                <td>
                  {p.active
                    ? <span className="tag">פעילה</span>
                    : <span className="muted small">כבויה</span>}
                </td>

                <td>
                  <button className="ghost" onClick={() => setDraft({ ...p })}>עריכה</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {draft !== null && (
        <div className="panel">
          <div className="panel-head">
            <h3>{draft.name}</h3>
          </div>

          <div className="panel-body">
            <label className="field">
              שם התוכנית
              <input
                value={draft.name}
                onChange={(e) => setDraft({ ...draft, name: e.target.value })}
              />
            </label>

            <label className="field">
              מספר מחשבים
              <input
                type="number"
                min={1}
                value={draft.deviceLimit}
                onChange={(e) => setDraft({ ...draft, deviceLimit: Number(e.target.value) })}
                dir="ltr"
              />
            </label>

            <label className="field">
              מחיר חודשי בשקלים, כולל מע״מ
              <input
                type="number"
                min={0}
                step="0.01"
                value={draft.monthly}
                onChange={(e) => setDraft({ ...draft, monthly: Number(e.target.value) })}
                dir="ltr"
              />
            </label>

            <label className="field">
              מחיר שנתי בשקלים, כולל מע״מ
              <input
                type="number"
                min={0}
                step="0.01"
                value={draft.yearly}
                onChange={(e) => setDraft({ ...draft, yearly: Number(e.target.value) })}
                dir="ltr"
              />
            </label>

            {/*
              ההנחה נגזרת, ולא נקבעת.

              נאמר במפורש כדי שמנהל לא יחפש שדה אחוזים שאינו קיים,
              ויבין שכדי לשנות הנחה משנים את המחיר השנתי.
            */}
            <p className="muted small">
              {draft.monthly > 0 && draft.yearly > 0 ? (
                <>
                  שנה מלאה בתשלום חודשי: {shekel(draft.monthly * 12)}. המחיר השנתי חוסך{" "}
                  {shekel(Math.max(0, draft.monthly * 12 - draft.yearly))} — {draftDiscount}%.
                </>
              ) : (
                "ההנחה השנתית מחושבת מהמחירים ואינה נקבעת ישירות."
              )}
            </p>

            <label className="field" style={{ flexDirection: "row", gap: 8, alignItems: "center" }}>
              <input
                type="checkbox"
                checked={draft.active}
                onChange={(e) => setDraft({ ...draft, active: e.target.checked })}
              />
              פעילה — מוצגת ללקוחות וניתנת לרכישה
            </label>

            <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
              <button className="primary" disabled={busy} onClick={() => void save()}>
                {busy ? "שומר…" : "שמירה"}
              </button>

              <button className="ghost" disabled={busy} onClick={() => setDraft(null)}>
                ביטול
              </button>
            </div>

            <p className="muted small">
              שינוי מחיר חל על רכישות חדשות בלבד. מנוי קיים ממשיך במחיר שבו נמכר.
            </p>
          </div>
        </div>
      )}
    </main>
  );
}
