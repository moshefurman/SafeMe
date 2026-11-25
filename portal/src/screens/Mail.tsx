import { useCallback, useEffect, useState } from "react";

import { api, ApiError } from "../api";

/**
 * הדואר היוצא.
 *
 * המסך קיים כדי לענות על שאלה שלא הייתה לה תשובה: האם ההתראות בכלל
 * נשלחות. עד כאן הדרך היחידה לדעת הייתה לחכות שהתראה אמיתית לא
 * תגיע — כלומר לגלות ברגע היקר ביותר.
 */

interface MailState {
  provider: "none" | "console" | "resend";
  fromAddress: string | null;
  replyTo: string | null;
  supportEmail: string | null;
  hasApiKey: boolean;
  lastOkAt: string | null;
  lastErrorAt: string | null;
  lastError: string | null;
}

const PROVIDERS: Array<{ value: MailState["provider"]; label: string; hint: string }> = [
  { value: "none", label: "כבוי", hint: "שום הודעה אינה נשלחת" },
  { value: "console", label: "יומן בלבד", hint: "ההודעות נכתבות ליומן השרת. לפיתוח" },
  { value: "resend", label: "Resend", hint: "שליחה אמיתית" },
];

function when(iso: string | null): string {
  return iso === null ? "מעולם" : new Date(iso).toLocaleString("he-IL");
}

export function Mail(): JSX.Element {
  const [state, setState] = useState<MailState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [testTo, setTestTo] = useState("");

  const [provider, setProvider] = useState<MailState["provider"]>("none");
  const [from, setFrom] = useState("");
  const [replyTo, setReplyTo] = useState("");
  const [support, setSupport] = useState("");

  const load = useCallback(async () => {
    try {
      const r = await api.get<MailState>("/api/portal/v1/mail");

      setState(r);
      setProvider(r.provider);
      setFrom(r.fromAddress ?? "");
      setReplyTo(r.replyTo ?? "");
      setSupport(r.supportEmail ?? "");
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "טעינת הגדרות הדואר נכשלה");
    }
  }, []);

  useEffect(() => void load(), [load]);

  if (error !== null && state === null) return <p className="error">{error}</p>;
  if (state === null) return <p className="muted">טוען…</p>;

  const healthy = state.provider !== "none"
    && state.lastOkAt !== null
    && (state.lastErrorAt === null || state.lastOkAt > state.lastErrorAt);

  return (
    <>
      <h1>דואר יוצא</h1>

      {error !== null && <p className="error">{error}</p>}
      {note !== null && <p className="ok">{note}</p>}

      <section className="panel">
        <div className="panel-head">
          <h2>מצב</h2>
          <span className={healthy ? "pill ok" : "pill warn"}>
            {state.provider === "none" ? "כבוי" : healthy ? "שולח" : "לא אומת"}
          </span>
        </div>

        <div className="panel-body">
          {state.provider === "none" && (
            <p className="warn-text">
              הדואר כבוי. כל ההתראות נבלעות בשקט — כולל קישור העצירה
              שמגן על כתובת ההתראות.
            </p>
          )}

          <table className="rows">
            <tbody>
              <tr>
                <td>שליחה אחרונה שהצליחה</td>
                <td>{when(state.lastOkAt)}</td>
              </tr>
              <tr>
                <td>כישלון אחרון</td>
                <td>{when(state.lastErrorAt)}</td>
              </tr>
              {state.lastError !== null && (
                <tr>
                  <td>מה נאמר</td>
                  <td className="mono small">{state.lastError}</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel" style={{ marginTop: 16 }}>
        <div className="panel-head">
          <h2>הגדרות</h2>
        </div>

        <div className="panel-body">
          <label>
            ספק
            <select
              value={provider}
              disabled={busy}
              onChange={(e) => setProvider(e.target.value as MailState["provider"])}
            >
              {PROVIDERS.map((p) => (
                <option key={p.value} value={p.value}>{p.label}</option>
              ))}
            </select>
          </label>

          <p className="muted small">
            {PROVIDERS.find((p) => p.value === provider)?.hint}
          </p>

          {provider === "resend" && (
            <p className={state.hasApiKey ? "muted small" : "warn-text"}>
              {state.hasApiKey
                ? "מפתח ה-API מוגדר בסביבת השרת."
                : "חסר RESEND_API_KEY בסביבת השרת. בלעדיו לא תישלח שום הודעה."}
            </p>
          )}

          <label style={{ width: "100%" }}>
            כתובת שולח
            <input
              value={from}
              disabled={busy}
              placeholder="Filter+‎ <alerts@filterplus.co.il>"
              onChange={(e) => setFrom(e.target.value)}
            />
          </label>

          <label style={{ width: "100%" }}>
            כתובת מענה (לא חובה)
            <input
              value={replyTo}
              disabled={busy}
              onChange={(e) => setReplyTo(e.target.value)}
            />
          </label>

          <label style={{ width: "100%" }}>
            כתובת לפניות (מוצגת למשתמשים)
            <input
              value={support}
              disabled={busy}
              onChange={(e) => setSupport(e.target.value)}
              dir="ltr"
            />
          </label>

          {/*
            שונה מכתובת מענה, ולכן שדה נפרד.

            "מענה" הוא לאן חוזרת תשובה על הודעה שיצאה. "פניות" היא
            מה שמוצג בפורטל למי שנתקע — הורה שההסרה שלו דרך המוקד,
            או חשבון מושעה. לרוב זו אותה כתובת, ולא תמיד.

            ריק פירושו שלא יוצג דבר. "פנו לתמיכה" בלי יעד גרוע
            מכלום — הוא נראה כמו מוצא ואינו כזה.
          */}
          <p className="muted small">
            כתובת המענה היא לאן חוזרת תשובה על הודעה שנשלחה. כתובת הפניות מוצגת
            בפורטל למי שצריך עזרה — למשל מי שההסרה אצלו עוברת דרך המוקד. אם היא ריקה,
            לא יוצג דבר.
          </p>

          <p className="muted small">
            מפתח ה-API אינו נערך כאן. הוא נשמר בסביבת השרת בלבד, כדי
            שלא יעבור דרך הדפדפן, יומני השרת והגיבויים.
          </p>

          <button
            disabled={busy}
            onClick={() => {
              void (async () => {
                setBusy(true);
                setError(null);
                setNote(null);

                try {
                  await api.put("/api/portal/v1/mail", {
                    provider,
                    fromAddress: from.trim() === "" ? null : from.trim(),
                    replyTo: replyTo.trim() === "" ? null : replyTo.trim(),
                    supportEmail: support.trim() === "" ? null : support.trim(),
                  });

                  setNote("נשמר.");
                  await load();
                } catch (e) {
                  setError(e instanceof ApiError ? e.message : "השמירה נכשלה");
                } finally {
                  setBusy(false);
                }
              })();
            }}
          >
            שמור
          </button>
        </div>
      </section>

      <section className="panel" style={{ marginTop: 16 }}>
        <div className="panel-head">
          <h2>שליחת בדיקה</h2>
        </div>

        <div className="panel-body">
          <p className="muted small">
            הדרך היחידה לדעת שההגדרה נכונה בלי לחכות שהתראה אמיתית לא תגיע.
          </p>

          <div style={{ display: "flex", gap: 8 }}>
            <input
              type="email"
              placeholder="לאן לשלוח"
              value={testTo}
              disabled={busy}
              onChange={(e) => setTestTo(e.target.value)}
            />
            <button
              disabled={busy || testTo.trim() === ""}
              onClick={() => {
                void (async () => {
                  setBusy(true);
                  setError(null);
                  setNote(null);

                  try {
                    const r = await api.post<{ note: string }>(
                      "/api/portal/v1/mail/test",
                      { to: testTo.trim() },
                    );

                    setNote(r.note);
                  } catch (e) {
                    setError(e instanceof ApiError ? e.message : "השליחה נכשלה");
                  } finally {
                    await load();
                    setBusy(false);
                  }
                })();
              }}
            >
              שלח בדיקה
            </button>
          </div>
        </div>
      </section>
    </>
  );
}
