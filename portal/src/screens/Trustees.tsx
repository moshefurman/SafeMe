import { useCallback, useEffect, useState } from "react";

import { ApiError, api } from "../api";

/**
 * נאמן: אדם אחר מבעל החשבון, שמחזיק את המפתח.
 *
 * הנאמן אינו נכנס למרכז הניהול ואין לו סיסמה. הוא מקבל דוא"ל עם
 * קישור, ומאשר או דוחה. המסך הזה הוא הצד של בעל החשבון: מי
 * הנאמנים, מה התפקיד שלהם, ומה מחכה להם.
 *
 * מה שהמסך אומר במפורש, כי זה ההפך ממה שמצפים: להוסיף נאמן זה
 * מיידי, ולהסיר אותו לא. נאמן שאפשר להסיר בלחיצה אינו שומר על דבר.
 */

type Mode = "inform" | "approve";

interface Trustee {
  id: string;
  name: string;
  email: string;
  verified: boolean;
  removalEffectiveAt: string | null;
}

interface PendingRequest {
  id: string;
  summary: string;
  method: string;
  path: string;
  body: unknown;
  status: "pending" | "approved" | "denied" | "cancelled" | "executed";
  createdAt: string;
  decidedAt: string | null;
  decidedBy: string | null;
}

interface View {
  available: boolean;
  mode: Mode;
  max?: number;
  trustees: Trustee[];
  requests: PendingRequest[];
}

const STATUS: Record<PendingRequest["status"], { label: string; tone: string }> = {
  pending: { label: "ממתינה לנאמן", tone: "tag warn" },
  approved: { label: "אושרה, אפשר לבצע", tone: "tag ok" },
  denied: { label: "נדחתה", tone: "tag" },
  cancelled: { label: "בוטלה", tone: "tag" },
  executed: { label: "בוצעה", tone: "tag" },
};

const when = (iso: string): string =>
  new Date(iso).toLocaleString("he-IL", { dateStyle: "short", timeStyle: "short" });

export function Trustees(): JSX.Element {
  const [view, setView] = useState<View | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");

  const load = useCallback(async () => {
    try {
      setView(await api.get<View>("/api/portal/v1/trustees"));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "טעינת הנאמנים נכשלה");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  /** פעולה אחת, עם אותו טיפול בהודעה ובשגיאה. */
  async function run(action: () => Promise<{ note?: string; code?: string } | undefined>) {
    setBusy(true);
    setError(null);
    setNote(null);

    try {
      const r = await action();

      // קוד הסרה שהונפק אחרי אישור מוצג כאן, כי זה המקום שבו בוצע
      setNote(r?.code ? `קוד ההסרה: ${r.code}` : r?.note ?? "בוצע.");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "הפעולה נכשלה");
    } finally {
      setBusy(false);
      await load();
    }
  }

  /** ביצוע של פעולה שהנאמן כבר אישר: אותה בקשה בדיוק, שוב. */
  function execute(request: PendingRequest) {
    void run(() => {
      const method = request.method.toUpperCase();

      if (method === "DELETE") return api.del<{ note?: string }>(request.path);
      if (method === "PATCH") return api.patch<{ note?: string }>(request.path, request.body);
      if (method === "PUT") return api.put<{ note?: string }>(request.path, request.body);

      return api.post<{ note?: string; code?: string }>(request.path, request.body);
    });
  }

  if (view === null) {
    return error !== null ? <p className="error">{error}</p> : <p className="muted">טוען…</p>;
  }

  if (!view.available) {
    return (
      <div className="panel">
        <p className="panel-body muted">הגדרת נאמן עדיין אינה זמינה בחשבון הזה.</p>
      </div>
    );
  }

  const active = view.trustees.filter((t) => t.verified);
  const open = view.requests.filter((r) => r.status === "pending" || r.status === "approved");
  const past = view.requests.filter((r) => r.status !== "pending" && r.status !== "approved");
  const full = view.trustees.length >= (view.max ?? 3);

  return (
    <>
      {error !== null && <p className="error">{error}</p>}
      {note !== null && <p className="ok-note">{note}</p>}

      {/* ─────────────────────────────── מה זה נאמן */}

      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head">
          <h2>מי הנאמן, ומה התפקיד שלו</h2>
        </div>

        <div className="panel-body">
          <p className="muted small">
            נאמן הוא אדם שאתה סומך עליו, והוא לא אתה: בן זוג, חבר, רב, או מנהל. כשתרצה
            להקל על הסינון או להסיר את התוכנה, הוא יקבל על כך דוא"ל. הוא אינו צריך
            חשבון או סיסמה, רק ללחוץ על הקישור.
          </p>

          <p className="muted small">
            {active.length === 0
              ? "כרגע אין נאמן, ולכן מי שמחזיק בכניסה לחשבון הזה הוא גם מי שמאשר לעצמו. "
                + "במשפחה ובארגון זה בדרך כלל נכון: ההורה או מנהל המשרד הם הנאמן. "
                + "בחשבון אישי, שבו בעל החשבון הוא גם המשתמש, כדאי למנות נאמן."
              : `לחשבון ${active.length === 1 ? "נאמן אחד" : `${active.length} נאמנים`}. די שאחד מהם יאשר.`}
          </p>
        </div>
      </div>

      {/* ─────────────────────────────── בקשות פתוחות */}

      {open.length > 0 && (
        <div className="panel" style={{ marginBottom: 16 }}>
          <div className="panel-head">
            <h2>בקשות פתוחות</h2>
          </div>

          <ul className="settings-list">
            {open.map((r) => (
              <li key={r.id}>
                <div>
                  <b>{r.summary}</b>
                  <span>
                    <span className={STATUS[r.status].tone}>{STATUS[r.status].label}</span>
                    {" "}נשלחה {when(r.createdAt)}
                    {r.status === "approved" && r.decidedBy ? ` · אישר: ${r.decidedBy}` : ""}
                  </span>
                </div>

                {r.status === "approved" ? (
                  <button className="primary" disabled={busy} onClick={() => execute(r)}>
                    בצע עכשיו
                  </button>
                ) : (
                  <button
                    disabled={busy}
                    onClick={() => void run(() =>
                      api.post<{ note: string }>(`/api/portal/v1/trustees/requests/${r.id}/remind`))}
                  >
                    שלח תזכורת
                  </button>
                )}

                <button
                  className="ghost"
                  disabled={busy}
                  onClick={() => void run(() =>
                    api.post<{ note: string }>(`/api/portal/v1/trustees/requests/${r.id}/cancel`))}
                >
                  בטל
                </button>
              </li>
            ))}
          </ul>

          <p className="panel-body muted small" style={{ paddingTop: 0 }}>
            בקשה ממתינה עד שהנאמן עונה, בלי מועד אחרון. אישור תקף לפעולה הזו בלבד,
            ולפעם אחת.
          </p>
        </div>
      )}

      {/* ─────────────────────────────── הנאמנים */}

      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head">
          <h2>הנאמנים של החשבון</h2>
        </div>

        {view.trustees.length === 0 ? (
          <p className="panel-body muted small">עוד לא מונה נאמן.</p>
        ) : (
          <ul className="settings-list">
            {view.trustees.map((t) => (
              <li key={t.id}>
                <div>
                  <b>{t.name}</b>
                  <span>
                    <bdi dir="ltr">{t.email}</bdi>
                    {" · "}
                    {!t.verified
                      ? "הוזמן, ועוד לא אישר את התפקיד"
                      : t.removalEffectiveAt !== null
                        ? `בהסרה: תיכנס לתוקף ב-${when(t.removalEffectiveAt)}, אלא אם יעצור אותה`
                        : "נאמן פעיל"}
                  </span>
                </div>

                {t.verified && t.removalEffectiveAt !== null ? (
                  <button
                    disabled={busy}
                    onClick={() => void run(() =>
                      api.post<{ note: string }>(`/api/portal/v1/trustees/${t.id}/keep`))}
                  >
                    השאר אותו
                  </button>
                ) : (
                  <button
                    className="ghost"
                    disabled={busy}
                    onClick={() => {
                      if (t.verified && !window.confirm(
                        `לבקש להסיר את ${t.name}? ההסרה אינה מיידית: הוא יקבל הודעה, ואם לא יאשר היא תיכנס לתוקף בעוד 7 ימים.`)) {
                        return;
                      }

                      void run(() =>
                        api.post<{ note: string }>(`/api/portal/v1/trustees/${t.id}/remove`));
                    }}
                  >
                    {t.verified ? "הסר" : "בטל הזמנה"}
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}

        <div className="panel-body">
          {full ? (
            <p className="muted small">אפשר למנות עד {view.max ?? 3} נאמנים.</p>
          ) : (
            <>
              <b>מינוי נאמן</b>

              <div className="trustee-add">
                <label>
                  <span className="muted small">שם</span>
                  <input
                    type="text"
                    value={name}
                    maxLength={80}
                    disabled={busy}
                    onChange={(e) => setName(e.target.value)}
                  />
                </label>

                <label>
                  <span className="muted small">דוא"ל</span>
                  <input
                    type="email"
                    dir="ltr"
                    value={email}
                    maxLength={200}
                    disabled={busy}
                    onChange={(e) => setEmail(e.target.value)}
                  />
                </label>

                <button
                  className="primary"
                  disabled={busy || !name.trim() || !email.trim()}
                  onClick={() => void run(async () => {
                    const r = await api.post<{ note: string }>(
                      "/api/portal/v1/trustees", { name: name.trim(), email: email.trim() });

                    setName("");
                    setEmail("");

                    return r;
                  })}
                >
                  שלח הזמנה
                </button>
              </div>

              <p className="muted small">
                הנאמן מקבל דוא"ל שמסביר את התפקיד, ונכנס לתפקיד רק אחרי שאישר. מינוי
                נאמן הוא מיידי. הסרה שלו אינה מיידית: הוא מאשר אותה, או שהיא נכנסת
                לתוקף אחרי 7 ימים שבהם הוא יכול לעצור אותה.
              </p>
            </>
          )}
        </div>
      </div>

      {/* ─────────────────────────────── מצב */}

      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head">
          <h2>מה הנאמן עושה</h2>
        </div>

        <div className="panel-body">
          <div className="setup-choices" role="radiogroup" aria-label="תפקיד הנאמן">
            <label className={view.mode === "approve" ? "on" : undefined}>
              <input
                type="radio"
                name="trustee-mode"
                checked={view.mode === "approve"}
                disabled={busy}
                onChange={() => void run(() =>
                  api.post<{ note: string }>("/api/portal/v1/trustees/mode", { mode: "approve" }))}
              />
              <span>
                <b>מאשר</b>
                <span>
                  הקלה בסינון והסרה של התוכנה לא מתבצעות בלי אישורו. החמרה נשארת
                  מיידית.
                </span>
              </span>
            </label>

            <label className={view.mode === "inform" ? "on" : undefined}>
              <input
                type="radio"
                name="trustee-mode"
                checked={view.mode === "inform"}
                disabled={busy}
                onChange={() => void run(() =>
                  api.post<{ note: string }>("/api/portal/v1/trustees/mode", { mode: "inform" }))}
              />
              <span>
                <b>רק מקבל הודעות</b>
                <span>כל הקלה מתבצעת מיד, והנאמן מקבל עליה הודעה בדוא"ל.</span>
              </span>
            </label>
          </div>

          <p className="muted small">
            {active.length === 0
              ? "הבחירה תיכנס לתוקף כשיהיה נאמן פעיל."
              : "מעבר מ\"מאשר\" ל\"רק מקבל הודעות\" הוא הקלה, ולכן הוא עצמו דורש את אישור הנאמן."}
          </p>

          <details className="dl-more">
            <summary>אילו פעולות נחשבות הקלה?</summary>

            <ul className="muted small" style={{ lineHeight: 1.7 }}>
              <li>הנפקת קוד הסרה לתוכנה, והסרת מחשב מהחשבון.</li>
              <li>כיבוי רשימה לבנה, הוספת אתר אליה, והפעלת למידה.</li>
              <li>מחיקת שעות חסימה, וביטול חסימת גלישה מיידית.</li>
              <li>אישור רשת, הקלה ביחס לרשתות חדשות, וביטול כלל ברשימה השחורה של הרשתות.</li>
              <li>כיבוי סינון יוטיוב או מנועי AI, התרת ערוצים, והסרת מילים חסומות.</li>
              <li>כיבוי חסימת ה-VPN ותוכנות העקיפה.</li>
              <li>הוצאת מחשב מקבוצה, ומחיקת קבוצה.</li>
            </ul>
          </details>
        </div>
      </div>

      {/* ─────────────────────────────── היסטוריה */}

      {past.length > 0 && (
        <div className="panel">
          <div className="panel-head">
            <h2>בקשות קודמות</h2>
          </div>

          <table>
            <tbody>
              {past.map((r) => (
                <tr key={r.id} style={{ cursor: "default" }}>
                  <td>{r.summary}</td>
                  <td><span className={STATUS[r.status].tone}>{STATUS[r.status].label}</span></td>
                  <td style={{ color: "var(--muted)", fontSize: 13 }}>
                    {when(r.decidedAt ?? r.createdAt)}
                    {r.decidedBy ? ` · ${r.decidedBy}` : ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
