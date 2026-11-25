import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api";

interface ApprovedDomain {
  id: string;
  domain: string;
  source: string;
  createdAt: string;
}

interface WhitelistView {
  enabled: boolean;
  domains: ApprovedDomain[];
  systemDomains: string[];
  maxDomains: number;
}

interface AddResult {
  input: string;
  domain: string;
  ok: boolean;
  reason?: string;
  already?: boolean;
}

interface AddResponse {
  added: number;
  results: AddResult[];
  note?: string;
}

function splitInput(text: string): string[] {
  return text.split(/[\s,;]+/).map((s) => s.trim()).filter((s) => s !== "");
}

export function GroupWhitelist({ groupId }: { groupId: string }): JSX.Element {
  const base = `/api/portal/v1/groups/${groupId}/whitelist`;

  const [view, setView] = useState<WhitelistView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [draft, setDraft] = useState("");
  const [rejected, setRejected] = useState<AddResult[]>([]);

  const load = useCallback(async () => {
    try {
      const r = await api.get<WhitelistView>(base);
      setView(r);
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "טעינת הרשימה הלבנה נכשלה");
    }
  }, [base]);

  useEffect(() => void load(), [load]);

  const run = useCallback(async (action: () => Promise<string | null | undefined>, failure: string) => {
    setBusy(true);
    setError(null);
    setNote(null);

    try {
      const message = await action();
      if (message) setNote(message);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : failure);
    } finally {
      setBusy(false);
    }
  }, [load]);

  const setEnabled = (enabled: boolean) =>
    void run(async () => (await api.post<{ note: string }>(base, { enabled })).note, "השינוי נכשל");

  const addManual = () => {
    const domains = splitInput(draft);
    if (domains.length === 0) return;

    void run(async () => {
      const r = await api.post<AddResponse>(`${base}/domains`, { domains });
      const refused = r.results.filter((x) => !x.ok);
      setRejected(refused);
      setDraft(refused.map((x) => x.input).join("\n"));
      if (r.added === 0) return refused.length === 0 ? "האתרים האלה כבר ברשימה." : null;
      return `${r.added === 1 ? "אתר אחד נוסף" : `${r.added} אתרים נוספו`}. ${r.note ?? ""}`;
    }, "ההוספה נכשלה");
  };

  const removeDomain = (id: string) =>
    void run(async () => (await api.del<{ note: string }>(`${base}/domains/${id}`)).note, "ההסרה נכשלה");

  if (view === null && error === null) return <p className="muted panel-body">טוען…</p>;

  if (view === null) {
    return <div className="panel-body"><p className="error">{error}</p></div>;
  }

  const draftCount = splitInput(draft).length;

  return (
    <div className="panel-body wl">
      {error !== null && <p className="error">{error}</p>}
      {note !== null && <p className="ok-note">{note}</p>}

      <label className="eg-toggle wl-toggle">
        <input
          type="checkbox"
          checked={view.enabled}
          disabled={busy}
          onChange={(e) => setEnabled(e.target.checked)}
        />
        <span>
          <b>{view.enabled ? "פעילה: רק האתרים שברשימה נפתחים" : "כבויה"}</b>
          <span className="muted small">
            {view.enabled
              ? "מחשבים בקבוצה שאין להם רשימה לבנה אישית יקבלו את הרשימה הזו. מחשב עם רשימה אישית — רק הרשימה שלו חלה."
              : "הקבוצה אינה מגבילה את האתרים שמחשביה פותחים."}
          </span>
        </span>
      </label>

      {view.enabled && view.domains.length === 0 && (
        <p className="warn-text">
          הרשימה ריקה. מחשבים שמקבלים אותה לא יוכלו לגלוש כלל, חוץ מ-Filter+‎.
        </p>
      )}

      <section className="wl-section">
        <h3>
          אתרים מאושרים
          {view.domains.length > 0 && <span className="muted small"> · {view.domains.length}</span>}
        </h3>

        {view.domains.length === 0 ? (
          <p className="muted small">עוד לא אושרו אתרים.</p>
        ) : (
          <ul className="wl-list">
            {view.domains.map((d) => (
              <li key={d.id}>
                <span className="wl-domain" dir="ltr">{d.domain}</span>
                <button className="ghost" disabled={busy} onClick={() => removeDomain(d.id)}>הסר</button>
              </li>
            ))}
          </ul>
        )}

        <div className="wl-add">
          <textarea
            dir="ltr"
            rows={3}
            value={draft}
            disabled={busy}
            placeholder={"example.co.il\nhttps://www.kids-site.org/games"}
            onChange={(e) => setDraft(e.target.value)}
            aria-label="אתרים להוספה"
          />
          <div className="wl-actions">
            <button disabled={busy || draftCount === 0} onClick={addManual}>
              {draftCount > 1 ? `הוסף ${draftCount} אתרים` : "הוסף"}
            </button>
            <span className="muted small">
              אפשר להדביק כמה אתרים או קישורים, מופרדים ברווח, בפסיק או בשורה חדשה.
            </span>
          </div>
        </div>

        {rejected.length > 0 && (
          <ul className="wl-rejected" role="status">
            {rejected.map((r) => (
              <li key={`${r.input}|${r.domain}`}>
                <span className="wl-domain" dir="ltr">{r.domain || r.input}</span>
                <span>{r.reason ?? "אתר זה אינו ניתן לאישור"}</span>
              </li>
            ))}
          </ul>
        )}

        <p className="muted small">
          למידה אינה זמינה ברמת הקבוצה — ההתנהגות של כל מחשב שונה. להוספת אתרים דרך למידה,
          היכנסו למסך של המחשב הספציפי.
        </p>
      </section>

      {view.systemDomains.length > 0 && (
        <p className="muted small">
          תמיד פתוחים, גם ברשימה ריקה:{" "}
          <span dir="ltr">{view.systemDomains.join(", ")}</span>
        </p>
      )}
    </div>
  );
}
