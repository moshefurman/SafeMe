import { useCallback, useEffect, useState } from "react";

import { api, ApiError } from "../api";

/**
 * הכרעות רשת למחשב הזה בלבד.
 *
 * ברירת המחדל היא שאישור רשת חל על כל החשבון — הורה שמאשר את הרשת
 * אצל סבתא מאשר אותה גם לילד השני. במשפחה אחת זה נוח; במשפחה
 * שרוצה כלל שונה לכל ילד, או בארגון, זה בדיוק ההפך.
 *
 * המסך הזה הוא החריג, ולכן הוא אומר במפורש מה גובר על מה. הורה
 * שרואה "מאושרת" ואינו יודע אם זה לחשבון או למחשב הזה יקבל הפתעה
 * בפעם הבאה — וזו בדיוק ההפתעה שהיכולת נועדה למנוע, לא ליצור.
 */

interface NetworkRow {
  id: string;
  ssid: string | null;
  approval: "pending" | "approved" | "blocked";
  device_id: string | null;
  device_name: string | null;
  device_machine: string | null;
}

const LABEL: Record<string, string> = {
  pending: "ממתינה",
  approved: "מאושרת",
  blocked: "חסומה",
};

export function DeviceNetworks({ deviceId }: { deviceId: string }): JSX.Element | null {
  const [rows, setRows] = useState<NetworkRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  /*
   * היכולת נבדקת דרך התשובה מהשרת ולא לפניה.
   *
   * שאילתה נפרדת ל"האם יש לי את היכולת" היא מקור שני לאותה אמת,
   * והשניים מתפצלים. כאן הכפתור קיים תמיד, והשרת אומר מה חסר —
   * וההודעה שלו מסבירה מה היכולת נותנת.
   */
  const [locked, setLocked] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const r = await api.get<{ networks: NetworkRow[] }>("/api/portal/v1/networks");

      setRows(r.networks);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "טעינת הרשתות נכשלה");
      setRows([]);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function decide(network: NetworkRow, approval: "approved" | "blocked") {
    setBusy(network.id);
    setError(null);
    setNote(null);
    setLocked(null);

    try {
      const r = await api.post<{ note: string }>(
        `/api/portal/v1/networks/${network.id}/decide-for-device`,
        { deviceId, approval });

      setNote(r.note);
      await load();
    } catch (e) {
      const message = e instanceof ApiError ? e.message : "הפעולה נכשלה";

      /*
       * חוסר ביכולת אינו שגיאה אדומה.
       *
       * הוא מצב תקין של חשבון שלא קנה תוספת, וצביעתו כתקלה שולחת
       * את ההורה לחפש משהו שבור.
       */
      if (e instanceof ApiError && e.status === 403) setLocked(message);
      else setError(message);
    } finally {
      setBusy(null);
    }
  }

  if (rows === null) return <p className="muted">טוען…</p>;

  /*
   * רק רשתות שיש עליהן מה להחליט.
   *
   * שורה של מחשב אחר אינה נוגעת למסך הזה, והצגתה הייתה מזמינה
   * לחיצה שמשנה משהו אצל מישהו אחר.
   */
  const relevant = rows.filter((n) => n.device_id === null || n.device_id === deviceId);

  if (relevant.length === 0) {
    return (
      <div className="panel">
        <p className="panel-body muted">
          עוד לא נרשמו רשתות. רשת מופיעה כאן אחרי שמחשב בחשבון התחבר אליה.
        </p>
      </div>
    );
  }

  return (
    <div className="panel" style={{ marginBottom: 16 }}>
      <div className="panel-head">
        <h2>רשתות למחשב הזה</h2>
      </div>

      <div className="panel-body">
        {locked !== null && (
          <p className="muted">{locked}</p>
        )}

        {note  !== null && <p className="muted">{note}</p>}
        {error !== null && <p className="error">{error}</p>}

        <table className="rows">
          <thead>
            <tr>
              <th>רשת</th>
              <th>מצב</th>
              <th>חל על</th>
              <th />
            </tr>
          </thead>

          <tbody>
            {relevant.map((n) => (
              <tr key={n.id}>
                <td>{n.ssid?.trim() || "רשת ללא שם"}</td>
                <td>{LABEL[n.approval] ?? n.approval}</td>

                <td className="muted small">
                  {n.device_id === null ? "כל החשבון" : "המחשב הזה"}
                </td>

                <td>
                  <div style={{ display: "flex", gap: 8 }}>
                    <button
                      className="ghost"
                      disabled={busy === n.id}
                      onClick={() => void decide(n, "approved")}
                    >
                      אשר כאן
                    </button>

                    <button
                      className="ghost"
                      disabled={busy === n.id}
                      onClick={() => void decide(n, "blocked")}
                    >
                      חסום כאן
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
