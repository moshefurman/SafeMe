import { useCallback, useEffect, useState } from "react";

import { api, ApiError } from "../api";

/**
 * יומני אבחון מהמחשב.
 *
 * כשמשהו נשבר אצל לקוח אין דרך לדעת מה קרה: יומן האירועים יושב על
 * המחשב שלו, הוא לא יידע לפתוח אותו, ואיש מאיתנו לא יהיה שם. כל
 * אבחון עד היום דרש גישה למכונה, ובשדה לא תהיה כזו.
 *
 * שני דברים שהמסך אומר במפורש, כי הם לא מובנים מאליהם:
 *
 *   שהיומן מגיע בפעימה ולא מיד — מחשב כבוי פשוט יענה כשיחזור,
 *   ובלי המשפט הזה מי שלוחץ ולא רואה כלום יחשוב שזה שבור.
 *
 *   מה נאסף. יומן מהמחשב של מישהו אחר אינו דבר שמבקשים בשקט.
 */

interface LogEntry {
  id: string;
  agent_version: string | null;
  byte_length: number;
  collected_at: string;
  received_at: string;
  expires_at: string;
}

export function DeviceLogs({ deviceId }: { deviceId: string }): JSX.Element {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const r = await api.get<{ logs: LogEntry[] }>(
        `/api/portal/v1/devices/${deviceId}/logs`);

      setLogs(r.logs);
    } catch (e) {
      /*
       * כשל בטעינה נאמר, ולא נבלע.
       *
       * הגרסה הראשונה החזירה רשימה ריקה בשקט, ואז "טרם התקבלו
       * יומנים" נראה זהה ל"אין הרשאה לקרוא את הטבלה" — וזה בדיוק
       * ההבדל שחיפשנו כשהשליחה נכשלה ואיש לא ידע למה.
       */
      setLogs([]);
      setError(e instanceof ApiError ? e.message : "טעינת רשימת היומנים נכשלה");
    }
  }, [deviceId]);

  useEffect(() => { void load(); }, [load]);

  async function request() {
    setBusy(true);
    setError(null);
    setNote(null);

    try {
      const r = await api.post<{ note: string }>(
        `/api/portal/v1/devices/${deviceId}/logs/request`);

      setNote(r.note);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "הבקשה נכשלה");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel" style={{ marginBottom: 16 }}>
      <div className="panel-head">
        <h2>יומן טכני לתמיכה</h2>
        <div className="spacer" />

        <button className="ghost" disabled={busy} onClick={() => void request()}>
          {busy ? "מבקש…" : "בקש יומן מהמחשב"}
        </button>
      </div>

      <div className="panel-body">
        <p className="muted small">
          קובץ טכני שהמחשב שולח לפי בקשה, כדי שהתמיכה תוכל לאבחן תקלה בלי גישה
          למחשב. אין בו צורך בשימוש רגיל.
        </p>

        <p className="muted small">
          הבקשה מגיעה למחשב בפעימה הבאה, בדרך כלל תוך שלוש דקות. מחשב כבוי או מנותק
          ישלח כשיחזור.
        </p>

        {/*
          מה נאסף ומה לא.

          יומן מהמחשב של מישהו אחר אינו דבר שמבקשים בשקט, וההורה
          רואה כאן בדיוק את אותה רשימה.
        */}
        <p className="muted small">
          נאספים: יומן האירועים של הסוכן ביממה האחרונה, מצב השירותים והגרסה, ויומני
          התקנה. לא נאספים תוכן גלישה, היסטוריה או קבצים. היומן נמחק אוטומטית אחרי
          שבועיים.
        </p>

        {note  !== null && <p className="muted">{note}</p>}
        {error !== null && <p className="error">{error}</p>}

        {logs.length === 0 ? (
          <p className="muted small">טרם התקבלו יומנים מהמחשב הזה.</p>
        ) : (
          <table className="rows">
            <thead>
              <tr>
                <th>נאסף</th>
                <th>גרסה</th>
                <th>גודל</th>
                <th>נמחק ב</th>
                <th />
              </tr>
            </thead>

            <tbody>
              {logs.map((l) => (
                <tr key={l.id}>
                  <td>{new Date(l.collected_at).toLocaleString("he-IL")}</td>
                  <td dir="ltr">{l.agent_version ?? "—"}</td>
                  <td style={{ fontVariantNumeric: "tabular-nums" }}>
                    {(l.byte_length / 1024).toFixed(0)} ק״ב
                  </td>
                  <td className="muted small">
                    {new Date(l.expires_at).toLocaleDateString("he-IL")}
                  </td>
                  <td>
                    {/*
                      קישור ולא קריאת fetch: הקובץ דחוס ונשלח עם
                      Content-Disposition, והדפדפן יודע לשמור אותו
                      בעצמו. משיכה לזיכרון רק כדי לשמור היא עבודה
                      מיותרת על קובץ שעלול להיות גדול.
                    */}
                    <a
                      className="link"
                      href={`/api/portal/v1/devices/${deviceId}/logs/${l.id}`}
                    >
                      הורדה
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
