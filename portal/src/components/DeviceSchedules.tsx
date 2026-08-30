import { useCallback, useEffect, useState } from "react";

import { api, ApiError } from "../api";

/**
 * חלונות זמן שבהם המחשב חסום.
 *
 * המנגנון קיים בסוכן מזמן, ומעולם לא היה אפשר להגדיר אותו. זה המסך
 * שסוגר את הפער.
 *
 * החלון נשמר בשעון המקומי של המחשב ולא ב-UTC: הורה שאומר "אין
 * אינטרנט אחרי עשר" מתכוון לעשר אצלו, ומחשב שנוסע לחו"ל צריך
 * להמשיך להיחסם בעשר המקומית שלו.
 */

interface Schedule {
  id: string;
  days: number[];
  from: string;
  to: string;
  label: string | null;
  enabled: boolean;
  description: string;
}

/** 0 ראשון עד 6 שבת — המספור של DayOfWeek, שהסוכן משווה מולו. */
const DAYS = [
  { value: 0, short: "א" },
  { value: 1, short: "ב" },
  { value: 2, short: "ג" },
  { value: 3, short: "ד" },
  { value: 4, short: "ה" },
  { value: 5, short: "ו" },
  { value: 6, short: "ש" },
];

export function DeviceSchedules({ deviceId }: { deviceId: string }): JSX.Element {
  const [rows, setRows] = useState<Schedule[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [from, setFrom] = useState("22:00");
  const [to, setTo] = useState("07:00");
  const [days, setDays] = useState<number[]>([]);

  const load = useCallback(async () => {
    try {
      const r = await api.get<{ schedules: Schedule[] }>(
        `/api/portal/v1/devices/${deviceId}/schedules`);

      setRows(r.schedules);
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "טעינת חלונות הזמן נכשלה");
    }
  }, [deviceId]);

  useEffect(() => void load(), [load]);

  const add = useCallback(async () => {
    setBusy(true);
    setError(null);
    setNote(null);

    try {
      const r = await api.post<{ note: string }>(
        `/api/portal/v1/devices/${deviceId}/schedules`,
        { from, to, days },
      );

      setNote(r.note);
      setDays([]);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "הוספת החלון נכשלה");
    } finally {
      setBusy(false);
    }
  }, [deviceId, from, to, days, load]);

  const remove = useCallback(async (id: string) => {
    setBusy(true);
    setError(null);

    try {
      await api.del(`/api/portal/v1/devices/${deviceId}/schedules/${id}`);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "ההסרה נכשלה");
    } finally {
      setBusy(false);
    }
  }, [deviceId, load]);

  if (rows === null && error === null) return <p className="muted">טוען…</p>;

  // חלון שחוצה חצות. נאמר במפורש, כי "22:00 עד 07:00" נקרא כטווח ריק.
  const crossesMidnight = from > to;

  return (
    <div className="panel-body">
      {error !== null && <p className="error">{error}</p>}
      {note !== null && <p className="ok">{note}</p>}

      <p className="muted small">
        בשעות האלה המחשב לא יוכל לגלוש. הזמן הוא לפי השעון של המחשב עצמו,
        ולכן הוא נשאר נכון גם בנסיעה לחו"ל.
      </p>

      {rows !== null && rows.length === 0 ? (
        <p className="muted small">אין חלונות. המחשב יכול לגלוש בכל שעה.</p>
      ) : (
        <table className="rows">
          <tbody>
            {(rows ?? []).map((row) => (
              <tr key={row.id}>
                <td>{row.description}</td>
                <td style={{ textAlign: "left" }}>
                  <button
                    className="ghost"
                    disabled={busy}
                    onClick={() => void remove(row.id)}
                  >
                    הסר
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div style={{ display: "flex", gap: 10, alignItems: "flex-end", flexWrap: "wrap" }}>
        <label>
          מ
          <input type="time" value={from} disabled={busy}
                 onChange={(e) => setFrom(e.target.value)} />
        </label>

        <label>
          עד
          <input type="time" value={to} disabled={busy}
                 onChange={(e) => setTo(e.target.value)} />
        </label>

        <button disabled={busy || from === to} onClick={() => void add()}>
          הוסף חלון
        </button>
      </div>

      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        {DAYS.map((day) => {
          const on = days.includes(day.value);

          return (
            <button
              key={day.value}
              className={on ? "day on" : "day"}
              disabled={busy}
              onClick={() =>
                setDays(on
                  ? days.filter((d) => d !== day.value)
                  : [...days, day.value].sort())}
            >
              {day.short}
            </button>
          );
        })}

        <span className="muted small" style={{ alignSelf: "center" }}>
          {days.length === 0 ? "כל ימות השבוע" : `${days.length} ימים`}
        </span>
      </div>

      {crossesMidnight && (
        <p className="muted small">
          החלון חוצה חצות: מ-{from} בלילה עד {to} למחרת בבוקר.
        </p>
      )}

      {from === to && (
        <p className="warn-text">
          שעת ההתחלה והסיום זהות, ולכן החלון לא יחסום דבר.
        </p>
      )}
    </div>
  );
}
