import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api";

interface Schedule {
  id: string;
  days: number[];
  from: string;
  to: string;
  label: string | null;
  enabled: boolean;
  description: string;
}

const HOURS = Array.from({ length: 24 }, (_, h) => String(h).padStart(2, "0"));
const MINUTES = Array.from({ length: 12 }, (_, m) => String(m * 5).padStart(2, "0"));

const DAYS = [
  { value: 0, short: "א" },
  { value: 1, short: "ב" },
  { value: 2, short: "ג" },
  { value: 3, short: "ד" },
  { value: 4, short: "ה" },
  { value: 5, short: "ו" },
  { value: 6, short: "ש" },
];

export function GroupSchedules({ groupId }: { groupId: string }): JSX.Element {
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
        `/api/portal/v1/groups/${groupId}/schedules`);
      setRows(r.schedules);
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "טעינת שעות החסימה נכשלה");
    }
  }, [groupId]);

  useEffect(() => void load(), [load]);

  const add = useCallback(async () => {
    setBusy(true);
    setError(null);
    setNote(null);

    try {
      const r = await api.post<{ note: string }>(
        `/api/portal/v1/groups/${groupId}/schedules`,
        { from, to, days },
      );
      setNote(r.note);
      setDays([]);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "ההוספה נכשלה");
    } finally {
      setBusy(false);
    }
  }, [groupId, from, to, days, load]);

  const remove = useCallback(async (id: string) => {
    setBusy(true);
    setError(null);

    try {
      await api.del(`/api/portal/v1/groups/${groupId}/schedules/${id}`);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "ההסרה נכשלה");
    } finally {
      setBusy(false);
    }
  }, [groupId, load]);

  if (rows === null && error === null) return <p className="muted">טוען…</p>;

  const crossesMidnight = from > to;

  return (
    <div className="panel-body">
      {error !== null && <p className="error">{error}</p>}
      {note !== null && <p className="ok">{note}</p>}

      <p className="muted small">
        שעות חסימה ברמת קבוצה. מחשב שמוגדרות לו שעות אישיות — רק ההגדרה
        האישית חלה. מחשב בלי הגדרה אישית — יקבל את שעות הקבוצה.
      </p>

      {rows !== null && rows.length === 0 ? (
        <p className="muted small">לא הוגדרו שעות חסימה לקבוצה.</p>
      ) : (
        <table className="rows">
          <tbody>
            {(rows ?? []).map((row) => (
              <tr key={row.id}>
                <td>{row.description}</td>
                <td style={{ textAlign: "left" }}>
                  <button className="ghost" disabled={busy} onClick={() => void remove(row.id)}>
                    הסר
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div style={{ display: "flex", gap: 10, alignItems: "flex-end", flexWrap: "wrap" }}>
        <TimePick label="מהשעה" value={from} onChange={setFrom} disabled={busy} />
        <TimePick label="עד השעה" value={to} onChange={setTo} disabled={busy} />
        <button disabled={busy || from === to} onClick={() => void add()}>הוסף</button>
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
                setDays(on ? days.filter((d) => d !== day.value) : [...days, day.value].sort())}
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
          החסימה נמשכת אל תוך הלילה: מ-{from} עד {to} למחרת בבוקר.
        </p>
      )}

      {from === to && (
        <p className="warn-text">שעת ההתחלה והסיום זהות, ולכן לא ייחסם דבר.</p>
      )}
    </div>
  );
}

function TimePick({
  label, value, onChange, disabled,
}: {
  label: string; value: string; onChange: (next: string) => void; disabled: boolean;
}): JSX.Element {
  const [hour, minute] = value.split(":");

  return (
    <div className="time-pick">
      <span className="time-pick-label">{label}</span>
      <span className="time-pick-fields" dir="ltr">
        <span className="time-pick-field">
          <select value={hour} disabled={disabled} onChange={(e) => onChange(`${e.target.value}:${minute}`)}>
            {HOURS.map((h) => <option key={h} value={h}>{h}</option>)}
          </select>
          <small>שעה</small>
        </span>
        <span className="time-pick-colon">:</span>
        <span className="time-pick-field">
          <select value={minute} disabled={disabled} onChange={(e) => onChange(`${hour}:${e.target.value}`)}>
            {MINUTES.map((m) => <option key={m} value={m}>{m}</option>)}
          </select>
          <small>דקות</small>
        </span>
      </span>
    </div>
  );
}
