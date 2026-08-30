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

/*
 * שעון 24 שעות, מובטח.
 *
 * input type="time" מציג AM/PM לפי שפת הדפדפן ומתעלם מ-lang של הדף.
 * מי שהדפדפן שלו באנגלית היה רואה 10:00 PM גם במסך עברי, ואין דרך
 * לכפות עליו אחרת. בוררים פותרים את זה לגמרי, והם גם נוחים יותר
 * במגע ובקריאה מימין לשמאל.
 */
const HOURS = Array.from({ length: 24 }, (_, h) => String(h).padStart(2, "0"));

// חמש דקות. שעת שינה אינה נקבעת ברזולוציית דקה, ושישים אפשרויות
// בבורר הן רשימה שצריך לגלול בה.
const MINUTES = Array.from({ length: 12 }, (_, m) => String(m * 5).padStart(2, "0"));

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
      setError(e instanceof ApiError ? e.message : "טעינת שעות החסימה נכשלה");
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
      setError(e instanceof ApiError ? e.message : "ההוספה נכשלה");
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

  // חסימה שנמשכת אל תוך הלילה. נאמר במפורש, כי "22:00 עד 07:00"
  // נקרא כטווח ריק.
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
        <p className="muted small">לא הוגדרו שעות חסימה. המחשב יכול לגלוש תמיד.</p>
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
        <TimePick label="מהשעה" value={from} onChange={setFrom} disabled={busy} />
        <TimePick label="עד השעה" value={to} onChange={setTo} disabled={busy} />

        <button disabled={busy || from === to} onClick={() => void add()}>
          הוסף
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
          החסימה נמשכת אל תוך הלילה: מ-{from} עד {to} למחרת בבוקר.
        </p>
      )}

      {from === to && (
        <p className="warn-text">
          שעת ההתחלה והסיום זהות, ולכן לא ייחסם דבר.
        </p>
      )}
    </div>
  );
}

/**
 * בורר שעה ודקה, תמיד בשעון 24.
 *
 * מפוצל לשני בוררים ולא לשדה אחד, כי הקלדת "22:00" בשדה חופשי
 * מזמינה כל צורת קלט אפשרית — 22, 10 בערב, 22.00 — וכל אחת מהן
 * דורשת פענוח שיטעה. בורר יכול להחזיר רק ערך תקין.
 */
function TimePick({
  label,
  value,
  onChange,
  disabled,
}: {
  label: string;
  value: string;
  onChange: (next: string) => void;
  disabled: boolean;
}): JSX.Element {
  const [hour, minute] = value.split(":");

  return (
    <label>
      {label}
      <span style={{ display: "inline-flex", gap: 4, marginInlineStart: 8 }}>
        <select
          value={hour}
          disabled={disabled}
          onChange={(e) => onChange(`${e.target.value}:${minute}`)}
        >
          {HOURS.map((h) => <option key={h} value={h}>{h}</option>)}
        </select>

        <span style={{ alignSelf: "center" }}>:</span>

        <select
          value={minute}
          disabled={disabled}
          onChange={(e) => onChange(`${hour}:${e.target.value}`)}
        >
          {MINUTES.map((m) => <option key={m} value={m}>{m}</option>)}
        </select>
      </span>
    </label>
  );
}
