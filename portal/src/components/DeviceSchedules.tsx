import { useCallback, useEffect, useState } from "react";

import { api, ApiError } from "../api";
import { ScheduleForm } from "./ScheduleForm";

/**
 * זמני גלישה: חלונות זמן שבהם הגלישה חסומה, למחשב או לקבוצה.
 *
 * החלון נשמר בשעון המקומי של המחשב ולא ב-UTC: מי שאומר "אין
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

function Schedules({ base, group }: { base: string; group: boolean }): JSX.Element {
  const [rows, setRows] = useState<Schedule[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const r = await api.get<{ schedules: Schedule[] }>(base);

      setRows(r.schedules);
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "טעינת שעות החסימה נכשלה");
    }
  }, [base]);

  useEffect(() => {
    setRows(null);
    setNote(null);
    void load();
  }, [load]);

  const add = useCallback(async (window: { from: string; to: string; days: number[] }) => {
    setBusy(true);
    setError(null);
    setNote(null);

    try {
      const r = await api.post<{ note: string }>(base, window);

      setNote(r.note);
      await load();

      return true;
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "ההוספה נכשלה");

      return false;
    } finally {
      setBusy(false);
    }
  }, [base, load]);

  const remove = useCallback(async (id: string) => {
    setBusy(true);
    setError(null);

    try {
      await api.del(`${base}/${id}`);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "ההסרה נכשלה");
    } finally {
      setBusy(false);
    }
  }, [base, load]);

  if (rows === null && error === null) return <p className="muted panel-body">טוען…</p>;

  return (
    <div className="panel-body">
      {error !== null && <p className="error">{error}</p>}
      {note !== null && <p className="ok">{note}</p>}

      <p className="muted small">
        {group
          ? "בשעות האלה מחשבי הקבוצה לא יוכלו לגלוש. מחשב שהוגדרו לו שעות משלו פועל לפי השעות שלו, ולא לפי הקבוצה."
          : "בשעות האלה המחשב לא יוכל לגלוש. בשאר הזמן הגלישה פתוחה. הזמן הוא לפי השעון של המחשב עצמו."}
      </p>

      {rows !== null && rows.length === 0 ? (
        <p className="state-line">
          <b>אין שעות חסימה.</b>{" "}
          {group ? "מחשבי הקבוצה יכולים לגלוש בכל שעה." : "המחשב יכול לגלוש בכל שעה."}
        </p>
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

      <ScheduleForm busy={busy} onAdd={add} />
    </div>
  );
}

export function DeviceSchedules({ deviceId }: { deviceId: string }): JSX.Element {
  return <Schedules base={`/api/portal/v1/devices/${deviceId}/schedules`} group={false} />;
}

export function GroupSchedules({ groupId }: { groupId: string }): JSX.Element {
  return <Schedules base={`/api/portal/v1/groups/${groupId}/schedules`} group />;
}
