import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api";
import { AddDevice } from "../components/AddDevice";
import { StatusChip } from "../components/StatusChip";
import { deviceLabel } from "../fleet";
import { Groups } from "./Groups";
import {
  HEALTH_LABEL,
  relativeTime,
  type DeviceRow,
  type Summary,
} from "../types";

/**
 * המחשבים שלי.
 *
 * רשימת המחשבים היא הדבר הראשון במסך, לפני כל דבר אחר. מי שנכנס
 * בבוקר רוצה לראות את המחשבים שלו, ולא לגלול מעבר לטופס הוספה
 * ולשורת מספרים כדי להגיע אליהם.
 *
 * המיון בשרת מביא קודם את מה שדורש טיפול: לא מסונן, אחר כך חסום,
 * ורק אחר כך תקין.
 */
export function Dashboard({
  onOpenDevice,
  onOpenGroup,
}: {
  onOpenDevice: (id: string) => void;
  onOpenGroup: (id: string) => void;
}) {
  const [devices, setDevices] = useState<DeviceRow[] | null>(null);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    try {
      const [list, totals] = await Promise.all([
        api.get<{ devices: DeviceRow[] }>("/api/portal/v1/devices"),
        api.get<Summary>("/api/portal/v1/summary"),
      ]);

      setDevices(list.devices);
      setSummary(totals);
      setError(null);
    } catch {
      setError("טעינת הנתונים נכשלה");
    }
  }, []);

  useEffect(() => {
    void load();

    // רענון תקופתי. הפעימה מגיעה כל שלוש דקות, ולכן אין טעם בתדירות גבוהה.
    const timer = setInterval(() => void load(), 30_000);

    return () => clearInterval(timer);
  }, [load]);

  async function refresh() {
    setRefreshing(true);
    await load();
    setRefreshing(false);
  }

  // מחשבים ששתקו מספיק זמן כדי שזו כבר לא תקלה רגעית
  const silent = (devices ?? []).filter(
    (d) => d.health === "missing" || d.health === "offline" || d.health === "tampered",
  );

  const unnamed = (devices ?? []).filter((d) => !d.display_name?.trim());
  const empty = devices !== null && devices.length === 0;

  return (
    <>
      <div className="page-head">
        <h1>המחשבים שלי</h1>

        <div className="spacer" />

        <button disabled={refreshing} onClick={() => void refresh()}>
          {refreshing ? "מרענן…" : "רענן"}
        </button>

        {!empty && (
          <button className="primary" onClick={() => setAdding(!adding)}>
            {adding ? "סגור" : "הוסף מחשב"}
          </button>
        )}
      </div>

      {error && <div className="error">{error}</div>}

      {(adding || empty) && <AddDevice />}

      {/*
        מחשב בלי כינוי.

        שם המחשב ב-Windows הוא משהו כמו DESKTOP-4F2K9A, וזה מה
        שהיה מופיע בהתראה. מי שמקבל אותה אינו יודע על איזה מחשב
        מדובר, ולכן הכינוי הוא חובה ולא קישוט.
      */}
      {unnamed.map((d) => (
        <NameDevice key={d.id} device={d} onSaved={() => void load()} />
      ))}

      {!empty && (
        <div className="panel">
          <div className="panel-head">
            <h2>מחשבים</h2>
            <div className="spacer" />
            <span className="device-sub">
              {devices === null ? "" : `${devices.length} מחשבים · מתעדכן כל 30 שניות`}
            </span>
          </div>

          {devices === null && <div className="empty">טוען...</div>}

          {devices && devices.length > 0 && (
            <div className="scroller">
              <table>
                <thead>
                  <tr>
                    <th>מחשב</th>
                    <th>מצב</th>
                    <th>קבוצה</th>
                    <th>ספק סינון</th>
                    <th>דיווח אחרון</th>
                    <th><span className="sr-only">פתיחה</span></th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map((device) => (
                    <tr key={device.id} onClick={() => onOpenDevice(device.id)}>
                      <td>
                        <div className="device-name">{deviceLabel(device)}</div>
                        {device.display_name && device.machine_name && (
                          <div className="device-sub">{device.machine_name}</div>
                        )}
                      </td>
                      <td>
                        <StatusChip status={device.lockout_active ? "blocked" : device.last_status} />
                        {device.health && device.health !== "healthy" && (
                          <span className={`health ${device.health}`} style={{ marginInlineStart: 6 }}>
                            {HEALTH_LABEL[device.health] ?? device.health}
                          </span>
                        )}
                      </td>
                      <td style={{ color: "var(--ink-2)", fontSize: 13 }}>
                        {device.group_name ?? <span className="muted">—</span>}
                      </td>
                      <td>{device.detected_provider ?? <span className="muted">לא זוהה</span>}</td>
                      <td style={{ color: "var(--muted)", fontSize: 13 }}>
                        {relativeTime(device.last_seen_at)}
                      </td>
                      <td style={{ textAlign: "left" }}>
                        <button
                          className="ghost"
                          onClick={(e) => { e.stopPropagation(); onOpenDevice(device.id); }}
                        >
                          לוח בקרה
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {silent.length > 0 && (
        <div className="alarm" style={{ marginTop: 16 }}>
          <div className="alarm-head">
            <span className="alarm-dot" />
            {silent.length === 1
              ? "מחשב אחד הפסיק לדווח"
              : `${silent.length} מחשבים הפסיקו לדווח`}
          </div>

          <p className="alarm-body">
            מחשב שאינו מדווח עשוי להיות כבוי, או שההגנה עליו הופסקה.
            כשהוא יחזור, Filter+‎ יבדוק ביומן האירועים של Windows אם המחשב
            היה דלוק בזמן הזה, ויציג את התשובה.
          </p>

          <ul className="alarm-list">
            {silent.map((d) => (
              <li key={d.id}>
                <button className="link" onClick={() => onOpenDevice(d.id)}>
                  {deviceLabel(d)}
                </button>
                <span>{HEALTH_LABEL[d.health ?? ""] ?? d.health}</span>
                <span className="alarm-when">{relativeTime(d.last_seen_at)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {summary && !empty && (
        <div className="tiles compact">
          <div className="tile safe">
            <div className="n">{summary.safe}</div>
            <div className="l">מוגנים</div>
          </div>
          <div className="tile low">
            <div className="n">{summary.lowFilter}</div>
            <div className="l">סינון חלקי</div>
          </div>
          <div className="tile bad">
            <div className="n">{summary.unfiltered}</div>
            <div className="l">אינם מסוננים</div>
          </div>
          <div className="tile blocked">
            <div className="n">{summary.blocked}</div>
            <div className="l">חסומים</div>
          </div>
          {(summary.whitelist ?? 0) > 0 && (
            <div className="tile whitelist">
              <div className="n">{summary.whitelist}</div>
              <div className="l">רשימה לבנה</div>
            </div>
          )}
          <div className="tile offline">
            <div className="n">{summary.offline}</div>
            <div className="l">מנותקים</div>
          </div>
        </div>
      )}

      {!empty && <Groups onOpen={onOpenGroup} />}
    </>
  );
}

/** בקשת כינוי למחשב שעוד אין לו. */
function NameDevice({ device, onSaved }: { device: DeviceRow; onSaved: () => void }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function save() {
    setBusy(true);
    setError(null);

    try {
      await api.patch(`/api/portal/v1/devices/${device.id}/display-name`, {
        displayName: name.trim(),
      });
      onSaved();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "שמירת הכינוי נכשלה");
    } finally {
      setBusy(false);
    }
  }

  const id = `name-${device.id}`;

  return (
    <div className="name-device">
      <label htmlFor={id}>
        <b>צריך לתת כינוי למחשב {device.machine_name ?? "החדש"}</b>
        <span className="muted small">
          הכינוי הוא מה שיופיע בהתראות, למשל "קבלה" או "המחשב של דני". בלעדיו לא
          ברור איזה מחשב שלח התראה.
        </span>
      </label>

      <div className="name-device-row">
        <input
          id={id}
          type="text"
          value={name}
          maxLength={60}
          disabled={busy}
          placeholder="כינוי למחשב"
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter" && name.trim()) void save(); }}
        />
        <button className="primary" disabled={busy || !name.trim()} onClick={() => void save()}>
          שמור
        </button>
      </div>

      {error !== null && <p className="error">{error}</p>}
    </div>
  );
}
