import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import { AddDevice } from "../components/AddDevice";
import { DeviceSetup } from "../components/DeviceSetup";
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
  accountType,
  setupId,
  onSetup,
}: {
  onOpenDevice: (id: string) => void;
  onOpenGroup: (id: string) => void;
  accountType: string | null;
  /** המחשב שאשף ההגדרה שלו פתוח, אם יש. */
  setupId: string | null;
  onSetup: (id: string | null) => void;
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

  const inSetup = setupId === null ? null : (devices ?? []).find((d) => d.id === setupId) ?? null;

  if (inSetup !== null) {
    return (
      <DeviceSetup
        key={inSetup.id}
        device={inSetup}
        onChanged={() => void load()}
        onClose={(openDashboard) => {
          onSetup(null);
          void load();
          if (openDashboard) onOpenDevice(inSetup.id);
        }}
      />
    );
  }

  return (
    <>
      <div className="page-head">
        <h1>ראשי</h1>

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

      {(adding || empty) && <AddDevice accountType={accountType} />}

      {/*
        מחשב חדש שעוד לא הוגדר.

        מחשב בלי כינוי הוא מחשב שהותקן ואיש לא עבר על ההגדרות שלו.
        במקום לבקש רק כינוי, נפתח אשף שעובר על כל הגדרות הסינון.
      */}
      {unnamed.map((d) => (
        <div className="name-device" key={d.id}>
          <div>
            <b>מחשב חדש נוסף לחשבון: {d.machine_name ?? "מחשב ללא שם"}</b>
            <div className="muted small">
              הוא עדיין בלי כינוי ועם הגדרות ברירת המחדל. ההגדרה לוקחת כשתי דקות:
              כינוי, קבוצה, זמני גלישה, רשימה לבנה, רשתות וסינון תוכן.
            </div>
          </div>

          <div>
            <button className="primary" onClick={() => onSetup(d.id)}>הגדר את המחשב</button>
          </div>
        </div>
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
