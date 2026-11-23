import { useEffect, useState } from "react";
import { api } from "../api";
import { AddDevice } from "../components/AddDevice";
import { StatusChip } from "../components/StatusChip";
import {
  HEALTH_LABEL,
  PROFILE_LABEL,
  relativeTime,
  type DeviceRow,
  type Summary,
} from "../types";

/**
 * מסך המחשבים.
 *
 * המיון בשרת מביא קודם את מה שדורש טיפול: לא מסונן, אחר כך חסום,
 * ורק אחר כך תקין. מנהל שנכנס לבוקר רואה את הבעיות למעלה בלי לחפש.
 */
export function Dashboard({ onOpenDevice }: { onOpenDevice: (id: string) => void }) {
  const [devices, setDevices] = useState<DeviceRow[] | null>(null);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const [list, totals] = await Promise.all([
          api.get<{ devices: DeviceRow[] }>("/api/portal/v1/devices"),
          api.get<Summary>("/api/portal/v1/summary"),
        ]);

        if (cancelled) return;

        setDevices(list.devices);
        setSummary(totals);
      } catch {
        if (!cancelled) setError("טעינת הנתונים נכשלה");
      }
    }

    void load();

    // רענון תקופתי. הפעימה מגיעה כל שלוש דקות, ולכן אין טעם בתדירות גבוהה.
    const timer = setInterval(() => void load(), 30_000);

    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  // מחשבים ששתקו מספיק זמן כדי שזו כבר לא תקלה רגעית
  const silent = (devices ?? []).filter(
    (d) => d.health === "missing" || d.health === "offline" || d.health === "tampered",
  );

  return (
    <div className="shell">
      <h1>מחשבים</h1>
      <p className="sub">מצב ההגנה של כל מחשב מנוהל, מתעדכן כל 30 שניות</p>

      {error && <div className="error">{error}</div>}

      <AddDevice />

      {/*
        * מחשבים שהפסיקו לדווח, בראש המסך.
        *
        * מחשב ששותק אינו "שורה עם ערך אחר בטבלה" — הוא הסימן היחיד
        * שההגנה אולי אינה פועלת. אם הוא נבלע ברשימה, ההורה יגלה רק
        * כשיחפש, וזה בדיוק מה שלא יקרה.
        */}
      {silent.length > 0 && (
        <div className="alarm">
          <div className="alarm-head">
            <span className="alarm-dot" />
            {silent.length === 1
              ? "מחשב אחד הפסיק לדווח"
              : `${silent.length} מחשבים הפסיקו לדווח`}
          </div>

          <p className="alarm-body">
            מחשב שאינו מדווח עשוי להיות כבוי — או שההגנה עליו הופסקה.
            כשהוא יחזור, SafeMe יבדוק ביומן האירועים של Windows אם המחשב
            היה דלוק בזמן הזה, ויציג את התשובה.
          </p>

          <ul className="alarm-list">
            {silent.map((d) => (
              <li key={d.id}>
                <button className="link" onClick={() => onOpenDevice(d.id)}>
                  {d.display_name ?? d.machine_name ?? "מחשב ללא שם"}
                </button>
                <span>{HEALTH_LABEL[d.health ?? ""] ?? d.health}</span>
                <span className="alarm-when">{relativeTime(d.last_seen_at)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {summary && (
        <div className="tiles">
          <div className="tile">
            <div className="n">{summary.total}</div>
            <div className="l">סך המחשבים</div>
          </div>
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
            <div className="l">בנעילה</div>
          </div>
          {/*
            רק כשיש כאלה. רוב החשבונות אינם משתמשים ברשימה לבנה,
            ואריח קבוע של אפס היה מוסיף מספר שאינו אומר להם דבר.
          */}
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

      <div className="panel">
        <div className="panel-head">
          <h2>רשימת מחשבים</h2>
          <div className="spacer" />
          <span className="device-sub">{devices?.length ?? 0} רשומות</span>
        </div>

        {devices === null && <div className="empty">טוען...</div>}

        {devices?.length === 0 && (
          <div className="empty">עוד אין מחשבים.</div>
        )}

        {devices && devices.length > 0 && (
          <div className="scroller">
            <table>
              <thead>
                <tr>
                  <th>מחשב</th>
                  <th>מצב</th>
                  <th>ציון</th>
                  <th>ספק סינון</th>
                  <th>סוג</th>
                  <th>דיווח</th>
                  <th>פעימה אחרונה</th>
                  <th>אירועים</th>
                </tr>
              </thead>
              <tbody>
                {devices.map((device) => (
                  <tr key={device.id} onClick={() => onOpenDevice(device.id)}>
                    <td>
                      <div className="device-name">
                        {device.display_name ?? device.machine_name ?? "מחשב ללא שם"}
                      </div>
                      <div className="device-sub">
                        {device.display_name && device.machine_name ? device.machine_name : device.hwid.slice(0, 16) + "…"}
                      </div>
                    </td>
                    <td>
                      <StatusChip status={device.lockout_active ? "blocked" : device.last_status} />
                    </td>
                    <td className="num">{device.last_score ?? "—"}</td>
                    <td>{device.detected_provider ?? <span style={{ color: "var(--muted)" }}>לא זוהה</span>}</td>
                    <td style={{ color: "var(--ink-2)", fontSize: 13 }}>
                      {PROFILE_LABEL[device.install_profile] ?? device.install_profile}
                    </td>
                    <td>
                      {device.health && device.health !== "healthy" ? (
                        <span className={`health ${device.health}`}>
                          {HEALTH_LABEL[device.health] ?? device.health}
                        </span>
                      ) : (
                        <span style={{ color: "var(--muted)", fontSize: 13 }}>—</span>
                      )}
                    </td>
                    <td style={{ color: "var(--muted)", fontSize: 13 }}>
                      {relativeTime(device.last_seen_at)}
                    </td>
                    <td className="num">
                      {Number(device.open_events) > 0 ? (
                        <span style={{ color: "var(--low)" }}>{device.open_events}</span>
                      ) : (
                        "—"
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
