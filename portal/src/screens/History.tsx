import { useCallback, useEffect, useState } from "react";

import { ApiError, api } from "../api";
import { DeviceLogs } from "../components/DeviceLogs";
import { NetworkHistory } from "../components/NetworkHistory";
import { STATUS_COLOR } from "../components/Shield";
import { ScopePicker, deviceLabel, type Fleet } from "../fleet";
import { toPlain, type PlainEntry } from "../timeline-plain";
import {
  STATUS_LABEL,
  type SecurityStatus,
  type Timeline,
  type TimelineEntry,
} from "../types";

/**
 * היסטוריה והתראות.
 *
 * כל מה שעונה על "מה קרה": ההתראות הפתוחות של כל החשבון למעלה,
 * ומתחתן ההיסטוריה של מחשב אחד שבוחרים. המסך הזה הוא קריאה בלבד,
 * ואין בו הגדרה שאפשר לשנות.
 */

interface AlertRow {
  id: string;
  kind: string;
  state: string;
  first_seen_at: string;
  device_id?: string;
  display_name: string | null;
  machine_name?: string | null;
}

const ALERT: Record<string, { label: string; bad: boolean }> = {
  "device.silent": { label: "הפסיק לדווח", bad: true },
  "device.unfiltered": { label: "מחובר בלי סינון", bad: true },
  "device.tamper": { label: "חשד לחבלה", bad: true },
  "device.lockout": { label: "הגלישה חסומה", bad: false },
};

const COMMAND_LABEL: Record<string, string> = {
  lockout: "חסימת גלישה נדרשה",
  release_lockout: "ביטול חסימה נדרש",
  run_audit: "בדיקה נדרשה",
  refresh_policy: "רענון הגדרות",
};

const COMMAND_STATE: Record<string, string> = {
  pending: "ממתין לאיסוף",
  delivered: "נמסר למחשב",
  acked: "אושר",
  expired: "פג תוקף",
  cancelled: "בוטל",
};

function mergeTimeline(timeline: Timeline): TimelineEntry[] {
  return [...timeline.events, ...timeline.commands, ...timeline.heartbeats]
    .sort((a, b) => new Date(b.at).getTime() - new Date(a.at).getTime());
}

const clock = (iso: string): string =>
  new Date(iso).toLocaleTimeString("he-IL", { hour: "2-digit", minute: "2-digit" });

const dayKey = (iso: string): string => new Date(iso).toDateString();

/** "היום", "אתמול", או תאריך מלא. */
function dayTitle(iso: string): string {
  const date = new Date(iso);
  const today = new Date();
  const yesterday = new Date(Date.now() - 86_400_000);

  if (date.toDateString() === today.toDateString()) return "היום";
  if (date.toDateString() === yesterday.toDateString()) return "אתמול";

  return date.toLocaleDateString("he-IL", { weekday: "long", day: "numeric", month: "long" });
}

/** מתי: שעה אחת לאירוע, טווח למצב שנמשך. */
function when(entry: PlainEntry): string {
  if (entry.since === entry.at) return clock(entry.at);

  return dayKey(entry.since) === dayKey(entry.at)
    ? `${clock(entry.since)} עד ${clock(entry.at)}`
    : `מ-${new Date(entry.since).toLocaleDateString("he-IL", { day: "numeric", month: "numeric" })} ${clock(entry.since)} עד ${clock(entry.at)}`;
}

export function History({
  fleet,
  deviceId,
  onDevice,
}: {
  fleet: Fleet;
  deviceId: string | null;
  onDevice: (id: string) => void;
}): JSX.Element {
  const devices = fleet.devices ?? [];
  const current = devices.find((d) => d.id === deviceId) ?? devices[0] ?? null;

  const [alerts, setAlerts] = useState<AlertRow[] | null>(null);

  useEffect(() => {
    api.get<{ alerts: AlertRow[] }>("/api/portal/v1/alerts")
      .then((r) => setAlerts(r.alerts))
      .catch(() => setAlerts([]));
  }, []);

  return (
    <>
      <div className="page-head">
        <h1>היסטוריה והתראות</h1>
      </div>

      {/* ─────────────────────────────── התראות פתוחות */}

      <div className="panel" style={{ marginBottom: 18 }}>
        <div className="panel-head">
          <h2>התראות פתוחות</h2>
          <div className="spacer" />
          <span className="device-sub">בכל המחשבים</span>
        </div>

        {alerts === null ? (
          <p className="panel-body muted">טוען…</p>
        ) : alerts.length === 0 ? (
          <p className="panel-body muted">אין התראות פתוחות. כל המחשבים תקינים.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>מחשב</th>
                <th>מה קרה</th>
                <th>מאז</th>
                <th><span className="sr-only">פתיחה</span></th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((a) => {
                const info = ALERT[a.kind] ?? { label: a.kind, bad: true };

                return (
                  <tr
                    key={a.id}
                    onClick={a.device_id ? () => onDevice(a.device_id!) : undefined}
                    style={a.device_id ? undefined : { cursor: "default" }}
                  >
                    <td>
                      <div className="device-name">
                        {a.display_name?.trim() || a.machine_name?.trim() || "מחשב ללא כינוי"}
                      </div>
                    </td>
                    <td>
                      <span className={info.bad ? "tag warn" : "tag"}>{info.label}</span>
                    </td>
                    <td style={{ color: "var(--muted)", fontSize: 13 }}>
                      {new Date(a.first_seen_at).toLocaleString("he-IL", { dateStyle: "short", timeStyle: "short" })}
                    </td>
                    <td style={{ textAlign: "left" }}>
                      {a.device_id && <span className="muted small">להיסטוריה של המחשב ↓</span>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}

        <p className="panel-body muted small" style={{ paddingTop: 0 }}>
          התראה נסגרת מעצמה כשהמצב חוזר לתקין. לאן ומתי ההתראות נשלחות בדוא"ל
          קובעים בלשונית הגדרות, תחת התראות.
        </p>
      </div>

      {/* ─────────────────────────────── היסטוריה של מחשב אחד */}

      {fleet.devices === null ? (
        <p className="muted">טוען…</p>
      ) : current === null ? (
        <div className="panel">
          <p className="panel-body muted">עוד אין מחשבים בחשבון.</p>
        </div>
      ) : (
        <>
          <div className="scope-row">
            <ScopePicker
              fleet={fleet}
              kinds={["device"]}
              value={{ kind: "device", id: current.id }}
              onChange={(next) => { if (next.kind === "device") onDevice(next.id); }}
              label="ההיסטוריה של"
            />
          </div>

          <DeviceTimeline key={`t-${current.id}`} deviceId={current.id} />

          <div className="panel" style={{ marginBottom: 18 }}>
            <div className="panel-head">
              <h2>היסטוריית חיבורים</h2>
              <div className="spacer" />
              <span className="device-sub">לאילו רשתות {deviceLabel(current)} התחבר, ומתי</span>
            </div>

            <div className="panel-body no-pad-scroll">
              <NetworkHistory key={`n-${current.id}`} deviceId={current.id} />
            </div>
          </div>

          <DeviceLogs key={`l-${current.id}`} deviceId={current.id} />
        </>
      )}
    </>
  );
}

/**
 * מה קרה במחשב.
 *
 * שתי תצוגות. "עיקרי הדברים" מציגה רק שינויים: מצב שנמשך שלוש
 * שעות הוא שורה אחת עם טווח שעות, והאירועים מקובצים לפי יום. "יומן
 * מלא" הוא הגלם, שורה לכל דיווח, בשביל מי שמאבחן תקלה.
 *
 * התצוגה הפשוטה הקודמת הציגה מונה ("37 בדיקות ברצף") ותאריך מלא
 * בכל שורה, ונקראה כמו אותו יומן בניסוח אחר.
 */
function DeviceTimeline({ deviceId }: { deviceId: string }): JSX.Element {
  const [timeline, setTimeline] = useState<TimelineEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [detailed, setDetailed] = useState(false);

  const load = useCallback(async () => {
    try {
      setTimeline(mergeTimeline(
        await api.get<Timeline>(`/api/portal/v1/devices/${deviceId}/timeline`)));
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "טעינת ההיסטוריה נכשלה");
    }
  }, [deviceId]);

  useEffect(() => { void load(); }, [load]);

  const plain = toPlain(timeline ?? []);

  return (
    <div className="panel" style={{ marginBottom: 18 }}>
      <div className="panel-head">
        <h2>מה קרה במחשב</h2>
        <div className="spacer" />

        <button
          className={detailed ? "link" : "link on"}
          aria-pressed={!detailed}
          onClick={() => setDetailed(false)}
        >
          עיקרי הדברים
        </button>
        <button
          className={detailed ? "link on" : "link"}
          aria-pressed={detailed}
          onClick={() => setDetailed(true)}
        >
          יומן מלא
        </button>
        <button className="link" onClick={() => void load()}>רענן</button>
      </div>

      {error !== null && <p className="panel-body error">{error}</p>}
      {timeline === null && error === null && <div className="empty">טוען...</div>}
      {timeline !== null && timeline.length === 0 && <div className="empty">עוד לא נרשמה פעילות</div>}

      {!detailed && plain.length > 0 && (
        <div className="timeline plain">
          {plain.map((entry, i) => {
            const previous = plain[i - 1];
            const newDay = previous === undefined || dayKey(previous.at) !== dayKey(entry.at);

            return (
              <div key={entry.id}>
                {newDay && <h3 className="day-head">{dayTitle(entry.at)}</h3>}

                <div className={`entry tone-${entry.tone}`}>
                  <span className="mark" />

                  <span className="what">
                    <b>{entry.title}</b>
                    {entry.why !== "" && <div className="muted small">{entry.why}</div>}
                  </span>

                  <span className="when">{when(entry)}</span>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {detailed && timeline !== null && (
        <div className="timeline">
          {timeline.map((entry) => {
            const color =
              entry.kind === "heartbeat"
                ? STATUS_COLOR[(entry.name as SecurityStatus) ?? "unknown"]
                : entry.kind === "command"
                  ? "#4d94d1"
                  : "#d68e0c";

            return (
              <div className="entry" key={`${entry.kind}-${entry.id}`}>
                <span className="mark" style={{ background: color }} />

                <span className="what">
                  {entry.kind === "heartbeat" && (
                    <>
                      <b>דיווח</b>{" "}
                      <span>
                        {STATUS_LABEL[(entry.name as SecurityStatus) ?? "unknown"]}
                        {entry.score !== null && entry.score !== undefined
                          ? ` · ציון ${entry.score}`
                          : ""}
                      </span>
                    </>
                  )}

                  {entry.kind === "command" && (
                    <>
                      <b>{COMMAND_LABEL[entry.name] ?? entry.name}</b>{" "}
                      <span>
                        {COMMAND_STATE[entry.detail ?? ""] ?? entry.detail}
                        {entry.reason ? ` · ${entry.reason}` : ""}
                      </span>
                    </>
                  )}

                  {entry.kind === "event" && (
                    <>
                      <b>{entry.name}</b> <span>{entry.detail ?? ""}</span>
                    </>
                  )}
                </span>

                <span className="when">
                  {new Date(entry.at).toLocaleString("he-IL", {
                    day: "2-digit",
                    month: "2-digit",
                    hour: "2-digit",
                    minute: "2-digit",
                  })}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
