import { useCallback, useEffect, useState } from "react";
import { ApiError, api } from "../api";
import { NetworkHistory } from "../components/NetworkHistory";
import { StatusChip } from "../components/StatusChip";
import { STATUS_COLOR } from "../components/Shield";
import {
  HEALTH_LABEL,
  MODE_LABEL,
  PROFILE_LABEL,
  STATUS_LABEL,
  relativeTime,
  type DeviceRow,
  type SecurityStatus,
  type Timeline,
  type TimelineEntry,
} from "../types";
import { toPlain } from "../timeline-plain";
import { DeviceSchedules } from "../components/DeviceSchedules";
import { DeviceWhitelist } from "../components/DeviceWhitelist";
import { DeviceLogs } from "../components/DeviceLogs";
import { DeviceNetworks } from "../components/DeviceNetworks";
import { DeviceFloor } from "../components/DeviceFloor";
import { DeviceUninstall } from "../components/DeviceUninstall";

/** מיזוג שלושת המקורות לציר זמן אחד ממוין. */
function mergeTimeline(timeline: Timeline): TimelineEntry[] {
  return [...timeline.events, ...timeline.commands, ...timeline.heartbeats]
    .sort((a, b) => new Date(b.at).getTime() - new Date(a.at).getTime())
    .slice(0, 60);
}

const COMMAND_LABEL: Record<string, string> = {
  lockout: "נעילה נדרשה",
  release_lockout: "שחרור נדרש",
  run_audit: "בדיקה נדרשה",
  refresh_policy: "רענון מדיניות",
};

const COMMAND_STATE: Record<string, string> = {
  pending: "ממתין לאיסוף",
  delivered: "נמסר למחשב",
  acked: "אושר",
  expired: "פג תוקף",
  cancelled: "בוטל",
};

export function DeviceDetail({ id, onBack }: { id: string; onBack: () => void }) {
  const [device, setDevice] = useState<DeviceRow | null>(null);
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [askLock, setAskLock] = useState(false);
  const [minutes, setMinutes] = useState(60);
  const [reason, setReason] = useState("");
  const [detailed, setDetailed] = useState(false);
  const [editingName, setEditingName] = useState(false);
  const [editName, setEditName] = useState("");

  async function load() {
    try {
      const [detail, entries] = await Promise.all([
        api.get<DeviceRow>(`/api/portal/v1/devices/${id}`),
        api.get<Timeline>(`/api/portal/v1/devices/${id}/timeline`),
      ]);

      setDevice(detail);
      setTimeline(mergeTimeline(entries));
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "טעינת פרטי המחשב נכשלה");
    }
  }

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  async function act(path: string, body?: unknown, message?: string) {
    setBusy(true);
    setError(null);
    setNotice(null);

    try {
      await api.post(`/api/portal/v1/devices/${id}/${path}`, body);
      setNotice(message ?? "הפקודה נוצרה");
      await load();
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "הפעולה נכשלה");
    } finally {
      setBusy(false);
      setAskLock(false);
    }
  }

  /*
   * ההוק לפני כל return מוקדם, ולא אחריו.
   *
   * הוא הוצב כאן בטעות אחרי הענף של "טוען", ואז מספר ההוקים
   * השתנה בין הרינדור הראשון לשני — React זורק, והמסך קורס
   * בלחיצה על מחשב. זה כלל ולא העדפה: React מזהה הוקים לפי
   * סדר הקריאה, ולא לפי שם.
   */
  const retire = useCallback(async () => {
    if (!window.confirm("להסיר את המחשב מהחשבון? התוכנה תמשיך לפעול במחשב עצמו.")) {
      return;
    }

    setBusy(true);

    try {
      const result = await api.post<{ note: string }>(`/api/portal/v1/devices/${id}/retire`);

      setNotice(result.note);
      onBack();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "ההסרה נכשלה");
    } finally {
      setBusy(false);
    }
  }, [id, onBack]);

  const saveDisplayName = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      await api.patch(`/api/portal/v1/devices/${id}/display-name`, {
        displayName: editName.trim() || null,
      });
      setEditingName(false);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "שינוי השם נכשל");
    } finally {
      setBusy(false);
    }
  }, [id, editName]);

  if (!device) {
    return (
      <div className="shell">
        <button className="link" onClick={onBack}>← חזרה לרשימה</button>
        {error ? <div className="error">{error}</div> : <div className="empty">טוען...</div>}
      </div>
    );
  }

  const status: SecurityStatus = device.lockout_active ? "blocked" : device.last_status ?? "unknown";

  return (
    <div className="shell">
      <button className="link" onClick={onBack}>← חזרה לרשימה</button>

      <div style={{ display: "flex", alignItems: "center", gap: 12, margin: "10px 0 4px" }}>
        <h1 style={{ margin: 0 }}>
          {device.machine_name ?? "מחשב ללא שם"}
        </h1>
        <StatusChip status={status} />
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
        {editingName ? (
          <>
            <input
              type="text"
              value={editName}
              onChange={(e) => setEditName(e.target.value)}
              disabled={busy}
              autoFocus
              maxLength={60}
              placeholder="כינוי"
              onKeyDown={(e) => { if (e.key === "Enter") void saveDisplayName(); if (e.key === "Escape") setEditingName(false); }}
            />
            <button disabled={busy} onClick={() => void saveDisplayName()}>שמור</button>
            <button className="ghost" onClick={() => setEditingName(false)}>ביטול</button>
          </>
        ) : (
          <>
            <span className="muted">{device.display_name ? `כינוי: ${device.display_name}` : "ללא כינוי"}</span>
            <button className="ghost" onClick={() => { setEditName(device.display_name ?? ""); setEditingName(true); }}>
              {device.display_name ? "שנה כינוי" : "הוסף כינוי"}
            </button>
          </>
        )}
      </div>

      <p className="sub">
        {device.tenant_name} · פעימה אחרונה {relativeTime(device.last_seen_at)}
      </p>

      {error && <div className="error">{error}</div>}
      {notice && <div className="notice">{notice}</div>}

      {/*
        היסטוריית הרשתות לפני ציר הזמן, ובכוונה.

        ציר הזמן עונה על "מה קרה במחשב"; זו עונה על "איפה הוא היה",
        וזו השאלה שהורה בא לשאול.
      */}
      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head">
          <h2>היסטוריית חיבורים</h2>
        </div>

        <div className="panel-body no-pad-scroll">
          <NetworkHistory deviceId={id} />
        </div>
      </div>

      {/*
        חלונות זמן.

        לכל מחשב בנפרד, כי זו כל הנקודה: מה שנכון לילד בן שבע אינו
        מה שנכון לבן שבע־עשרה, ושניהם באותו חשבון.
      */}
      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head">
          <h2>שעות שבהן אין גלישה</h2>
        </div>

        <DeviceSchedules deviceId={id} />
      </div>

      {/*
        רשימה לבנה, מיד אחרי שעות החסימה.

        שתיהן אותו סוג של החלטה — מה המחשב הזה רשאי לעשות, בנפרד
        משאר המחשבים בחשבון — ושתיהן מתפרסמות באותה שכבת מדיניות.
      */}
      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head">
          <h2>רשימה לבנה: גלישה לאתרים מאושרים בלבד</h2>
        </div>

        <DeviceWhitelist deviceId={id} />
      </div>

      {/*
        הסרת התוכנה, כאן ולא בלשונית נפרדת.

        ההורה כבר יודע על איזה מחשב מדובר, ואינו צריך להעביר קוד
        זיהוי בין שני מסכים ולזכור לאיזה מחשב הוא שייך.
      */}
      <DeviceUninstall
        deviceName={device.display_name ?? device.machine_name ?? "המחשב"}
      />

      {/*
        יומני אבחון.

        לפני ההסרה ואחרי ההגדרות, כי זה הסדר שבו מטפלים בתקלה:
        מבינים מה קרה, ורק אם אין ברירה מסירים.
      */}
      {/*
        רשתות למחשב הזה, לפני היומנים.

        זו הגדרה שמשנה התנהגות; היומנים הם אבחון של תקלה. הסדר הוא
        מה שההורה עושה לעיתים קרובות יותר.
      */}
      <DeviceNetworks deviceId={id} />

      {/*
        הרצפה, אחרי הרשתות ולפני היומנים.

        הורה רואה כאן מה המחשב אוכף לכל הפחות; המוקד רואה גם את
        הכפתור. ההנפקה אינה מחילה — היא נמסרת בפעימה הבאה, והרצפה
        המוצגת מתעדכנת רק אחרי שהמחשב דיווח שהחיל.
      */}
      <DeviceFloor deviceId={id} floor={device.policy_floor} onIssued={() => void load()} />

      <DeviceLogs deviceId={id} />

      {/*
        הסרה מהחשבון.

        נחוצה לשני דברים: מחשב שיצא משימוש, ומחשב שצריך להירשם
        מחדש עם הגדרות מקלות מאלה שיש לו. רישום חוזר רשאי רק
        להחמיר — אחרת קישור התקנה שדלף היה כלי להורדת ההגנה —
        ולכן הרפיה עוברת דרך הפעולה המאומתת הזו.
      */}
      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head">
          <h2>הסרה מהחשבון</h2>
        </div>

        {/*
          התוכן בעטיפה מרופדת.

          ל-.panel אין ריפוד משלו — רק ל-.panel-head — ולכן תוכן
          שיושב בו ישירות נצמד לקצה. שאר הפאנלים לא נתקלו בזה כי
          הם מכילים טבלאות עם ריפוד משלהן.
        */}
        <div className="panel-body">
          <p className="muted small">
            מסיר את המחשב מהרשימה. ההיסטוריה שלו נשמרת. התקנה חדשה על אותו
            מחשב תירשם מחדש ותקבל את ההגדרות של הקישור החדש.
          </p>

          <p className="muted small">
            זה אינו מסיר את התוכנה מהמחשב — היא תמשיך לפעול לפי מה שיש לה עד
            שתוסר שם.
          </p>

          <button className="danger" disabled={busy} onClick={() => void retire()}>
            הסר מהחשבון
          </button>
        </div>
      </div>

      <div className="detail-grid">
        <div className="panel">
          <div className="panel-head">
            <h2>מה קרה במחשב</h2>

            {/*
              שתי שפות, ולא ניסוח אחד שמתפשר.

              מה שהסוכן שולח נכתב למי שכתב אותו: "coverage_gap",
              ושישים שורות "פעימה · מוגן · ציון 100" ברצף. הכול נכון,
              ואף אחד מזה אינו תשובה לשאלה שהורה בא לשאול.

              אין כאן מידע שנמחק — יש בחירה מה מוצג כברירת מחדל.
            */}
            <div className="spacer" />

            <button
              className={detailed ? "link" : "link on"}
              onClick={() => setDetailed(false)}
            >
              פשוט
            </button>
            <button
              className={detailed ? "link on" : "link"}
              onClick={() => setDetailed(true)}
            >
              מפורט
            </button>

            <button className="link" onClick={() => void load()}>רענן</button>
          </div>

          {timeline.length === 0 && <div className="empty">עוד לא נרשמה פעילות</div>}

          {!detailed && (
            <div className="timeline plain">
              {toPlain(timeline).map((entry) => (
                <div className={`entry tone-${entry.tone}`} key={entry.id}>
                  <span className="mark" />

                  <span className="what">
                    <b>
                      {entry.title}
                      {entry.repeats > 1 && (
                        <span className="muted small"> · {entry.repeats} בדיקות ברצף</span>
                      )}
                    </b>
                    {entry.why !== "" && <div className="muted small">{entry.why}</div>}
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
              ))}
            </div>
          )}

          {detailed && (
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
                          <b>פעימה</b>{" "}
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

        <div>
          <div className="panel" style={{ marginBottom: 18 }}>
            <div className="panel-head">
              <h2>פרטים</h2>
            </div>

            <dl className="kv">
              <dt>מזהה חומרה</dt>
              <dd className="hwid">{device.hwid}</dd>

              <dt>סוג התקנה</dt>
              <dd>{PROFILE_LABEL[device.install_profile] ?? device.install_profile}</dd>

              <dt>מצב אכיפה</dt>
              <dd>{MODE_LABEL[device.enforcement_mode] ?? device.enforcement_mode}</dd>

              <dt>מצב קשר</dt>
              <dd>{HEALTH_LABEL[device.health ?? ""] ?? "—"}</dd>

              <dt>ספק סינון</dt>
              <dd>{device.detected_provider ?? "לא זוהה"}</dd>

              <dt>ציון אחרון</dt>
              <dd className="num">{device.last_score ?? "—"}</dd>

              <dt>רשת אלחוטית</dt>
              <dd>{device.wifi_ssid ?? "—"}</dd>

              <dt>חוקי רשת</dt>
              <dd className="num">{device.wfp_filter_count ?? "—"}</dd>

              <dt>גרסת מדיניות</dt>
              <dd className="num">{device.policy_version ?? "—"}</dd>

              <dt>גרסת SafeMe</dt>
              <dd className="num">{device.agent_version ?? "—"}</dd>

              <dt>מערכת הפעלה</dt>
              <dd>{device.os_version ?? "—"}</dd>
            </dl>

            <div className="actions">
              <button
                className="danger"
                disabled={busy}
                onClick={() => setAskLock(true)}
              >
                נעילה יזומה
              </button>

              <button
                disabled={busy}
                onClick={() => void act("release", {}, "השחרור בדרך למחשב")}
              >
                שחרור
              </button>

              <button
                disabled={busy}
                onClick={() => void act("audit", {}, "הבדיקה בדרך למחשב")}
              >
                בדוק עכשיו
              </button>
            </div>
          </div>
        </div>
      </div>

      {askLock && (
        <div className="modal-back" onClick={() => setAskLock(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h2>נעילה יזומה</h2>

            <p className="sub" style={{ marginBottom: 16 }}>
              המחשב ייחסם עד תום המשך שנבחר. הפקודה תגיע אליו בפעימה
              הבאה, תוך עד שלוש דקות.
            </p>

            <div className="field">
              <label htmlFor="minutes">משך בדקות</label>
              <input
                id="minutes"
                type="number"
                min={1}
                max={1440}
                value={minutes}
                onChange={(e) => setMinutes(Number(e.target.value))}
              />
            </div>

            <div className="field">
              <label htmlFor="reason">סיבה</label>
              <input
                id="reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="שעת שינה"
              />
            </div>

            <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
              <button
                className="primary"
                disabled={busy || reason.trim().length < 2}
                onClick={() =>
                  void act("lockout", { minutes, reason: reason.trim() }, "הנעילה בדרך למחשב")
                }
              >
                נעל
              </button>
              <button onClick={() => setAskLock(false)}>ביטול</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
