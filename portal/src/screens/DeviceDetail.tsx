import { useCallback, useEffect, useState } from "react";
import { ApiError, api } from "../api";
import { StatusChip } from "../components/StatusChip";
import { deviceLabel } from "../fleet";
import {
  HEALTH_LABEL,
  MODE_LABEL,
  relativeTime,
  type DeviceRow,
  type SecurityStatus,
} from "../types";

/**
 * לוח הבקרה של מחשב אחד.
 *
 * המסך הזה עונה על שאלה אחת: מה המצב של המחשב הזה, ואילו הגדרות
 * חלות עליו. הוא אינו המקום שבו משנים אותן.
 *
 * עד עכשיו כל ההגדרות של המוצר ישבו כאן, אחת מתחת לשנייה, והמסך
 * הפך לדף ארוך שצריך לגלול בו כדי למצוא משהו. עכשיו כל הגדרה
 * יושבת בלשונית של הנושא שלה, וכאן יש שורת סיכום עם קישור אליה.
 */

type BrowseTopic = "whitelist" | "schedules" | "networks" | "floor";
type SettingsTopic = "uninstall" | "retire";

interface WhitelistSummary {
  enabled: boolean;
  learningUntil: string | null;
  domains: unknown[];
}

interface ScheduleSummary {
  id: string;
  description: string;
}

export function DeviceDetail({
  id,
  onBack,
  onBrowse,
  onHistory,
  onSettings,
  onSetup,
}: {
  id: string;
  onBack: () => void;
  /** פתיחת אשף ההגדרה של המחשב הזה. */
  onSetup: () => void;
  onBrowse: (topic: BrowseTopic) => void;
  onHistory: () => void;
  onSettings: (topic: SettingsTopic) => void;
}) {
  const [device, setDevice] = useState<DeviceRow | null>(null);
  const [whitelist, setWhitelist] = useState<WhitelistSummary | null>(null);
  const [schedules, setSchedules] = useState<ScheduleSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [askLock, setAskLock] = useState(false);
  const [minutes, setMinutes] = useState(60);
  const [reason, setReason] = useState("");
  const [editingName, setEditingName] = useState(false);
  const [editName, setEditName] = useState("");

  const load = useCallback(async () => {
    try {
      setDevice(await api.get<DeviceRow>(`/api/portal/v1/devices/${id}`));
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "טעינת פרטי המחשב נכשלה");
    }

    /*
     * הסיכומים נטענים בנפרד, וכישלון בהם אינו מפיל את המסך.
     *
     * הם שורת תקציר ולא העיקר. חשבון בלי הרשאה לרשימה לבנה צריך
     * לראות את המחשב שלו, ולא הודעת שגיאה במקומו.
     */
    api.get<WhitelistSummary>(`/api/portal/v1/devices/${id}/whitelist`)
      .then(setWhitelist)
      .catch(() => setWhitelist(null));

    api.get<{ schedules: ScheduleSummary[] }>(`/api/portal/v1/devices/${id}/schedules`)
      .then((r) => setSchedules(r.schedules))
      .catch(() => setSchedules(null));
  }, [id]);

  useEffect(() => { void load(); }, [load]);

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

  const saveDisplayName = useCallback(async () => {
    // כינוי הוא חובה: אפשר לשנות אותו, לא למחוק
    if (!editName.trim()) return;

    setBusy(true);
    setError(null);

    try {
      await api.patch(`/api/portal/v1/devices/${id}/display-name`, {
        displayName: editName.trim(),
      });
      setEditingName(false);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "שינוי הכינוי נכשל");
    } finally {
      setBusy(false);
    }
  }, [id, editName, load]);

  if (!device) {
    return (
      <>
        <button className="link" onClick={onBack}>→ חזרה לראשי</button>
        {error ? <div className="error">{error}</div> : <div className="empty">טוען...</div>}
      </>
    );
  }

  const status: SecurityStatus = device.lockout_active ? "blocked" : device.last_status ?? "unknown";
  const named = Boolean(device.display_name?.trim());
  const floorMode = device.policy_floor?.mode ?? "enforce";

  return (
    <>
      <button className="link" onClick={onBack}>→ חזרה לראשי</button>

      <div className="page-head" style={{ marginTop: 10 }}>
        {editingName || !named ? (
          <div className="name-edit">
            <label htmlFor="device-nick" className="muted small">
              {named ? "כינוי המחשב" : "צריך לתת למחשב כינוי. הוא מה שיופיע בהתראות."}
            </label>

            <div className="name-device-row">
              <input
                id="device-nick"
                type="text"
                value={editName}
                onChange={(e) => setEditName(e.target.value)}
                disabled={busy}
                autoFocus={named}
                maxLength={60}
                placeholder="למשל: קבלה, המחשב של דני"
                onKeyDown={(e) => {
                  if (e.key === "Enter") void saveDisplayName();
                  if (e.key === "Escape" && named) setEditingName(false);
                }}
              />
              <button className="primary" disabled={busy || !editName.trim()} onClick={() => void saveDisplayName()}>
                שמור
              </button>
              {named && <button className="ghost" onClick={() => setEditingName(false)}>ביטול</button>}
            </div>
          </div>
        ) : (
          <>
            <h1>{deviceLabel(device)}</h1>
            <StatusChip status={status} />
            <button
              className="ghost"
              onClick={() => { setEditName(device.display_name ?? ""); setEditingName(true); }}
            >
              שנה כינוי
            </button>
          </>
        )}
      </div>

      <p className="sub">
        {device.machine_name && (
          <>שם המחשב ב-Windows‏: <bdi dir="ltr">{device.machine_name}</bdi> · </>
        )}
        דיווח אחרון {relativeTime(device.last_seen_at)}
        {device.health && device.health !== "healthy"
          ? ` · ${HEALTH_LABEL[device.health] ?? device.health}`
          : ""}
      </p>

      {error && <div className="error">{error}</div>}
      {notice && <div className="notice">{notice}</div>}

      <div className="detail-grid">
        <div>
          {/* ─────────────────────────────── ההגדרות שחלות על המחשב */}

          <div className="panel" style={{ marginBottom: 18 }}>
            <div className="panel-head">
              <h2>ההגדרות של המחשב</h2>
              <div className="spacer" />
              <button className="ghost" onClick={onSetup}>עבור על כל ההגדרות</button>
            </div>

            <ul className="settings-list">
              <li>
                <div>
                  <b>רשימה לבנה</b>
                  <span>
                    {whitelist === null
                      ? "—"
                      : whitelist.enabled
                        ? `פעילה: נפתחים רק ${whitelist.domains.length} האתרים שאושרו`
                        : "כבויה: הגלישה אינה מוגבלת לרשימת אתרים"}
                  </span>
                </div>
                <button onClick={() => onBrowse("whitelist")}>שנה</button>
              </li>

              <li>
                <div>
                  <b>זמני גלישה</b>
                  <span>
                    {schedules === null
                      ? "—"
                      : schedules.length === 0
                        ? "אין שעות חסימה: אפשר לגלוש בכל שעה"
                        : schedules.map((s) => s.description).join(" · ")}
                  </span>
                </div>
                <button onClick={() => onBrowse("schedules")}>שנה</button>
              </li>

              <li>
                <div>
                  <b>רשתות</b>
                  <span>
                    {device.wifi_ssid ? `מחובר עכשיו ל-${device.wifi_ssid}` : "אין רשת אלחוטית פעילה"}
                    {device.detected_provider ? ` · ספק סינון: ${device.detected_provider}` : " · לא זוהה ספק סינון"}
                  </span>
                </div>
                <button onClick={() => onBrowse("networks")}>שנה</button>
              </li>

              <li>
                <div>
                  <b>קבוצה</b>
                  <span>
                    {device.group_name
                      ? `${device.group_name}. הגדרות הקבוצה חלות כשאין למחשב הגדרה אישית.`
                      : "המחשב אינו משויך לקבוצה"}
                  </span>
                </div>
              </li>

              <li>
                <div>
                  <b>הגנת מינימום</b>
                  <span>
                    {MODE_LABEL[floorMode] ?? floorMode}. נקבעה בהתקנה, ואי אפשר להקל ממנה מרחוק.
                  </span>
                </div>
                <button onClick={() => onBrowse("floor")}>פרטים</button>
              </li>
            </ul>
          </div>

          {/* ─────────────────────────────── פעולות */}

          <div className="panel" style={{ marginBottom: 18 }}>
            <div className="panel-head">
              <h2>פעולות</h2>
            </div>

            <ul className="settings-list">
              <li>
                <div>
                  <b>היסטוריה והתראות</b>
                  <span>מה קרה במחשב, ולאילו רשתות הוא התחבר.</span>
                </div>
                <button onClick={onHistory}>פתח</button>
              </li>

              <li>
                <div>
                  <b>בדיקה עכשיו</b>
                  <span>המחשב יבדוק מחדש אם החיבור שלו מסונן, בלי לחכות לבדיקה הבאה.</span>
                </div>
                <button disabled={busy} onClick={() => void act("audit", {}, "הבדיקה בדרך למחשב")}>
                  בדוק
                </button>
              </li>

              {/*
                "נעילה יזומה" ו"שחרור" היו שני כפתורים בלי הסבר, ומי
                שלא כתב אותם לא ידע מה הם עושים. עכשיו כל אחד נקרא
                בשם של מה שקורה, ורק האחד שרלוונטי למצב מוצג.
              */}
              {device.lockout_active ? (
                <li>
                  <div>
                    <b>הגלישה במחשב חסומה עכשיו</b>
                    <span>
                      {device.lockout_until
                        ? `עד ${new Date(device.lockout_until).toLocaleString("he-IL", { dateStyle: "short", timeStyle: "short" })}. `
                        : ""}
                      ביטול החסימה מחזיר את הגלישה, אם החיבור מסונן.
                    </span>
                  </div>
                  <button disabled={busy} onClick={() => void act("release", {}, "ביטול החסימה בדרך למחשב")}>
                    בטל חסימה
                  </button>
                </li>
              ) : (
                <li>
                  <div>
                    <b>חסימת גלישה עכשיו</b>
                    <span>
                      חוסם את כל הגלישה במחשב לזמן שתבחר, למשל עד סוף היום. אפשר לבטל בכל רגע.
                    </span>
                  </div>
                  <button className="danger" disabled={busy} onClick={() => setAskLock(true)}>
                    חסום
                  </button>
                </li>
              )}

              <li>
                <div>
                  <b>הסרת Filter+‎ מהמחשב</b>
                  <span>מסירים מהמחשב עצמו, עם קוד שמונפק בהגדרות.</span>
                </div>
                <button onClick={() => onSettings("uninstall")}>להסרה</button>
              </li>
            </ul>
          </div>
        </div>

        <div>
          <div className="panel" style={{ marginBottom: 18 }}>
            <div className="panel-head">
              <h2>פרטים טכניים</h2>
            </div>

            <dl className="kv">
              <dt>מצב קשר</dt>
              <dd>{HEALTH_LABEL[device.health ?? ""] ?? "—"}</dd>

              <dt>ספק סינון</dt>
              <dd>{device.detected_provider ?? "לא זוהה"}</dd>

              <dt>ציון סינון</dt>
              <dd className="num">{device.last_score ?? "—"}</dd>

              <dt>רשת אלחוטית</dt>
              <dd>{device.wifi_ssid ?? "—"}</dd>

              <dt>גרסת Filter+‎</dt>
              <dd className="num">{device.agent_version ?? "—"}</dd>

              <dt>מערכת הפעלה</dt>
              <dd>{device.os_version ?? "—"}</dd>

              <dt>גרסת הגדרות</dt>
              <dd className="num">{device.policy_version ?? "—"}</dd>

              <dt>מזהה חומרה</dt>
              <dd className="hwid">{device.hwid}</dd>
            </dl>
          </div>
        </div>
      </div>

      {askLock && (
        <div className="modal-back" onClick={() => setAskLock(false)}>
          <div className="modal" role="dialog" aria-modal="true" aria-labelledby="lock-title" onClick={(e) => e.stopPropagation()}>
            <h2 id="lock-title">חסימת גלישה עכשיו</h2>

            <p className="sub" style={{ marginBottom: 16 }}>
              כל הגלישה במחשב תיחסם עד תום הזמן שנבחר. הפקודה מגיעה למחשב
              בדיווח הבא שלו, תוך עד שלוש דקות.
            </p>

            <div className="field">
              <label htmlFor="minutes">לכמה דקות</label>
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
              <label htmlFor="reason">סיבה (נרשמת בהיסטוריה)</label>
              <input
                id="reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="למשל: סוף יום העבודה"
              />
            </div>

            <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
              <button
                className="primary"
                disabled={busy || reason.trim().length < 2}
                onClick={() =>
                  void act("lockout", { minutes, reason: reason.trim() }, "החסימה בדרך למחשב")
                }
              >
                חסום
              </button>
              <button onClick={() => setAskLock(false)}>ביטול</button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
