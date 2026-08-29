import { useCallback, useEffect, useState } from "react";

import { api, ApiError } from "../api";

/**
 * הגדרות ההתראות.
 *
 * המסך בנוי סביב הבחנה אחת: לא כל שינוי כאן שווה בסיכונו. "מתי
 * לקבל" הוא העדפה, ו"לאן" הוא ההגנה עצמה — מי שמפנה את ההתראות
 * לכתובת שלו מנטרל את המוצר בלי לגעת בסינון, ואיש אינו רואה דבר.
 *
 * לכן הכתובת הראשית מקבלת אזור נפרד עם אזהרה, ולא עוד שדה בטופס.
 */

type Channel = "off" | "immediate" | "daily";

interface Settings {
  primary_email: string;
  on_device_silent: Channel;
  on_unfiltered: Channel;
  on_new_network: Channel;
  on_tamper: Channel;
  on_lockout: Channel;
  weekly_digest: boolean;
  quiet_from: number | null;
  quiet_to: number | null;
}

interface Recipient {
  id: string;
  email: string;
  verified_at: string | null;
  created_at: string;
}

interface PendingChange {
  id: string;
  from_email: string;
  new_email: string;
  requested_at: string;
  effective_at: string;
}

interface Payload {
  settings: Settings | null;
  recipients: Recipient[];
  pendingChange: PendingChange | null;
}

/** השדות, בשמם ובמה שהם באמת אומרים להורה. */
const KINDS: Array<{ key: keyof Settings; label: string; hint: string }> = [
  {
    key: "on_device_silent",
    label: "מחשב הפסיק לדווח",
    hint: "עשוי להיות כבוי — או שההגנה עליו הופסקה",
  },
  {
    key: "on_unfiltered",
    label: "חיבור לא מסונן",
    hint: "המחשב יצא לאינטרנט שלא דרך ספק מאושר",
  },
  {
    key: "on_new_network",
    label: "רשת חדשה",
    hint: "המחשב נראה על רשת שלא ראית קודם",
  },
  {
    key: "on_tamper",
    label: "חשד לחבלה",
    hint: "מישהו ניסה לעצור או לשנות את התוכנה",
  },
  {
    key: "on_lockout",
    label: "נעילה",
    hint: "המחשב ננעל, או שוחרר מנעילה",
  },
];

const CHANNELS: Array<{ value: Channel; label: string }> = [
  { value: "immediate", label: "מיד" },
  { value: "daily", label: "סיכום יומי" },
  { value: "off", label: "לא לשלוח" },
];

function hoursLeft(iso: string): string {
  const ms = new Date(iso).getTime() - Date.now();

  if (ms <= 0) return "בכל רגע";

  const hours = Math.round(ms / 3_600_000);

  return hours <= 1 ? "בתוך שעה" : `בעוד ${hours} שעות`;
}

export function Notifications(): JSX.Element {
  const [data, setData] = useState<Payload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [newAddress, setNewAddress] = useState("");
  const [newPrimary, setNewPrimary] = useState("");

  const load = useCallback(async () => {
    try {
      setData(await api.get<Payload>("/api/portal/v1/notifications"));
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "טעינת ההגדרות נכשלה");
    }
  }, []);

  useEffect(() => void load(), [load]);

  const save = useCallback(
    async (patch: Record<string, unknown>) => {
      setBusy(true);
      setNote(null);

      try {
        await api.put("/api/portal/v1/notifications", patch);
        await load();
      } catch (e) {
        setError(e instanceof ApiError ? e.message : "השמירה נכשלה");
      } finally {
        setBusy(false);
      }
    },
    [load],
  );

  if (error !== null && data === null) return <p className="error">{error}</p>;
  if (data === null) return <p className="muted">טוען…</p>;

  const s = data.settings;

  if (s === null) {
    return <p className="muted">עוד לא הוגדרו התראות לחשבון הזה.</p>;
  }

  return (
    <>
      <h1>התראות</h1>

      {error !== null && <p className="error">{error}</p>}
      {note !== null && <p className="ok">{note}</p>}

      {/* ─────────────────────────────── מתי לקבל */}

      <section className="panel">
        <div className="panel-head">
          <h2>על מה לקבל התראה</h2>
        </div>

        <div className="panel-body">
          <p className="muted small">
            הכיבוי נוגע רק למה שנשלח לתיבה. כל מה שקורה נשאר במרכז הניהול
            ובהיסטוריה בכל מקרה.
          </p>

          <table className="rows">
            <tbody>
              {KINDS.map((k) => (
                <tr key={k.key}>
                  <td>
                    <b>{k.label}</b>
                    <div className="muted small">{k.hint}</div>
                  </td>
                  <td style={{ width: 160 }}>
                    <select
                      value={s[k.key] as Channel}
                      disabled={busy}
                      onChange={(e) => {
                        const field = k.key
                          .replace(/_(.)/g, (_, c: string) => c.toUpperCase());

                        void save({ [field]: e.target.value });
                      }}
                    >
                      {CHANNELS.map((c) => (
                        <option key={c.value} value={c.value}>
                          {c.label}
                        </option>
                      ))}
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* ─────────────────────────────── שעות שקט */}

      <section className="panel" style={{ marginTop: 16 }}>
        <div className="panel-head">
          <h2>שעות שקט</h2>
        </div>

        <div className="panel-body">
          <p className="muted small">
            בשעות האלה התראות נצברות ונשלחות אחר כך, במקום להעיר אותך.
            הן נדחות ולא נמחקות.
          </p>

          <p className="muted small">
            <b>חשד לחבלה ונעילה נשלחים תמיד</b>, גם בשעות שקט. השעות שבהן
            ההורה ישן הן בדיוק השעות שבהן כדאי לנסות.
          </p>

          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <label>
              מ־
              <select
                value={s.quiet_from ?? ""}
                disabled={busy}
                onChange={(e) =>
                  void save(
                    e.target.value === ""
                      ? { quietFrom: null, quietTo: null }
                      : { quietFrom: Number(e.target.value), quietTo: s.quiet_to ?? 7 },
                  )
                }
              >
                <option value="">כבוי</option>
                {Array.from({ length: 24 }, (_, h) => (
                  <option key={h} value={h}>
                    {String(h).padStart(2, "0")}:00
                  </option>
                ))}
              </select>
            </label>

            {s.quiet_from !== null && (
              <label>
                עד
                <select
                  value={s.quiet_to ?? 7}
                  disabled={busy}
                  onChange={(e) =>
                    void save({ quietFrom: s.quiet_from, quietTo: Number(e.target.value) })
                  }
                >
                  {Array.from({ length: 24 }, (_, h) => (
                    <option key={h} value={h}>
                      {String(h).padStart(2, "0")}:00
                    </option>
                  ))}
                </select>
              </label>
            )}
          </div>
        </div>
      </section>

      {/* ─────────────────────────────── כתובות נוספות */}

      <section className="panel" style={{ marginTop: 16 }}>
        <div className="panel-head">
          <h2>כתובות נוספות</h2>
        </div>

        <div className="panel-body">
          <p className="muted small">
            כתובת נוספת מקבלת את אותן התראות. היא מתחילה לקבל רק אחרי
            שבעליה מאשר בקישור שנשלח אליו — אחרת הוספת כתובת הייתה דרך
            שקטה להעביר את ההתראות למי שרוצה לדעת מתי אפשר לפעול.
          </p>

          {data.recipients.length === 0 ? (
            <p className="muted small">אין כתובות נוספות.</p>
          ) : (
            <table className="rows">
              <tbody>
                {data.recipients.map((r) => (
                  <tr key={r.id}>
                    <td>{r.email}</td>
                    <td>
                      {r.verified_at === null ? (
                        <span className="pill warn">ממתין לאישור</span>
                      ) : (
                        <span className="pill ok">מאושרת</span>
                      )}
                    </td>
                    <td style={{ textAlign: "left" }}>
                      <button
                        className="ghost"
                        disabled={busy}
                        onClick={() => {
                          void (async () => {
                            setBusy(true);

                            try {
                              await api.del(
                                `/api/portal/v1/notifications/recipients/${r.id}`,
                              );
                              await load();
                            } catch (e) {
                              setError(
                                e instanceof ApiError ? e.message : "ההסרה נכשלה",
                              );
                            } finally {
                              setBusy(false);
                            }
                          })();
                        }}
                      >
                        הסר
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          <div style={{ display: "flex", gap: 8 }}>
            <input
              type="email"
              placeholder="כתובת נוספת"
              value={newAddress}
              disabled={busy}
              onChange={(e) => setNewAddress(e.target.value)}
            />
            <button
              disabled={busy || newAddress.trim() === ""}
              onClick={() => {
                void (async () => {
                  setBusy(true);
                  setError(null);

                  try {
                    const r = await api.post<{ note: string }>(
                      "/api/portal/v1/notifications/recipients",
                      { email: newAddress.trim() },
                    );

                    setNewAddress("");
                    setNote(r.note);
                    await load();
                  } catch (e) {
                    setError(e instanceof ApiError ? e.message : "ההוספה נכשלה");
                  } finally {
                    setBusy(false);
                  }
                })();
              }}
            >
              הוסף
            </button>
          </div>
        </div>
      </section>

      {/* ─────────────────────────────── הכתובת הראשית */}

      <section className="panel danger-panel" style={{ marginTop: 16 }}>
        <div className="panel-head">
          <h2>כתובת ההתראות הראשית</h2>
        </div>

        <div className="panel-body">
          <p>
            ההתראות נשלחות היום אל <b>{s.primary_email}</b>
          </p>

          {data.pendingChange !== null ? (
            <>
              <p className="warn-text">
                יש בקשה פתוחה להעביר את ההתראות אל{" "}
                <b>{data.pendingChange.new_email}</b>. היא תיכנס לתוקף{" "}
                {hoursLeft(data.pendingChange.effective_at)}.
              </p>

              <p className="muted small">
                אם לא ביקשת את זה — עצור עכשיו. הודעה עם קישור עצירה נשלחה
                גם לכתובת הנוכחית.
              </p>

              <button
                className="danger"
                disabled={busy}
                onClick={() => {
                  void (async () => {
                    setBusy(true);

                    try {
                      await api.post(
                        "/api/portal/v1/notifications/primary-email/cancel",
                        {},
                      );
                      setNote("הבקשה בוטלה. כתובת ההתראות לא השתנתה.");
                      await load();
                    } catch (e) {
                      setError(e instanceof ApiError ? e.message : "הביטול נכשל");
                    } finally {
                      setBusy(false);
                    }
                  })();
                }}
              >
                עצור את ההחלפה
              </button>
            </>
          ) : (
            <>
              <p className="muted small">
                החלפת הכתובת אינה מיידית. אנחנו מודיעים לשתי הכתובות,
                והשינוי נכנס לתוקף אחרי 24 שעות — כדי שתספיק לעצור החלפה
                שלא ביקשת.
              </p>

              <p className="muted small">
                זו אינה בירוקרטיה: מי שמשיג גישה לחשבון אינו צריך לגעת
                בסינון כדי לנטרל את ההגנה. די שיפנה את ההתראות אליו.
              </p>

              <div style={{ display: "flex", gap: 8 }}>
                <input
                  type="email"
                  placeholder="כתובת חדשה"
                  value={newPrimary}
                  disabled={busy}
                  onChange={(e) => setNewPrimary(e.target.value)}
                />
                <button
                  disabled={busy || newPrimary.trim() === ""}
                  onClick={() => {
                    void (async () => {
                      setBusy(true);
                      setError(null);

                      try {
                        const r = await api.post<{ note: string }>(
                          "/api/portal/v1/notifications/primary-email",
                          { email: newPrimary.trim() },
                        );

                        setNewPrimary("");
                        setNote(r.note);
                        await load();
                      } catch (e) {
                        setError(e instanceof ApiError ? e.message : "הבקשה נכשלה");
                      } finally {
                        setBusy(false);
                      }
                    })();
                  }}
                >
                  בקש החלפה
                </button>
              </div>
            </>
          )}
        </div>
      </section>
    </>
  );
}
