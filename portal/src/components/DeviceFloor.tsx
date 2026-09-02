import { useEffect, useState } from "react";

import { api, ApiError } from "../api";

/**
 * רצפת המדיניות של המחשב, והורדתה.
 *
 * הרצפה נקבעת בהתקנה ונחתמת, והסוכן דוחה כל מדיניות שמקלה ממנה.
 * זו ההגנה החזקה במוצר: גם שרת שנפרץ אינו יכול לכבות אכיפה. ולכן
 * הורדתה היא ההקלה המשמעותית ביותר שיש — היא מרשה למחשב לרדת
 * מתחת למה שנקבע כשהותקן.
 *
 * המסך למוקד בלבד. הורה רואה את הרצפה במסך המחשב אבל אינו מוריד
 * אותה בעצמו — זה עובר דרך פנייה, ועולה קרדיט.
 *
 * מה שהמסך חייב לומר במפורש: שההיתר אינו מוחל ברגע הלחיצה. הוא
 * נמסר בפעימה הבאה, והסוכן מאמת אותו בעצמו ורשאי לדחות. הרצפה
 * שמוצגת כאן מתעדכנת רק אחרי שהמחשב דיווח שהחיל — ומי שלא יידע
 * את זה יחשוב שהפעולה נכשלה.
 */

export interface FloorSpec {
  mode: "monitor" | "warn" | "enforce";
  onRedAction: "none" | "warn" | "lockout";
  minScoreForGreen: number;
  minScoreForYellow: number;
  requireProvider: string[];
}

const MODE: Record<FloorSpec["mode"], string> = {
  monitor: "מעקב בלבד",
  warn: "התראה",
  enforce: "אכיפה",
};

const ACTION: Record<FloorSpec["onRedAction"], string> = {
  none: "ללא פעולה",
  warn: "התראה",
  lockout: "נעילה",
};

/** רצפה מהמסד, שעשויה להיות חלקית. שדה חסר מוצג כברירת המחדל שהסוכן מניח. */
function normalize(raw: Partial<FloorSpec> | null | undefined): FloorSpec {
  return {
    mode: raw?.mode ?? "enforce",
    onRedAction: raw?.onRedAction ?? "lockout",
    minScoreForGreen: raw?.minScoreForGreen ?? 85,
    minScoreForYellow: raw?.minScoreForYellow ?? 60,
    requireProvider: raw?.requireProvider ?? [],
  };
}

export function DeviceFloor({
  deviceId,
  floor,
  onIssued,
}: {
  deviceId: string;
  floor: Partial<FloorSpec> | null | undefined;
  onIssued: () => void;
}): JSX.Element | null {
  const [platform, setPlatform] = useState(false);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState<FloorSpec>(() => normalize(floor));
  const [providers, setProviders] = useState("");
  const [reason, setReason] = useState("");
  const [waive, setWaive] = useState(false);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const current = normalize(floor);

  /*
   * הרשאה דרך השרת, לא דרך ניחוש.
   *
   * הכפתור מופיע רק למי שיכול ללחוץ עליו. הורה שרואה "הורד רצפה"
   * ומקבל 403 חושב שמשהו שבור — בעוד זה מצב תקין.
   */
  useEffect(() => {
    api.get<{ role: string }>("/api/portal/v1/auth/me")
      .then((me) => setPlatform(me.role === "platform_admin"))
      .catch(() => setPlatform(false));
  }, []);

  function begin() {
    setDraft(current);
    setProviders(current.requireProvider.join(", "));
    setReason("");
    setWaive(false);
    setNote(null);
    setError(null);
    setEditing(true);
  }

  async function submit() {
    setBusy(true);
    setError(null);
    setNote(null);

    const target: FloorSpec = {
      ...draft,
      requireProvider: providers.split(",").map((p) => p.trim()).filter((p) => p.length > 0),
    };

    try {
      const r = await api.post<{ note: string; reasons: string[] }>(
        `/api/portal/v1/devices/${deviceId}/lower-floor`,
        { floor: target, reason: reason.trim() || undefined, waiveCredit: waive });

      setNote(`${r.note} (${r.reasons.join("; ")})`);
      setEditing(false);
      onIssued();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "ההנפקה נכשלה");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel" style={{ marginBottom: 16 }}>
      <div className="panel-head">
        <h2>רצפת המדיניות</h2>

        {platform && !editing && (
          <button className="ghost" onClick={begin}>הורדת רצפה</button>
        )}
      </div>

      <div className="panel-body">
        <p className="muted small">
          המינימום שהמחשב אוכף, כפי שנקבע בהתקנה. מדיניות מקלה ממנו נדחית במחשב
          עצמו — גם אם השרת שולח אותה.
        </p>

        <table className="rows">
          <tbody>
            <tr>
              <th>מצב אכיפה</th>
              <td>{MODE[current.mode]}</td>
            </tr>
            <tr>
              <th>במצב אדום</th>
              <td>{ACTION[current.onRedAction]}</td>
            </tr>
            <tr>
              <th>סף ירוק / צהוב</th>
              <td style={{ fontVariantNumeric: "tabular-nums" }}>
                {current.minScoreForGreen} / {current.minScoreForYellow}
              </td>
            </tr>
            <tr>
              <th>ספקים נדרשים</th>
              <td dir="ltr" style={{ textAlign: "right" }}>
                {current.requireProvider.length === 0
                  ? <span className="muted small">ללא דרישה</span>
                  : current.requireProvider.join(", ")}
              </td>
            </tr>
          </tbody>
        </table>

        {note  !== null && <p className="muted">{note}</p>}
        {error !== null && <p className="error">{error}</p>}

        {editing && (
          <>
            <p className="muted small" style={{ marginTop: 12 }}>
              ההיתר עולה קרדיט אחד ונמסר למחשב בפעימה הבאה. המחשב מאמת אותו
              בעצמו, והרצפה שלמעלה תתעדכן רק אחרי שהוא דיווח שהחיל.
            </p>

            <label className="field">
              מצב אכיפה
              <select
                value={draft.mode}
                onChange={(e) => setDraft({ ...draft, mode: e.target.value as FloorSpec["mode"] })}
              >
                {(Object.keys(MODE) as FloorSpec["mode"][]).map((m) => (
                  <option key={m} value={m}>{MODE[m]}</option>
                ))}
              </select>
            </label>

            <label className="field">
              במצב אדום
              <select
                value={draft.onRedAction}
                onChange={(e) => setDraft({
                  ...draft, onRedAction: e.target.value as FloorSpec["onRedAction"],
                })}
              >
                {(Object.keys(ACTION) as FloorSpec["onRedAction"][]).map((a) => (
                  <option key={a} value={a}>{ACTION[a]}</option>
                ))}
              </select>
            </label>

            <label className="field">
              סף ירוק
              <input
                type="number" min={0} max={100} dir="ltr"
                value={draft.minScoreForGreen}
                onChange={(e) => setDraft({ ...draft, minScoreForGreen: Number(e.target.value) })}
              />
            </label>

            <label className="field">
              סף צהוב
              <input
                type="number" min={0} max={100} dir="ltr"
                value={draft.minScoreForYellow}
                onChange={(e) => setDraft({ ...draft, minScoreForYellow: Number(e.target.value) })}
              />
            </label>

            <label className="field">
              ספקים נדרשים, מופרדים בפסיק. ריק פירושו ללא דרישה.
              <input
                dir="ltr"
                value={providers}
                onChange={(e) => setProviders(e.target.value)}
                placeholder="netfree, rimon"
              />
            </label>

            <label className="field">
              סיבה, לתיעוד
              <input
                value={reason}
                maxLength={200}
                onChange={(e) => setReason(e.target.value)}
              />
            </label>

            <label className="field" style={{ flexDirection: "row", gap: 8, alignItems: "center" }}>
              <input type="checkbox" checked={waive} onChange={(e) => setWaive(e.target.checked)} />
              בלי לגבות קרדיט
            </label>

            <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
              <button className="danger" disabled={busy} onClick={() => void submit()}>
                {busy ? "מנפיק…" : "הנפק היתר"}
              </button>

              <button className="ghost" disabled={busy} onClick={() => setEditing(false)}>
                ביטול
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
