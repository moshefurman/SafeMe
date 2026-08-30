import { useCallback, useState } from "react";

import { api, ApiError } from "../api";

/**
 * מסך המוקד להנפקת קודי הסרה.
 *
 * זו הפעולה הרגישה ביותר במוצר, ולכן המסך בנוי בשני שלבים ולא
 * באחד: קודם מברר של מי המחשב, ורק אחרי שהנציג אישר שאימת זהות
 * מונפק הקוד.
 *
 * ההפרדה אינה בירוקרטיה. נציג שרואה את הקוד באותו מסך שבו מופיעים
 * פרטי החשבון עלול למסור אותו לפני שאימת — ושני מסכים הופכים את
 * האימות לצעד שקורה, ולא לצעד שמניחים שקרה.
 */

interface Device {
  name: string;
  tenantName: string;
  ownerEmail: string | null;
  status: string;
  lastSeenAt: string | null;
}

interface Lookup {
  issuedUtc: string;
  ageMinutes: number;
  offlineEmergency: boolean;
  device: Device | null;
}

export function UninstallDesk(): JSX.Element {
  const [challenge, setChallenge] = useState("");
  const [lookup, setLookup] = useState<Lookup | null>(null);
  const [code, setCode] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [verified, setVerified] = useState(false);
  const [reason, setReason] = useState("");

  const reset = useCallback(() => {
    setLookup(null);
    setCode(null);
    setNote(null);
    setVerified(false);
    setReason("");
  }, []);

  const find = useCallback(async () => {
    setBusy(true);
    setError(null);
    reset();

    try {
      setLookup(await api.post<Lookup>("/api/portal/v1/uninstall/lookup", {
        challenge: challenge.trim(),
      }));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "פענוח קוד האתגר נכשל");
    } finally {
      setBusy(false);
    }
  }, [challenge, reset]);

  const issue = useCallback(async () => {
    setBusy(true);
    setError(null);

    try {
      const r = await api.post<{ code: string; note: string }>(
        "/api/portal/v1/uninstall/issue",
        { challenge: challenge.trim(), identityVerified: true, reason: reason.trim() },
      );

      setCode(r.code);
      setNote(r.note);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "הנפקת הקוד נכשלה");
    } finally {
      setBusy(false);
    }
  }, [challenge, reason]);

  // האתגר תקף שלושים דקות. אחריהן ההנפקה תיכשל אצל הלקוח.
  const stale = lookup !== null && lookup.ageMinutes > 30;

  return (
    <>
      <h1>הנפקת קוד הסרה</h1>

      {error !== null && <p className="error">{error}</p>}

      <section className="panel">
        <div className="panel-head">
          <h2>1 · קוד האתגר מהלקוח</h2>
        </div>

        <div className="panel-body">
          <p className="muted small">
            הלקוח מקריא 36 תווים ממסך ההסרה. אפשר להקליד עם או בלי מקפים.
          </p>

          <input
            className="mono"
            style={{ width: "100%" }}
            placeholder="040YCS-NN2A5K-FP0J82-0VM081-081G81-863PBG"
            value={challenge}
            disabled={busy}
            onChange={(e) => setChallenge(e.target.value)}
          />

          <button disabled={busy || challenge.trim().length < 20} onClick={() => void find()}>
            מי זה?
          </button>
        </div>
      </section>

      {lookup !== null && (
        <section className="panel" style={{ marginTop: 16 }}>
          <div className="panel-head">
            <h2>2 · אימות זהות</h2>
            {stale && <span className="pill warn">האתגר פג</span>}
          </div>

          <div className="panel-body">
            {stale && (
              <p className="warn-text">
                האתגר הופק לפני {lookup.ageMinutes} דקות והוא תקף ל-30 בלבד.
                בקשו מהלקוח להפיק קוד חדש — הנפקה עכשיו לא תתקבל אצלו.
              </p>
            )}

            {lookup.device === null ? (
              <p className="warn-text">
                המחשב אינו מוכר במסד. ייתכן שהוא נרשם לחשבון אחר, או שההתקנה
                בוצעה ללא חשבון. אפשר להנפיק, וההנפקה תתועד — אך אין מול מה
                לאמת כאן.
              </p>
            ) : (
              <table className="rows">
                <tbody>
                  <tr><td>מחשב</td><td><b>{lookup.device.name}</b></td></tr>
                  <tr><td>חשבון</td><td>{lookup.device.tenantName}</td></tr>
                  <tr><td>בעל החשבון</td><td>{lookup.device.ownerEmail ?? "—"}</td></tr>
                  <tr><td>מצב</td><td>{lookup.device.status}</td></tr>
                  <tr>
                    <td>דיווח אחרון</td>
                    <td>
                      {lookup.device.lastSeenAt === null
                        ? "מעולם"
                        : new Date(lookup.device.lastSeenAt).toLocaleString("he-IL")}
                    </td>
                  </tr>
                </tbody>
              </table>
            )}

            <p className="muted small">
              אמתו מול הפרטים שנרשמו בפתיחת החשבון לפני שממשיכים.
            </p>

            <label style={{ width: "100%" }}>
              סיבת ההסרה
              <input
                placeholder="לדוגמה: המחשב נמכר"
                value={reason}
                disabled={busy}
                onChange={(e) => setReason(e.target.value)}
              />
            </label>

            <label className="check">
              <input
                type="checkbox"
                checked={verified}
                disabled={busy}
                onChange={(e) => setVerified(e.target.checked)}
              />
              אימתי את זהות הפונה מול פרטי החשבון
            </label>

            <button
              className="danger"
              disabled={busy || !verified || reason.trim().length < 3}
              onClick={() => void issue()}
            >
              הנפק קוד הסרה
            </button>
          </div>
        </section>
      )}

      {code !== null && (
        <section className="panel" style={{ marginTop: 16 }}>
          <div className="panel-head">
            <h2>3 · הקוד ללקוח</h2>
          </div>

          <div className="panel-body">
            {note !== null && <p className="muted small">{note}</p>}

            <textarea className="mono" readOnly rows={5} value={code}
                      style={{ width: "100%" }} />

            <button
              onClick={() => {
                void navigator.clipboard.writeText(code).catch(() => undefined);
              }}
            >
              העתק
            </button>

            <p className="muted small">
              הקוד ארוך מכדי להקראה בטלפון. שלחו אותו לכתובת שרשומה בחשבון.
            </p>
          </div>
        </section>
      )}
    </>
  );
}
