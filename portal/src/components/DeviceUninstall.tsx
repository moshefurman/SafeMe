import { useCallback, useEffect, useState } from "react";

import { api, ApiError } from "../api";

/**
 * הסרת התוכנה מהמחשב הזה.
 *
 * יושב בתוך מסך המחשב ולא בלשונית נפרדת, כי כאן ההורה כבר יודע על
 * איזה מחשב מדובר. לשונית נפרדת הייתה מחייבת אותו להעביר קוד זיהוי
 * בין שני מסכים ולזכור לאיזה מחשב הוא שייך.
 *
 * מה שמוצג תלוי במה שנבחר בהתקנה. מי שבחר במוקד לא יראה כאן שדה
 * שיתסכל אותו, אלא הסבר מה לעשות.
 */

type Policy = "self_service" | "support_only";

interface PolicyState {
  policy: Policy;
  locked: boolean;
}

export function DeviceUninstall({ deviceName }: { deviceName: string }) {
  const [state, setState] = useState<PolicyState | null>(null);
  const [challenge, setChallenge] = useState("");
  const [code, setCode] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setState(await api.get<PolicyState>("/api/portal/v1/uninstall/policy"));
    } catch {
      /*
       * כשל בטעינת ההגדרה אינו מוצג כשגיאה.
       *
       * זה אזור משני במסך, וכישלון בו לא אמור לצבוע את כל דף
       * המחשב באדום. מה שקורה הוא שהאזור פשוט לא מופיע.
       */
      setState(null);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function issue() {
    setBusy(true);
    setError(null);
    setCode(null);

    try {
      const r = await api.post<{ code: string }>(
        "/api/portal/v1/uninstall/self", { challenge: challenge.trim() });

      setCode(r.code);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "ההנפקה נכשלה");
    } finally {
      setBusy(false);
    }
  }

  if (state === null) return null;

  return (
    <div className="panel" style={{ marginBottom: 16 }}>
      <div className="panel-head">
        <h2>הסרת SafeMe מ{deviceName}</h2>
      </div>

      <div className="panel-body">
        {state.policy === "support_only" ? (
          <>
            <p className="muted">
              בהתקנה נבחר שההסרה תיעשה דרך המוקד בלבד. הרץ את ההסרה על המחשב,
              ומסור לנציג את קוד הזיהוי שיופיע. השירות כרוך בתשלום.
            </p>

            {/*
              מזכיר שזו הבחירה שלו ולא מגבלה שהוטלה עליו. ברגע שבו
              הוא הכי מתפתה, זה ההבדל בין "המערכת מציקה לי" לבין
              "החלטתי כך כשהייתי צלול".
            */}
            <p className="muted small">
              זו הבחירה שנעשתה בהתקנה, ושינוי שלה עובר גם הוא דרך המוקד.
            </p>
          </>
        ) : (
          <>
            <p className="muted">
              הרץ את ההסרה על המחשב. יופיע קוד זיהוי — הדבק אותו כאן, וקבל
              בחזרה את קוד ההסרה.
            </p>

            <label className="field">
              קוד הזיהוי מהמחשב
              <input
                value={challenge}
                onChange={(e) => setChallenge(e.target.value)}
                spellCheck={false}
                dir="ltr"
              />
            </label>

            <button disabled={busy || challenge.trim().length < 20} onClick={() => void issue()}>
              {busy ? "מנפיק..." : "הנפק קוד הסרה"}
            </button>

            {error && <p className="error">{error}</p>}

            {code && (
              <div className="issued">
                <p className="muted small">הקלד את הקוד הזה במסך ההסרה שבמחשב:</p>
                <code dir="ltr">{code}</code>
                <p className="muted small">ההנפקה תועדה.</p>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
