import { useCallback, useEffect, useState } from "react";

import { api, ApiError } from "../api";
import { SupportLink } from "./SupportLink";

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

export function DeviceUninstall() {
  const [state, setState] = useState<PolicyState | null>(null);
  const [challenge, setChallenge] = useState("");
  const [code, setCode] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

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

      /*
       * העתקה מיד עם ההנפקה.
       *
       * הקוד קיים בשביל להיות מוקלד במסך שממתין במחשב, וכל צעד בין
       * ההנפקה לשם הוא הזדמנות לטעות — במיוחד בקוד שאין בו משמעות
       * לקרוא ולזכור.
       *
       * ההודעה חשובה לא פחות מההעתקה: העתקה שקטה ללוח היא בדיוק
       * הסוג שמישהו מבצע פעמיים ואז מדביק את הקודם.
       */
      try {
        await navigator.clipboard.writeText(r.code);
        setCopied(true);
        window.setTimeout(() => setCopied(false), 4000);
      } catch {
        // דפדפן שחוסם גישה ללוח. הקוד מוצג ממילא וניתן לסימון ידני.
        setCopied(false);
      }
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
        <h2>הסרת Filter+‎ ממחשב</h2>
      </div>

      <div className="panel-body">
        <p className="muted small">
          ההסרה נעשית במחשב עצמו, ודורשת קוד שרק מי שמחובר לחשבון הזה יכול
          להנפיק. מי שיושב מול המחשב אינו יכול להסיר את התוכנה בלי הקוד.
        </p>

        {state.policy === "support_only" ? (
          <>
            <p className="muted">
              בהתקנה נבחר שההסרה תיעשה דרך המוקד בלבד. במחשב שממנו מסירים, מריצים את{" "}
              <code dir="ltr">FilterPlus.Uninstaller.exe</code> מהתיקייה{" "}
              <code dir="ltr">C:\Program Files\FilterPlus</code>, ומוסרים לנציג את קוד
              הזיהוי שיופיע. השירות כרוך בתשלום.
            </p>

            {/*
              מזכיר שזו הבחירה שלו ולא מגבלה שהוטלה עליו. ברגע שבו
              הוא הכי מתפתה, זה ההבדל בין "המערכת מציקה לי" לבין
              "החלטתי כך כשהייתי צלול".
            */}
            <p className="muted small">
              זו הבחירה שנעשתה בהתקנה, ושינוי שלה עובר גם הוא דרך המוקד.
            </p>

            {/*
              ועם כתובת.

              המסך אמר "יש לפנות למוקד" ולא אמר איך — מבוי סתום
              בדיוק ברגע שבו ההורה הכי צריך עזרה.
            */}
            <SupportLink prefix="פנייה למוקד:" />
          </>
        ) : (
          <>
            <ol className="steps">
              <li>
                במחשב שממנו מסירים, פותחים את התיקייה{" "}
                <code dir="ltr">C:\Program Files\FilterPlus</code> ומריצים את{" "}
                <code dir="ltr">FilterPlus.Uninstaller.exe</code>.
              </li>
              <li>חלון ההסרה מציג <b>קוד זיהוי</b>. מעתיקים אותו לשדה שכאן למטה.</li>
              <li>לוחצים "הנפק קוד הסרה", ומקבלים כאן <b>קוד הסרה</b>.</li>
              <li>מקלידים את קוד ההסרה בחלון ההסרה שבמחשב, והתוכנה מוסרת.</li>
            </ol>

            <p className="muted small">
              קוד ההסרה מתאים רק למחשב שהציג את קוד הזיהוי, ורק לזמן קצר. כל הנפקה
              נרשמת, ונשלחת עליה התראה.
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
                <p className="muted small">
                  {copied
                    ? "הקוד הועתק ללוח. הדבק אותו במסך ההסרה שבמחשב:"
                    : "הקלד את הקוד הזה במסך ההסרה שבמחשב:"}
                </p>

                <code dir="ltr">{code}</code>

                <button
                  className="ghost"
                  onClick={() => {
                    navigator.clipboard.writeText(code).then(
                      () => {
                        setCopied(true);
                        window.setTimeout(() => setCopied(false), 4000);
                      },
                      () => setError("הדפדפן חסם את ההעתקה. אפשר לסמן את הקוד ידנית."),
                    );
                  }}
                >
                  {copied ? "הועתק ✓" : "העתק שוב"}
                </button>

                <p className="muted small">ההנפקה תועדה.</p>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
