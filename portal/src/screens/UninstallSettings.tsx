import { useCallback, useEffect, useState } from "react";

import { api, ApiError } from "../api";

/**
 * הסרת התוכנה — ההגדרה, וההנפקה.
 *
 * שני חלקים באותו מסך, ובכוונה. מי שמגיע לכאן מגיע בשביל אחד
 * מהשניים, ולפצל אותם לשתי לשוניות היה מחייב אותו לדעת מראש איזה
 * מהם הוא צריך.
 *
 * ההגדרה נבחרת בהתקנה ואז ננעלת. זה אינו קישוח טכני אלא כל התכלית:
 * מי שקנה את המוצר כדי לגדור את עצמו יודע שברגע החולשה הוא ימצא כל
 * דרך, ולכן הוא בוחר מראש שתהיה דרך אחת שעוברת דרך אדם אחר. גדר
 * שאפשר לפתוח מבפנים גרועה מהיעדר גדר.
 */

type Policy = "self_service" | "support_only";

interface PolicyState {
  policy: Policy;
  locked: boolean;
  chosenAt: string | null;
}

export function UninstallSettings() {
  const [state, setState] = useState<PolicyState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const [challenge, setChallenge] = useState("");
  const [code, setCode] = useState<string | null>(null);
  const [issueError, setIssueError] = useState<string | null>(null);
  const [issuing, setIssuing] = useState(false);

  const load = useCallback(async () => {
    try {
      setState(await api.get<PolicyState>("/api/portal/v1/uninstall/policy"));
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "טעינת ההגדרה נכשלה");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function choose(policy: Policy) {
    setSaving(true);
    setError(null);

    try {
      await api.post("/api/portal/v1/uninstall/policy", { policy });

      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "השמירה נכשלה");
    } finally {
      setSaving(false);
    }
  }

  async function issue() {
    setIssuing(true);
    setIssueError(null);
    setCode(null);

    try {
      const r = await api.post<{ code: string }>(
        "/api/portal/v1/uninstall/self", { challenge: challenge.trim() });

      setCode(r.code);
    } catch (e) {
      setIssueError(e instanceof ApiError ? e.message : "ההנפקה נכשלה");
    } finally {
      setIssuing(false);
    }
  }

  if (state === null) {
    return <section className="panel"><div className="panel-body">{error ?? "טוען..."}</div></section>;
  }

  return (
    <>
      <section className="panel">
        <div className="panel-head">איך מסירים את SafeMe מהמחשב</div>
        <div className="panel-body">

        {state.locked ? (
          <>
            <p className="warn-text">
              {state.policy === "self_service"
                ? "בחרת שתוכל להסיר בעצמך, מכאן."
                : "בחרת שההסרה תיעשה דרך המוקד בלבד."}
            </p>

            {/*
              הניסוח מזכיר שזו הבחירה שלו ולא מגבלה שהוטלה עליו.
              ברגע שבו הוא הכי מתפתה, זה ההבדל בין "המערכת מציקה לי"
              לבין "החלטתי כך כשהייתי צלול".
            */}
            <p className="muted">
              הבחירה נעשית פעם אחת, בהתקנה. שינוי שלה — לכל כיוון — עובר דרך
              המוקד ובתשלום. זה מה שהופך אותה למשמעותית: הגדרה שאפשר להחזיר
              לאחור בשתיים בלילה אינה מגבילה איש.
            </p>

            {state.chosenAt && (
              <p className="muted small">
                נבחר ב-{new Date(state.chosenAt).toLocaleString("he-IL")}
              </p>
            )}
          </>
        ) : (
          <>
            <p className="muted">
              בחר עכשיו. אחרי הבחירה, שינוי יעבור דרך המוקד ובתשלום.
            </p>

            <div className="choices">
              <button
                className="choice"
                disabled={saving}
                onClick={() => void choose("self_service")}
              >
                <b>אני אסיר בעצמי</b>
                <span>
                  תוכל להנפיק לעצמך קוד הסרה מהמסך הזה, בכל שעה, בלי לפנות
                  לאיש. נוח, ותלוי רק בך.
                </span>
              </button>

              <button
                className="choice"
                disabled={saving}
                onClick={() => void choose("support_only")}
              >
                <b>רק דרך המוקד</b>
                <span>
                  הסרה תדרוש שיחה עם אדם, ותהיה כרוכה בתשלום. בחר בזה אם
                  אתה יודע שברגע החולשה תחפש דרך.
                </span>
              </button>
            </div>
          </>
        )}

          {error && <p className="error">{error}</p>}
        </div>
      </section>

      {state.locked && state.policy === "self_service" && (
        <section className="panel">
          <div className="panel-head">הנפקת קוד הסרה</div>
          <div className="panel-body">

          <p className="muted">
            הרץ את ההסרה על המחשב. יופיע קוד זיהוי — הדבק אותו כאן, וקבל
            בחזרה את קוד ההסרה.
          </p>

          <label className="field">
            קוד הזיהוי מהמחשב
            <input
              value={challenge}
              onChange={(e) => setChallenge(e.target.value)}
              placeholder="למשל ABCD-EFGH-..."
              spellCheck={false}
              dir="ltr"
            />
          </label>

          <button
            disabled={issuing || challenge.trim().length < 20}
            onClick={() => void issue()}
          >
            {issuing ? "מנפיק..." : "הנפק קוד הסרה"}
          </button>

          {issueError && <p className="error">{issueError}</p>}

          {code && (
            <div className="issued">
              <p className="muted small">הקלד את הקוד הזה במסך ההסרה שבמחשב:</p>
              <code dir="ltr">{code}</code>
              <p className="muted small">
                ההנפקה תועדה. הקוד תקף למחשב הזה בלבד.
              </p>
            </div>
          )}
          </div>
        </section>
      )}

      {state.locked && state.policy === "support_only" && (
        <section className="panel">
          <div className="panel-head">הסרה</div>
          <div className="panel-body">
          <p className="muted">
            ההסרה עוברת דרך המוקד. הרץ את ההסרה על המחשב, ומסור לנציג את קוד
            הזיהוי שיופיע. השירות כרוך בתשלום.
          </p>
          </div>
        </section>
      )}
    </>
  );
}
