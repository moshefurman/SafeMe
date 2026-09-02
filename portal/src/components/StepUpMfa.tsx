import { useCallback, useEffect, useRef, useState } from "react";

import { api, setStepUpHandler } from "../api";

/**
 * אימות שני באמצע העבודה.
 *
 * פעולות רגישות דורשות אימות מהחמש דקות האחרונות. הדרישה נכונה —
 * מי שהשאיר מחשב פתוח לא אמור לשנות דרכו הגדרות מערכת — אבל
 * הפורטל טיפל בה רק בטעינה הראשונה, ולכן המשתמש קיבל שגיאה בלי
 * שום דרך לספק את מה שהיא מבקשת.
 *
 * זה נצפה בשטח: שמירת הגדרות הדואר נכשלה שוב ושוב, והדרך היחידה
 * הייתה לצאת ולהיכנס מחדש.
 *
 * הרכיב יושב במעטפת ומקבל שליטה מכל בקשה שנתקלת בדרישה. אחרי
 * אימות מוצלח הבקשה המקורית נשלחת שוב, פעם אחת — כך שמבחינת
 * המשתמש הפעולה פשוט הצליחה.
 */
export function StepUpMfa(): JSX.Element | null {
  const [open, setOpen] = useState(false);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  /*
   * ההבטחה של הבקשה הממתינה.
   *
   * ב-ref ולא ב-state: היא נקבעת בתוך המטפל ונקראת מתוך אירוע
   * אחר לגמרי, ורינדור מחדש בין השניים היה מאבד אותה.
   */
  const resolver = useRef<((ok: boolean) => void) | null>(null);

  useEffect(() => {
    setStepUpHandler(() => new Promise<boolean>((resolve) => {
      resolver.current = resolve;

      setCode("");
      setError(null);
      setOpen(true);
    }));

    return () => setStepUpHandler(null);
  }, []);

  const finish = useCallback((ok: boolean) => {
    setOpen(false);

    resolver.current?.(ok);
    resolver.current = null;
  }, []);

  async function submit() {
    setBusy(true);
    setError(null);

    try {
      await api.post("/api/portal/v1/auth/mfa/verify", { code: code.trim() });

      finish(true);
    } catch {
      setError("הקוד שגוי. נסה שוב.");
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  if (!open) return null;

  return (
    <div className="modal-back">
      <div className="modal">
        <h3>נדרש אימות דו-שלבי</h3>

        <p className="muted small">
          הפעולה שביקשת משנה הגדרות מערכת, ולכן היא דורשת קוד עדכני מאפליקציית
          האימות. אחרי האישור הפעולה תימשך מעצמה.
        </p>

        <label className="field">
          קוד בן שש ספרות
          <input
            autoFocus
            value={code}
            onChange={(e) => setCode(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && code.trim().length === 6) void submit(); }}
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            dir="ltr"
          />
        </label>

        {error !== null && <p className="error">{error}</p>}

        <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
          <button
            className="primary"
            disabled={busy || code.trim().length !== 6}
            onClick={() => void submit()}
          >
            {busy ? "בודק…" : "אשר"}
          </button>

          {/*
            ביטול מחזיר false, והבקשה המקורית נכשלת כרגיל.
            מסך שאי אפשר לצאת ממנו הוא מלכודת, גם כשהוא צודק.
          */}
          <button className="ghost" disabled={busy} onClick={() => finish(false)}>
            ביטול
          </button>
        </div>
      </div>
    </div>
  );
}
