import { useCallback, useEffect, useState } from "react";

import { api, ApiError } from "../api";

/**
 * אבטחת החשבון.
 *
 * עד כה אימות דו-שלבי היה קיים בשרת אך נגיש רק לצוות החברה, ולא
 * מפני שהוחלט כך — פשוט לא היה מסך. הורה שרצה להפעיל אותו לא יכול
 * היה, וזה החשבון ששולט על ההגנה של כל מחשבי הבית: מי שנכנס אליו
 * יכול לאשר רשתות, להקל מדיניות, ולהנפיק קוד הסרה.
 *
 * הכיבוי דורש קוד ולא סיסמה. מי שהשיג פעילות פתוחה — מחשב שנשאר
 * פתוח — היה מכבה בלחיצה את ההגנה שנועדה בדיוק לזה.
 */

interface Me {
  role: string;
  mfaEnrolled: boolean;
}

type Stage = "idle" | "enrolling" | "disabling";

export function Security(): JSX.Element {
  const [me, setMe] = useState<Me | null>(null);
  const [stage, setStage] = useState<Stage>("idle");
  const [secret, setSecret] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setMe(await api.get<Me>("/api/portal/v1/auth/me"));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "טעינת החשבון נכשלה");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function begin() {
    setBusy(true);
    setError(null);

    try {
      const r = await api.post<{ secret: string }>("/api/portal/v1/auth/mfa/enroll");

      setSecret(r.secret);
      setStage("enrolling");
      setCode("");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "ההפעלה נכשלה");
    } finally {
      setBusy(false);
    }
  }

  async function submit() {
    setBusy(true);
    setError(null);

    const path = stage === "enrolling"
      ? "/api/portal/v1/auth/mfa/confirm"
      : "/api/portal/v1/auth/mfa/disable";

    try {
      await api.post(path, { code: code.trim() });

      setNote(stage === "enrolling"
        ? "האימות הדו-שלבי פעיל. בכניסה הבאה יידרש קוד."
        : "האימות הדו-שלבי כובה.");

      setStage("idle");
      setSecret(null);
      setCode("");

      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "הקוד שגוי");
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  if (me === null) return <main className="shell"><p className="muted">טוען…</p></main>;

  const platform = me.role === "platform_admin" || me.role === "support_operator";

  return (
    <main className="shell">
      <h2>אבטחת החשבון</h2>

      <div className="panel">
        <div className="panel-head">
          <h3>אימות דו-שלבי</h3>
        </div>

        <div className="panel-body">
          <p className="muted">
            {me.mfaEnrolled
              ? "פעיל. בכל כניסה יידרש קוד מאפליקציית האימות."
              : "כבוי. סיסמה לבדה פותחת את החשבון."}
          </p>

          {/*
            למה זה חשוב דווקא בחשבון הזה.

            נאמר במפורש ולא כסיסמה כללית על אבטחה: מי שנכנס לחשבון
            הזה יכול לאשר רשתות, להקל מדיניות ולהנפיק קוד הסרה —
            כלומר לפרק את ההגנה מבלי לגעת במחשב.
          */}
          {!me.mfaEnrolled && (
            <p className="muted small">
              מי שנכנס לחשבון הזה יכול לאשר רשתות, להקל מדיניות ולהנפיק קוד הסרה —
              כלומר לפרק את ההגנה בלי לגעת במחשב.
            </p>
          )}

          {note  !== null && <p className="muted">{note}</p>}
          {error !== null && <p className="error">{error}</p>}

          {stage === "idle" ? (
            me.mfaEnrolled ? (
              platform ? (
                <p className="muted small">
                  אימות דו-שלבי הוא חובה לחשבונות ניהול ואינו ניתן לכיבוי.
                </p>
              ) : (
                <button
                  className="ghost"
                  disabled={busy}
                  onClick={() => { setStage("disabling"); setCode(""); setNote(null); }}
                >
                  כיבוי אימות דו-שלבי
                </button>
              )
            ) : (
              <button className="primary" disabled={busy} onClick={() => void begin()}>
                {busy ? "מכין…" : "הפעל אימות דו-שלבי"}
              </button>
            )
          ) : (
            <>
              {secret !== null && (
                <>
                  <p className="muted small">
                    הזן את המפתח באפליקציית אימות (Google Authenticator, Authy וכדומה),
                    ואז הקלד את הקוד שהיא מציגה.
                  </p>

                  {/*
                    המפתח בבלוק נפרד וניתן לסימון.

                    הוא מוצג פעם אחת: אחרי האישור הוא כבר לא יוחזר,
                    ומי שלא שמר אותו יצטרך להתחיל מהתחלה.
                  */}
                  <code dir="ltr" className="dl-url">{secret}</code>
                </>
              )}

              {stage === "disabling" && (
                <p className="muted small">
                  הקלד קוד מאפליקציית האימות כדי לאשר את הכיבוי.
                </p>
              )}

              <label className="field">
                קוד בן שש ספרות
                <input
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength={6}
                  dir="ltr"
                />
              </label>

              <div style={{ display: "flex", gap: 8 }}>
                <button
                  className="primary"
                  disabled={busy || code.trim().length !== 6}
                  onClick={() => void submit()}
                >
                  {busy ? "בודק…" : stage === "enrolling" ? "אשר והפעל" : "אשר וכבה"}
                </button>

                <button
                  className="ghost"
                  disabled={busy}
                  onClick={() => { setStage("idle"); setSecret(null); setCode(""); setError(null); }}
                >
                  ביטול
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </main>
  );
}
