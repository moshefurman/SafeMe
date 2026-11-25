import { useCallback, useEffect, useState } from "react";

import { api, ApiError, setCsrfToken } from "../api";
import { Logo } from "../components/Logo";

/**
 * השלמת הרשמה שהתחילה ב-Google.
 *
 * Google מאמת מי המשתמש, ולא יותר מזה. שם החשבון וארבע הספרות של
 * תעודת הזהות הם דברים שהוא אינו יודע — והשניים האלה נחוצים: הספרות
 * הן העוגן היחיד לאימות הסרה בתקופת הניסיון, כי אין כרטיס אשראי.
 *
 * לכן זה מסך ולא שאלה שאפשר לדלג עליה. מה שכן נחסך מהמשתמש הוא
 * הסיסמה, אימות המייל, והקלדת הכתובת.
 */
export function GoogleComplete({
  onDone,
  onCancel,
}: {
  onDone: () => void;
  onCancel: () => void;
}): JSX.Element {
  const [pending, setPending] = useState<{ email: string; name: string | null } | null>(null);
  const [accountType, setAccountType] = useState<"family" | "business">("family");
  const [accountName, setAccountName] = useState("");
  const [idLast4, setIdLast4] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [expired, setExpired] = useState(false);

  useEffect(() => {
    void api
      .get<{ email: string; name: string | null }>("/api/portal/v1/auth/google/pending")
      .then((p) => {
        setPending(p);

        // הצעה לשם החשבון מהשם ב-Google. ניתן לשינוי, אבל חוסך
        // הקלדה למי שממילא היה כותב את אותו דבר.
        if (p.name !== null) setAccountName(`משפחת ${p.name.split(" ").at(-1) ?? p.name}`);
      })
      .catch(() => setExpired(true));
  }, []);

  const submit = useCallback(async () => {
    setBusy(true);
    setError(null);

    try {
      const result = await api.post<{ csrfToken: string }>(
        "/api/portal/v1/auth/google/complete",
        { accountType, accountName, idLast4 },
      );

      setCsrfToken(result.csrfToken);
      onDone();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "פתיחת החשבון נכשלה");

      if (e instanceof ApiError && e.status === 410) setExpired(true);
    } finally {
      setBusy(false);
    }
  }, [accountType, accountName, idLast4, onDone]);

  if (expired) {
    return (
      <div className="auth-wrap">
        <div className="auth-card" style={{ maxWidth: 440 }}>
          <Logo size={40} />

          <h1>ההרשמה פגה</h1>

          <p className="sub">
            עברו יותר מרבע שעה מאז הכניסה דרך Google. יש להתחיל מחדש — שום דבר
            לא נשמר.
          </p>

          <div className="auth-foot">
            <button className="link" onClick={onCancel}>
              ← חזרה לאתר
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (pending === null) return <p className="muted">טוען…</p>;

  const ready = accountName.trim().length >= 2 && /^\d{4}$/.test(idLast4);

  return (
    <div className="auth-wrap">
      <div className="auth-card" style={{ maxWidth: 440 }}>
        <Logo size={40} />

        <h1>עוד שני פרטים</h1>

        <p className="sub">
          נכנסת כ-<b dir="ltr">{pending.email}</b>. אין צורך בסיסמה ואין צורך
          לאמת את הכתובת.
        </p>

        {error !== null && <div className="error">{error}</div>}

        <label>
          סוג החשבון
          <select
            value={accountType}
            disabled={busy}
            onChange={(e) => setAccountType(e.target.value as "family" | "business")}
          >
            <option value="family">משפחה</option>
            <option value="business">ארגון</option>
          </select>
        </label>

        <label>
          שם החשבון
          <input
            value={accountName}
            disabled={busy}
            maxLength={120}
            placeholder="משפחת כהן"
            onChange={(e) => setAccountName(e.target.value)}
          />
        </label>

        <label>
          ארבע ספרות אחרונות של תעודת הזהות
          <input
            dir="ltr"
            inputMode="numeric"
            maxLength={4}
            value={idLast4}
            disabled={busy}
            placeholder="1234"
            onChange={(e) => setIdLast4(e.target.value.replace(/\D/g, ""))}
          />
        </label>

        <p className="muted small">
          זו הדרך שבה המוקד יוודא שאתה זה אתה כשתבקש קוד הסרה. בתקופת הניסיון
          אין כרטיס אשראי, ולכן זה העוגן היחיד. נשמר מגובב, לא כטקסט.
        </p>

        <button
          className="primary"
          disabled={!ready || busy}
          onClick={() => void submit()}
        >
          {busy ? "פותח חשבון..." : "התחל 30 יום ניסיון"}
        </button>

        <div className="auth-foot">
          <button className="link muted-link" onClick={onCancel}>
            ← ביטול
          </button>
        </div>
      </div>
    </div>
  );
}
