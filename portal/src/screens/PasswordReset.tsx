import { useState } from "react";

import { api, ApiError } from "../api";
import { Logo } from "../components/Logo";

/**
 * שני מסכים של אותו מסלול: בקשת קישור, וקביעת סיסמה חדשה.
 *
 * עד כה לא היה שום מסלול התאוששות — משתמש ששכח סיסמה היה נעול
 * מחוץ לחשבון, ומנהל הפלטפורמה נחלץ רק דרך סקריפט שרץ כבעל
 * הסכמה. עם אלפי הורים זו פנייה שבועית קבועה למוקד על משהו
 * שאמור לפתור את עצמו.
 *
 * מה שהמסך אומר, ומה שהוא נזהר לא לומר: התשובה זהה בין כתובת
 * רשומה לשאינה רשומה. מסך שמבדיל הופך את עצמו לכלי לגילוי מי
 * לקוח — ואצל מוצר שכל תכליתו סינון בבית, רשימת לקוחות היא מידע
 * רגיש בפני עצמו.
 */
export function PasswordReset({
  token,
  onDone,
}: {
  /** קיים כשהגענו מקישור במייל. null במסך הבקשה. */
  token: string | null;
  onDone: () => void;
}): JSX.Element {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function requestLink(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);

    try {
      const r = await api.post<{ note: string }>(
        "/api/portal/v1/auth/password/forgot", { email: email.trim() });

      setNote(r.note);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "הבקשה נכשלה");
    } finally {
      setBusy(false);
    }
  }

  async function setNew(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);

    try {
      const r = await api.post<{ note: string }>(
        "/api/portal/v1/auth/password/reset", { token, password });

      setNote(r.note);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "האיפוס נכשל");
    } finally {
      setBusy(false);
    }
  }

  const mismatch = confirm.length > 0 && password !== confirm;

  return (
    <div className="auth-wrap" id="main" role="main" tabIndex={-1}>
      <div className="auth-card">
        <button className="auth-back" onClick={onDone}>← חזרה להתחברות</button>

        <Logo size={40} />

        <h1>{token === null ? "איפוס סיסמה" : "סיסמה חדשה"}</h1>

        {note !== null ? (
          <>
            <p className="muted">{note}</p>

            <button className="primary" onClick={onDone}>להתחברות</button>
          </>
        ) : token === null ? (
          <form onSubmit={(e) => void requestLink(e)}>
            <p className="muted small">
              הזן את כתובת האימייל של החשבון. אם היא רשומה, יישלח אליה קישור לקביעת
              סיסמה חדשה.
            </p>

            <label className="field">
              כתובת אימייל
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
                dir="ltr"
                required
              />
            </label>

            {error !== null && <p className="error">{error}</p>}

            <button className="primary" type="submit" disabled={busy}>
              {busy ? "שולח…" : "שלח קישור"}
            </button>
          </form>
        ) : (
          <form onSubmit={(e) => void setNew(e)}>
            <p className="muted small">
              הסיסמה חייבת להיות באורך עשרה תווים לפחות. אחרי השינוי כל החיבורים
              הפתוחים לחשבון יינתקו.
            </p>

            <label className="field">
              סיסמה חדשה
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
                dir="ltr"
                required
              />
            </label>

            <label className="field">
              שוב, לאימות
              <input
                type="password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                autoComplete="new-password"
                dir="ltr"
                required
              />
            </label>

            {/*
              אי-התאמה נאמרת מיד ולא אחרי השליחה.

              סיסמה שהוקלדה פעמיים בשגיאה היא הדבר היחיד כאן שאפשר
              לתפוס בלי השרת, וכשל שחוזר מהשרת על משהו שידענו כבר
              הוא סיבוב מיותר על מסך שממילא מתסכל.
            */}
            {mismatch && <p className="error">הסיסמאות אינן זהות</p>}
            {error !== null && <p className="error">{error}</p>}

            <button
              className="primary"
              type="submit"
              disabled={busy || mismatch || password.length < 10}
            >
              {busy ? "מחליף…" : "קבע סיסמה"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
