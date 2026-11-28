import { useEffect, useState } from "react";

import { ApiError, api } from "../api";
import { Logo } from "../components/Logo";

/**
 * הדף שהנאמן פותח מהקישור שקיבל בדוא"ל.
 *
 * הנאמן אינו משתמש במערכת. הוא אולי אינו יודע מה זה Filter+‎, ולכן
 * הדף אומר במילים מה מבקשים ממנו ומה יקרה בכל בחירה.
 *
 * פתיחת הדף אינה מאשרת דבר. תוכנות דוא"ל וסורקי אבטחה פותחים
 * קישורים לבד, ואישור אוטומטי היה מאשר בקשות שאיש לא קרא. ההחלטה
 * נעשית רק בלחיצה על כפתור.
 */

type Action = "accept" | "decline" | "approve" | "deny" | "approve_removal" | "stop_removal";

type Link =
  | { kind: "invite"; trusteeName: string; tenantName: string }
  | { kind: "request"; summary: string; tenantName: string; requesterName: string; createdAt: string }
  | { kind: "removal"; trusteeName: string; tenantName: string; effectiveAt: string };

export function TrusteeLink({
  token,
  by,
  onHome,
}: {
  token: string;
  by: string | null;
  onHome: () => void;
}): JSX.Element {
  const [link, setLink] = useState<Link | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.get<Link>(`/api/portal/v1/trustee/link?token=${encodeURIComponent(token)}`)
      .then(setLink)
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : "הקישור אינו תקף."));
  }, [token]);

  async function decide(action: Action) {
    setBusy(true);
    setError(null);

    try {
      const r = await api.post<{ note: string }>("/api/portal/v1/trustee/link", {
        token,
        action,
        ...(by !== null ? { by } : {}),
      });

      setDone(r.note);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "הפעולה נכשלה");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-wrap" id="main" role="main" tabIndex={-1}>
      <div className="auth-card trustee-card">
        <Logo size={40} />

        {done !== null ? (
          <>
            <h1>נרשם</h1>
            <p className="sub">{done}</p>
            <p className="muted small">אפשר לסגור את הדף.</p>
          </>
        ) : error !== null && link === null ? (
          <>
            <h1>הקישור אינו תקף</h1>
            <p className="sub">{error}</p>
            <p className="muted small">
              ייתכן שכבר ענית על הבקשה הזו, שמישהו אחר ענה עליה, או שהיא בוטלה.
            </p>
          </>
        ) : link === null ? (
          <p className="muted">טוען…</p>
        ) : link.kind === "invite" ? (
          <>
            <h1>{link.trusteeName}, ביקשו ממך להיות נאמן</h1>

            <p className="sub">
              של <b>{link.tenantName}</b>, ב-Filter+‎: סינון אינטרנט למחשבים.
            </p>

            <p className="muted small">
              נאמן הוא אדם שסומכים עליו. כשבעל החשבון ירצה להקל על הסינון או להסיר
              אותו, תקבל על כך דוא"ל, ואם כך הוגדר, השינוי לא יתבצע בלי אישורך.
              אין צורך בחשבון או בסיסמה, ואפשר לצאת מהתפקיד בהמשך.
            </p>

            {error !== null && <p className="error">{error}</p>}

            <div className="trustee-actions">
              <button className="primary" disabled={busy} onClick={() => void decide("accept")}>
                אני מקבל את התפקיד
              </button>
              <button disabled={busy} onClick={() => void decide("decline")}>לא, תודה</button>
            </div>
          </>
        ) : link.kind === "request" ? (
          <>
            <h1>בקשה לאישורך</h1>

            <p className="sub">
              <b>{link.requesterName}</b>, מ{link.tenantName}, מבקש:
            </p>

            <p className="trustee-ask">{link.summary}</p>

            <p className="muted small">
              הבקשה נשלחה ב-{new Date(link.createdAt).toLocaleString("he-IL", { dateStyle: "short", timeStyle: "short" })}.
              אם תאשר, בעל החשבון יוכל לבצע את הפעולה הזו, פעם אחת. אם תדחה, היא לא
              תתבצע. אין מועד אחרון, ואם אינך בטוח, עדיף לברר איתו לפני שמאשרים.
            </p>

            {error !== null && <p className="error">{error}</p>}

            <div className="trustee-actions">
              <button className="primary" disabled={busy} onClick={() => void decide("approve")}>
                אני מאשר
              </button>
              <button className="danger" disabled={busy} onClick={() => void decide("deny")}>
                אני דוחה
              </button>
            </div>
          </>
        ) : (
          <>
            <h1>מבקשים להסיר אותך מתפקיד הנאמן</h1>

            <p className="sub">
              של <b>{link.tenantName}</b>.
            </p>

            <p className="muted small">
              אם לא תעשה דבר, ההסרה תיכנס לתוקף ב-
              {new Date(link.effectiveAt).toLocaleString("he-IL", { dateStyle: "short", timeStyle: "short" })}.
              אחריה בעל החשבון יוכל להקל על הסינון בלי אישורך. אפשר לאשר את ההסרה
              עכשיו, או לעצור אותה ולהישאר בתפקיד.
            </p>

            {error !== null && <p className="error">{error}</p>}

            <div className="trustee-actions">
              <button className="primary" disabled={busy} onClick={() => void decide("stop_removal")}>
                עצור את ההסרה
              </button>
              <button disabled={busy} onClick={() => void decide("approve_removal")}>
                אני מאשר את ההסרה
              </button>
            </div>
          </>
        )}

        <button className="link muted-link" onClick={onHome}>לאתר Filter+‎</button>
      </div>
    </div>
  );
}
