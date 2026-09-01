import { useCallback, useState } from "react";

import { api, ApiError } from "../api";
import { ActiveLinks } from "./ActiveLinks";

/**
 * הוספת מחשב.
 *
 * כל מה שההורה צריך לעשות הוא להוריד קובץ ולהריץ אותו. אין קוד
 * להקליד ואין הגדרה למלא — האסימון יושב בשם הקובץ, והמתקין קורא
 * אותו משם.
 *
 * זה גם למה הכפתור מוריד ולא מציג קוד: ברגע שמישהו מעתיק קוד
 * ומדביק אותו, נפתחת דרך לטעות שאי אפשר לאבחן מרחוק.
 *
 * ובכל זאת יש כאן גם קוד, כי המצב שבו הוא נדרש קיים: מתקין שכבר
 * הורד, קובץ שהדפדפן שינה את שמו, או התקנה במחשב שאין בו גישה
 * לחשבון. בלי כפתור, מי שנזקק לקוד חילץ אותו ידנית מתוך הקישור
 * המלא — וזה בדיוק המקום שבו נופלת טעות.
 */
interface Issued {
  fileName: string;
  downloadPath: string;
  expiresAt: string;
  maxUses: number;
}

export function AddDevice(): JSX.Element {
  const [issued, setIssued] = useState<Issued | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const [copiedCode, setCopiedCode] = useState(false);

  const issue = useCallback(async () => {
    setBusy(true);
    setError(null);

    try {
      setIssued(
        await api.post<Issued>("/api/portal/v1/enroll-tokens", {
          installProfile: "family_child",
          maxUses: 3,
          expiresInDays: 30,
        }),
      );
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "יצירת הקישור נכשלה");
    } finally {
      setBusy(false);
    }
  }, []);

  /*
   * הקוד יושב בשם הקובץ, ומשם מחלצים אותו.
   *
   * לא שדה נפרד מהשרת: שני מקורות לאותו ערך מתפצלים, וקוד שאינו
   * תואם לשם הקובץ הוא בדיוק סוג התקלה שאי אפשר לאבחן בטלפון.
   */
  const code = issued === null
    ? null
    : /ENR-[0-9A-Fa-f]{24}/.exec(issued.fileName)?.[0].toUpperCase() ?? null;

  const copyCode = useCallback(async () => {
    if (code === null) return;

    try {
      await navigator.clipboard.writeText(code);
      setCopiedCode(true);
      window.setTimeout(() => setCopiedCode(false), 2500);
    } catch {
      setError("הדפדפן חסם את ההעתקה. הקוד מוצג למטה וניתן לסימון ידני.");
    }
  }, [code]);

  const copy = useCallback(async () => {
    if (issued === null) return;

    const url = new URL(issued.downloadPath, window.location.origin).toString();

    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2500);
    } catch {
      // דפדפן שחוסם גישה ללוח. הקישור גלוי ממילא וניתן להעתקה ידנית.
      setError("הדפדפן חסם את ההעתקה. אפשר לסמן את הקישור ולהעתיק ידנית.");
    }
  }, [issued]);

  return (
    <section className="add-device">
      <h3>הוספת מחשב</h3>

      {error !== null && <p className="error">{error}</p>}

      {issued === null ? (
        <>
          <p className="muted small">
            הורד את המתקין והרץ אותו על המחשב שברצונך להגן עליו. הקישור מקשר את
            המחשב לחשבון שלך — אין מה להקליד.
          </p>

          <button className="primary" disabled={busy} onClick={() => void issue()}>
            {busy ? "מכין…" : "צור קישור התקנה"}
          </button>
        </>
      ) : (
        <>
          <div className="dl-row">
            <a className="dl-btn" href={issued.downloadPath}>
              הורדת המתקין
            </a>

            <button className="ghost" onClick={() => void copy()}>
              {copied ? "הועתק ✓" : "העתק קישור"}
            </button>

            {/*
              העתקת הקוד לבדו.

              נדרש כשהמתקין כבר הורד, או כששם הקובץ השתנה בדרך —
              אז המתקין מבקש את הקוד במסך, וההורה נאלץ לחלץ אותו
              מתוך הכתובת המלאה.
            */}
            {code !== null && (
              <button className="ghost" onClick={() => void copyCode()}>
                {copiedCode ? "הועתק ✓" : "העתק קוד"}
              </button>
            )}
          </div>

          <p className="muted small dl-note">
            {describeLimits(issued)}
          </p>

          {code !== null && (
            <p className="muted small dl-note">
              קוד ההתקנה: <code dir="ltr">{code}</code>
            </p>
          )}

          <details className="dl-more">
            <summary>הקישור עצמו</summary>

            <code dir="ltr" className="dl-url">
              {new URL(issued.downloadPath, window.location.origin).toString()}
            </code>

            <p className="muted small">
              אפשר לשלוח אותו למחשב אחר. שם הקובץ הוא מה שמקשר אותו לחשבון,
              והמתקין מזהה אותו גם אם הדפדפן הוסיף &quot;(1)&quot; או
              &quot;עותק&quot;. מה שכן חשוב: אין למחוק את החלק שמתחיל
              ב-ENR.
            </p>
          </details>

          <button className="link muted-link" onClick={() => setIssued(null)}>
            צור קישור נוסף
          </button>
        </>
      )}

      <ActiveLinks reload={issued} />
    </section>
  );
}

/**
 * מה מגביל את הקישור.
 *
 * שני המספרים נאמרים מראש ולא כשהם נגמרים: הורה שגילה שהקישור
 * מוצה באמצע התקנה על המחשב השלישי אינו יודע אם זו תקלה או כוונה.
 */
function describeLimits(issued: Issued): string {
  const date = new Date(issued.expiresAt);

  const until = Number.isNaN(date.getTime())
    ? ""
    : ` · בתוקף עד ${date.toLocaleDateString("he-IL", { day: "numeric", month: "long" })}`;

  return `תקף ל-${issued.maxUses} התקנות${until}`;
}
