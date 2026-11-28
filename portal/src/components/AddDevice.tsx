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

    try {
      await navigator.clipboard.writeText(
        new URL(issued.downloadPath, window.location.origin).toString());
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2500);
    } catch {
      // דפדפן שחוסם גישה ללוח. הקישור גלוי ממילא וניתן להעתקה ידנית.
      setError("הדפדפן חסם את ההעתקה. אפשר לסמן את הקישור ולהעתיק ידנית.");
    }
  }, [issued]);

  const url = issued === null
    ? ""
    : new URL(issued.downloadPath, window.location.origin).toString();

  return (
    <section className="add-device">
      <h3>הוספת מחשב</h3>

      {error !== null && <p className="error">{error}</p>}

      {issued === null ? (
        <>
          <p className="muted small">
            מכינים כאן מתקין שכבר מקושר לחשבון שלך, מורידים אותו ומריצים אותו על
            המחשב שרוצים להגן עליו. אין מה להקליד בהתקנה.
          </p>

          <button className="primary" disabled={busy} onClick={() => void issue()}>
            {busy ? "מכין…" : "הכן מתקין"}
          </button>
        </>
      ) : (
        <>
          {/*
            שלושה צעדים, ובהם כפתור אחד.

            הגרסה הקודמת הציגה שלושה כפתורים בשורה: הורדה, העתקת
            קישור והעתקת קוד, בלי לומר מתי צריך כל אחד. מי שהתקין
            בפעם הראשונה לא ידע אם עליו להעתיק משהו, והתשובה ברוב
            המקרים היא שלא. לכן הקישור והקוד ירדו לשני סעיפים
            סגורים, שכל אחד מהם נקרא בשם המצב שבו הוא נחוץ.
          */}
          <ol className="steps">
            <li>
              <b>מורידים את המתקין</b> במחשב שרוצים להגן עליו.
              <div className="dl-row">
                <a className="dl-btn" href={issued.downloadPath}>
                  הורדת המתקין
                </a>
              </div>
            </li>
            <li>
              <b>מריצים את הקובץ שירד</b> ומאשרים את ההתקנה. המחשב מתחבר לחשבון
              לבד.
            </li>
            <li>
              <b>נותנים למחשב כינוי.</b> תוך דקה או שתיים הוא יופיע ברשימה כאן,
              עם בקשה לכינוי.
            </li>
          </ol>

          <p className="muted small dl-note">
            {describeLimits(issued)}
          </p>

          <details className="dl-more">
            <summary>המחשב שרוצים להגן עליו הוא מחשב אחר?</summary>

            <p className="muted small">
              שולחים אליו את הקישור הזה (בדוא"ל או בהודעה), פותחים אותו שם,
              והמתקין יורד. הקישור הוא אותו מתקין בדיוק, ואין צורך להעתיק אותו אם
              מתקינים על המחשב הזה.
            </p>

            <a dir="ltr" className="dl-url" href={issued.downloadPath}>{url}</a>

            <div className="dl-row">
              <button className="ghost" onClick={() => void copy()}>
                {copied ? "הועתק ✓" : "העתק קישור"}
              </button>
            </div>
          </details>

          {code !== null && (
            <details className="dl-more">
              <summary>המתקין ביקש "קוד התקנה"?</summary>

              <p className="muted small">
                ברוב ההתקנות זה לא קורה, ואין צורך בקוד. המתקין מזהה את החשבון
                לפי שם הקובץ שירד. רק אם שם הקובץ השתנה בדרך (למשל נשלח בתוכנה
                שמשנה שמות קבצים), המתקין יבקש את הקוד הזה במקום:
              </p>

              <code dir="ltr" className="dl-url">{code}</code>

              <div className="dl-row">
                <button className="ghost" onClick={() => void copyCode()}>
                  {copiedCode ? "הועתק ✓" : "העתק קוד"}
                </button>
              </div>
            </details>
          )}

          <button className="link muted-link" onClick={() => setIssued(null)}>
            הכן מתקין נוסף
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
