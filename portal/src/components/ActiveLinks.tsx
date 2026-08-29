import { useCallback, useEffect, useState } from "react";

import { api, ApiError } from "../api";

/**
 * קישורי ההתקנה הפעילים.
 *
 * האסימון עצמו אינו נשמר בשרת — רק גיבוב שלו — ולכן אי אפשר להציג
 * קישור שכבר הונפק. מה שמוצג הוא מה שצריך כדי להחליט אם לבטל.
 *
 * והשדה שבאמת חשוב כאן הוא ההגדרות. הן נקבעות ברגע היצירה ונחתמות
 * עם הקישור, ולכן קישור ישן נושא הגדרות ישנות לנצח — ומחשב שנרשם
 * דרכו נתקע בהן, בלי שום דרך לשנות חוץ מהסרה והתקנה מחדש.
 */
interface TokenRow {
  id: string;
  install_profile: string;
  enforcement_mode: string;
  policy_floor: { mode?: string; onRedAction?: string } | null;
  uses: number;
  max_uses: number;
  expires_at: string;
  created_at: string;
  expired: boolean;
}

export function ActiveLinks({ reload }: { reload?: unknown }): JSX.Element | null {
  const [tokens, setTokens] = useState<TokenRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setTokens((await api.get<{ tokens: TokenRow[] }>("/api/portal/v1/enroll-tokens")).tokens);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "טעינת הקישורים נכשלה");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load, reload]);

  const revoke = useCallback(
    async (id: string) => {
      if (!window.confirm("לבטל את הקישור? מחשבים שכבר נרשמו דרכו ימשיכו לעבוד.")) return;

      setBusy(id);

      try {
        await api.post(`/api/portal/v1/enroll-tokens/${id}/revoke`);
        await load();
      } catch (e) {
        setError(e instanceof ApiError ? e.message : "הביטול נכשל");
      } finally {
        setBusy(null);
      }
    },
    [load],
  );

  if (tokens === null || tokens.length === 0) return null;

  const usable = tokens.filter((t) => !t.expired && t.uses < t.max_uses);

  return (
    <details className="links-box">
      <summary>
        קישורים פעילים ({usable.length})
      </summary>

      {error !== null && <p className="error">{error}</p>}

      <ul className="link-list">
        {tokens.map((t) => {
          const spent = t.uses >= t.max_uses;
          const dead = t.expired || spent;

          return (
            <li key={t.id} className={dead ? "spent" : undefined}>
              <div className="link-what">
                <span>
                  {describeFloor(t)}
                  {stale(t) && <span className="tag warn">לא תואם להגדרות</span>}
                </span>
                <span className="muted small">
                  {formatDate(t.created_at)} · {t.uses}/{t.max_uses}
                  {t.expired ? " · פג" : spent ? " · מוצה" : ""}
                </span>
              </div>

              <button
                className="ghost"
                disabled={busy === t.id}
                onClick={() => void revoke(t.id)}
              >
                בטל
              </button>
            </li>
          );
        })}
      </ul>

      <p className="muted small">
        ביטול אינו נוגע במחשבים שכבר נרשמו — הם ממשיכים לפעול. הוא רק מונע
        שימוש נוסף בקישור.
      </p>

      {tokens.some(stale) && (
        <p className="muted small" style={{ color: "var(--low)" }}>
          קישור המסומן &quot;לא תואם להגדרות&quot; נוצר לפני שההגדרות שונו. מחשב
          שיירשם דרכו לא יקבל את ההגדרות הנוכחיות, ואי אפשר לתקן זאת אחר כך.
          צור קישור חדש במקומו.
        </p>
      )}
    </details>
  );
}

/**
 * קישור שנושא הגדרות מחמירות מאלה שבחשבון.
 *
 * מחשב שנרשם דרכו ידחה את המדיניות בכל פעימה — לנצח, כי הרצפה
 * נחתמת ברישום. זה נראה כאן כי אחרת אין שום סימן: הקישור מוריד
 * קובץ, ההתקנה מצליחה, והמחשב פשוט לא מקבל הגדרות.
 *
 * הסימון הוא על אכיפה ונעילה, שהם המצבים שנוצרו לפני שההגדרות
 * רוככו. הוא מכוון להיות שמרני: עדיף לסמן קישור תקין מאשר להחמיץ
 * אחד שבור.
 */
function stale(t: TokenRow): boolean {
  const mode = t.policy_floor?.mode ?? t.enforcement_mode;

  return mode === "enforce" || t.policy_floor?.onRedAction === "lockout";
}

/**
 * ההגדרות שהקישור נושא.
 *
 * מוצגות כי הן מה שקובע: קישור ישן נושא הגדרות ישנות, ומחשב שנרשם
 * דרכו יקבל אותן — גם אם ההגדרות בחשבון השתנו מאז.
 */
function describeFloor(t: TokenRow): string {
  const mode = t.policy_floor?.mode ?? t.enforcement_mode;
  const action = t.policy_floor?.onRedAction ?? "";

  const label = mode === "monitor" ? "תצפית" : mode === "warn" ? "התראה" : "אכיפה";

  return action === "lockout" ? `${label} · נעילה באדום` : label;
}

function formatDate(iso: string): string {
  const date = new Date(iso);

  return Number.isNaN(date.getTime())
    ? "—"
    : date.toLocaleDateString("he-IL", { day: "numeric", month: "numeric" });
}
