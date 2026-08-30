import { useEffect, useState } from "react";

import { api, ApiError } from "../api";
import type { NetworkSessionRow } from "../types";

/**
 * היסטוריית החיבורים של מחשב.
 *
 * שורה לכל חיבור, לא לכל פעימה. זו ההחלטה שהופכת את המסך לקריא:
 * מחשב שדופק פעימה כל שלוש דקות היה מייצר מאות שורות ביום, ומי
 * שמחפש "מתי הוא היה על רשת שאינה הביתית" לא היה מוצא כלום.
 *
 * מה שההורה בא לראות כאן הוא רצף: איפה המחשב היה, מתי, וכמה זמן.
 * ולכן החיבור הפעיל מסומן במפורש — בלעדיו הוא נראה כמו חיבור שנגמר
 * ברגע זה.
 */
export function NetworkHistory({ deviceId }: { deviceId: string }): JSX.Element {
  const [sessions, setSessions] = useState<NetworkSessionRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;

    void api
      .get<{ sessions: NetworkSessionRow[] }>(`/api/portal/v1/devices/${deviceId}/networks`)
      .then((r) => {
        if (alive) setSessions(r.sessions);
      })
      .catch((e: unknown) => {
        if (alive) setError(e instanceof ApiError ? e.message : "טעינת ההיסטוריה נכשלה");
      });

    return () => {
      alive = false;
    };
  }, [deviceId]);

  if (error !== null) return <p className="error">{error}</p>;
  if (sessions === null) return <p className="muted">טוען היסטוריה…</p>;

  if (sessions.length === 0) {
    return <p className="muted">עוד לא נרשמו חיבורים לרשת.</p>;
  }

  return (
    <div className="scroller">
      <table className="history">
        <thead>
          <tr>
            <th>רשת</th>
            <th>מתי</th>
            <th>משך</th>
            <th>תוצאה</th>
          </tr>
        </thead>
        <tbody>
          {sessions.map((s) => {
            const live = s.ended_at === null;

            return (
              <tr key={s.id} className={live ? "live" : undefined}>
                <td>
                  {s.ssid?.trim() || "רשת ללא שם"}
                  {s.hotspot_confidence === "certain" && (
                    <span className="tag warn">שיתוף מטלפון</span>
                  )}
                </td>
                <td>{formatRange(s.started_at, s.ended_at)}</td>
                <td className="nums">{formatSpan(s.started_at, s.ended_at)}</td>
                <td>
                  <span className={`out ${s.outcome}`}>{OUTCOMES[s.outcome] ?? s.outcome}</span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

const OUTCOMES: Record<string, string> = {
  allowed: "מותר",
  blocked: "נחסם",
  pending: "המתין לאישור",

  /*
   * "היה נחסם" ולא "נחסם".
   *
   * במצב תצפית ההכרעה הייתה לחסום, והאכיפה לא חסמה דבר. הצגת
   * כוונה כעובדה היא מה שגרם למסך לומר "חסום" בזמן שהגלישה עבדה —
   * ומוצר שמדווח על חסימה שלא קרתה מלמד שאי אפשר להאמין למה שכתוב.
   */
  observed: "היה נחסם · תצפית",
};

/**
 * מתי החיבור התחיל.
 *
 * התאריך מוצג רק כשהוא אינו היום: רשימה שבה כל שורה חוזרת על
 * תאריך היום קשה לסריקה, ומה שמעניין בה הוא השעה.
 */
function formatRange(start: string, end: string | null): string {
  const from = new Date(start);

  if (Number.isNaN(from.getTime())) return "—";

  const today = new Date().toDateString() === from.toDateString();

  const day = today
    ? "היום"
    : from.toLocaleDateString("he-IL", { day: "numeric", month: "numeric" });

  const time = from.toLocaleTimeString("he-IL", { hour: "2-digit", minute: "2-digit" });

  return end === null ? `${day} ${time} — מחובר` : `${day} ${time}`;
}

function formatSpan(start: string, end: string | null): string {
  const from = new Date(start).getTime();
  const to = end === null ? Date.now() : new Date(end).getTime();

  if (Number.isNaN(from) || Number.isNaN(to) || to < from) return "—";

  const minutes = Math.round((to - from) / 60_000);

  if (minutes < 1) return "פחות מדקה";
  if (minutes < 60) return `${minutes} דק׳`;

  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;

  if (hours < 24) return rest === 0 ? `${hours} שע׳` : `${hours} שע׳ ${rest} דק׳`;

  return `${Math.round(hours / 24)} ימים`;
}
