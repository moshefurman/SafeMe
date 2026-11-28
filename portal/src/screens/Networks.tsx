import { useCallback, useEffect, useState } from "react";

import { api, ApiError } from "../api";
import { BlockRules } from "../components/BlockRules";
import type {
  NetworkApproval,
  NetworkPolicy,
  NetworkRow,
  NetworksResponse,
} from "../types";

/**
 * מסך הרשתות.
 *
 * הרשתות הממתינות למעלה ובמסגרת משלהן, כי הן היחידות שדורשות פעולה.
 * שאר הרשימה היא היסטוריה — מעניינת, אבל לא דחופה.
 *
 * לכל רשת מוצגת הסיבה שבגללה היא סומנה, ולא רק הסימון. הורה שרואה
 * "רשת לא מוכרת" מאשר מתוך עייפות. הורה שרואה "שער בטווח של שיתוף
 * אינטרנט מאייפון" מחליט.
 */

const POLICY_LABELS: Record<NetworkPolicy, { title: string; detail: string }> = {
  strict: {
    title: "מחמיר",
    detail: "כל רשת חדשה נחסמת עד שתאושר כאן, גם אם היא מסוננת.",
  },
  balanced: {
    title: "מאוזן",
    detail:
      "רשת חדשה שכבר עוברת דרך ספק סינון מאושר מותרת אוטומטית. כל השאר ממתין לאישורך.",
  },
  lenient: {
    title: "מקל",
    detail: "כל רשת חדשה מותרת, ונשלחת התראה. מתאים למעקב בלבד, לא לחסימה.",
  },
};

const APPROVAL_LABELS: Record<NetworkApproval, string> = {
  pending: "ממתינה לאישור",
  approved: "מאושרת",
  blocked: "חסומה",
};

export function Networks(): JSX.Element {
  const [data, setData] = useState<NetworksResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setData(await api.get<NetworksResponse>("/api/portal/v1/networks"));
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "טעינת הרשתות נכשלה");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const decide = useCallback(
    async (id: string, approval: NetworkApproval) => {
      setBusy(id);
      setNotice(null);

      try {
        const result = await api.post<{ warning: string | null }>(
          `/api/portal/v1/networks/${id}/decide`,
          { approval },
        );

        if (result.warning) setNotice(result.warning);

        await load();
      } catch (e) {
        setError(e instanceof ApiError ? e.message : "הפעולה נכשלה");
      } finally {
        setBusy(null);
      }
    },
    [load],
  );

  /*
   * שכחת רשת.
   *
   * מוחקת אותה ואת ההיסטוריה שלה. בפעם הבאה היא תיראה חדשה
   * ותישפט לפי המדיניות — וזו גם הדרך לבדוק את המסלול מהתחלה.
   */
  const forget = useCallback(
    async (id: string, ssid: string | null) => {
      const name = ssid?.trim() || "הרשת ללא שם";

      if (!window.confirm(`לשכוח את ${name}? ההיסטוריה שלה תימחק, והיא תישפט מחדש בחיבור הבא.`)) {
        return;
      }

      setBusy(id);
      setNotice(null);

      try {
        await api.post(`/api/portal/v1/networks/${id}/forget`);
        await load();
      } catch (e) {
        setError(e instanceof ApiError ? e.message : "המחיקה נכשלה");
      } finally {
        setBusy(null);
      }
    },
    [load],
  );

  const setPolicy = useCallback(
    async (networkPolicy: NetworkPolicy) => {
      setBusy("policy");

      try {
        await api.post("/api/portal/v1/settings/network-policy", { networkPolicy });
        await load();
      } catch (e) {
        setError(e instanceof ApiError ? e.message : "שינוי ההגדרה נכשל");
      } finally {
        setBusy(null);
      }
    },
    [load],
  );

  if (error && data === null) return <p className="error">{error}</p>;
  if (data === null) return <p className="muted">טוען…</p>;

  const pending = data.networks.filter((n) => n.approval === "pending");
  const rest = data.networks.filter((n) => n.approval !== "pending");

  return (
    <div className="networks">
      {/*
        מה זו "רשת", ומה זו "רשת חדשה".

        השאלה שחזרה: אם זו אותה חברת אינטרנט, זו רשת חדשה? התשובה
        היא כן, ובלי המשפט הזה המסך נקרא כאילו הוא מדבר על ספקים.
      */}
      <p className="muted small scope-note">
        רשת היא הנקודה שדרכה המחשב מתחבר לאינטרנט: הנתב במשרד, ה-Wi-Fi בבית, או
        נקודה חמה מטלפון. "רשת חדשה" היא רשת שהמחשב עוד לא התחבר אליה, גם אם היא
        של אותה חברת אינטרנט ואותו ספק סינון. הזיהוי הוא לפי הנתב, ולא לפי החברה.
      </p>

      {error !== null && <p className="error">{error}</p>}
      {notice !== null && <p className="warn-note">{notice}</p>}

      {pending.length > 0 && (
        <section className="pending-block">
          <h3>
            {pending.length === 1
              ? "רשת אחת ממתינה לאישורך"
              : `${pending.length} רשתות ממתינות לאישורך`}
          </h3>

          <div className="net-list">
            {pending.map((n) => (
              <NetworkCard
                key={n.id}
                network={n}
                busy={busy === n.id}
                onDecide={decide}
                onForget={forget}
              />
            ))}
          </div>
        </section>
      )}

      <section className="policy-block">
        <h3>מה לעשות כשמחשב מתחבר לרשת חדשה</h3>

        <div className="policy-options">
          {(Object.keys(POLICY_LABELS) as NetworkPolicy[]).map((key) => (
            <label
              key={key}
              className={`policy-option${data.policy === key ? " selected" : ""}`}
            >
              <input
                type="radio"
                name="network-policy"
                checked={data.policy === key}
                disabled={busy !== null}
                onChange={() => void setPolicy(key)}
              />
              <span className="policy-title">{POLICY_LABELS[key].title}</span>
              <span className="policy-detail">{POLICY_LABELS[key].detail}</span>
            </label>
          ))}
        </div>

        <p className="muted small">
          שיתוף אינטרנט מטלפון שזוהה בוודאות נחסם בכל ההגדרות, גם במקל. זו דרך
          העקיפה השכיחה ביותר, והיא לעולם אינה מסוננת.
        </p>
      </section>

      <BlockRules />

      <section>
        <h3>רשתות מוכרות</h3>

        {rest.length === 0 ? (
          <p className="muted">עוד לא נרשמו רשתות.</p>
        ) : (
          <div className="net-list">
            {rest.map((n) => (
              <NetworkCard
                key={n.id}
                network={n}
                busy={busy === n.id}
                onDecide={decide}
                onForget={forget}
              />
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

interface CardProps {
  network: NetworkRow;
  busy: boolean;
  onDecide: (id: string, approval: NetworkApproval) => Promise<void>;
  onForget: (id: string, ssid: string | null) => Promise<void>;
}

function NetworkCard({ network, busy, onDecide, onForget }: CardProps): JSX.Element {
  const hot = network.hotspot_confidence;
  const suspicious = hot === "likely" || hot === "certain";

  return (
    <article className={`net-card ${network.approval}${suspicious ? " hot" : ""}`}>
      <header>
        <span className="net-name">
          {network.ssid?.trim() || "רשת ללא שם"}

          {/*
            תג היקף, רק כשההכרעה אינה כללית.

            רשת בלי תג היא ההתנהגות הרגילה, ותג על כולן היה רעש.
            מה שצריך לבלוט הוא החריג.
          */}
          {network.device_id !== null && (
            <span className="tag" style={{ marginInlineStart: 8 }}>
              {network.device_name ?? network.device_machine ?? "מחשב מסוים"} בלבד
            </span>
          )}
        </span>
        <span className={`net-badge ${network.approval}`}>
          {APPROVAL_LABELS[network.approval]}
        </span>
      </header>

      {hot !== "none" && (
        <p className={`net-hot ${hot}`}>
          {hot === "certain"
            ? "שיתוף אינטרנט מטלפון"
            : hot === "likely"
              ? "נראית כשיתוף אינטרנט מטלפון"
              : "כנראה שיתוף אינטרנט מטלפון"}
          {network.hotspot_reasons.length > 0 && (
            <span className="net-why"> — {network.hotspot_reasons.join("; ")}</span>
          )}
        </p>
      )}

      <dl className="net-facts">
        {network.detected_provider !== null && (
          <>
            <dt>סינון</dt>
            <dd>{network.detected_provider}</dd>
          </>
        )}
        {network.gateway_ip !== null && (
          <>
            <dt>שער</dt>
            <dd className="mono">{network.gateway_ip}</dd>
          </>
        )}
        <dt>חיבורים</dt>
        <dd>
          {network.session_count} · {formatDuration(Number(network.total_seconds))}
        </dd>
        <dt>נראתה לאחרונה</dt>
        <dd>{formatWhen(network.last_seen_at)}</dd>
      </dl>

      <footer>
        {network.approval !== "approved" && (
          <button disabled={busy} onClick={() => void onDecide(network.id, "approved")}>
            אשר
          </button>
        )}
        {network.approval !== "blocked" && (
          <button
            className="danger"
            disabled={busy}
            onClick={() => void onDecide(network.id, "blocked")}
          >
            חסום
          </button>
        )}

        {/* שכחה אינה חסימה, ולכן היא שקטה ולא אדומה */}
        <button
          className="ghost net-forget"
          disabled={busy}
          title="מוחק את הרשת ואת ההיסטוריה שלה"
          onClick={() => void onForget(network.id, network.ssid)}
        >
          שכח
        </button>
      </footer>
    </article>
  );
}

/**
 * משך בשפה שקוראים.
 *
 * "4 שעות" ולא "14,400 שניות" — ההורה רוצה לדעת כמה זמן המחשב היה
 * על הרשת הזו, לא לחשב.
 */
function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 60) return "פחות מדקה";

  const hours = Math.floor(seconds / 3600);
  const minutes = Math.round((seconds % 3600) / 60);

  if (hours === 0) return `${minutes} דקות`;
  if (hours < 24) return minutes === 0 ? `${hours} שעות` : `${hours} שעות ו-${minutes} דקות`;

  return `${Math.round(hours / 24)} ימים`;
}

function formatWhen(iso: string): string {
  const date = new Date(iso);

  return Number.isNaN(date.getTime())
    ? "—"
    : date.toLocaleString("he-IL", { dateStyle: "short", timeStyle: "short" });
}
