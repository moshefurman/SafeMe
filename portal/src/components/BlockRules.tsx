import { useCallback, useEffect, useState } from "react";

import { api, ApiError } from "../api";
import type { BlockRuleKind, BlockRuleRow, BlockRulesResponse } from "../types";

/**
 * הרשימה השחורה.
 *
 * ההבדל מחסימת רשת בודדת, וזה כל מה שהיא מוסיפה: הכללים חלים גם על
 * רשתות שטרם נראו. הורה שיודע שהשכן משאיר רשת פתוחה אינו צריך לחכות
 * שהילד יתחבר כדי לחסום אותה.
 *
 * ולכן זו רשימה של כללים ולא של שמות. רשימה של רשתות ספציפיות נכתבת
 * אחרי המעשה ומפגרת אחרי הרשת הבאה; קטגוריה תופסת גם את מה שעדיין
 * לא קיים.
 */

const KINDS: Record<BlockRuleKind, { label: string; hint: string; placeholder: string }> = {
  category: {
    label: "קטגוריה",
    hint: "חל על כל רשת שמתאימה לתיאור, גם על רשת שעוד לא נראתה.",
    placeholder: "",
  },
  ssid: {
    label: "שם רשת",
    hint: 'כוכבית מחליפה כל טקסט. "‎*אורח*‎" יתפוס גם "רשת אורחים".',
    placeholder: "*אורח*",
  },
  gateway: {
    label: "טווח כתובות",
    hint: "תופס נתב מסוים גם כששם הרשת שלו משתנה.",
    placeholder: "192.168.1.0/24",
  },
};

export function BlockRules(): JSX.Element {
  const [data, setData] = useState<BlockRulesResponse | null>(null);
  const [kind, setKind] = useState<BlockRuleKind>("category");
  const [pattern, setPattern] = useState("");
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setData(await api.get<BlockRulesResponse>("/api/portal/v1/networks/rules"));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "טעינת הכללים נכשלה");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const add = useCallback(async () => {
    setBusy(true);
    setError(null);
    setNotice(null);

    try {
      await api.post("/api/portal/v1/networks/rules", {
        kind,
        pattern,
        ...(note.trim() ? { note: note.trim() } : {}),
      });

      setPattern("");
      setNote("");
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "הוספת הכלל נכשלה");
    } finally {
      setBusy(false);
    }
  }, [kind, pattern, note, load]);

  const remove = useCallback(
    async (id: string) => {
      setBusy(true);
      setError(null);
      setNotice(null);

      try {
        const result = await api.post<{ note: string | null }>(
          `/api/portal/v1/networks/rules/${id}/delete`,
        );

        if (result.note) setNotice(result.note);

        await load();
      } catch (e) {
        setError(e instanceof ApiError ? e.message : "ביטול הכלל נכשל");
      } finally {
        setBusy(false);
      }
    },
    [load],
  );

  if (data === null) return <p className="muted">טוען…</p>;

  const categories = Object.entries(data.categories);

  return (
    <section className="rules">
      <h3>רשימה שחורה</h3>

      <p className="muted small rules-lead">
        כללים שחלים גם על רשתות שטרם נראו. חסימה של רשת בודדת נעשית ברשימה
        למעלה; כאן חוסמים מראש.
      </p>

      {error !== null && <p className="error">{error}</p>}
      {notice !== null && <p className="ok-note">{notice}</p>}

      {/* ─────────────────────────── הוספה */}

      <div className="rule-add">
        <div className="rule-kinds">
          {(Object.keys(KINDS) as BlockRuleKind[]).map((k) => (
            <button
              key={k}
              className={kind === k ? "chip on" : "chip"}
              disabled={busy}
              onClick={() => {
                setKind(k);
                setPattern("");
              }}
            >
              {KINDS[k].label}
            </button>
          ))}
        </div>

        {kind === "category" ? (
          <select
            className="rule-input"
            disabled={busy}
            value={pattern}
            onChange={(e) => setPattern(e.target.value)}
          >
            <option value="">בחר קטגוריה…</option>
            {categories.map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        ) : (
          <input
            className="rule-input mono"
            dir="ltr"
            disabled={busy}
            placeholder={KINDS[kind].placeholder}
            value={pattern}
            onChange={(e) => setPattern(e.target.value)}
          />
        )}

        <input
          className="rule-input"
          disabled={busy}
          placeholder="הערה (לא חובה) — תוצג כשרשת נחסמת"
          value={note}
          onChange={(e) => setNote(e.target.value)}
        />

        <button disabled={busy || pattern.trim() === ""} onClick={() => void add()}>
          הוסף כלל
        </button>
      </div>

      <p className="muted small">{KINDS[kind].hint}</p>

      {/* ─────────────────────────── הרשימה */}

      {data.rules.length === 0 ? (
        <p className="muted rules-empty">אין כללים. כל רשת נבדקת לפי ההגדרה שלמעלה בלבד.</p>
      ) : (
        <ul className="rule-list">
          {data.rules.map((rule) => (
            <li key={rule.id}>
              <div className="rule-what">
                <span className="rule-kind">{KINDS[rule.kind].label}</span>
                <span className={rule.kind === "category" ? "" : "mono"}>
                  {rule.kind === "category"
                    ? (data.categories[rule.pattern] ?? rule.pattern)
                    : rule.pattern}
                </span>
                {rule.note !== null && <span className="muted small">· {rule.note}</span>}
              </div>

              <span className="muted small rule-hits">{describeHits(rule)}</span>

              <button className="ghost" disabled={busy} onClick={() => void remove(rule.id)}>
                בטל
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/**
 * כמה פעמים הכלל תפס.
 *
 * זה ההבדל בין רשימה שמתחזקים לבין רשימה שגדלה לנצח: כלל שלא תפס
 * אף פעם הוא מועמד לביטול, וכלל שתופס כל יום מסביר את עצמו.
 */
function describeHits(rule: BlockRuleRow): string {
  if (rule.hit_count === 0) return "עוד לא תפס";

  const when = rule.last_hit_at === null ? "" : ` · אחרון ${formatWhen(rule.last_hit_at)}`;

  return `${rule.hit_count === 1 ? "תפס פעם אחת" : `תפס ${rule.hit_count} פעמים`}${when}`;
}

function formatWhen(iso: string): string {
  const date = new Date(iso);

  return Number.isNaN(date.getTime())
    ? "—"
    : date.toLocaleDateString("he-IL", { day: "numeric", month: "numeric" });
}
