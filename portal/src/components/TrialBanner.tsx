import type { TrialInfo } from "../types";

/**
 * באנר מצב הניסיון.
 *
 * מוצג רק כשיש מה לומר. הצבע מתחזק ככל שמתקרב הסוף, כדי שהתזכורת
 * לא תיראה זהה ביום הראשון וביום האחרון.
 */
export function TrialBanner({ trial }: { trial: TrialInfo }) {
  if (trial.phase === "paid") return null;

  const tone =
    trial.phase === "trial_expired" || trial.phase === "canceled"
      ? { border: "var(--bad)", text: "#f0a49e", bg: "rgba(206,56,46,0.12)" }
      : trial.phase === "trial_ending" || trial.phase === "grace"
        ? { border: "var(--low)", text: "#e8bd6b", bg: "rgba(214,142,12,0.12)" }
        : { border: "var(--accent)", text: "#a9d0ee", bg: "var(--accent-soft)" };

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 12,
        flexWrap: "wrap",
        background: tone.bg,
        border: `1px solid ${tone.border}66`,
        borderRadius: 10,
        padding: "11px 16px",
        marginBottom: 22,
        fontSize: 13.5,
        color: tone.text,
      }}
    >
      <span style={{ fontWeight: 500 }}>{trial.headline}</span>

      {trial.phase !== "trial_expired" && trial.endsAt && (
        <span style={{ color: "var(--muted)" }}>
          עד {new Date(trial.endsAt).toLocaleDateString("he-IL")}
        </span>
      )}

      <span style={{ flex: 1 }} />

      {trial.needsAttention && (
        <span style={{ color: "var(--muted)", fontSize: 12.5 }}>
          ההגנה על המכשירים ממשיכה לפעול
        </span>
      )}
    </div>
  );
}
