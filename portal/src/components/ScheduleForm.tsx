import { useState } from "react";

/**
 * טופס הוספת שעות חסימה, משותף למחשב ולקבוצה.
 *
 * הטופס סגור עד שמבקשים אותו, והשעות ריקות עד שבוחרים אותן.
 *
 * הגרסה הקודמת הציגה תמיד "22:00 עד 07:00" מוכן לשליחה, ומי שנכנס
 * למסך קרא את זה כהגדרה קיימת — בזמן שהשורה שמעליו אמרה "לא הוגדרו
 * שעות חסימה". שני המשפטים סתרו זה את זה, והאמת הייתה דווקא השנייה.
 */

const HOURS = Array.from({ length: 24 }, (_, h) => String(h).padStart(2, "0"));

// חמש דקות. שישים אפשרויות בבורר הן רשימה שצריך לגלול בה.
const MINUTES = Array.from({ length: 12 }, (_, m) => String(m * 5).padStart(2, "0"));

/** 0 ראשון עד 6 שבת — המספור של DayOfWeek, שהסוכן משווה מולו. */
const DAYS = [
  { value: 0, short: "א" },
  { value: 1, short: "ב" },
  { value: 2, short: "ג" },
  { value: 3, short: "ד" },
  { value: 4, short: "ה" },
  { value: 5, short: "ו" },
  { value: 6, short: "ש" },
];

export function ScheduleForm({
  busy,
  onAdd,
}: {
  busy: boolean;
  /** מחזיר true כשההוספה הצליחה, ואז הטופס נסגר. */
  onAdd: (window: { from: string; to: string; days: number[] }) => Promise<boolean>;
}): JSX.Element {
  const [open, setOpen] = useState(false);
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [days, setDays] = useState<number[]>([]);

  function close() {
    setOpen(false);
    setFrom("");
    setTo("");
    setDays([]);
  }

  if (!open) {
    return (
      <div>
        <button disabled={busy} onClick={() => setOpen(true)}>
          הוסף שעות חסימה
        </button>
      </div>
    );
  }

  const chosen = from !== "" && to !== "";
  const same = chosen && from === to;

  return (
    <div className="sched-form">
      <b>שעות חסימה חדשות</b>

      <div style={{ display: "flex", gap: 10, alignItems: "flex-end", flexWrap: "wrap" }}>
        <TimePick label="חסום מהשעה" value={from} onChange={setFrom} disabled={busy} />
        <TimePick label="עד השעה" value={to} onChange={setTo} disabled={busy} />
      </div>

      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        {DAYS.map((day) => {
          const on = days.includes(day.value);

          return (
            <button
              key={day.value}
              className={on ? "day on" : "day"}
              disabled={busy}
              aria-pressed={on}
              onClick={() =>
                setDays(on
                  ? days.filter((d) => d !== day.value)
                  : [...days, day.value].sort())}
            >
              {day.short}
            </button>
          );
        })}

        <span className="muted small" style={{ alignSelf: "center" }}>
          {days.length === 0 ? "לא נבחרו ימים: חל בכל ימות השבוע" : `${days.length} ימים`}
        </span>
      </div>

      {chosen && !same && (
        <p className="muted small">
          {from > to
            ? `הגלישה תיחסם מ-${from} עד ${to} למחרת.`
            : `הגלישה תיחסם מ-${from} עד ${to}.`}
        </p>
      )}

      {same && (
        <p className="warn-text">שעת ההתחלה והסיום זהות, ולכן לא ייחסם דבר.</p>
      )}

      <div style={{ display: "flex", gap: 8 }}>
        <button
          className="primary"
          disabled={busy || !chosen || same}
          onClick={() => {
            void onAdd({ from, to, days }).then((ok) => { if (ok) close(); });
          }}
        >
          {busy ? "שומר…" : "שמור"}
        </button>

        <button className="ghost" disabled={busy} onClick={close}>ביטול</button>
      </div>
    </div>
  );
}

/**
 * בורר שעה ודקה, תמיד בשעון 24.
 *
 * שני בוררים ולא שדה אחד: input type="time" מציג AM/PM לפי שפת
 * הדפדפן, ושדה חופשי מזמין כל צורת קלט. בורר מחזיר רק ערך תקין.
 */
function TimePick({
  label,
  value,
  onChange,
  disabled,
}: {
  label: string;
  value: string;
  onChange: (next: string) => void;
  disabled: boolean;
}): JSX.Element {
  const [hour = "", minute = ""] = value === "" ? [] : value.split(":");

  return (
    <div className="time-pick">
      <span className="time-pick-label">{label}</span>

      {/* שעה ודקה נקראות משמאל לימין גם בטקסט עברי */}
      <span className="time-pick-fields" dir="ltr">
        <span className="time-pick-field">
          <select
            value={hour}
            disabled={disabled}
            aria-label={`${label}, שעה`}
            onChange={(e) => onChange(`${e.target.value}:${minute || "00"}`)}
          >
            {hour === "" && <option value="">--</option>}
            {HOURS.map((h) => <option key={h} value={h}>{h}</option>)}
          </select>
          <small>שעה</small>
        </span>

        <span className="time-pick-colon">:</span>

        <span className="time-pick-field">
          <select
            value={minute}
            disabled={disabled || hour === ""}
            aria-label={`${label}, דקות`}
            onChange={(e) => onChange(`${hour}:${e.target.value}`)}
          >
            {minute === "" && <option value="">--</option>}
            {MINUTES.map((m) => <option key={m} value={m}>{m}</option>)}
          </select>
          <small>דקות</small>
        </span>
      </span>
    </div>
  );
}
