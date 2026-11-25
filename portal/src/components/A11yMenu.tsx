import { useEffect, useRef, useState } from "react";

/*
 * תפריט הנגישות.
 *
 * ארבע התאמות, כולן מקומיות לדפדפן: גודל טקסט, ניגודיות גבוהה,
 * הדגשת קישורים ועצירת תנועה. ההתאמה היא מחלקה על <html>, וה-CSS
 * עושה את השאר — כך שהיא חלה על כל מסך, גם על כאלה שייכתבו בעתיד.
 *
 * הבחירה נשמרת ב-localStorage ומוחלת לפני הציור הראשון (applyStored
 * נקרא מ-main.tsx), כדי שמי שבחר ניגודיות גבוהה לא יראה הבזק של
 * הערכה הרגילה בכל טעינה.
 */

const KEY = "filterplus.a11y";

/** האירוע שמודיע למסכים שההתאמות השתנו (למשל כדי לעצור אנימציה). */
export const A11Y_EVENT = "filterplus-a11y";

interface Prefs {
  text: 0 | 1 | 2;
  contrast: boolean;
  links: boolean;
  motion: boolean;
}

const DEFAULTS: Prefs = { text: 0, contrast: false, links: false, motion: false };

function read(): Prefs {
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return DEFAULTS;

    const p = JSON.parse(raw) as Partial<Prefs>;

    return {
      text: p.text === 1 || p.text === 2 ? p.text : 0,
      contrast: p.contrast === true,
      links: p.links === true,
      motion: p.motion === true,
    };
  } catch {
    // אחסון חסום או ערך פגום: מתנהגים כאילו לא נבחר דבר.
    return DEFAULTS;
  }
}

function apply(p: Prefs): void {
  const c = document.documentElement.classList;

  c.toggle("a11y-text-1", p.text === 1);
  c.toggle("a11y-text-2", p.text === 2);
  c.toggle("a11y-contrast", p.contrast);
  c.toggle("a11y-links", p.links);
  c.toggle("a11y-no-motion", p.motion);

  window.dispatchEvent(new Event(A11Y_EVENT));
}

/** מחיל את הבחירה השמורה. נקרא פעם אחת, לפני הציור הראשון. */
export function applyStoredA11y(): void {
  apply(read());
}

/** האם התנועה נעצרה — בהעדפת המערכת או בתפריט הנגישות. */
export function motionReduced(): boolean {
  return (
    document.documentElement.classList.contains("a11y-no-motion") ||
    (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false)
  );
}

const TEXT_LABEL = ["רגיל", "גדול", "גדול מאוד"] as const;

export function A11yMenu(): JSX.Element {
  const [open, setOpen] = useState(false);
  const [prefs, setPrefs] = useState<Prefs>(read);

  const wrapRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);

  function update(next: Prefs): void {
    setPrefs(next);
    apply(next);

    try {
      window.localStorage.setItem(KEY, JSON.stringify(next));
    } catch {
      // ההתאמה חלה גם כשאי אפשר לשמור אותה; היא רק לא תישמר לביקור הבא.
    }
  }

  // Escape ולחיצה מחוץ לתפריט סוגרים אותו, והמיקוד חוזר לכפתור.
  useEffect(() => {
    if (!open) return;

    function onKey(event: KeyboardEvent): void {
      if (event.key !== "Escape") return;

      setOpen(false);
      buttonRef.current?.focus();
    }

    function onPointer(event: PointerEvent): void {
      if (!wrapRef.current?.contains(event.target as Node)) setOpen(false);
    }

    window.addEventListener("keydown", onKey);
    window.addEventListener("pointerdown", onPointer);

    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("pointerdown", onPointer);
    };
  }, [open]);

  const changed =
    prefs.text !== 0 || prefs.contrast || prefs.links || prefs.motion;

  return (
    <div className="a11y" ref={wrapRef}>
      <button
        ref={buttonRef}
        className="a11y-toggle"
        aria-label="תפריט נגישות"
        aria-expanded={open}
        aria-controls="a11y-panel"
        onClick={() => setOpen((o) => !o)}
      >
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor"
          strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <circle cx="12" cy="4.6" r="1.7" fill="currentColor" stroke="none" />
          <path d="M5 8.6c4.6 1.2 9.4 1.2 14 0" />
          <path d="M12 9.6v5" />
          <path d="M12 14.6l-3.2 6" />
          <path d="M12 14.6l3.2 6" />
        </svg>
      </button>

      {open && (
        <div className="a11y-panel" id="a11y-panel" role="group" aria-label="התאמות נגישות">
          <p className="a11y-title">נגישות</p>

          <div className="a11y-row">
            <span id="a11y-text-label">גודל טקסט</span>

            <div className="a11y-seg" role="group" aria-labelledby="a11y-text-label">
              {TEXT_LABEL.map((label, index) => (
                <button
                  key={label}
                  aria-pressed={prefs.text === index}
                  onClick={() => update({ ...prefs, text: index as 0 | 1 | 2 })}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          <button
            className="a11y-switch"
            aria-pressed={prefs.contrast}
            onClick={() => update({ ...prefs, contrast: !prefs.contrast })}
          >
            ניגודיות גבוהה
          </button>

          <button
            className="a11y-switch"
            aria-pressed={prefs.links}
            onClick={() => update({ ...prefs, links: !prefs.links })}
          >
            הדגשת קישורים
          </button>

          <button
            className="a11y-switch"
            aria-pressed={prefs.motion}
            onClick={() => update({ ...prefs, motion: !prefs.motion })}
          >
            עצירת תנועה
          </button>

          <div className="a11y-foot">
            <button className="link" disabled={!changed} onClick={() => update(DEFAULTS)}>
              איפוס
            </button>

            <a className="link" href="/accessibility.html">הצהרת נגישות</a>
          </div>
        </div>
      )}
    </div>
  );
}
