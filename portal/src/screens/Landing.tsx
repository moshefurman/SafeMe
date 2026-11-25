import { useCallback, useEffect, useRef, useState } from "react";
import { Logo } from "../components/Logo";
import { Shield, STATUS_COLOR } from "../components/Shield";
import type { SecurityStatus } from "../types";
import "../landing.css";

/**
 * דף הנחיתה.
 *
 * הרעיון המרכזי: להראות את המוצר עצמו במקום לתאר אותו. תג המצב
 * שבגיבור הוא אותו תג שרץ בפינת המסך אצל המשתמש, עם אותם צבעים
 * ואותו מגן — כך שמי שנכנס לאתר כבר ראה את הדבר שהוא מתקין.
 *
 * הדף אינו נגלל למטה אלא הצידה: כל מקטע הוא לוח בגובה המסך המלא,
 * והמעבר ביניהם הוא גלילה אופקית שנעצרת על כל לוח. שורת התוויות
 * שמעל היא גם הניווט וגם מד המיקום.
 */

interface Stage {
  status: SecurityStatus;
  state: string;
  title: string;
  sub: string;
  score: number;
}

/**
 * מחזור המצבים בגיבור.
 *
 * הסדר מספר את הסיפור של המוצר: מחשב ברשת פתוחה, ואז שתי הדרכים
 * שבהן הוא מוגן — רשימה לבנה במשרד, ספק סינון מאומת בבית.
 */
const STAGES: Stage[] = [
  {
    status: "unknown",
    state: "בודק",
    title: "מזהה את הרשת",
    sub: "Filter+‎ בודק לאיזו רשת המחשב מחובר ומה מותר בה.",
    score: 2,
  },
  {
    status: "unfiltered",
    state: "לא מוגן",
    title: "רשת פתוחה, בלי סינון",
    sub: "כך נראה מחשב משרדי רגיל: כל אתר נפתח, ואיש אינו יודע.",
    score: 1,
  },
  {
    status: "whitelist",
    state: "רשימה לבנה",
    title: "נפתחים רק אתרים שאושרו",
    sub: "המחשב גולש לרשימה שהגדרתם. כל השאר פשוט אינו נפתח.",
    score: 5,
  },
  {
    status: "safe",
    state: "מוגן",
    title: "ספק הסינון מאומת",
    sub: "בבית: המחשב יוצא לאינטרנט רק דרך ספק הסינון שבחרתם.",
    score: 5,
  },
];

/*
 * רק ספקים שהזיהוי שלהם נמדד מול מחשב מסונן אמיתי.
 *
 * אתרוג ונתיב הופיעו כאן בעבר, ואין להם עדיין כללי זיהוי: מחשב
 * שמחובר דרכם היה מדווח "אינו מסונן". שם ברשימה הזו הוא הבטחה.
 */
const PROVIDERS = ["נטפרי", "רימון"];

/** התוויות שבסרגל — לוח אחד לכל אחת, באותו סדר. */
const PANELS = [
  { id: "lp-hero", label: "Filter+‎" },
  { id: "lp-gap", label: "הבעיה" },
  { id: "lp-what", label: "מה מקבלים" },
  { id: "lp-how", label: "איך זה עובד" },
  { id: "lp-who", label: "למי זה מתאים" },
  { id: "lp-principle", label: "העיקרון" },
  { id: "lp-faq", label: "שאלות" },
  { id: "lp-start", label: "להתחיל" },
] as const;

/**
 * אייקוני קו, בסגנון הלוגו: קו אחיד, קצוות מעוגלים, בלי מילוי.
 *
 * מסלולים מוטמעים ולא ספריית אייקונים: יש כאן פחות מתריסר, וספרייה
 * שלמה בשבילם הייתה תלות בלי תמורה. הצבע מגיע מ-currentColor,
 * כך שהמסגרת שסביבם קובעת אותו.
 */
const ICONS = {
  // רשימה עם סימוני וי
  list: ["M4 6.5l1.6 1.6L8.4 5", "M4 12.5l1.6 1.6 2.8-3.1", "M4 18.5l1.6 1.6 2.8-3.1", "M12 7h8", "M12 13h8", "M12 19h5"],
  // בועת שיחה עם ניצוץ
  ai: ["M20 12a8 8 0 0 1-11.6 7.1L4 20l1-4.2A8 8 0 1 1 20 12Z", "M12 8.2l.9 2.4 2.4.9-2.4.9-.9 2.4-.9-2.4-2.4-.9 2.4-.9Z"],
  // אוזניות
  audio: ["M4 14v-2a8 8 0 0 1 16 0v2", "M4 14h3v5H5.5A1.5 1.5 0 0 1 4 17.5Z", "M20 14h-3v5h1.5a1.5 1.5 0 0 0 1.5-1.5Z"],
  // שעון
  clock: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z", "M12 7v5l3.2 2"],
  // מסך עם שורות
  manage: ["M3 5h18v11H3Z", "M9 20h6", "M12 16v4", "M7 9h5", "M7 12h8"],
  // מנעול
  lock: ["M6 11h12v9H6Z", "M8.5 11V8a3.5 3.5 0 0 1 7 0v3", "M12 14.5v2"],
  // בניין
  office: ["M5 21V4h10v17", "M15 9h4v12", "M3 21h18", "M8.5 8h3", "M8.5 12h3", "M8.5 16h3"],
  // סוגריים של קוד
  code: ["M8 7l-5 5 5 5", "M16 7l5 5-5 5", "M13.5 5l-3 14"],
  // בית
  home: ["M3 11.5 12 4l9 7.5", "M5.5 10v10h13V10", "M10 20v-5.5h4V20"],
} as const;

function Icon({ name }: { name: keyof typeof ICONS }) {
  return (
    <span className="lp-icon" aria-hidden="true">
      <svg
        width="20"
        height="20"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        {ICONS[name].map((d) => (
          <path key={d} d={d} />
        ))}
      </svg>
    </span>
  );
}

function prefersReducedMotion() {
  return window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
}

/**
 * חץ הניווט.
 *
 * מסלול SVG ולא התו ‹ או ›.
 *
 * לתווים האלה יש תכונת Bidi_Mirrored, כלומר הדפדפן הופך אותם
 * בהקשר ימין-לשמאל. החץ שנכתב "אחורה" הוצג בפועל כשהוא מצביע
 * קדימה, ושני הכפתורים נראו זהים ומצביעים לאותו כיוון. ל-SVG
 * אין את ההתנהגות הזו.
 */
function Chevron({ back }: { back: boolean }) {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={back ? "M9 5 L16 12 L9 19" : "M15 5 L8 12 L15 19"} />
    </svg>
  );
}

export function Landing({
  onStart,
  onLogin,
}: {
  onStart: () => void;
  onLogin: () => void;
}) {
  const [step, setStep] = useState(0);
  const [active, setActive] = useState(0);

  const deckRef = useRef<HTMLDivElement>(null);
  const tabsRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // כיבוד העדפת המערכת: מי שביקש פחות תנועה רואה את המצב המוגן
    // בלבד, בלי מחזור.
    if (prefersReducedMotion()) {
      setStep(STAGES.length - 1);
      return;
    }

    const timer = window.setInterval(() => {
      setStep((s) => (s + 1) % STAGES.length);
    }, 2600);

    return () => window.clearInterval(timer);
  }, []);

  const goTo = useCallback((index: number) => {
    const deck = deckRef.current;
    if (!deck) return;

    const target = Math.max(0, Math.min(PANELS.length - 1, index));
    const panel = deck.children[target] as HTMLElement | undefined;
    if (!panel) return;

    setActive(target);

    /*
     * scrollIntoView ולא חישוב של scrollLeft.
     *
     * בכיוון RTL ערכי הגלילה האופקית שליליים בדפדפנים מסוימים וחיוביים
     * באחרים, וכל חישוב ידני היה צריך לזהות איזו מוסכמה פעילה. הפונקציה
     * הזו מקבלת אלמנט ולא מספר, ולכן היא נכונה בשני הכיוונים.
     */
    panel.scrollIntoView({
      behavior: prefersReducedMotion() ? "auto" : "smooth",
      inline: "start",
      block: "nearest",
    });
  }, []);

  /**
   * סנכרון התווית הפעילה עם הלוח שנעצרו עליו.
   *
   * העדכון קורה כשהגלילה נחה, ולא תוך כדי: מעבר מהלוח הראשון
   * לאחרון חולף על פני כל מה שביניהם, והתווית הייתה מהבהבת על כל
   * תחנה בדרך. המדידה היא של מרחק בין קצוות ולא של scrollLeft, כי
   * ב-RTL הערך הזה שלילי בדפדפנים מסוימים וחיובי באחרים.
   */
  useEffect(() => {
    const deck = deckRef.current;
    if (!deck) return;

    let timer = 0;

    function settle() {
      const deck = deckRef.current;
      if (!deck) return;

      const edge = deck.getBoundingClientRect().left;
      let nearest = 0;
      let best = Infinity;

      for (let i = 0; i < deck.children.length; i += 1) {
        const gap = Math.abs(deck.children[i]!.getBoundingClientRect().left - edge);
        if (gap < best) {
          best = gap;
          nearest = i;
        }
      }

      setActive(nearest);
    }

    function onScroll() {
      window.clearTimeout(timer);
      timer = window.setTimeout(settle, 120);
    }

    deck.addEventListener("scroll", onScroll, { passive: true });

    return () => {
      deck.removeEventListener("scroll", onScroll);
      window.clearTimeout(timer);
    };
  }, []);

  /* מקשי החיצים. ב-RTL הלוח הבא נמצא משמאל, ולכן החץ שמאלה מקדם. */
  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      const target = event.target as HTMLElement | null;
      if (target && /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName)) return;

      if (event.key === "ArrowLeft") goTo(active + 1);
      else if (event.key === "ArrowRight") goTo(active - 1);
      else if (event.key === "Home") goTo(0);
      else if (event.key === "End") goTo(PANELS.length - 1);
      else return;

      event.preventDefault();
    }

    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [active, goTo]);

  /* תווית שיצאה מגבולות הסרגל נגררת בחזרה אל תוך התצוגה */
  useEffect(() => {
    const tab = tabsRef.current?.querySelector<HTMLElement>(`[data-tab="${active}"]`);

    tab?.scrollIntoView({
      behavior: prefersReducedMotion() ? "auto" : "smooth",
      inline: "center",
      block: "nearest",
    });
  }, [active]);

  const stage = STAGES[step]!;
  const color = STATUS_COLOR[stage.status];

  return (
    <div className="lp">
      {/* ─────────────────────────────────────────── סרגל עליון */}

      <nav className="lp-nav">
        <button className="lp-brand" onClick={() => goTo(0)}>
          <Logo size={22} />
          Filter+‎
        </button>

        <div className="lp-tabs" role="tablist" aria-label="מקטעי הדף" ref={tabsRef}>
          {PANELS.map((panel, index) => (
            <button
              key={panel.id}
              className="lp-tab"
              role="tab"
              data-tab={index}
              aria-selected={index === active}
              aria-controls={panel.id}
              onClick={() => goTo(index)}
            >
              {panel.label}
            </button>
          ))}
        </div>

        <button className="lp-btn lp-nav-login" onClick={onLogin}>
          כניסה
        </button>
      </nav>

      {/* ────────────────────────────────────── סיפון הלוחות */}

      <div className="lp-deck" ref={deckRef}>
        {/* ─────────────────────────────────────────── גיבור */}

        <section
          className="lp-panel"
          id="lp-hero"
          role="tabpanel"
          data-panel={0}
          aria-label={PANELS[0].label}
        >
          <div className="lp-inner lp-hero">
            <div>
              <span className="lp-eyebrow">30 יום ניסיון · ללא כרטיס אשראי</span>

              {/*
                * שתי שורות נפרדות ולא <br> בתוך כותרת אחת: שבירה ידנית
                * בעברית מייצרת שורה יתומה ברוחבי מסך מסוימים.
                */}
              <h1 className="lp-h1">
                <span className="lp-h1-line">סינון אינטרנט למשרד,</span>
                <span className="lp-h1-line">
                  {/*
                    * הנקודה בתוך ה-em ולא אחריו: ב-RTL סימן פיסוק שיושב
                    * מחוץ להדגשה מנותק ממנה ברווח, ונוחת בקצה השורה
                    * כאילו הוא איבר עצמאי.
                    */}
                  <em>בלי לגעת באבטחת המידע.</em>
                </span>
              </h1>

              <p className="lp-lead">
                Filter+‎ מסנן מחשבים שאי אפשר להתקין בהם סינון רגיל. הוא פועל על
                המחשב עצמו: בלי תעודת אבטחה, בלי לפענח תעבורה מוצפנת ובלי
                להעביר את הגלישה דרך שרת חיצוני — בדיוק הדברים שבגללם ארגונים
                דוחים סינון רגיל.
              </p>

              <div className="lp-cta-row">
                <button className="lp-btn primary" onClick={onStart}>
                  התחל 30 יום ניסיון
                </button>

                {/* קישור עוגן היה גורר את הדף במאונך. כאן זה מעבר לוח. */}
                <button className="lp-btn" onClick={() => goTo(2)}>
                  מה מקבלים
                </button>
              </div>

              <p className="lp-fineprint">
                ל-Windows 10 ומעלה. ההתקנה לוקחת דקות ספורות, ואין צורך בפרטי
                תשלום כדי להתחיל.
              </p>
            </div>

            <div className="lp-badge-stage">
              <div
                className="lp-badge"
                style={{ ["--glow" as string]: `${color}26` }}
                aria-live="polite"
              >
                <div className="lp-badge-state">{stage.state}</div>

                <Shield status={stage.status} size={78} />

                <div className="lp-badge-title" style={{ color }}>
                  {stage.title}
                </div>

                <div className="lp-badge-sub">{stage.sub}</div>

                <div className="lp-badge-meter">
                  {[0, 1, 2, 3, 4].map((i) => (
                    <i
                      key={i}
                      style={i < stage.score ? { background: color } : undefined}
                    />
                  ))}
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* ────────────────────────────────── מה הבעיה בעצם */}

        <section
          className="lp-panel"
          id="lp-gap"
          role="tabpanel"
          data-panel={1}
          aria-label={PANELS[1].label}
        >
          <div className="lp-inner">
            <div className="lp-kicker">הבעיה</div>

            <h2 className="lp-h2">סינון רגיל לא נכנס לכל משרד.</h2>

            <p className="lp-sub">
              רוב פתרונות הסינון מיירטים את התעבורה המוצפנת ומתקינים תעודת אבטחה
              משלהם. בארגון זה מתנגש עם נהלי אבטחת המידע ועם כלי העבודה — ולכן
              המחשבים נשארים בלי סינון בכלל.
            </p>

            <div className="lp-compare">
              <div className="lp-card">
                <h3>
                  <span className="lp-dot" style={{ background: "var(--muted)" }} />
                  סינון רגיל
                </h3>
                <ul>
                  <li>מתקין תעודת אבטחה ומפענח תעבורה מוצפנת</li>
                  <li>הגלישה עוברת דרך שרת של הספק</li>
                  <li>לרוב תלוי ברשת: רשת אחרת, ואין סינון</li>
                  <li>נשבר בשדרוג תשתית, בלי שאיש יודע</li>
                </ul>
              </div>

              <div className="lp-card">
                <h3>
                  <span className="lp-dot" style={{ background: "var(--brand)" }} />
                  Filter+‎
                </h3>
                <ul>
                  <li>פועל על המחשב עצמו, בלי תעודה ובלי יירוט</li>
                  <li>הגלישה נשארת ישירה, במהירות מלאה</li>
                  <li>ההגנה הולכת עם המחשב לכל רשת</li>
                  <li>מדווח כשמשהו משתנה או כשמנסים לעקוף</li>
                </ul>
              </div>
            </div>
          </div>
        </section>

        {/* ───────────────────────────────────── מה מקבלים */}

        <section
          className="lp-panel"
          id="lp-what"
          role="tabpanel"
          data-panel={2}
          aria-label={PANELS[2].label}
        >
          <div className="lp-inner">
            <div className="lp-kicker">מה מקבלים</div>

            <h2 className="lp-h2">מה Filter+‎ עושה במחשב.</h2>

            {/*
              כל שורה כאן היא יכולת שקיימת בסוכן או בתוסף היום. מה שעוד
              לא נבנה — חסימת תמונות בכל האתרים, מסרונים, macOS — אינו
              מופיע, גם אם הוא בתוכנית.
            */}
            <div className="lp-grid-3 lp-features">
              <div className="lp-card">
                <Icon name="list" />
                <h4>רשימה לבנה</h4>
                <p>
                  המחשב פותח רק אתרים שאישרתם. מצב למידה אוסף את האתרים שהעבודה
                  צריכה, ואתם בוחרים מתוכם.
                </p>
              </div>

              <div className="lp-card">
                <Icon name="ai" />
                <h4>כלי בינה מלאכותית</h4>
                <p>
                  ב-ChatGPT, Copilot, Claude, Gemini ודומיהם: תמונות מוסתרות,
                  ותשובה שמכילה מילה שחסמתם מטושטשת.
                </p>
              </div>

              <div className="lp-card">
                <Icon name="audio" />
                <h4>יוטיוב לשמיעה בלבד</h4>
                <p>
                  שמע בלי וידאו ובלי תמונות ממוזערות, ורשימת ערוצים שמוצגים
                  במלואם.
                </p>
              </div>

              <div className="lp-card">
                <Icon name="clock" />
                <h4>שעות ורשתות</h4>
                <p>
                  שעות גלישה מוגדרות, ואישור לכל רשת חדשה. נקודה חמה ו-Wi-Fi
                  ציבורי ממתינים לאישור שלכם.
                </p>
              </div>

              <div className="lp-card">
                <Icon name="manage" />
                <h4>ניהול מרוכז</h4>
                <p>
                  כל המחשבים במסך אחד, קבוצות עם מדיניות משותפת, והתראה בדוא"ל
                  כשמשהו משתנה.
                </p>
              </div>

              <div className="lp-card">
                <Icon name="lock" />
                <h4>עמיד לעקיפה</h4>
                <p>
                  אפשר לחסום דפדפנים חלופיים, VPN ותוכנות עקיפה. הסרה רק עם קוד
                  חד-פעמי.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* ───────────────────────────────────── איך זה עובד */}

        <section
          className="lp-panel"
          id="lp-how"
          role="tabpanel"
          data-panel={3}
          aria-label={PANELS[3].label}
        >
          <div className="lp-inner">
            <div className="lp-kicker">איך זה עובד</div>

            <h2 className="lp-h2">שלושה שלבים, ואז זה פשוט רץ.</h2>

            <div className="lp-grid-3">
              <div className="lp-card">
                <div className="lp-step-num">01</div>
                <h4>פותחים חשבון</h4>
                <p>
                  הרשמה קצרה, ומקבלים קובץ התקנה שמשויך לחשבון. אין צורך בכרטיס
                  אשראי במשך כל תקופת הניסיון.
                </p>
              </div>

              <div className="lp-card">
                <div className="lp-step-num">02</div>
                <h4>מתקינים על המחשב</h4>
                <p>
                  המתקין יודע לבד לאיזה חשבון להתחבר. תוך דקות המחשב מופיע במרכז
                  הניהול.
                </p>
              </div>

              <div className="lp-card">
                <div className="lp-step-num">03</div>
                <h4>בונים את הרשימה</h4>
                <p>
                  מפעילים מצב למידה ליום עבודה, מאשרים את האתרים שנאספו, ומפעילים
                  את הסינון.
                </p>
              </div>
            </div>

            <p className="lp-fineprint">
              העדכונים מותקנים לבד, והסינון ממשיך לפעול גם כשאין קשר עם השרת.
            </p>
          </div>
        </section>

        {/* ─────────────────────────────────── למי זה מתאים */}

        <section
          className="lp-panel"
          id="lp-who"
          role="tabpanel"
          data-panel={4}
          aria-label={PANELS[4].label}
        >
          <div className="lp-inner">
            <div className="lp-kicker">למי זה מתאים</div>

            <h2 className="lp-h2">שלושה מסלולים.</h2>

            <div className="lp-grid-3">
              <div className="lp-card">
                <Icon name="office" />
                <h4>משרד וארגון</h4>
                <p>
                  מחשבים שאין בהם סינון כלל. רשימה לבנה לכל קבוצה, ניהול מרוכז,
                  ותיעוד של כל שינוי ושל כל ניסיון עקיפה.
                </p>
              </div>

              <div className="lp-card">
                <Icon name="code" />
                <h4>בית תוכנה וסביבה מאובטחת</h4>
                <p>
                  בלי תעודות ובלי יירוט, כך ש-Git, Docker וכלי הענן אינם נתקלים
                  בשגיאות תעודה. מצב הלמידה אוסף את השרתים שהם צריכים.
                </p>
              </div>

              <div className="lp-card">
                <Icon name="home" />
                <h4>בית ועבודה מרחוק</h4>
                <p>
                  מוודא שהמחשב יוצא לאינטרנט רק דרך ספק הסינון שבחרתם, גם כשהוא
                  עובר לרשת אחרת.
                </p>
              </div>
            </div>

            <div className="lp-providers">
              <span className="lp-providers-label">בבית, לצד הספק שלכם:</span>

              {PROVIDERS.map((p) => (
                <span className="lp-provider" key={p}>
                  {p}
                </span>
              ))}
            </div>
          </div>
        </section>

        {/* ──────────────────────────────────────────── המחגר */}

        <section
          className="lp-panel"
          id="lp-principle"
          role="tabpanel"
          data-panel={5}
          aria-label={PANELS[5].label}
        >
          <div className="lp-inner">
            <div className="lp-kicker">העיקרון</div>

            <h2 className="lp-h2">להחמיר — כן. להקל — לא לבד.</h2>

            <p className="lp-sub">
              סינון שמי שיושב מול המחשב יכול לכבות אינו סינון. ב-Filter+‎ אפשר
              תמיד להדק את ההגנה, מרחוק ומיד. להקל אותה או להסיר אותה אי אפשר
              בלי אישור נוסף — גם למי שמנהל את החשבון.
            </p>

            <div className="lp-ratchet">
              <div className="lp-ratchet-side yes">
                <div className="lp-ratchet-label">אפשר מיד</div>
                <p className="lp-ratchet-text">
                  להוסיף חסימות, לצמצם את הרשימה, לנעול מחשב מרחוק, לדרוש אימות
                  נוסף.
                </p>
              </div>

              <div className="lp-ratchet-side no">
                <div className="lp-ratchet-label">דורש אישור</div>
                <p className="lp-ratchet-text">
                  להקל את המדיניות, להוריד את רמת האכיפה, ולהסיר את התוכנה — כולל
                  אימות זהות וחלון צינון.
                </p>
              </div>
            </div>

            <p className="lp-fineprint">
              כל בקשת הסרה נרשמת ונשלחת עליה התראה לבעל החשבון, גם אם היא בוטלה.
            </p>
          </div>
        </section>

        {/* ──────────────────────────────────────────── שאלות */}

        <section
          className="lp-panel"
          id="lp-faq"
          role="tabpanel"
          data-panel={6}
          aria-label={PANELS[6].label}
        >
          <div className="lp-inner">
            <div className="lp-kicker">שאלות</div>

            <h2 className="lp-h2">מה ששואלים לפני שמתקינים.</h2>

            <div className="lp-compare lp-faq">
              <div className="lp-card">
                <h4>הגלישה עוברת דרך השרתים שלכם?</h4>
                <p>
                  לא. הסינון נעשה על המחשב עצמו והגלישה נשארת ישירה, בלי האטה
                  ובלי הגבלת נפח.
                </p>
              </div>

              <div className="lp-card">
                <h4>צריך להתקין תעודת אבטחה?</h4>
                <p>
                  לא. Filter+‎ אינו מפענח תעבורה מוצפנת, ואינו אוסף סיסמאות או
                  פרטי תשלום.
                </p>
              </div>

              <div className="lp-card">
                <h4>כבר יש סינון ברשת. למה צריך עוד?</h4>
                <p>
                  סינון ברשת מגן רק כשמחוברים אליה. Filter+‎ יושב על המחשב, ומזהה
                  מעבר לנקודה חמה או לרשת אחרת.
                </p>
              </div>

              <div className="lp-card">
                <h4>באילו מחשבים זה עובד?</h4>
                <p>
                  Windows 10 ומעלה, עם Chrome ו-Edge. את שאר הדפדפנים אפשר
                  לחסום, כדי שלא ישמשו מעקף.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* ─────────────────────────────────── קריאה לפעולה */}

        <section
          className="lp-panel"
          id="lp-start"
          role="tabpanel"
          data-panel={7}
          aria-label={PANELS[7].label}
        >
          <div className="lp-inner lp-final">
            <h2 className="lp-h2">30 יום. בלי כרטיס אשראי. בלי התחייבות.</h2>

            <p className="lp-sub lp-centered">
              מתקינים על מחשב אחד ורואים איך זה מרגיש. אם זה לא מתאים — פשוט
              מסירים בסוף הניסיון.
            </p>

            <div className="lp-cta-row">
              <button className="lp-btn primary" onClick={onStart}>
                התחל עכשיו
              </button>

              <button className="lp-btn" onClick={onLogin}>
                כבר יש לי חשבון
              </button>
            </div>

            {/*
              מסלול נפרד לגמרי, ולכן הוא מופרד גם ויזואלית.

              מי שמגיע לכאן אינו רוצה לנהל מחשב אלא לנטרל אותו, ואין
              לו צורך בחשבון. הצגתו ככפתור שלישי בשורה היה מזמין
              לחיצה בטעות על פעולה שאין ממנה חזרה.
            */}
            <div className="lp-blocker">
              <p className="lp-blocker-title">רק לחסום מחשב, בלי חשבון?</p>

              <p className="lp-blocker-body">
                יש מסלול נפרד: המחשב נשאר בלי אינטרנט כלל, וההסרה מחייבת קוד
                חד-פעמי מהמוקד שנוצר מול המחשב הזה בלבד. בתשלום, ובלי דרך
                לבטל מהמחשב עצמו.
              </p>

              <a className="lp-blocker-link" href="/d/blocker">
                הורדת גרסת החסימה
              </a>
            </div>

            <p className="lp-fineprint">Filter+‎ · סינון אינטרנט למשרדים, לארגונים ולבית</p>
          </div>
        </section>
      </div>

      {/* ──────────────────────────────────── פס תחתון וחיצים */}

      <div className="lp-rail">
        <div className="lp-rail-dots" aria-hidden="true">
          {PANELS.map((panel, index) => (
            <i key={panel.id} className={index === active ? "on" : undefined} />
          ))}
        </div>

        <div className="lp-rail-spacer" />

        {/*
          * ב-RTL הלוח הקודם נמצא מימין והבא משמאל, ולכן החץ שאומר
          * "אחורה" מצביע ימינה. סדר ה-DOM נותן לו גם את המקום הימני.
          */}
        <button
          className="lp-arrow"
          onClick={() => goTo(active - 1)}
          disabled={active === 0}
          aria-label="הקודם"
        >
          <Chevron back />
        </button>

        <button
          className="lp-arrow"
          onClick={() => goTo(active + 1)}
          disabled={active === PANELS.length - 1}
          aria-label="הבא"
        >
          <Chevron back={false} />
        </button>
      </div>
    </div>
  );
}
