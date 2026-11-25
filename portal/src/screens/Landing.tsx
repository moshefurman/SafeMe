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

/** מחזור המצבים בגיבור. הסדר מספר סיפור: מזוהה, נחסם, מוגן. */
const STAGES: Stage[] = [
  {
    status: "unknown",
    state: "בודק חיבור",
    title: "מזהה את הרשת",
    sub: "FilterPlus בודק דרך איזה חיבור המחשב יוצא לאינטרנט.",
    score: 2,
  },
  {
    status: "unfiltered",
    state: "לא מוגן",
    title: "החיבור אינו מסונן",
    sub: "המחשב חובר לרשת ללא סינון. הגישה נחסמת עד שהמצב יתוקן.",
    score: 1,
  },
  {
    status: "low_filter",
    state: "סינון חלקי",
    title: "הסינון נחלש",
    sub: "זוהה סינון חלקי בלבד. המשתמש מקבל התראה ודקות לתקן.",
    score: 3,
  },
  {
    status: "safe",
    state: "מוגן",
    title: "החיבור מסונן ומאומת",
    sub: "המחשב מחובר דרך ספק מאושר. הכול תקין.",
    score: 5,
  },
];

const PROVIDERS = ["נטפרי", "רימון", "אתרוג", "נתיב"];

/** התוויות שבסרגל — לוח אחד לכל אחת, באותו סדר. */
const PANELS = [
  { id: "lp-hero", label: "FilterPlus" },
  { id: "lp-gap", label: "הפער" },
  { id: "lp-how", label: "איך זה עובד" },
  { id: "lp-who", label: "למי זה מתאים" },
  { id: "lp-principle", label: "העיקרון" },
  { id: "lp-start", label: "להתחיל" },
] as const;

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
          Filter+
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
                * בעברית מייצרת שורה יתומה ברוחבי מסך מסוימים, ובפועל
                * גררה את המילה "כך" לשורה שלישית לבדה.
                */}
              <h1 className="lp-h1">
                <span className="lp-h1-line">החלטתם לסנן.</span>
                <span className="lp-h1-line">
                  {/*
                    * הנקודה בתוך ה-em ולא אחריו: ב-RTL סימן פיסוק שיושב
                    * מחוץ להדגשה מנותק ממנה ברווח, ונוחת בקצה השורה
                    * כאילו הוא איבר עצמאי.
                    */}
                  FilterPlus דואג <em>שזה יישאר כך.</em>
                </span>
              </h1>

              <p className="lp-lead">
                סינון אינטרנט קל להתקין וקל לעקוף. FilterPlus הוא שכבה נוספת: הוא
                מוודא שהמחשב מחובר רק דרך ספק סינון מאושר — ואם מישהו מנתק,
                מחליף רשת או מנסה לכבות אותו, הגישה נחסמת והמנהל מקבל התראה.
              </p>

              <div className="lp-cta-row">
                <button className="lp-btn primary" onClick={onStart}>
                  התחל 30 יום ניסיון
                </button>

                {/* קישור עוגן היה גורר את הדף במאונך. כאן זה מעבר לוח. */}
                <button className="lp-btn" onClick={() => goTo(2)}>
                  איך זה עובד
                </button>
              </div>

              <p className="lp-fineprint">
                ההתקנה לוקחת שתי דקות. אין צורך בפרטי תשלום כדי להתחיל.
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
            <div className="lp-kicker">הפער</div>

            <h2 className="lp-h2">סינון הוא החלטה. שמירה עליו היא עבודה יומיומית.</h2>

            <p className="lp-sub">
              ברגע שההגדרה נעשית, שום דבר לא מוודא שהיא נשארת. חיבור לרשת אחרת,
              נקודה חמה מהטלפון, או הסרה של התוכנה — כל אחד מאלה מחזיר את המחשב
              לאינטרנט פתוח, בלי שאיש יידע.
            </p>

            <div className="lp-compare">
              <div className="lp-card">
                <h3>
                  <span className="lp-dot" style={{ background: "var(--muted)" }} />
                  סינון לבדו
                </h3>
                <ul>
                  <li>מגן כל עוד הוא פעיל</li>
                  <li>לא יודע לומר אם הוא עדיין פעיל</li>
                  <li>ניתן להסרה או לעקיפה בלי עקבות</li>
                  <li>רשת אחרת עוקפת אותו לגמרי</li>
                </ul>
              </div>

              <div className="lp-card">
                <h3>
                  <span className="lp-dot" style={{ background: "var(--safe)" }} />
                  סינון עם FilterPlus
                </h3>
                <ul>
                  <li>בודק את מצב החיבור כל כמה דקות</li>
                  <li>חוסם גישה כשהסינון אינו פעיל</li>
                  <li>מזהה ניסיונות עקיפה ומדווח</li>
                  <li>הסרה אפשרית רק דרך קוד מהחברה</li>
                </ul>
              </div>
            </div>
          </div>
        </section>

        {/* ───────────────────────────────────── איך זה עובד */}

        <section
          className="lp-panel"
          id="lp-how"
          role="tabpanel"
          data-panel={2}
          aria-label={PANELS[2].label}
        >
          <div className="lp-inner">
            <div className="lp-kicker">איך זה עובד</div>

            <h2 className="lp-h2">שלושה שלבים, ואז זה פשוט רץ.</h2>

            <div className="lp-grid-3">
              <div className="lp-card">
                <div className="lp-step-num">01</div>
                <h4>פותחים חשבון</h4>
                <p>
                  הרשמה קצרה, ומקבלים קוד התקנה. אין צורך בכרטיס אשראי במשך כל
                  תקופת הניסיון.
                </p>
              </div>

              <div className="lp-card">
                <div className="lp-step-num">02</div>
                <h4>מתקינים על המחשב</h4>
                <p>
                  המתקין יודע לבד לאיזה חשבון להתחבר. בהתקנה נקבע מצב האכיפה —
                  התראה בלבד או חסימה מלאה.
                </p>
              </div>

              <div className="lp-card">
                <div className="lp-step-num">03</div>
                <h4>רואים הכול במקום אחד</h4>
                <p>
                  מרכז הניהול מציג את מצב כל מחשב בזמן אמת, ושולח התראה כשמשהו
                  משתנה.
                </p>
              </div>
            </div>

            <div className="lp-providers">
              {PROVIDERS.map((p) => (
                <span className="lp-provider" key={p}>
                  {p}
                </span>
              ))}
            </div>

            <p className="lp-fineprint">
              FilterPlus אינו מחליף את הסינון — הוא מוודא שהוא פעיל. אתם ממשיכים עם
              הספק שכבר בחרתם.
            </p>
          </div>
        </section>

        {/* ─────────────────────────────────── למי זה מתאים */}

        <section
          className="lp-panel"
          id="lp-who"
          role="tabpanel"
          data-panel={3}
          aria-label={PANELS[3].label}
        >
          <div className="lp-inner">
            <div className="lp-kicker">למי זה מתאים</div>

            <h2 className="lp-h2">שלוש דרכים להתקין.</h2>

            <div className="lp-grid-3">
              <div className="lp-card">
                <h4>הורה למחשב של הילד</h4>
                <p>
                  ההורה מנהל, רואה את מצב המחשב ומקבל התראות. הילד אינו יכול
                  לשנות או להסיר.
                </p>
              </div>

              <div className="lp-card">
                <h4>למחשב שלי</h4>
                <p>
                  התחייבות אישית שאי אפשר לבטל ברגע חולשה. ההסרה עוברת דרך
                  החברה, גם כשמדובר בחשבון שלך.
                </p>
              </div>

              <div className="lp-card">
                <h4>ארגון</h4>
                <p>
                  מדיניות אחידה לכל המחשבים, ניהול מרוכז, ותיעוד מלא של כל שינוי
                  ושל כל ניסיון עקיפה.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* ──────────────────────────────────────────── המחגר */}

        <section
          className="lp-panel"
          id="lp-principle"
          role="tabpanel"
          data-panel={4}
          aria-label={PANELS[4].label}
        >
          <div className="lp-inner">
            <div className="lp-kicker">העיקרון</div>

            <h2 className="lp-h2">להחמיר — כן. להקל — לא לבד.</h2>

            <p className="lp-sub">
              זו ההחלטה שמייחדת את FilterPlus. אפשר תמיד להדק את ההגנה, מרחוק ומיד.
              להקל אותה או להסיר אותה אי אפשר בלי אישור מהחברה — גם למי שמנהל את
              החשבון, וגם למי שיושב מול המחשב.
            </p>

            <div className="lp-ratchet">
              <div className="lp-ratchet-side yes">
                <div className="lp-ratchet-label">אפשר מיד</div>
                <p className="lp-ratchet-text">
                  להחמיר את מצב האכיפה, להוסיף חסימות, לנעול מחשב מרחוק, לדרוש
                  אימות נוסף.
                </p>
              </div>

              <div className="lp-ratchet-side no">
                <div className="lp-ratchet-label">דורש אישור החברה</div>
                <p className="lp-ratchet-text">
                  להקל את המדיניות, להוריד את רמת האכיפה, ולהסיר את התוכנה — כולל
                  אימות זהות וחלון צינון.
                </p>
              </div>
            </div>

            <p className="lp-fineprint">
              כל בקשת הסרה נרשמת ונשלחת התראה לבעל החשבון, גם אם היא בוטלה.
            </p>
          </div>
        </section>

        {/* ─────────────────────────────────── קריאה לפעולה */}

        <section
          className="lp-panel"
          id="lp-start"
          role="tabpanel"
          data-panel={5}
          aria-label={PANELS[5].label}
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

            <p className="lp-fineprint">FilterPlus · אכיפת חיבור אינטרנט מסונן</p>
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
