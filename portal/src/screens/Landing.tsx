import { useEffect, useState } from "react";
import { Shield, STATUS_COLOR } from "../components/Shield";
import type { SecurityStatus } from "../types";
import "../landing.css";

/**
 * דף הנחיתה.
 *
 * הרעיון המרכזי: להראות את המוצר עצמו במקום לתאר אותו. תג המצב
 * שבגיבור הוא אותו תג שרץ בפינת המסך אצל המשתמש, עם אותם צבעים
 * ואותו מגן — כך שמי שנכנס לאתר כבר ראה את הדבר שהוא מתקין.
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
    sub: "SafeMe בודק דרך איזה חיבור המחשב יוצא לאינטרנט.",
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

export function Landing({
  onStart,
  onLogin,
}: {
  onStart: () => void;
  onLogin: () => void;
}) {
  const [step, setStep] = useState(0);

  useEffect(() => {
    // כיבוד העדפת המערכת: מי שביקש פחות תנועה רואה את המצב המוגן
    // בלבד, בלי מחזור.
    const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

    if (reduced) {
      setStep(STAGES.length - 1);
      return;
    }

    const timer = window.setInterval(() => {
      setStep((s) => (s + 1) % STAGES.length);
    }, 2600);

    return () => window.clearInterval(timer);
  }, []);

  const stage = STAGES[step]!;
  const color = STATUS_COLOR[stage.status];

  return (
    <div className="lp">
      <nav className="lp-nav">
        <div className="lp-wrap lp-nav-inner">
          <div className="lp-brand">
            <Shield color="var(--accent)" size={24} />
            SafeMe
          </div>

          <div className="spacer" />

          <div className="lp-nav-links">
            <a href="#how">איך זה עובד</a>
            <a href="#who">למי זה מתאים</a>
            <a href="#removal">הסרה</a>
          </div>

          <button className="lp-btn" onClick={onLogin}>
            כניסה
          </button>
        </div>
      </nav>

      {/* ─────────────────────────────────────────── גיבור */}

      <header className="lp-wrap lp-hero">
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
              SafeMe דואג <em>שזה יישאר כך.</em>
            </span>
          </h1>

          <p className="lp-lead">
            סינון אינטרנט קל להתקין וקל לעקוף. SafeMe הוא שכבה נוספת: הוא
            מוודא שהמחשב מחובר רק דרך ספק סינון מאושר — ואם מישהו מנתק,
            מחליף רשת או מנסה לכבות אותו, הגישה נחסמת והמנהל מקבל התראה.
          </p>

          <div className="lp-cta-row">
            <button className="lp-btn primary" onClick={onStart}>
              התחל 30 יום ניסיון
            </button>

            <a className="lp-btn" href="#how">
              איך זה עובד
            </a>
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
      </header>

      {/* ────────────────────────────────── מה הבעיה בעצם */}

      <section className="lp-wrap lp-section">
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
              סינון עם SafeMe
            </h3>
            <ul>
              <li>בודק את מצב החיבור כל כמה דקות</li>
              <li>חוסם גישה כשהסינון אינו פעיל</li>
              <li>מזהה ניסיונות עקיפה ומדווח</li>
              <li>הסרה אפשרית רק דרך קוד מהחברה</li>
            </ul>
          </div>
        </div>
      </section>

      {/* ─────────────────────────────────────── איך זה עובד */}

      <section className="lp-wrap lp-section" id="how">
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
          SafeMe אינו מחליף את הסינון — הוא מוודא שהוא פעיל. אתם ממשיכים עם
          הספק שכבר בחרתם.
        </p>
      </section>

      {/* ──────────────────────────────────── למי זה מתאים */}

      <section className="lp-wrap lp-section" id="who">
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
      </section>

      {/* ────────────────────────────────────────── המחגר */}

      <section className="lp-wrap lp-section" id="removal">
        <div className="lp-kicker">העיקרון</div>

        <h2 className="lp-h2">להחמיר — כן. להקל — לא לבד.</h2>

        <p className="lp-sub">
          זו ההחלטה שמייחדת את SafeMe. אפשר תמיד להדק את ההגנה, מרחוק ומיד.
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

        <p className="lp-fineprint" style={{ marginTop: 20 }}>
          כל בקשת הסרה נרשמת ונשלחת התראה לבעל החשבון, גם אם היא בוטלה.
        </p>
      </section>

      {/* ───────────────────────────────────── קריאה לפעולה */}

      <section className="lp-wrap lp-final">
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
      </section>

      <footer className="lp-wrap lp-foot">
        <Shield color="var(--muted)" size={18} />
        <span>SafeMe</span>
        <span className="lp-foot-spacer" />
        <span>אכיפת חיבור אינטרנט מסונן</span>
      </footer>
    </div>
  );
}
