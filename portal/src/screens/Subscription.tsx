import { useCallback, useEffect, useState } from "react";

import { api, ApiError } from "../api";
import { SupportLink } from "../components/SupportLink";

/**
 * המנוי, כפי שההורה רואה אותו.
 *
 * שלושה דברים שהמסך חייב לומר, ואף אחד מהם אינו מובן מאליו:
 *
 *   כמה מחשבים מותרים וכמה בשימוש — כי זו הסיבה השכיחה ביותר
 *   שהתקנה תיכשל, ועדיף שההורה יראה את זה לפני ולא אחרי.
 *
 *   מתי החיוב הבא וכמה — עסקה מתמשכת שמפתיעה היא תלונה.
 *
 *   שההגנה אינה נפסקת עם סיום המנוי. זה ההפך ממה שרוב האנשים
 *   מניחים, ומי שיבטל ויצפה שהמחשב ייפתח יגלה אחרת בדיוק כשזה
 *   יפריע לו.
 */

interface Subscription {
  id: string;
  planName: string;
  status: string;
  interval: string;
  price: number;
  deviceLimit: number;
  currentPeriodEnd: string | null;
  cancelAtPeriodEnd: boolean;
  cardLast4: string | null;
}

interface Payment {
  amount: number;
  succeeded: boolean;
  failureReason: string | null;
  receiptUrl: string | null;
  chargedAt: string;
}

interface Plan {
  id: string;
  name: string;
  deviceLimit: number;
  monthly: number;
  yearly: number;
  yearlyDiscountPercent: number;
  priceMissing: boolean;
}

const shekel = (n: number): string =>
  n.toLocaleString("he-IL", { style: "currency", currency: "ILS", maximumFractionDigits: 2 });

/*
 * הסבר בעברית לכל מצב, ולא המילה מהמסד.
 *
 * "past_due" אינו אומר דבר להורה, ו"unpaid" נשמע כמו איום. מה
 * שחשוב הוא מה קורה עכשיו ומה נדרש ממנו.
 */
const STATUS: Record<string, { label: string; detail: string; bad: boolean }> = {
  trialing: {
    label: "תקופת ניסיון",
    detail: "עדיין לא בוצע חיוב.",
    bad: false,
  },
  active: {
    label: "מנוי פעיל",
    detail: "הכול תקין.",
    bad: false,
  },
  past_due: {
    label: "החיוב לא עבר",
    detail: "ננסה שוב בימים הקרובים. כדאי לעדכן אמצעי תשלום.",
    bad: true,
  },
  unpaid: {
    label: "המנוי אינו בתוקף",
    detail: "המחשבים ממשיכים להיות מוגנים, אך אי אפשר לנהל אותם או להוסיף חדשים.",
    bad: true,
  },
};

export function Subscription(): JSX.Element {
  const [sub, setSub] = useState<Subscription | null>(null);
  const [used, setUsed] = useState(0);
  const [plans, setPlans] = useState<Plan[]>([]);
  const [payments, setPayments] = useState<Payment[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState(false);

  const load = useCallback(async () => {
    try {
      const [s, p, h] = await Promise.all([
        api.get<{ subscription: Subscription | null; used: number }>(
          "/api/portal/v1/subscription"),
        api.get<{ plans: Plan[] }>("/api/portal/v1/plans"),
        api.get<{ payments: Payment[] }>("/api/portal/v1/payments"),
      ]);

      setSub(s.subscription);
      setUsed(s.used);
      setPlans(p.plans);
      setPayments(h.payments);
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "טעינת המנוי נכשלה");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function act(path: string) {
    setBusy(true);
    setError(null);
    setNote(null);

    try {
      const r = await api.post<{ note: string }>(path);

      setNote(r.note);
      setConfirming(false);

      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "הפעולה נכשלה");
    } finally {
      setBusy(false);
    }
  }

  const state = sub === null ? null : STATUS[sub.status] ?? {
    label: sub.status, detail: "", bad: false,
  };

  return (
    <main className="shell">
      <h2>מנוי ותשלומים</h2>

      {note  !== null && <p className="muted">{note}</p>}
      {error !== null && <p className="error">{error}</p>}

      {sub === null ? (
        <div className="panel">
          <div className="panel-head"><h3>אין מנוי פעיל</h3></div>

          <div className="panel-body">
            <p className="muted">
              הבחירה שלמטה קובעת כמה מחשבים אפשר להגן עליהם.
            </p>

            {plans.length === 0 ? (
              <p className="muted small">טרם הוגדרו תוכניות. יש לפנות אלינו.</p>
            ) : (
              <div className="tiles">
                {plans.map((p) => (
                  <div className="tile" key={p.id}>
                    <div className="l">{p.name}</div>
                    <div className="n">{p.deviceLimit}</div>
                    <div className="l">מחשבים</div>

                    {p.priceMissing ? (
                      <p className="muted small">המחיר טרם נקבע.</p>
                    ) : (
                      <p className="muted small">
                        {shekel(p.monthly)} לחודש
                        {p.yearlyDiscountPercent > 0 && (
                          <>
                            <br />
                            או {shekel(p.yearly)} לשנה — חיסכון {p.yearlyDiscountPercent}%
                          </>
                        )}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            )}

            {/*
              אין כאן כפתור רכישה, ובכוונה.

              הסליקה עדיין לא מחוברת, וכפתור שנראה כמו רכישה ואינו
              גובה הוא בדיוק סוג התקלה שעלתה לנו כל אתמול: מנגנון
              שמדווח הצלחה על מה שלא קרה.
            */}
            <p className="muted small">
              לפתיחת מנוי, פנו אלינו. תשלום מקוון ייפתח בקרוב.
            </p>

            <SupportLink />
          </div>
        </div>
      ) : (
        <>
          <div className="tiles">
            <div className={state?.bad ? "tile bad" : "tile safe"}>
              <div className="n" style={{ fontSize: 19 }}>{state?.label}</div>
              <div className="l">{sub.planName}</div>
            </div>

            {/*
              מחשבים בשימוש מול המותר.

              זו הסיבה השכיחה ביותר שהתקנה נכשלת, ועדיף שההורה
              יראה אותה לפני שהוא עומד מול מחשב ומנסה.
            */}
            <div className={used >= sub.deviceLimit ? "tile low" : "tile"}>
              <div className="n">{used} / {sub.deviceLimit}</div>
              <div className="l">מחשבים בשימוש</div>
            </div>

            <div className="tile">
              <div className="n" style={{ fontSize: 19 }}>{shekel(sub.price)}</div>
              <div className="l">{sub.interval === "yearly" ? "לשנה" : "לחודש"}</div>
            </div>

            {sub.currentPeriodEnd !== null && (
              <div className="tile">
                <div className="n" style={{ fontSize: 19 }}>
                  {new Date(sub.currentPeriodEnd).toLocaleDateString("he-IL")}
                </div>
                <div className="l">
                  {sub.cancelAtPeriodEnd ? "המנוי מסתיים" : "החיוב הבא"}
                </div>
              </div>
            )}
          </div>

          <div className="panel">
            <div className="panel-body">
              {state !== null && <p className="muted">{state.detail}</p>}

              {sub.cardLast4 !== null && (
                <p className="muted small">כרטיס המסתיים ב-{sub.cardLast4}</p>
              )}

              {sub.cancelAtPeriodEnd ? (
                <>
                  <p className="muted">
                    המנוי יסתיים בסוף התקופה ולא יבוצע חיוב נוסף. עד אז הכול ממשיך כרגיל.
                  </p>

                  <button className="primary" disabled={busy}
                          onClick={() => void act("/api/portal/v1/subscription/resume")}>
                    {busy ? "מבטל…" : "בטל את הביטול"}
                  </button>
                </>
              ) : confirming ? (
                <>
                  {/*
                    אישור אחד, ובלי ניסיון שימור.

                    החוק דורש ביטול מקוון פשוט. מסך שמנסה לשכנע
                    לפני שהוא מבטל הוא בדיוק מה שהדרישה נועדה
                    למנוע — ולכן כאן רק נאמר מה יקרה, ולא למה
                    כדאי להישאר.
                  */}
                  <p className="muted">
                    המנוי יסתיים בסוף התקופה ששולמה, ולא יבוצע חיוב נוסף.
                    {" "}
                    <b>ההגנה על המחשבים אינה נפסקת עם סיום המנוי.</b>
                  </p>

                  <div style={{ display: "flex", gap: 8 }}>
                    <button className="danger" disabled={busy}
                            onClick={() => void act("/api/portal/v1/subscription/cancel")}>
                      {busy ? "מבטל…" : "אישור ביטול"}
                    </button>

                    <button className="ghost" disabled={busy} onClick={() => setConfirming(false)}>
                      חזרה
                    </button>
                  </div>
                </>
              ) : (
                <button className="ghost" onClick={() => setConfirming(true)}>
                  ביטול מנוי
                </button>
              )}
            </div>
          </div>
        </>
      )}

      {payments.length > 0 && (
        <div className="panel">
          <div className="panel-head"><h3>חיובים</h3></div>

          <table className="rows">
            <thead>
              <tr>
                <th>תאריך</th>
                <th>סכום</th>
                <th>תוצאה</th>
                <th>קבלה</th>
              </tr>
            </thead>

            <tbody>
              {payments.map((p, i) => (
                <tr key={i}>
                  <td>{new Date(p.chargedAt).toLocaleString("he-IL")}</td>
                  <td style={{ fontVariantNumeric: "tabular-nums" }}>{shekel(p.amount)}</td>
                  <td>
                    {p.succeeded
                      ? <span className="tag">שולם</span>
                      : <span className="error">{p.failureReason ?? "נכשל"}</span>}
                  </td>
                  <td>
                    {p.receiptUrl !== null
                      ? <a className="link" href={p.receiptUrl} target="_blank" rel="noreferrer">הורדה</a>
                      : <span className="muted small">—</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </main>
  );
}
