import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { api, ApiError } from "../api";

/**
 * רשימה לבנה: המחשב גולש רק לאתרים שאושרו.
 *
 * זו ההגדרה המחמירה ביותר במוצר, והיא גם הקשה ביותר להגדיר. אתר
 * אחד נטען מעשרות שמות — תמונות משם אחד, גופנים משני, כניסה
 * משלישי — והורה שיאשר רק את מה שכתוב בשורת הכתובת יקבל דף שבור
 * ויסיק שהמוצר לא עובד.
 *
 * לכן המסך בנוי סביב הלמידה: מפעילים אותה לזמן קצוב, גולשים במחשב
 * לאתרים הרצויים, והמסך מציג את כל מה שהמחשב ביקש — מקובץ לפי
 * האתר שכל שם שייך לו. ההורה מסמן ומאשר.
 *
 * דבר אחד שהמסך חייב לומר בקול: המחשב אינו מקבל דחיפות מהשרת.
 * הוא שואל אחת לשלוש דקות, ולכן כל שינוי כאן — ובעיקר תחילת
 * הלמידה — מגיע אליו באיחור. הורה שלוחץ "התחל" ומיד גולש יגלה
 * אחר כך רשימה ריקה.
 */

interface ApprovedDomain {
  id: string;
  domain: string;
  source: "manual" | "learned";
  createdAt: string;
}

interface ObservedDomain {
  domain: string;
  registrable: string;
  hits: number;
  lastSeenAt: string;
  blocked: boolean;
  reason?: string;
  approved: boolean;
}

interface WhitelistView {
  enabled: boolean;
  learningUntil: string | null;
  serverTime: string;
  domains: ApprovedDomain[];
  observed: ObservedDomain[];
  systemDomains: string[];
  maxDomains: number;
}

interface AddResult {
  input: string;
  domain: string;
  ok: boolean;
  reason?: string;
  already?: boolean;
}

interface AddResponse {
  added: number;
  results: AddResult[];
  note?: string;
}

interface Group {
  registrable: string;
  hits: number;
  rows: ObservedDomain[];
  /** שמות שעוד אפשר לסמן: לא חסומים ולא מאושרים. */
  open: string[];
  blocked: boolean;
}

/**
 * הלמידה נפתחת בלחיצה ונסגרת בלחיצה. התקרה קיימת רק כדי שלמידה
 * שנשכחה פתוחה לא תשאיר את המחשב פתוח לכל אתר עד אין קץ; זה
 * המרב שהשרת מקבל.
 */
const LEARN_CAP_MINUTES = 120;

/** בזמן למידה הרשימה מתרעננת לבד, כדי שההורה יראה אותה מתמלאת. */
const REFRESH_MS = 15_000;

/** רווחים, פסיקים, נקודה־פסיק ושורות. הורה מדביק רשימה כמו שהיא. */
function splitInput(text: string): string[] {
  return text.split(/[\s,;]+/).map((s) => s.trim()).filter((s) => s !== "");
}

function countdown(ms: number): string {
  const total = Math.max(0, Math.ceil(ms / 1000));
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;

  return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

/** מקבץ את מה שנצפה לפי האתר, והנפוץ ביותר ראשון. */
function groupObserved(observed: ObservedDomain[]): Group[] {
  const map = new Map<string, Group>();

  for (const row of observed) {
    let group = map.get(row.registrable);

    if (group === undefined) {
      group = { registrable: row.registrable, hits: 0, rows: [], open: [], blocked: false };
      map.set(row.registrable, group);
    }

    group.rows.push(row);
    group.hits += row.hits;

    if (!row.blocked && !row.approved) group.open.push(row.domain);
  }

  for (const group of map.values()) {
    // קבוצה חסומה היא קבוצה שכל מה שבה חסום. שם חסום אחד בין
    // תמימים אינו פוסל את השאר — כל שם נבדק בעצמו ברגע האישור.
    group.blocked = group.rows.every((r) => r.blocked);
  }

  return [...map.values()].sort((a, b) => b.hits - a.hits || a.registrable.localeCompare(b.registrable));
}

export function DeviceWhitelist({ deviceId }: { deviceId: string }): JSX.Element {
  const base = `/api/portal/v1/devices/${deviceId}/whitelist`;

  const [view, setView] = useState<WhitelistView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [draft, setDraft] = useState("");
  const [rejected, setRejected] = useState<AddResult[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());

  /*
   * ההפרש בין שעון השרת לשעון הדפדפן, לספירה לאחור.
   *
   * סוף הלמידה נקבע בשרת. דפדפן ששעונו סוטה בחמש דקות היה מציג
   * "נותרו 20 דקות" כשנותרו 15 — או מכריז שהלמידה נגמרה בזמן
   * שהיא עוד רצה.
   */
  const skew = useRef(0);
  const [now, setNow] = useState(() => Date.now());

  const load = useCallback(async (quiet = false) => {
    try {
      const r = await api.get<WhitelistView>(base);

      skew.current = Date.parse(r.serverTime) - Date.now();
      setView(r);
      setNow(Date.now());

      // מה שסומן ונעלם מהרשימה בינתיים — אושר, הוסר — יורד מהסימון.
      const still = new Set(r.observed.filter((o) => !o.blocked && !o.approved).map((o) => o.domain));
      setSelected((prev) => new Set([...prev].filter((d) => still.has(d))));

      if (!quiet) setError(null);
    } catch (e) {
      // רענון שקט שנכשל אינו מחליף את המסך בשגיאה: הבא ינסה שוב.
      if (!quiet) setError(e instanceof ApiError ? e.message : "טעינת הרשימה הלבנה נכשלה");
    }
  }, [base]);

  useEffect(() => void load(), [load]);

  const remaining = view?.learningUntil
    ? Date.parse(view.learningUntil) - (now + skew.current)
    : 0;

  const learning = remaining > 0;

  // שעון הספירה לאחור. רץ רק כשיש מה לספור.
  useEffect(() => {
    if (!learning) return;

    const timer = window.setInterval(() => setNow(Date.now()), 1000);

    return () => window.clearInterval(timer);
  }, [learning]);

  // רענון הנצפים בזמן למידה, ועוד רענון אחד כשהיא נגמרת — המנה
  // האחרונה מהמחשב מגיעה אחרי סוף החלון.
  useEffect(() => {
    if (!learning) return;

    const timer = window.setInterval(() => void load(true), REFRESH_MS);

    return () => {
      window.clearInterval(timer);
      void load(true);
    };
  }, [learning, load]);

  /** עוטף פעולה: נעילת הכפתורים, ניקוי הודעות, טעינה מחדש, ושגיאה. */
  const run = useCallback(async (action: () => Promise<string | null | undefined>, failure: string) => {
    setBusy(true);
    setError(null);
    setNote(null);

    try {
      const message = await action();

      if (message) setNote(message);

      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : failure);
    } finally {
      setBusy(false);
    }
  }, [load]);

  const setEnabled = (enabled: boolean) =>
    void run(async () => (await api.post<{ note: string }>(base, { enabled })).note, "השינוי נכשל");

  /**
   * שולח אתרים לאישור, ומפריד בין מה שנוסף למה שנדחה.
   *
   * בקשה של עשרים שמות שאחד מהם נדחה אינה כישלון. התשעה־עשר
   * נוספו, והאחד מוצג בשמו עם הסיבה — לא הודעת שגיאה אחת שמשאירה
   * את ההורה לנחש מי.
   */
  const submit = useCallback(async (domains: string[], source: "manual" | "learned") => {
    const r = await api.post<AddResponse>(`${base}/domains`, { domains, source });
    const refused = r.results.filter((x) => !x.ok);

    setRejected(refused);

    if (source === "manual") {
      // מה שנדחה נשאר בתיבה, כדי שאפשר יהיה לתקן ולנסות שוב.
      setDraft(refused.map((x) => x.input).join("\n"));
    }

    if (r.added === 0) return refused.length === 0 ? "האתרים האלה כבר ברשימה." : null;

    return `${r.added === 1 ? "אתר אחד נוסף" : `${r.added} אתרים נוספו`}. ${r.note ?? ""}`;
  }, [base]);

  const addManual = () => {
    const domains = splitInput(draft);

    if (domains.length === 0) return;

    void run(() => submit(domains, "manual"), "ההוספה נכשלה");
  };

  const approve = (domains: string[]) => {
    if (domains.length === 0) return;

    void run(() => submit(domains, "learned"), "האישור נכשל");
  };

  const removeDomain = (id: string) =>
    void run(async () => (await api.del<{ note: string }>(`${base}/domains/${id}`)).note, "ההסרה נכשלה");

  const startLearning = () =>
    void run(
      async () =>
        (await api.post<{ note: string }>(`${base}/learning`, { minutes: LEARN_CAP_MINUTES })).note,
      "התחלת הלמידה נכשלה",
    );

  const stopLearning = () =>
    void run(async () => {
      await api.del(`${base}/learning`);
      return "הלמידה נעצרה. מה שהמחשב צבר עוד יגיע בדקות הקרובות.";
    }, "עצירת הלמידה נכשלה");

  const dismiss = (domains: string[]) => {
    if (domains.length === 0) return;

    void run(async () => {
      await api.post(`${base}/observed/dismiss`, { domains });
      return null;
    }, "ההסרה נכשלה");
  };

  const clearObserved = () => {
    if (!window.confirm("למחוק את כל מה שנצפה? האתרים שכבר אושרו אינם נמחקים.")) return;

    void run(async () => {
      await api.post(`${base}/observed/clear`);
      return null;
    }, "הניקוי נכשל");
  };

  const groups = useMemo(() => groupObserved(view?.observed ?? []), [view]);

  const toggle = (domains: string[], on: boolean) =>
    setSelected((prev) => {
      const next = new Set(prev);

      for (const d of domains) {
        if (on) next.add(d);
        else next.delete(d);
      }

      return next;
    });

  if (view === null && error === null) return <p className="muted panel-body">טוען…</p>;

  if (view === null) {
    return (
      <div className="panel-body">
        <p className="error">{error}</p>
      </div>
    );
  }

  const chosen = [...selected];
  const draftCount = splitInput(draft).length;

  return (
    <div className="panel-body wl">
      {error !== null && <p className="error">{error}</p>}
      {note !== null && <p className="ok-note">{note}</p>}

      {/* ─────────────────────────────── המתג */}

      <label className="eg-toggle wl-toggle">
        <input
          type="checkbox"
          checked={view.enabled}
          disabled={busy}
          onChange={(e) => setEnabled(e.target.checked)}
        />
        <span>
          <b>{view.enabled ? "פעילה: רק האתרים שברשימה נפתחים" : "כבויה"}</b>
          <span className="muted small">
            {view.enabled
              ? "כל אתר שאינו ברשימה שלמטה אינו נפתח במחשב הזה. אתרים למבוגרים אינם נפתחים גם אם נוספו."
              : "המחשב גולש כרגיל, לפי הסינון של הרשת. כשתופעל, ייפתחו רק האתרים שאישרת כאן."}
          </span>
        </span>
      </label>

      {view.enabled && view.domains.length === 0 && (
        <p className="warn-text">
          הרשימה ריקה, ולכן המחשב אינו פותח כרגע שום אתר מלבד מרכז הניהול של SafeMe.
          הוסיפו אתרים למטה, או הפעילו למידה.
        </p>
      )}

      {/* ─────────────────────────────── האתרים המאושרים */}

      <section className="wl-section">
        <h3>
          אתרים מאושרים
          {view.domains.length > 0 && <span className="muted small"> · {view.domains.length}</span>}
        </h3>

        {view.domains.length === 0 ? (
          <p className="muted small">עוד לא אושרו אתרים.</p>
        ) : (
          <ul className="wl-list">
            {view.domains.map((d) => (
              <li key={d.id}>
                {/* שם מתחם נקרא משמאל לימין גם במסך עברי, כמו כתובת או מספר. */}
                <span className="wl-domain" dir="ltr">{d.domain}</span>
                {d.source === "learned" && <span className="tag">נלמד</span>}
                <button className="ghost" disabled={busy} onClick={() => removeDomain(d.id)}>
                  הסר
                </button>
              </li>
            ))}
          </ul>
        )}

        <p className="muted small">
          אישור של אתר כולל את כל מה שתחתיו: example.co.il מתיר גם את www.example.co.il
          ואת images.example.co.il.
        </p>

        <div className="wl-add">
          <textarea
            dir="ltr"
            rows={3}
            value={draft}
            disabled={busy}
            placeholder={"example.co.il\nhttps://www.kids-site.org/games"}
            onChange={(e) => setDraft(e.target.value)}
            aria-label="אתרים להוספה"
          />
          <div className="wl-actions">
            <button disabled={busy || draftCount === 0} onClick={addManual}>
              {draftCount > 1 ? `הוסף ${draftCount} אתרים` : "הוסף"}
            </button>
            <span className="muted small">
              אפשר להדביק כמה אתרים או קישורים, מופרדים ברווח, בפסיק או בשורה חדשה.
            </span>
          </div>
        </div>

        {rejected.length > 0 && (
          <ul className="wl-rejected" role="status">
            {rejected.map((r) => (
              <li key={`${r.input}|${r.domain}`}>
                <span className="wl-domain" dir="ltr">{r.domain || r.input}</span>
                <span>{r.reason ?? "אתר זה אינו ניתן לאישור"}</span>
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* ─────────────────────────────── למידה */}

      <section className="wl-section">
        <h3>למידה</h3>

        <p className="muted small">
          אתר אחד נטען מעשרות כתובות — תמונות, גופנים, כניסה. בזמן הלמידה המחשב רושם כל
          כתובת שביקש, ואז בוחרים כאן מה לאשר. הלמידה אינה מאשרת דבר בעצמה.
        </p>

        {learning ? (
          <div className="wl-learning on">
            <div className="wl-clock">
              <b dir="ltr">{countdown(remaining)}</b>
              <span className="muted small">הלמידה פועלת. אם לא תופסק, תיעצר מעצמה בתום הזמן</span>
            </div>

            <div className="wl-actions">
              <button disabled={busy} onClick={stopLearning}>הפסק למידה</button>
            </div>

            <p className="small">
              עכשיו גלשו <b>במחשב עצמו</b> לאתרים שרוצים לאשר, והיכנסו לדפים שבאמת משתמשים בהם.
              {view.enabled
                ? " בזמן הלמידה נפתחים במחשב גם אתרים שאינם ברשימה, חוץ מאתרים למבוגרים."
                : ""}
            </p>
          </div>
        ) : (
          <div className="wl-learning">
            <div className="wl-actions">
              <button disabled={busy} onClick={startLearning}>התחל למידה</button>
              <span className="muted small">
                נמשכת עד שתלחצו "הפסק למידה", ולכל היותר שעתיים.
              </span>
            </div>
          </div>
        )}

        <p className="wl-hint small">
          <b>שימו לב:</b> המחשב מתעדכן מהשרת אחת לשלוש דקות, ולכן הלמידה מתחילה אצלו עד שלוש
          דקות אחרי הלחיצה. כדי להתחיל מיד, לחצו <b>"רענן מהשרת"</b> ב-SafeMe שליד השעון,
          במחשב עצמו.
        </p>
      </section>

      {/* ─────────────────────────────── מה שנצפה */}

      <section className="wl-section">
        <h3>
          מה שהמחשב ביקש
          {groups.length > 0 && <span className="muted small"> · {groups.length} אתרים</span>}
        </h3>

        {groups.length === 0 ? (
          <p className="muted small">
            {learning
              ? "עוד לא הגיע דבר. הרשימה מתעדכנת לבד, והשמות הראשונים מגיעים כמה דקות אחרי שהמחשב מתחיל ללמוד."
              : "אין מה להציג. הפעילו למידה וגלשו במחשב."}
          </p>
        ) : (
          <>
            <div className="wl-actions wl-bar">
              <button disabled={busy || chosen.length === 0} onClick={() => approve(chosen)}>
                אשר נבחרים{chosen.length > 0 ? ` (${chosen.length})` : ""}
              </button>
              <button className="ghost" disabled={busy || chosen.length === 0} onClick={() => dismiss(chosen)}>
                הסר מהרשימה
              </button>
              <button className="ghost" disabled={busy} onClick={clearObserved}>
                נקה הכול
              </button>
            </div>

            <div className="wl-groups">
              {groups.map((group) => {
                const picked = group.open.filter((d) => selected.has(d)).length;
                const all = group.open.length > 0 && picked === group.open.length;

                return (
                  <details key={group.registrable} className={group.blocked ? "wl-group blocked" : "wl-group"}>
                    <summary>
                      <input
                        type="checkbox"
                        checked={all}
                        disabled={busy || group.open.length === 0}
                        aria-label={`בחר את כל הכתובות של ${group.registrable}`}
                        // לחיצה על התיבה מסמנת; היא אינה אמורה גם לפתוח או לסגור את הקבוצה.
                        onClick={(e) => e.stopPropagation()}
                        onChange={(e) => toggle(group.open, e.target.checked)}
                        ref={(el) => { if (el) el.indeterminate = picked > 0 && !all; }}
                      />
                      <span className="wl-domain" dir="ltr">{group.registrable}</span>
                      <span className="muted small">
                        {group.rows.length === 1 ? "כתובת אחת" : `${group.rows.length} כתובות`}
                        {" · "}{group.hits.toLocaleString("he-IL")} בקשות
                      </span>
                      {group.blocked && <span className="tag wl-blocked-tag">חסום</span>}
                      {!group.blocked && group.open.length === 0 && <span className="tag ok">מאושר</span>}
                    </summary>

                    {group.blocked && (
                      <p className="wl-reason small">
                        {group.rows[0]?.reason ?? "אתר זה אינו ניתן לאישור"}
                      </p>
                    )}

                    <ul>
                      {group.rows.map((row) => (
                        <li key={row.domain}>
                          <label className="check">
                            <input
                              type="checkbox"
                              checked={selected.has(row.domain)}
                              disabled={busy || row.blocked || row.approved}
                              onChange={(e) => toggle([row.domain], e.target.checked)}
                            />
                            <span className="wl-domain" dir="ltr">{row.domain}</span>
                          </label>
                          <span className="muted small">{row.hits.toLocaleString("he-IL")}</span>
                          {row.approved && <span className="tag ok">מאושר</span>}
                          {row.blocked && !group.blocked && (
                            <span className="tag wl-blocked-tag" title={row.reason}>חסום</span>
                          )}
                        </li>
                      ))}
                    </ul>

                    {/*
                      אישור האתר כולו, ולא כתובת־כתובת.

                      זה מה שרוב ההורים רוצים עבור האתר שבשבילו התחילו
                      ללמוד: כל מה שתחתיו, כולל כתובות שעוד לא נצפו.
                      לשירותי צד שלישי — גופנים, תמונות — עדיף לאשר רק
                      את הכתובות שנצפו, ולכן שתי האפשרויות קיימות.
                    */}
                    {!group.blocked && group.open.length > 0 && (
                      <button
                        className="ghost"
                        disabled={busy}
                        onClick={() => approve([group.registrable])}
                      >
                        אשר את כל <span dir="ltr">{group.registrable}</span>
                      </button>
                    )}
                  </details>
                );
              })}
            </div>
          </>
        )}
      </section>

      {view.systemDomains.length > 0 && (
        <p className="muted small">
          תמיד פתוחים, גם ברשימה ריקה — בדיקת החיבור והשעון של Windows, ו-SafeMe עצמו:{" "}
          <span dir="ltr">{view.systemDomains.join(", ")}</span>
        </p>
      )}
    </div>
  );
}
