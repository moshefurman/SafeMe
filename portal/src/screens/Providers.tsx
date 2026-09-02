import { useCallback, useEffect, useState } from "react";

import { api, ApiError } from "../api";

/**
 * ניהול ספקי הסינון.
 *
 * זהו המסך שהופך את כללי הזיהוי לנתונים. ספק חדש שנכנס לשוק, טווח
 * כתובות שהתווסף, או תעודת שורש שהונפקה מחדש — כולם קורים בקצב
 * שאינו קצב שחרור הגרסאות, וכל עוד הם היו בקוד, שינוי דרש בנייה
 * ופריסה ובפועל לא קרה.
 *
 * שתי אמירות שהמסך עושה במפורש:
 *
 * שינוי כאן **מפרסם מדיניות חתומה חדשה**. הסוכן אוכף רק מה שנחתם,
 * ולכן זו אינה הגדרה ששמורה איפשהו אלא הפצה לכל המחשבים.
 *
 * ו"שלד" אינו "יש כללים". תבנית ניחוש כמו "CN=Etrog*" נראית ברשימה
 * בדיוק כמו טביעת אצבע שנמדדה, ולא תתאים לעולם. בלי ההבחנה, פער
 * נראה כמו משהו שעובד.
 */

interface Provider {
  key: string;
  displayName: string;
  trustLevel: "low" | "medium" | "high";
  enabled: boolean;
  /*
   * כל מקטעי הזיהוי, ולא רק אלה שהמסך עורך.
   *
   * הטיפוס הכיר שניים מתוך ארבעה, ולכן השמירה שלחה שניים ומחקה את
   * השאר בשקט — כולל מנפיק התעודה, הווקטור היחיד שמזהה ספק שמסנן
   * דרך פרוקסי. אותה השמטה הופיעה בשלושה מקומות: כאן, בסכימה
   * בשרת, ובטופס.
   *
   * מקטע שאינו נערך עדיין חייב להיות מוכר, כדי שאפשר יהיה להחזיר
   * אותו כפי שהתקבל.
   */
  detection: {
    rootCa?: { thumbprints?: string[]; subjectPatterns?: string[]; required?: boolean };
    network?: { cidrs?: string[]; asns?: number[]; reverseDnsPatterns?: string[] };
    tlsIssuer?: { patterns?: string[]; probes?: string[] };
    httpMarkers?: {
      url?: string;
      headers?: Record<string, string>;
      bodyContains?: string[];
      levelHosts?: string[];
      levelNames?: string[];
    };
  };
  hasRules: boolean;
  verified: boolean;
}

export function Providers(): JSX.Element {
  const [providers, setProviders] = useState<Provider[] | null>(null);
  const [editing, setEditing] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setProviders((await api.get<{ providers: Provider[] }>("/api/portal/v1/providers")).providers);
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "טעינת הספקים נכשלה");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const save = useCallback(
    async (key: string, patch: Partial<Provider> & { detection?: unknown }) => {
      setBusy(true);
      setError(null);
      setNotice(null);

      try {
        const result = await api.patch<{ policyVersion: number; note: string | null }>(
          `/api/portal/v1/providers/${key}`,
          patch,
        );

        setNotice(
          `נשמר ופורסם כגרסת מדיניות ${result.policyVersion}. ` +
            (result.note ?? "המחשבים יקבלו את השינוי בפעימה הבאה."),
        );

        setEditing(null);
        await load();
      } catch (e) {
        setError(e instanceof ApiError ? e.message : "השמירה נכשלה");
      } finally {
        setBusy(false);
      }
    },
    [load],
  );

  if (error !== null && providers === null) return <p className="error">{error}</p>;
  if (providers === null) return <p className="muted">טוען…</p>;

  return (
    <div className="providers">
      <h2>ספקי סינון</h2>

      <p className="muted lead">
        כללי הזיהוי שלפיהם הסוכן קובע אם החיבור עובר דרך ספק מאושר. כל שינוי
        כאן מפרסם מדיניות חתומה חדשה, והמחשבים מקבלים אותה בפעימה הבאה.
      </p>

      {error !== null && <p className="error">{error}</p>}
      {notice !== null && <p className="ok-note">{notice}</p>}

      <div className="prov-list">
        {providers.map((p) => (
          <ProviderCard
            key={p.key}
            provider={p}
            open={editing === p.key}
            busy={busy}
            onToggleOpen={() => setEditing(editing === p.key ? null : p.key)}
            onSave={save}
          />
        ))}
      </div>
    </div>
  );
}

interface CardProps {
  provider: Provider;
  open: boolean;
  busy: boolean;
  onToggleOpen: () => void;
  onSave: (key: string, patch: Partial<Provider> & { detection?: unknown }) => Promise<void>;
}

function ProviderCard({ provider, open, busy, onToggleOpen, onSave }: CardProps): JSX.Element {
  const [thumbprints, setThumbprints] = useState("");
  const [cidrs, setCidrs] = useState("");
  const [patterns, setPatterns] = useState("");
  const [issuerPatterns, setIssuerPatterns] = useState("");
  const [issuerProbes, setIssuerProbes] = useState("");
  const [levelHosts, setLevelHosts] = useState("");

  useEffect(() => {
    if (!open) return;

    setThumbprints((provider.detection.rootCa?.thumbprints ?? []).join("\n"));
    setCidrs((provider.detection.network?.cidrs ?? []).join("\n"));
    setPatterns((provider.detection.rootCa?.subjectPatterns ?? []).join("\n"));
  }, [open, provider]);

  const lines = (value: string): string[] =>
    value.split("\n").map((x) => x.trim()).filter((x) => x.length > 0);

  return (
    <article className={`prov-card${provider.enabled ? "" : " off"}`}>
      <header>
        <div className="prov-name">
          {provider.displayName}
          <span className="prov-key mono">{provider.key}</span>
        </div>

        <div className="prov-tags">
          {!provider.hasRules && <span className="tag warn">אין כללים</span>}
          {provider.hasRules && !provider.verified && (
            <span className="tag warn" title="הוגדר מראש ולא נבדק מול מחשב אמיתי">
              שלד לא מאומת
            </span>
          )}
          {provider.verified && <span className="tag ok">מאומת</span>}
          {!provider.enabled && <span className="tag">מכובה</span>}
        </div>
      </header>

      <dl className="prov-facts">
        <dt>תעודות שורש</dt>
        <dd>{provider.detection.rootCa?.thumbprints?.length ?? 0}</dd>
        <dt>טווחי כתובות</dt>
        <dd>{provider.detection.network?.cidrs?.length ?? 0}</dd>
        <dt>מנפיק תעודה</dt>
        <dd>{provider.detection.tlsIssuer?.patterns?.length ?? 0}</dd>
        <dt>קריאת רמה</dt>
        <dd>{(provider.detection.httpMarkers?.levelHosts?.length ?? 0) > 0 ? "כן" : "לא"}</dd>
      </dl>

      <footer>
        <button className="ghost" onClick={onToggleOpen} disabled={busy}>
          {open ? "סגור" : "ערוך כללים"}
        </button>

        <button
          className="ghost"
          disabled={busy}
          onClick={() => void onSave(provider.key, { enabled: !provider.enabled })}
        >
          {provider.enabled ? "כבה" : "הפעל"}
        </button>
      </footer>

      {open && (
        /*
          דוגמאות שמתארות צורה, ולא ערכים אמיתיים.

          ה-placeholder הקודם היה "*O=NetFree*" — שם של ספק אחד
          בתוך הכרטיס של ספק אחר. הדפדפן מציג אותו באפור כשהשדה
          ריק, וזה נראה בדיוק כמו ערך שמור: זה נקרא כ"רשמת תעודה
          של נטפרי אצל רימון".

          וזו לא רק אי-נוחות. ערך שנראה אמיתי בשדה ריק מזמין
          לחיצה על "שמור" כדי "לתקן" משהו שאינו שבור, ושמירה כאן
          מפרסמת מדיניות חתומה לכל המחשבים.
        */
        <div className="prov-edit">
          <label>
            טביעות אצבע של תעודות שורש
            <textarea
              dir="ltr"
              rows={4}
              value={thumbprints}
              disabled={busy}
              placeholder="40 או 64 תווים הקסדצימליים, בלי רווחים"
              onChange={(e) => setThumbprints(e.target.value)}
            />
            <span className="muted small">
              שורה לכל טביעה, 40 או 64 תווים. אפשר להעתיק מ-certmgr.msc, שדה
              Thumbprint, בלי רווחים.
            </span>
          </label>

          <label>
            טווחי כתובות
            <textarea
              dir="ltr"
              rows={3}
              value={cidrs}
              disabled={busy}
              placeholder="0.0.0.0/24"
              onChange={(e) => setCidrs(e.target.value)}
            />
            <span className="muted small">
              לספק שמסנן ברמת הרשת ואין לו תעודה. את הטווח אפשר לקבל מהספק, או
              לבדוק ב-RDAP של RIPE מול כתובת אמיתית.
            </span>
          </label>

          <label>
            תבניות שם בתעודה
            <textarea
              dir="ltr"
              rows={2}
              value={patterns}
              disabled={busy}
              placeholder="*O=שם הספק*"
              onChange={(e) => setPatterns(e.target.value)}
            />
            <span className="muted small">
              גיבוי לטביעה שטרם ראינו: הנפקה חדשה תזוהה לפי שם הנושא.
            </span>
          </label>

          {/*
            מנפיק התעודה — הווקטור החזק ביותר, ולא היה ניתן לעריכה.

            ספק שמסנן דרך פרוקסי אינו מתקין תעודה במחשב ואין לו
            בהכרח טווח כתובות משלו. מה שהוא חייב לעשות הוא להציג
            תעודה משלו על מארח שהוא חוסם — וזה מה שנמדד כאן.

            שם המנפיק אינו בהכרח שם הספק המסחרי: רימון מסננת דרך
            Netspark, והתעודה נושאת את שמם. תבנית שמחפשת "רימון" לא
            הייתה מתאימה לעולם.
          */}
          <label>
            תבניות שם מנפיק התעודה
            <textarea
              dir="ltr"
              rows={2}
              value={issuerPatterns}
              disabled={busy}
              placeholder="*שם המנפיק*"
              onChange={(e) => setIssuerPatterns(e.target.value)}
            />
            <span className="muted small">
              שם המנפיק אינו בהכרח שם הספק. רימון מסננת דרך Netspark, והתעודה
              נושאת את שמם.
            </span>
          </label>

          <label>
            מארחים לבדיקת מנפיק
            <textarea
              dir="ltr"
              rows={2}
              value={issuerProbes}
              disabled={busy}
              placeholder="מארח שהספק חוסם"
              onChange={(e) => setIssuerProbes(e.target.value)}
            />
            <span className="muted small">
              חייב להיות מארח שהספק מגיש עליו דף חסימה ולא מנתק. ניתוק אינו מציג
              תעודה, ואין ממנו מה ללמוד.
            </span>
          </label>

          <label>
            מארחים לקריאת רמת ההגנה
            <textarea
              dir="ltr"
              rows={2}
              value={levelHosts}
              disabled={busy}
              placeholder="מארח שהספק חוסם"
              onChange={(e) => setLevelHosts(e.target.value)}
            />
            <span className="muted small">
              דף החסימה מכיל את רמת הסינון של החשבון. בלי זה השדה יציג "לא נקראה".
            </span>
          </label>

          <button
            className="primary"
            disabled={busy}
            onClick={() =>
              void onSave(provider.key, {
                detection: {
                  rootCa: {
                    thumbprints: lines(thumbprints).map((t) => t.toUpperCase()),
                    subjectPatterns: lines(patterns),
                    required: false,
                  },
                  network: {
                    cidrs: lines(cidrs),
                    asns: provider.detection.network?.asns ?? [],
                    reverseDnsPatterns: provider.detection.network?.reverseDnsPatterns ?? [],
                  },
                  tlsIssuer: {
                    patterns: lines(issuerPatterns),
                    probes: lines(issuerProbes),
                  },

                  /*
                   * שאר סמני ה-HTTP נשלחים כפי שהם.
                   *
                   * המסך עורך את מארחי הרמה בלבד; הכותרת, הכתובת
                   * וסימני הגוף נשארים. השרת ממזג לפי מקטע, אבל
                   * מקטע שנשלח מוחלף במלואו — ולכן מה שלא נערך
                   * חייב להישלח חזרה.
                   */
                  ...(provider.detection.httpMarkers === undefined ? {} : {
                    httpMarkers: {
                      ...provider.detection.httpMarkers,
                      levelHosts: lines(levelHosts),
                    },
                  }),
                },
              })
            }
          >
            {busy ? "מפרסם…" : "שמור ופרסם"}
          </button>
        </div>
      )}
    </article>
  );
}
