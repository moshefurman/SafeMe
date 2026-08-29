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
 * ולכן זו אינה הגדרה ששמורה איפשהו אלא הפצה לכל המכשירים.
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
  detection: {
    rootCa?: { thumbprints?: string[]; subjectPatterns?: string[]; required?: boolean };
    network?: { cidrs?: string[]; asns?: number[]; reverseDnsPatterns?: string[] };
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
            (result.note ?? "המכשירים יקבלו את השינוי בפעימה הבאה."),
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
        כאן מפרסם מדיניות חתומה חדשה, והמכשירים מקבלים אותה בפעימה הבאה.
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
        <div className="prov-edit">
          <label>
            טביעות אצבע של תעודות שורש
            <textarea
              dir="ltr"
              rows={4}
              value={thumbprints}
              disabled={busy}
              placeholder="F30D2345BE5A0E9F3F4FCC49E471BF3CDCF38346"
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
              placeholder="213.151.48.0/20"
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
              placeholder="*O=NetFree*"
              onChange={(e) => setPatterns(e.target.value)}
            />
            <span className="muted small">
              גיבוי לטביעה שטרם ראינו: הנפקה חדשה תזוהה לפי שם הנושא.
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
