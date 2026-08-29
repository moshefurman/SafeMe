import { useCallback, useEffect, useState } from "react";

import { api, ApiError } from "../api";
import type { EgressMode, EgressResponse, EgressRule } from "../types";

/**
 * מסך ההגדרה של default-deny.
 *
 * ההגדרה הזו שונה משאר ההגדרות בפורטל בשני דברים, ושניהם מוצגים
 * למשתמש ולא מוסתרים ממנו.
 *
 * הראשון: היא מפרסמת מדיניות חתומה חדשה. הסוכן אוכף רק מה שנחתם,
 * ולכן שינוי כאן מגיע למחשבים בפעימה הבאה ולא מיידית.
 *
 * השני: היא יכולה לנתק מחשב. מצב שרתי-ספק עם רשימת כתובות שגויה
 * נועל את כל המשפחה. לכן ההסבר מפורט, והאפשרות המסוכנת דורשת קלט
 * מפורש ואינה ברירת מחדל.
 */

const MODES: Record<EgressMode, { title: string; detail: string; risk: string }> = {
  ispLevel: {
    title: "סינון ברמת הספק",
    detail:
      "המחשב יוצא לכל האינטרנט, והסינון קורה בדרך — זה המצב הרגיל של נטפרי ורימון כספק אינטרנט.",
    risk: "מותרים גלישה רגילה ושרתי השמות שתגדיר. VPN, שולחן עבודה מרוחק ומנהרות — חסומים.",
  },
  proxyEndpoint: {
    title: "רק שרתי הספק",
    detail:
      "המחשב מדבר רק עם שרתי הספק, והם יוצאים החוצה. זו הצורה החזקה, ואפשרית רק אם הספק באמת עובד כך.",
    risk:
      "רשימת כתובות שגויה תנתק את כל המחשבים לחלוטין. אל תבחר בזה בלי לוודא מול הספק.",
  },
};

export function Egress(): JSX.Element {
  const [data, setData] = useState<EgressResponse | null>(null);
  const [draft, setDraft] = useState<EgressRule | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const result = await api.get<EgressResponse>("/api/portal/v1/settings/egress");

      setData(result);
      setDraft(result.rule);
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "טעינת ההגדרה נכשלה");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const save = useCallback(async () => {
    if (draft === null) return;

    setBusy(true);
    setError(null);
    setNotice(null);

    try {
      const result = await api.post<EgressResponse & { note: string }>(
        "/api/portal/v1/settings/egress",
        {
          enabled: draft.enabled,
          mode: draft.mode,
          allowQuic: draft.allowQuic,
          resolvers: draft.resolvers,
          providerCidrs: draft.providerCidrs,
        },
      );

      setNotice(`נשמר. גרסת מדיניות ${result.version}. ${result.note}`);
      setData(result);
      setDraft(result.rule);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "השמירה נכשלה");
    } finally {
      setBusy(false);
    }
  }, [draft]);

  if (error !== null && draft === null) return <p className="error">{error}</p>;
  if (draft === null || data === null) return <p className="muted">טוען…</p>;

  const dirty = JSON.stringify(draft) !== JSON.stringify(data.rule);
  const update = (patch: Partial<EgressRule>) => setDraft({ ...draft, ...patch });

  return (
    <div className="egress">
      <h2>חסימת עקיפות</h2>

      <p className="muted lead">
        עד כה נחסם מה שידענו לזהות כרע, וכל השאר עבר. רשימה כזו תמיד מפגרת אחרי
        הכלי הבא — היא נכתבת רק אחרי שהוא כבר בשימוש. כשההגדרה הזו דלוקה, ההיתר
        הוא החריג: מותר מה שגלישה מסוננת צריכה, וכל השאר חסום — כולל מה שעדיין
        לא נולד.
      </p>

      {error !== null && <p className="error">{error}</p>}
      {notice !== null && <p className="ok-note">{notice}</p>}

      {/* ─────────────────────────────── מתג ראשי */}

      <section className="eg-main">
        <label className="eg-toggle">
          <input
            type="checkbox"
            checked={draft.enabled}
            disabled={busy}
            onChange={(e) => update({ enabled: e.target.checked })}
          />
          <span>
            <b>{draft.enabled ? "פעיל" : "כבוי"}</b>
            <span className="muted small">
              {draft.enabled
                ? "המחשבים חוסמים כל יציאה שאינה גלישה מסוננת."
                : "הסוכן חוסם רק כשמשהו חורג. זו ההתנהגות שהייתה עד כה."}
            </span>
          </span>
        </label>
      </section>

      {draft.enabled && (
        <>
          {/* ─────────────────────────────── איך הספק מסנן */}

          <section>
            <h3>איך הספק שלך מסנן</h3>

            <div className="eg-modes">
              {(Object.keys(MODES) as EgressMode[]).map((key) => (
                <label
                  key={key}
                  className={`eg-mode${draft.mode === key ? " selected" : ""}${
                    key === "proxyEndpoint" ? " strict" : ""
                  }`}
                >
                  <input
                    type="radio"
                    name="egress-mode"
                    checked={draft.mode === key}
                    disabled={busy}
                    onChange={() => update({ mode: key })}
                  />
                  <span className="eg-mode-title">{MODES[key].title}</span>
                  <span className="eg-mode-detail">{MODES[key].detail}</span>
                  <span
                    className={key === "proxyEndpoint" ? "eg-mode-risk danger" : "eg-mode-risk"}
                  >
                    {MODES[key].risk}
                  </span>
                </label>
              ))}
            </div>
          </section>

          {/* ─────────────────────────────── כתובות */}

          {draft.mode === "proxyEndpoint" && (
            <section>
              <h3>כתובות שרתי הספק</h3>

              <CidrList
                values={draft.providerCidrs}
                disabled={busy}
                placeholder="192.0.2.0/24"
                onChange={(providerCidrs) => update({ providerCidrs })}
              />

              <p className="muted small">
                חובה. השג את הרשימה מהספק — ניחוש ינתק את המחשבים.
              </p>
            </section>
          )}

          <section>
            <h3>שרתי השמות של הספק</h3>

            <CidrList
              values={draft.resolvers}
              disabled={busy}
              placeholder="198.51.100.5/32"
              onChange={(resolvers) => update({ resolvers })}
            />

            <p className="muted small">
              כשהרשימה מלאה, פורט 53 נפתח אליהם בלבד. רשימה ריקה מאפשרת להצביע על
              כל שרת שמות בעולם, כולל כזה שאינו מסנן — וזו עקיפה שלמה בשינוי הגדרה
              אחת.
            </p>
          </section>

          {/* ─────────────────────────────── QUIC */}

          <section>
            <label className="eg-toggle">
              <input
                type="checkbox"
                checked={draft.allowQuic}
                disabled={busy}
                onChange={(e) => update({ allowQuic: e.target.checked })}
              />
              <span>
                <b>אפשר QUIC</b>
                <span className="muted small">
                  QUIC מוצפן כולל הכותרות, ולכן חלק ממנגנוני הסינון אינם רואים
                  לתוכו. כשהוא חסום הדפדפן נופל אחורה ל-TCP, שהסינון כן קורא.
                  השאר כבוי אלא אם משהו לא עובד.
                </span>
              </span>
            </label>
          </section>

          {/* ─────────────────────────────── מה נחסם */}

          <section>
            <h3>מה נחסם ממילא</h3>

            <p className="muted small">
              הרשימה מתעדכנת מהשרת ואינה דורשת עדכון של הסוכן.
            </p>

            <div className="eg-blocks">
              {draft.blockedPorts.map((b) => (
                <span key={`${b.port}/${b.protocol}`} className="eg-chip">
                  {b.label || `פורט ${b.port}`}
                </span>
              ))}
              <span className="eg-chip">
                DNS מוצפן ({draft.blockedCidrs.length} שרתים)
              </span>
              {draft.blockInbound && <span className="eg-chip">תעבורה נכנסת</span>}
            </div>
          </section>
        </>
      )}

      {/* ─────────────────────────────── שמירה */}

      <div className="eg-actions">
        <button disabled={!dirty || busy} onClick={() => void save()}>
          {busy ? "מפרסם…" : "שמור ופרסם"}
        </button>

        {dirty && (
          <button className="ghost" disabled={busy} onClick={() => setDraft(data.rule)}>
            בטל שינויים
          </button>
        )}

        <span className="muted small">
          {dirty
            ? "השמירה מפרסמת גרסת מדיניות חדשה וחתומה. המחשבים יקבלו אותה בפעימה הבאה."
            : data.version === null
              ? "עוד לא פורסמה מדיניות ייעודית לחשבון הזה."
              : `גרסת מדיניות ${data.version}.`}
        </span>
      </div>
    </div>
  );
}

interface CidrListProps {
  values: string[];
  disabled: boolean;
  placeholder: string;
  onChange: (values: string[]) => void;
}

/**
 * עריכת רשימת כתובות.
 *
 * שדה טקסט אחד עם שורה לכל כתובת, ולא רשימת שדות עם כפתור הוספה:
 * מי שמקבל רשימה מהספק מדביק אותה, ולא מקליד שורה-שורה.
 */
function CidrList({ values, disabled, placeholder, onChange }: CidrListProps): JSX.Element {
  return (
    <textarea
      className="eg-cidrs"
      dir="ltr"
      rows={Math.max(3, values.length + 1)}
      disabled={disabled}
      placeholder={placeholder}
      value={values.join("\n")}
      onChange={(e) =>
        onChange(
          e.target.value
            .split("\n")
            .map((x) => x.trim())
            .filter((x) => x.length > 0),
        )
      }
    />
  );
}
