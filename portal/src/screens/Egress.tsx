import { useCallback, useEffect, useState } from "react";

import { api, ApiError } from "../api";
import type { BrowserRule, EgressMode, EgressResponse, EgressRule } from "../types";

/**
 * מסך הגבלות גלישה: יוטיוב שמע בלבד + חסימת עקיפות (VPN וכו׳).
 *
 * שינוי מפרסם מדיניות חתומה חדשה, והמחשבים מקבלים אותה בפעימה הבאה.
 */

const MODES: Record<EgressMode, { title: string; detail: string; risk: string }> = {
  ispLevel: {
    title: "רגיל — מתאים לרוב המשפחות",
    detail: "הגלישה עובדת כרגיל. הסינון של הספק ממשיך לעבוד, ורק תוכנות עקיפה נחסמות.",
    risk: "אתרים, דוא\"ל ווידאו עובדים. VPN ותוכנות עקיפה — נחסמים.",
  },
  proxyEndpoint: {
    title: "מחמיר — רק דרך שרתי הספק",
    detail: "כל הגלישה חייבת לעבור דרך שרתי הספק. הגנה מקסימלית, אבל דורשת הגדרה מדויקת.",
    risk:
      "⚠ אם הכתובות שגויות, כל המחשבים יישארו בלי אינטרנט. "
      + "אל תבחרו בזה בלי לבדוק מול הספק.",
  },
};

export function Egress(): JSX.Element {
  const [data, setData] = useState<EgressResponse | null>(null);
  const [draft, setDraft] = useState<EgressRule | null>(null);
  const [browser, setBrowser] = useState<BrowserRule>({ youtubeAudioOnly: false });
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const result = await api.get<EgressResponse>("/api/portal/v1/settings/egress");

      setData(result);
      setDraft(result.rule);
      setBrowser(result.browser);
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
          youtubeAudioOnly: browser.youtubeAudioOnly,
        },
      );

      setNotice(`נשמר. ${result.note}`);
      setData(result);
      setDraft(result.rule);
      setBrowser(result.browser);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "השמירה נכשלה");
    } finally {
      setBusy(false);
    }
  }, [draft, browser]);

  if (error !== null && draft === null) return <p className="error">{error}</p>;
  if (draft === null || data === null) return <p className="muted">טוען…</p>;

  const dirty = JSON.stringify(draft) !== JSON.stringify(data.rule)
    || JSON.stringify(browser) !== JSON.stringify(data.browser);
  const update = (patch: Partial<EgressRule>) => setDraft({ ...draft, ...patch });

  return (
    <div className="egress">
      <h2>הגבלות גלישה</h2>

      {error !== null && <p className="error">{error}</p>}
      {notice !== null && <p className="ok-note">{notice}</p>}

      {/* ─────────────────────────────── יוטיוב */}

      <section className="eg-main">
        <h3>יוטיוב</h3>

        <label className="eg-toggle">
          <input
            type="checkbox"
            checked={browser.youtubeAudioOnly}
            disabled={busy}
            onChange={(e) => setBrowser({ ...browser, youtubeAudioOnly: e.target.checked })}
          />
          <span>
            <b>{browser.youtubeAudioOnly ? "שמע בלבד" : "כבוי"}</b>
            <span className="muted small">
              {browser.youtubeAudioOnly
                ? "הסרטונים ביוטיוב חסומים — אפשר לשמוע אבל לא לצפות. דפדפנים חוץ מ-Chrome ו-Edge נחסמים."
                : "יוטיוב עובד כרגיל, בלי הגבלה."}
            </span>
          </span>
        </label>
      </section>

      {/* ─────────────────────────────── חסימת עקיפות */}

      <section className="eg-main">
        <h3>חסימת תוכנות עקיפה</h3>

        <p className="muted small">
          ילד שמתקין VPN או תוכנת עקיפה יכול לגלוש בלי שהסינון רואה. ההגדרה הזו חוסמת את זה.
        </p>

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
                ? "תוכנות עקיפה חסומות על כל המחשבים."
                : "אין חסימה של תוכנות עקיפה."}
            </span>
          </span>
        </label>
      </section>

      {draft.enabled && (
        <>
          {/* ─────────────────────────────── רמת חסימה */}

          <section>
            <h3>רמת חסימה</h3>

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
                חובה. בקש את הרשימה מהספק — כתובת שגויה תנתק את כל המחשבים.
              </p>
            </section>
          )}

          <section>
            <h3>כתובות שרתי הסינון</h3>

            <CidrList
              values={draft.resolvers}
              disabled={busy}
              placeholder="198.51.100.5/32"
              onChange={(resolvers) => update({ resolvers })}
            />

            <p className="muted small">
              כתובות שרתי הסינון של הספק. כשהרשימה מלאה, רק הם יענו לבקשות גלישה.
              רשימה ריקה מאפשרת לעקוף את הסינון.
            </p>
          </section>

          {/* ─────────────────────────────── גלישה מהירה */}

          <section>
            <label className="eg-toggle">
              <input
                type="checkbox"
                checked={draft.allowQuic}
                disabled={busy}
                onChange={(e) => update({ allowQuic: e.target.checked })}
              />
              <span>
                <b>גלישה מהירה</b>
                <span className="muted small">
                  {draft.allowQuic
                    ? "הגלישה מהירה יותר, אבל חלק מהסינון עלול לא לעבוד. כבה אם הספק אומר שצריך."
                    : "הסינון עובד על כל הגלישה. הפעל רק אם אתרים לא נטענים כמו שצריך."}
                </span>
              </span>
            </label>
          </section>

          {/* ─────────────────────────────── מה עוד נחסם */}

          <section>
            <h3>נחסם אוטומטית</h3>

            <p className="muted small">
              דברים שנחסמים תמיד, בלי קשר להגדרות. הרשימה מתעדכנת מהשרת.
            </p>

            <div className="eg-blocks">
              {draft.blockedPorts.map((b) => (
                <span key={`${b.port}/${b.protocol}`} className="eg-chip">
                  {b.label || `פורט ${b.port}`}
                </span>
              ))}
              {draft.blockedCidrs.length > 0 && (
                <span className="eg-chip">
                  שרתי DNS לא מסוננים ({draft.blockedCidrs.length})
                </span>
              )}
              {draft.blockInbound && <span className="eg-chip">חיבורים נכנסים</span>}
            </div>
          </section>
        </>
      )}

      {/* ─────────────────────────────── שמירה */}

      <div className="eg-actions">
        <button disabled={!dirty || busy} onClick={() => void save()}>
          {busy ? "שומר…" : "שמור"}
        </button>

        {dirty && (
          <button className="ghost" disabled={busy} onClick={() => { setDraft(data.rule); setBrowser(data.browser); }}>
            בטל שינויים
          </button>
        )}

        <span className="muted small">
          {dirty
            ? "השינויים יגיעו למחשבים תוך כמה דקות."
            : data.version === null
              ? "עוד לא שמרת הגדרות."
              : ""}
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
