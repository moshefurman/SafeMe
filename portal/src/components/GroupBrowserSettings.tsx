import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api";
import { customKeywords, effectiveKeywords } from "../data/default-blocked-keywords";

interface BrowserState {
  youtubeAudioOnly: boolean;
  youtubeHideThumbnails: boolean;
  youtubeAllowedChannels: string[];
  aiSafeMode: boolean;
  aiBlockedKeywords: string[];
}

const EMPTY: BrowserState = {
  youtubeAudioOnly: false,
  youtubeHideThumbnails: false,
  youtubeAllowedChannels: [],
  aiSafeMode: false,
  aiBlockedKeywords: [],
};

export function GroupBrowserSettings({ groupId }: { groupId: string }): JSX.Element {
  const [saved, setSaved] = useState<BrowserState>(EMPTY);
  const [draft, setDraft] = useState<BrowserState>(EMPTY);
  const [channelsText, setChannelsText] = useState("");
  const [keywordsText, setKeywordsText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const r = await api.get<BrowserState>(`/api/portal/v1/groups/${groupId}/browser`);
      const loaded: BrowserState = {
        youtubeAudioOnly: r.youtubeAudioOnly ?? false,
        youtubeHideThumbnails: r.youtubeHideThumbnails ?? false,
        youtubeAllowedChannels: r.youtubeAllowedChannels ?? [],
        aiSafeMode: r.aiSafeMode ?? false,
        aiBlockedKeywords: customKeywords(r.aiBlockedKeywords ?? []),
      };
      setSaved(loaded);
      setDraft(loaded);
      setChannelsText(loaded.youtubeAllowedChannels.join("\n"));
      setKeywordsText(loaded.aiBlockedKeywords.join("\n"));
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "טעינה נכשלה");
    }
  }, [groupId]);

  useEffect(() => { void load(); }, [load]);

  const save = useCallback(async () => {
    setBusy(true);
    setError(null);
    setNote(null);

    try {
      const r = await api.post<BrowserState & { note: string }>(
        `/api/portal/v1/groups/${groupId}/browser`,
        { ...draft, aiBlockedKeywords: effectiveKeywords(draft.aiBlockedKeywords) },
      );
      const result: BrowserState = {
        youtubeAudioOnly: r.youtubeAudioOnly,
        youtubeHideThumbnails: r.youtubeHideThumbnails,
        youtubeAllowedChannels: r.youtubeAllowedChannels ?? [],
        aiSafeMode: r.aiSafeMode,
        aiBlockedKeywords: customKeywords(r.aiBlockedKeywords ?? []),
      };
      setSaved(result);
      setDraft(result);
      setChannelsText(result.youtubeAllowedChannels.join("\n"));
      setKeywordsText(result.aiBlockedKeywords.join("\n"));
      setNote(r.note);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "השמירה נכשלה");
    } finally {
      setBusy(false);
    }
  }, [groupId, draft]);

  const dirty = JSON.stringify(draft) !== JSON.stringify(saved);

  return (
    <div className="panel-body">
      {error !== null && <p className="error">{error}</p>}
      {note !== null && <p className="ok">{note}</p>}

      <p className="muted small" style={{ marginBottom: 12 }}>
        הגדרות סינון עבור מחשבי הקבוצה. דורסות את ההגדרות הכלליות של החשבון.
      </p>

      {/* ─── יוטיוב ─── */}
      <h4 style={{ marginTop: 0 }}>יוטיוב</h4>

      <label className="eg-toggle">
        <input
          type="checkbox"
          checked={draft.youtubeAudioOnly}
          disabled={busy}
          onChange={(e) => setDraft({ ...draft, youtubeAudioOnly: e.target.checked })}
        />
        <span>
          <b>יוטיוב בשמע בלבד</b>
          <span className="muted small">
            {draft.youtubeAudioOnly
              ? " פעיל: אפשר לשמוע סרטונים אבל לא לצפות בהם."
              : " כבוי: יוטיוב עובד כרגיל."}
          </span>
        </span>
      </label>

      {draft.youtubeAudioOnly && (
        <div style={{ marginTop: 8 }}>
          <b>ערוצים מותרים</b>
          <span className="muted small"> קישור או שם הערוץ, אחד בכל שורה.</span>
          <textarea
            dir="ltr"
            rows={3}
            value={channelsText}
            disabled={busy}
            placeholder={"@NatGeo\nhttps://www.youtube.com/@NASA"}
            onChange={(e) => {
              setChannelsText(e.target.value);
              setDraft({
                ...draft,
                youtubeAllowedChannels: e.target.value.split("\n").map((l) => l.trim()).filter((l) => l !== ""),
              });
            }}
            style={{ width: "100%", marginTop: 4, fontFamily: "inherit" }}
          />
        </div>
      )}

      <label className="eg-toggle">
        <input
          type="checkbox"
          checked={draft.youtubeHideThumbnails}
          disabled={busy}
          onChange={(e) => setDraft({ ...draft, youtubeHideThumbnails: e.target.checked })}
        />
        <span>
          <b>הסתרת תמונות ממוזערות ביוטיוב</b>
          <span className="muted small">
            {draft.youtubeHideThumbnails
              ? " פעיל: התמונות הממוזערות מוסתרות."
              : " כבוי: התמונות מוצגות כרגיל."}
          </span>
        </span>
      </label>

      {/* ─── מנועי AI ─── */}
      <h4>מנועי AI</h4>

      <label className="eg-toggle">
        <input
          type="checkbox"
          checked={draft.aiSafeMode}
          disabled={busy}
          onChange={(e) => setDraft({ ...draft, aiSafeMode: e.target.checked })}
        />
        <span>
          <b>סינון במנועי AI</b>
          <span className="muted small">
            {draft.aiSafeMode
              ? " פעיל: תמונות בתשובות AI מוסתרות, ותשובה עם מילה חסומה מטושטשת."
              : " כבוי: אין סינון באתרי AI."}
          </span>
        </span>
      </label>

      {draft.aiSafeMode && (
        <div style={{ marginTop: 8 }}>
          <b>מילים חסומות</b>
          <span className="muted small">
            {" "}רשימה מובנית חלה תמיד. כאן אפשר להוסיף מילים משלך, אחת בכל שורה.
          </span>
          <textarea
            dir="auto"
            rows={3}
            value={keywordsText}
            disabled={busy}
            placeholder={"מילה נוספת\nביטוי שלם"}
            onChange={(e) => {
              setKeywordsText(e.target.value);
              setDraft({
                ...draft,
                aiBlockedKeywords: e.target.value.split("\n").map((l) => l.trim()).filter((l) => l !== ""),
              });
            }}
            style={{ width: "100%", marginTop: 4, fontFamily: "inherit" }}
          />
        </div>
      )}

      {/* ─── שמירה ─── */}
      {dirty && (
        <div style={{ marginTop: 16, display: "flex", gap: 10, alignItems: "center" }}>
          <button disabled={busy} onClick={() => void save()}>
            {busy ? "שומר…" : "שמור"}
          </button>
          <button
            className="ghost"
            disabled={busy}
            onClick={() => {
              setDraft(saved);
              setChannelsText(saved.youtubeAllowedChannels.join("\n"));
              setKeywordsText(saved.aiBlockedKeywords.join("\n"));
            }}
          >
            בטל
          </button>
        </div>
      )}
    </div>
  );
}
