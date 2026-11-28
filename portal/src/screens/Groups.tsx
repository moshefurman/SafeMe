import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api";
import type { GroupRow } from "../types";

/**
 * קבוצות, כחלק ממסך המחשבים.
 *
 * כשהן ישבו בלשונית משלהן לא היה ברור מה ההבדל בין "מחשבים"
 * ל"קבוצות". ההבדל נאמר כאן במשפט אחד, ליד המחשבים עצמם: קבוצה
 * אינה סוג אחר של דבר, היא דרך להגדיר כמה מחשבים בבת אחת.
 */
export function Groups({ onOpen }: { onOpen: (id: string) => void }): JSX.Element | null {
  const [groups, setGroups] = useState<GroupRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");

  const load = useCallback(async () => {
    try {
      const r = await api.get<{ groups: GroupRow[] }>("/api/portal/v1/groups");
      setGroups(r.groups);
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "טעינת הקבוצות נכשלה");
    }
  }, []);

  useEffect(() => void load(), [load]);

  const create = useCallback(async () => {
    if (!name.trim()) return;
    setBusy(true);
    setError(null);

    try {
      const r = await api.post<{ id: string }>("/api/portal/v1/groups", { name: name.trim() });
      setCreating(false);
      setName("");
      await load();
      onOpen(r.id);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "יצירת הקבוצה נכשלה");
    } finally {
      setBusy(false);
    }
  }, [name, load, onOpen]);

  if (groups === null && error === null) return null;

  return (
    <div className="panel" style={{ marginTop: 18 }}>
      <div className="panel-head">
        <h2>קבוצות</h2>
        <div className="spacer" />
        {!creating && <button onClick={() => setCreating(true)}>קבוצה חדשה</button>}
      </div>

      <div className="panel-body">
        <p className="muted small">
          קבוצה היא דרך לתת לכמה מחשבים את אותן הגדרות בבת אחת: רשימה לבנה, זמני
          גלישה וסינון תוכן. מגדירים פעם אחת לקבוצה, וכל מחשב שמשויך אליה מקבל
          אותן. בלי קבוצות, כל מחשב מוגדר בנפרד.
        </p>

        {error !== null && <p className="error">{error}</p>}

        {creating && (
          <div style={{ display: "flex", gap: 10, alignItems: "flex-end", flexWrap: "wrap" }}>
            <label style={{ flex: "1 1 220px" }}>
              <span className="muted small">שם הקבוצה</span>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                disabled={busy}
                autoFocus
                placeholder="למשל: מחשבי הקבלה"
                onKeyDown={(e) => { if (e.key === "Enter") void create(); }}
                maxLength={60}
              />
            </label>
            <button className="primary" disabled={busy || !name.trim()} onClick={() => void create()}>צור</button>
            <button className="ghost" onClick={() => { setCreating(false); setName(""); }}>ביטול</button>
          </div>
        )}

        {groups !== null && groups.length === 0 && !creating && (
          <p className="muted small">עוד אין קבוצות.</p>
        )}
      </div>

      {groups !== null && groups.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>קבוצה</th>
              <th>מחשבים</th>
              <th><span className="sr-only">פתיחה</span></th>
            </tr>
          </thead>
          <tbody>
            {groups.map((g) => (
              <tr key={g.id} onClick={() => onOpen(g.id)}>
                <td><div className="device-name">{g.name}</div></td>
                <td className="num">{g.memberCount}</td>
                <td style={{ textAlign: "left" }}>
                  <button className="ghost" onClick={(e) => { e.stopPropagation(); onOpen(g.id); }}>
                    ניהול הקבוצה
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
