import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api";
import type { GroupRow } from "../types";

export function Groups({ onOpen }: { onOpen: (id: string) => void }): JSX.Element {
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

  if (groups === null && error === null) return <p className="muted">טוען…</p>;

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <h2>קבוצות</h2>
        <button onClick={() => setCreating(true)}>קבוצה חדשה</button>
      </div>

      {error !== null && <p className="error">{error}</p>}

      {creating && (
        <div className="panel" style={{ marginBottom: 16 }}>
          <div className="panel-body" style={{ display: "flex", gap: 10, alignItems: "flex-end" }}>
            <label style={{ flex: 1 }}>
              <span className="muted small">שם הקבוצה</span>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                disabled={busy}
                autoFocus
                onKeyDown={(e) => { if (e.key === "Enter") void create(); }}
                maxLength={60}
              />
            </label>
            <button disabled={busy || !name.trim()} onClick={() => void create()}>צור</button>
            <button className="ghost" onClick={() => { setCreating(false); setName(""); }}>ביטול</button>
          </div>
        </div>
      )}

      {groups !== null && groups.length === 0 && !creating && (
        <p className="muted">
          אין קבוצות עדיין. קבוצות מאפשרות להגדיר שעות חסימה ורשימה לבנה פעם אחת
          ולהחיל על כמה מחשבים.
        </p>
      )}

      {groups !== null && groups.length > 0 && (
        <table className="rows">
          <thead>
            <tr>
              <th>שם</th>
              <th>מחשבים</th>
            </tr>
          </thead>
          <tbody>
            {groups.map((g) => (
              <tr key={g.id} className="clickable" onClick={() => onOpen(g.id)}>
                <td>{g.name}</td>
                <td>{g.memberCount}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
