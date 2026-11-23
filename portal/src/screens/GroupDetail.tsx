import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api";
import { GroupSchedules } from "../components/GroupSchedules";
import { GroupWhitelist } from "../components/GroupWhitelist";
import type { DeviceRow, GroupMember } from "../types";
import { STATUS_LABEL, type SecurityStatus } from "../types";

interface GroupData {
  id: string;
  name: string;
  members: GroupMember[];
}

export function GroupDetail({
  id,
  onBack,
  onOpenDevice,
}: {
  id: string;
  onBack: () => void;
  onOpenDevice?: (deviceId: string) => void;
}): JSX.Element {
  const [group, setGroup] = useState<GroupData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [editing, setEditing] = useState(false);
  const [editName, setEditName] = useState("");

  const [adding, setAdding] = useState(false);
  const [available, setAvailable] = useState<DeviceRow[] | null>(null);

  const load = useCallback(async () => {
    try {
      const r = await api.get<GroupData>(`/api/portal/v1/groups/${id}`);
      setGroup(r);
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "טעינת הקבוצה נכשלה");
    }
  }, [id]);

  useEffect(() => void load(), [load]);

  const rename = useCallback(async () => {
    if (!editName.trim()) return;
    setBusy(true);
    setError(null);

    try {
      await api.patch(`/api/portal/v1/groups/${id}`, { name: editName.trim() });
      setEditing(false);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "שינוי השם נכשל");
    } finally {
      setBusy(false);
    }
  }, [id, editName, load]);

  const deleteGroup = useCallback(async () => {
    if (!window.confirm("למחוק את הקבוצה? המחשבים לא יימחקו, רק ישוחררו מהקבוצה.")) return;
    setBusy(true);

    try {
      await api.del(`/api/portal/v1/groups/${id}`);
      onBack();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "המחיקה נכשלה");
      setBusy(false);
    }
  }, [id, onBack]);

  const addMember = useCallback(async (deviceId: string) => {
    setBusy(true);
    setError(null);

    try {
      const r = await api.post<{ note?: string }>(`/api/portal/v1/groups/${id}/members`, { deviceId });
      if (r.note) setNote(r.note);
      setAdding(false);
      setAvailable(null);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "השיוך נכשל");
    } finally {
      setBusy(false);
    }
  }, [id, load]);

  const removeMember = useCallback(async (deviceId: string) => {
    setBusy(true);
    setError(null);

    try {
      const r = await api.del<{ note?: string }>(`/api/portal/v1/groups/${id}/members/${deviceId}`);
      if (r.note) setNote(r.note);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "ההסרה נכשלה");
    } finally {
      setBusy(false);
    }
  }, [id, load]);

  const resetDevice = useCallback(async (deviceId: string) => {
    if (!window.confirm("לאפס את ההגדרות האישיות של המחשב הזה? יחזור להגדרות הקבוצה.")) return;
    setBusy(true);
    setError(null);

    try {
      const r = await api.post<{ note?: string; schedules: number; domains: number }>(
        `/api/portal/v1/devices/${deviceId}/reset-settings`);
      setNote(`אופסו ${r.schedules} שעות חסימה ו-${r.domains} אתרים. ${r.note ?? ""}`);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "האיפוס נכשל");
    } finally {
      setBusy(false);
    }
  }, []);

  const loadAvailable = useCallback(async () => {
    try {
      const r = await api.get<{ devices: DeviceRow[] }>("/api/portal/v1/devices");
      const memberIds = new Set(group?.members.map((m) => m.id) ?? []);
      setAvailable(r.devices.filter((d) => !memberIds.has(d.id)));
    } catch {
      setAvailable([]);
    }
  }, [group]);

  useEffect(() => {
    if (adding) void loadAvailable();
  }, [adding, loadAvailable]);

  if (group === null && error === null) return <p className="muted shell">טוען…</p>;

  return (
    <main className="shell">
      <div style={{ marginBottom: 16 }}>
        <button className="ghost" onClick={onBack}>← חזור לקבוצות</button>
      </div>

      {error !== null && <p className="error">{error}</p>}
      {note !== null && <p className="ok">{note}</p>}

      {group !== null && (
        <>
          {/* ─── כותרת ─── */}
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
            {editing ? (
              <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                <input
                  type="text"
                  value={editName}
                  onChange={(e) => setEditName(e.target.value)}
                  disabled={busy}
                  autoFocus
                  maxLength={60}
                  onKeyDown={(e) => { if (e.key === "Enter") void rename(); }}
                />
                <button disabled={busy || !editName.trim()} onClick={() => void rename()}>שמור</button>
                <button className="ghost" onClick={() => setEditing(false)}>ביטול</button>
              </div>
            ) : (
              <h2>
                {group.name}
                <button className="ghost" style={{ marginRight: 8 }} onClick={() => { setEditName(group.name); setEditing(true); }}>
                  שנה שם
                </button>
              </h2>
            )}

            <button className="danger" disabled={busy} onClick={() => void deleteGroup()}>
              מחק קבוצה
            </button>
          </div>

          {/* ─── חברי הקבוצה ─── */}
          <div className="panel">
            <div className="panel-header">
              <h3>מחשבים בקבוצה ({group.members.length})</h3>
              <button onClick={() => setAdding(true)} disabled={busy}>הוסף מחשב</button>
            </div>

            <div className="panel-body">
              {group.members.length === 0 && (
                <p className="muted small">אין מחשבים בקבוצה. לחצו "הוסף מחשב" כדי לשייך מחשבים.</p>
              )}

              {group.members.length > 0 && (
                <table className="rows">
                  <tbody>
                    {group.members.map((m) => (
                      <tr key={m.id}>
                        <td
                          className={onOpenDevice ? "clickable" : ""}
                          onClick={() => onOpenDevice?.(m.id)}
                        >
                          <div>{m.displayName || m.machineName || m.id.slice(0, 8)}</div>
                          {m.displayName && m.machineName && (
                            <div className="muted small">{m.machineName}</div>
                          )}
                        </td>
                        <td className="muted small">{STATUS_LABEL[m.lastStatus as SecurityStatus] ?? m.lastStatus}</td>
                        <td style={{ textAlign: "left", whiteSpace: "nowrap" }}>
                          <button className="ghost" disabled={busy} onClick={() => void resetDevice(m.id)}>
                            אפס הגדרות
                          </button>
                          <button className="ghost" disabled={busy} onClick={() => void removeMember(m.id)}>
                            הסר מקבוצה
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}

              {adding && (
                <div style={{ marginTop: 12, padding: 12, border: "1px solid var(--border)", borderRadius: 8 }}>
                  <h4>בחירת מחשב</h4>
                  {available === null ? (
                    <p className="muted">טוען…</p>
                  ) : available.length === 0 ? (
                    <p className="muted small">כל המחשבים כבר בקבוצה, או שאין מחשבים רשומים.</p>
                  ) : (
                    <table className="rows">
                      <tbody>
                        {available.map((d) => (
                          <tr key={d.id} className="clickable" onClick={() => void addMember(d.id)}>
                            <td>{d.display_name || d.machine_name || d.hwid.slice(0, 12)}</td>
                            <td className="muted small">
                              {d.group_name ? `בקבוצה: ${d.group_name}` : "ללא קבוצה"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                  <button className="ghost" style={{ marginTop: 8 }} onClick={() => { setAdding(false); setAvailable(null); }}>
                    ביטול
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* ─── שעות חסימה ─── */}
          <div className="panel" style={{ marginTop: 24 }}>
            <div className="panel-header"><h3>שעות חסימה</h3></div>
            <GroupSchedules groupId={id} />
          </div>

          {/* ─── רשימה לבנה ─── */}
          <div className="panel" style={{ marginTop: 24 }}>
            <div className="panel-header"><h3>רשימה לבנה</h3></div>
            <GroupWhitelist groupId={id} />
          </div>
        </>
      )}
    </main>
  );
}
