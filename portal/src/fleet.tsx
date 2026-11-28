import { useCallback, useEffect, useState } from "react";

import { api } from "./api";
import type { DeviceRow, GroupRow } from "./types";

/**
 * המחשבים והקבוצות של החשבון, לבוררים שבראש כל לשונית.
 *
 * כל הגדרה במוצר שייכת למחשב, לקבוצה או לחשבון כולו. עד עכשיו כדי
 * להגיע להגדרה היה צריך קודם להיכנס למחשב, והמסך של המחשב הפך לדף
 * אחד ארוך שמכיל הכול. הבורר הופך את הסדר: קודם בוחרים נושא, ואז
 * על מי הוא חל.
 */

export function deviceLabel(d: Pick<DeviceRow, "display_name" | "machine_name">): string {
  return d.display_name?.trim() || d.machine_name?.trim() || "מחשב ללא כינוי";
}

export interface Fleet {
  devices: DeviceRow[] | null;
  groups: GroupRow[];
  reload: () => Promise<void>;
}

export function useFleet(): Fleet {
  const [devices, setDevices] = useState<DeviceRow[] | null>(null);
  const [groups, setGroups] = useState<GroupRow[]>([]);

  const reload = useCallback(async () => {
    const [d, g] = await Promise.all([
      api.get<{ devices: DeviceRow[] }>("/api/portal/v1/devices").catch(() => ({ devices: [] })),
      // חשבון בלי הרשאה לקבוצות פשוט אינו מציג אותן
      api.get<{ groups: GroupRow[] }>("/api/portal/v1/groups").catch(() => ({ groups: [] })),
    ]);

    setDevices(d.devices);
    setGroups(g.groups);
  }, []);

  useEffect(() => { void reload(); }, [reload]);

  return { devices, groups, reload };
}

/** על מי ההגדרה חלה. */
export type Scope =
  | { kind: "account" }
  | { kind: "device"; id: string }
  | { kind: "group"; id: string };

export type ScopeKind = Scope["kind"];

function encode(scope: Scope): string {
  return scope.kind === "account" ? "account" : `${scope.kind}:${scope.id}`;
}

function decode(value: string): Scope {
  if (value.startsWith("device:")) return { kind: "device", id: value.slice(7) };
  if (value.startsWith("group:")) return { kind: "group", id: value.slice(6) };

  return { kind: "account" };
}

/**
 * בורר "על מי זה חל".
 *
 * מציג רק את מה שהנושא הנוכחי תומך בו: לרשימה לבנה אין הגדרה ברמת
 * החשבון, ולחסימת עקיפות אין הגדרה למחשב יחיד. אפשרות שאי אפשר
 * לבחור בה אינה מוצגת כאפורה, היא פשוט אינה שם.
 */
export function ScopePicker({
  fleet,
  kinds,
  value,
  onChange,
  label = "ההגדרות של",
}: {
  fleet: Fleet;
  kinds: readonly ScopeKind[];
  value: Scope;
  onChange: (next: Scope) => void;
  label?: string;
}): JSX.Element {
  const devices = fleet.devices ?? [];

  return (
    <label className="scope-pick">
      <span>{label}</span>

      <select value={encode(value)} onChange={(e) => onChange(decode(e.target.value))}>
        {kinds.includes("account") && <option value="account">כל החשבון</option>}

        {kinds.includes("device") && devices.length > 0 && (
          <optgroup label="מחשבים">
            {devices.map((d) => (
              <option key={d.id} value={`device:${d.id}`}>{deviceLabel(d)}</option>
            ))}
          </optgroup>
        )}

        {kinds.includes("group") && fleet.groups.length > 0 && (
          <optgroup label="קבוצות">
            {fleet.groups.map((g) => (
              <option key={g.id} value={`group:${g.id}`}>קבוצה: {g.name}</option>
            ))}
          </optgroup>
        )}
      </select>
    </label>
  );
}

/** לשוניות משנה בתוך מסך. */
export function SubTabs<T extends string>({
  tabs,
  value,
  onChange,
  label,
}: {
  tabs: ReadonlyArray<{ key: T; label: string }>;
  value: T;
  onChange: (next: T) => void;
  label: string;
}): JSX.Element {
  return (
    <nav className="subtabs" aria-label={label}>
      {tabs.map((t) => (
        <button
          key={t.key}
          className={t.key === value ? "subtab on" : "subtab"}
          aria-current={t.key === value ? "page" : undefined}
          onClick={() => onChange(t.key)}
        >
          {t.label}
        </button>
      ))}
    </nav>
  );
}
