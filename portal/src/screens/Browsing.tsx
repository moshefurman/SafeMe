import { useEffect, useState } from "react";

import { api } from "../api";
import { DeviceFloor } from "../components/DeviceFloor";
import { DeviceNetworks } from "../components/DeviceNetworks";
import { DeviceSchedules, GroupSchedules } from "../components/DeviceSchedules";
import { DeviceWhitelist } from "../components/DeviceWhitelist";
import { GroupBrowserSettings } from "../components/GroupBrowserSettings";
import { GroupWhitelist } from "../components/GroupWhitelist";
import { ScopePicker, SubTabs, type Fleet, type Scope, type ScopeKind } from "../fleet";
import { Egress } from "./Egress";
import { Networks } from "./Networks";
import type { DeviceRow } from "../types";

/**
 * הגדרות גלישה: כל מה שקובע מה מותר למחשב לעשות ברשת.
 *
 * כל נושא בלשונית משלו, ובכל נושא בוחרים על מי הוא חל. הבורר מציג
 * רק את מה שהנושא תומך בו.
 */

export type BrowsingTopic =
  | "whitelist" | "schedules" | "networks" | "content" | "bypass" | "floor";

const TOPICS: ReadonlyArray<{ key: BrowsingTopic; label: string }> = [
  { key: "whitelist", label: "רשימה לבנה" },
  { key: "schedules", label: "זמני גלישה" },
  { key: "networks", label: "רשתות" },
  { key: "content", label: "יוטיוב ומנועי AI" },
  { key: "bypass", label: "חסימת עקיפות" },
  { key: "floor", label: "הגנת מינימום" },
];

/** על מי כל נושא יכול לחול. הראשון הוא ברירת המחדל. */
const KINDS: Record<BrowsingTopic, readonly ScopeKind[]> = {
  whitelist: ["device", "group"],
  schedules: ["device", "group"],
  networks: ["account"],
  content: ["account", "group"],
  bypass: ["account"],
  floor: ["device"],
};

export function Browsing({
  fleet,
  topic,
  onTopic,
  scope,
  onScope,
}: {
  fleet: Fleet;
  topic: BrowsingTopic;
  onTopic: (next: BrowsingTopic) => void;
  scope: Scope;
  onScope: (next: Scope) => void;
}): JSX.Element {
  const kinds = KINDS[topic];
  const devices = fleet.devices ?? [];

  /*
   * ההיקף בפועל.
   *
   * מי שבחר מחשב ועבר לנושא שאין בו הגדרה למחשב אינו מאבד את
   * הבחירה: היא נשמרת, וכאן רק מחושב מה מוצג בינתיים. כשיחזור
   * לנושא של מחשבים, אותו מחשב יהיה שם.
   */
  const effective: Scope | null = (() => {
    if (scope.kind === "device" && !devices.some((d) => d.id === scope.id)) {
      // מחשב שהוסר בינתיים
    } else if (scope.kind === "group" && !fleet.groups.some((g) => g.id === scope.id)) {
      // קבוצה שנמחקה בינתיים
    } else if (kinds.includes(scope.kind)) {
      return scope;
    }

    for (const kind of kinds) {
      if (kind === "account") return { kind: "account" };
      if (kind === "device" && devices[0]) return { kind: "device", id: devices[0].id };
      if (kind === "group" && fleet.groups[0]) return { kind: "group", id: fleet.groups[0].id };
    }

    return null;
  })();

  const device = effective?.kind === "device"
    ? devices.find((d) => d.id === effective.id) ?? null
    : null;

  return (
    <>
      <div className="page-head">
        <h1>הגדרות גלישה</h1>
      </div>

      <SubTabs tabs={TOPICS} value={topic} onChange={onTopic} label="נושאי הגדרות הגלישה" />

      {fleet.devices === null ? (
        <p className="muted">טוען…</p>
      ) : effective === null ? (
        <div className="panel">
          <p className="panel-body muted">
            עוד אין מחשבים בחשבון. אחרי שמוסיפים מחשב בלשונית "המחשבים שלי",
            ההגדרות שלו יופיעו כאן.
          </p>
        </div>
      ) : (
        <>
          {kinds.length > 1 || kinds[0] !== "account" ? (
            <div className="scope-row">
              <ScopePicker fleet={fleet} kinds={kinds} value={effective} onChange={onScope} />

              {device?.group_name && (topic === "whitelist" || topic === "schedules") && (
                <span className="muted small">
                  המחשב שייך לקבוצה {device.group_name}. מה שמוגדר כאן למחשב גובר על הגדרת הקבוצה.
                </span>
              )}
            </div>
          ) : null}

          {/* ─────────────────────────────── רשימה לבנה */}

          {topic === "whitelist" && (
            <div className="panel">
              <div className="panel-head">
                <h2>רשימה לבנה: גלישה לאתרים מאושרים בלבד</h2>
              </div>

              <p className="panel-body muted small" style={{ paddingBottom: 0 }}>
                כשהרשימה פעילה, נפתחים רק האתרים שאושרו וכל השאר חסום. זו ההגנה
                החזקה ביותר במוצר. הדרך הנוחה לבנות את הרשימה היא "למידה": מפעילים
                אותה, גולשים במחשב לאתרים הנחוצים, ומאשרים כאן את מה שנאסף.
              </p>

              {effective.kind === "device"
                ? <DeviceWhitelist key={effective.id} deviceId={effective.id} />
                : effective.kind === "group"
                  ? <GroupWhitelist key={effective.id} groupId={effective.id} />
                  : null}
            </div>
          )}

          {/* ─────────────────────────────── זמני גלישה */}

          {topic === "schedules" && (
            <div className="panel">
              <div className="panel-head">
                <h2>זמני גלישה</h2>
              </div>

              {effective.kind === "device"
                ? <DeviceSchedules deviceId={effective.id} />
                : effective.kind === "group"
                  ? <GroupSchedules groupId={effective.id} />
                  : null}
            </div>
          )}

          {/* ─────────────────────────────── רשתות */}

          {/*
            ההכרעות של כל החשבון תמיד למעלה, כי שם יושבות הרשתות
            שממתינות לאישור. החריג למחשב אחד מתחתיהן, עם בורר משלו:
            מי שהגיע לכאן מלוח הבקרה של מחשב לא אמור להחמיץ בגלל זה
            רשת שמחכה לו.
          */}
          {topic === "networks" && (
            <>
              <Networks />

              {devices.length > 0 && (
                <NetworksForDevice
                  fleet={fleet}
                  deviceId={scope.kind === "device" ? scope.id : null}
                  onDevice={(id) => onScope({ kind: "device", id })}
                />
              )}
            </>
          )}

          {/* ─────────────────────────────── יוטיוב ומנועי AI */}

          {topic === "content" && (
            effective.kind === "group"
              ? (
                <div className="panel">
                  <div className="panel-head"><h2>יוטיוב ומנועי AI לקבוצה</h2></div>
                  <GroupBrowserSettings key={effective.id} groupId={effective.id} />
                </div>
              )
              : <Egress section="content" />
          )}

          {/* ─────────────────────────────── חסימת עקיפות */}

          {topic === "bypass" && <Egress section="bypass" />}

          {/* ─────────────────────────────── הגנת מינימום */}

          {topic === "floor" && device !== null && <FloorFor key={device.id} deviceId={device.id} />}
        </>
      )}
    </>
  );
}

/** אישור או חסימה של רשת למחשב אחד בלבד. */
function NetworksForDevice({
  fleet,
  deviceId,
  onDevice,
}: {
  fleet: Fleet;
  deviceId: string | null;
  onDevice: (id: string) => void;
}): JSX.Element | null {
  const devices = fleet.devices ?? [];
  const current = devices.find((d) => d.id === deviceId) ?? devices[0];

  if (current === undefined) return null;

  return (
    <section style={{ marginTop: 26 }}>
      <h3>חריג למחשב אחד</h3>

      <p className="muted small scope-note">
        אישור או חסימה של רשת למחשב אחד בלבד. הכרעה למחשב גוברת אצלו על ההכרעה
        של כל החשבון, ושאר המחשבים אינם מושפעים.
      </p>

      <div className="scope-row">
        <ScopePicker
          fleet={fleet}
          kinds={["device"]}
          value={{ kind: "device", id: current.id }}
          onChange={(next) => { if (next.kind === "device") onDevice(next.id); }}
          label="המחשב"
        />
      </div>

      <DeviceNetworks key={current.id} deviceId={current.id} />
    </section>
  );
}

/**
 * הגנת המינימום של מחשב אחד.
 *
 * רשימת המחשבים אינה נושאת את הרצפה, ולכן היא נטענת כאן מפרטי
 * המחשב עצמו.
 */
function FloorFor({ deviceId }: { deviceId: string }): JSX.Element {
  const [device, setDevice] = useState<DeviceRow | null>(null);
  const [failed, setFailed] = useState(false);

  const load = () => {
    api.get<DeviceRow>(`/api/portal/v1/devices/${deviceId}`)
      .then(setDevice)
      .catch(() => setFailed(true));
  };

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(load, [deviceId]);

  if (failed) return <p className="error">טעינת פרטי המחשב נכשלה</p>;
  if (device === null) return <p className="muted">טוען…</p>;

  return <DeviceFloor deviceId={deviceId} floor={device.policy_floor} onIssued={load} />;
}
