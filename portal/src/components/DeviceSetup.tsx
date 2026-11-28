import { useEffect, useState } from "react";

import { ApiError, api } from "../api";
import { Egress } from "../screens/Egress";
import { Networks } from "../screens/Networks";
import type { DeviceRow, GroupRow } from "../types";
import { DeviceNetworks } from "./DeviceNetworks";
import { DeviceSchedules } from "./DeviceSchedules";
import { DeviceWhitelist } from "./DeviceWhitelist";

/**
 * הגדרת מחשב חדש, שלב אחרי שלב.
 *
 * ההתקנה עצמה לוקחת שנייה, ומחשב שהותקן כך נשאר עם ברירות המחדל:
 * בלי כינוי, בלי זמני גלישה, בלי רשימה לבנה. מי שהתקין לא ידע
 * שיש מה להגדיר, כי שום דבר לא שאל אותו. האשף הזה שואל, נושא אחרי
 * נושא, ומי שעבר אותו ראה כל הגדרה שיש למוצר.
 *
 * כל שלב מציג את אותו רכיב שיושב בלשונית "הגדרות גלישה", ולא טופס
 * נפרד. כך מה שנקבע כאן הוא בדיוק מה שיופיע שם אחר כך, ואין שני
 * מקומות שיכולים לסתור זה את זה.
 *
 * מחשב שמצורף לקבוצה מקבל את ההגדרות שלה, ולכן אפשר לסיים שם.
 */

type StepKey =
  | "name" | "group" | "schedules" | "whitelist" | "networks" | "content" | "bypass" | "done";

const TITLES: Record<StepKey, string> = {
  name: "כינוי",
  group: "קבוצה",
  schedules: "זמני גלישה",
  whitelist: "רשימה לבנה",
  networks: "רשתות",
  content: "יוטיוב ומנועי AI",
  bypass: "חסימת עקיפות",
  done: "סיום",
};

export function DeviceSetup({
  device,
  onClose,
  onChanged,
}: {
  device: DeviceRow;
  /** סגירת האשף. מקבל true כשהמשתמש ביקש לעבור ללוח הבקרה של המחשב. */
  onClose: (openDashboard: boolean) => void;
  /** משהו נשמר, והרשימה שמאחורי האשף צריכה להתרענן. */
  onChanged: () => void;
}): JSX.Element {
  const [groups, setGroups] = useState<GroupRow[] | null>(null);
  const [step, setStep] = useState<StepKey>("name");
  const [name, setName] = useState(device.display_name ?? "");
  const [groupId, setGroupId] = useState<string>(device.group_id ?? "");
  const [savedGroup, setSavedGroup] = useState<string>(device.group_id ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  useEffect(() => {
    api.get<{ groups: GroupRow[] }>("/api/portal/v1/groups")
      .then((r) => setGroups(r.groups))
      .catch(() => setGroups([]));
  }, []);

  // שלב הקבוצה קיים רק כשיש קבוצות לבחור מהן
  const steps: StepKey[] = [
    "name",
    ...((groups ?? []).length > 0 ? ["group" as const] : []),
    "schedules", "whitelist", "networks", "content", "bypass", "done",
  ];

  const index = Math.max(0, steps.indexOf(step));
  const label = name.trim() || device.machine_name || "המחשב";
  const groupName = (groups ?? []).find((g) => g.id === savedGroup)?.name ?? null;

  function go(delta: number) {
    setError(null);
    setNote(null);
    setStep(steps[Math.min(steps.length - 1, Math.max(0, index + delta))]!);
  }

  async function saveName(): Promise<boolean> {
    if (!name.trim()) return false;
    if (name.trim() === (device.display_name ?? "")) return true;

    try {
      await api.patch(`/api/portal/v1/devices/${device.id}/display-name`, {
        displayName: name.trim(),
      });
      onChanged();

      return true;
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "שמירת הכינוי נכשלה");

      return false;
    }
  }

  async function saveGroup(): Promise<boolean> {
    if (groupId === savedGroup) return true;

    try {
      if (groupId === "") {
        await api.del(`/api/portal/v1/groups/${savedGroup}/members/${device.id}`);
      } else {
        const r = await api.post<{ note?: string }>(
          `/api/portal/v1/groups/${groupId}/members`, { deviceId: device.id });

        if (r.note) setNote(r.note);
      }

      setSavedGroup(groupId);
      onChanged();

      return true;
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "השיוך לקבוצה נכשל");

      return false;
    }
  }

  async function next() {
    setBusy(true);
    setError(null);

    const ok = step === "name" ? await saveName() : step === "group" ? await saveGroup() : true;

    setBusy(false);

    if (ok) {
      setNote(null);
      setStep(steps[Math.min(steps.length - 1, index + 1)]!);
    }
  }

  return (
    <div className="setup">
      <div className="page-head">
        <h1>הגדרת מחשב חדש: {label}</h1>
        <div className="spacer" />
        <button className="ghost" onClick={() => onClose(false)}>סגור והמשך אחר כך</button>
      </div>

      <ol className="setup-steps" aria-label="שלבי ההגדרה">
        {steps.map((s, i) => (
          <li
            key={s}
            className={i === index ? "on" : i < index ? "past" : undefined}
            aria-current={i === index ? "step" : undefined}
          >
            {/* אחרי שיש כינוי אפשר לקפוץ לכל שלב; לפניו לא, כי הוא חובה */}
            <button disabled={!name.trim() || busy} onClick={() => { setError(null); setNote(null); setStep(s); }}>
              <span className="setup-n">{i + 1}</span>
              {TITLES[s]}
            </button>
          </li>
        ))}
      </ol>

      {error !== null && <p className="error">{error}</p>}
      {note !== null && <p className="ok-note">{note}</p>}

      {/* ─────────────────────────────── כינוי */}

      {step === "name" && (
        <div className="panel">
          <div className="panel-head"><h2>איך לקרוא למחשב?</h2></div>

          <div className="panel-body">
            <p className="muted small">
              הכינוי הוא מה שיופיע בהתראות וברשימת המחשבים, למשל "קבלה" או "המחשב של
              דני". בלעדיו לא ברור איזה מחשב שלח התראה.
              {device.machine_name ? ` שם המחשב ב-Windows הוא ${device.machine_name}.` : ""}
            </p>

            <label className="field" htmlFor="setup-name">
              כינוי למחשב
              <input
                id="setup-name"
                type="text"
                value={name}
                maxLength={60}
                autoFocus
                disabled={busy}
                placeholder="כינוי למחשב"
                onChange={(e) => setName(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter" && name.trim()) void next(); }}
              />
            </label>
          </div>
        </div>
      )}

      {/* ─────────────────────────────── קבוצה */}

      {step === "group" && (
        <div className="panel">
          <div className="panel-head"><h2>לצרף את המחשב לקבוצה?</h2></div>

          <div className="panel-body">
            <p className="muted small">
              מחשב שמצורף לקבוצה מקבל מיד את כל ההגדרות שלה: רשימה לבנה, זמני גלישה
              וסינון יוטיוב ו-AI. אין צורך להגדיר אותן שוב.
            </p>

            <div className="setup-choices" role="radiogroup" aria-label="קבוצה">
              <label className={groupId === "" ? "on" : undefined}>
                <input
                  type="radio"
                  name="setup-group"
                  checked={groupId === ""}
                  disabled={busy}
                  onChange={() => setGroupId("")}
                />
                <span>
                  <b>בלי קבוצה</b>
                  <span>המחשב יוגדר בנפרד, בשלבים הבאים.</span>
                </span>
              </label>

              {(groups ?? []).map((g) => (
                <label key={g.id} className={groupId === g.id ? "on" : undefined}>
                  <input
                    type="radio"
                    name="setup-group"
                    checked={groupId === g.id}
                    disabled={busy}
                    onChange={() => setGroupId(g.id)}
                  />
                  <span>
                    <b>{g.name}</b>
                    <span>{g.memberCount === 1 ? "מחשב אחד בקבוצה" : `${g.memberCount} מחשבים בקבוצה`}</span>
                  </span>
                </label>
              ))}
            </div>
          </div>
        </div>
      )}

      {/*
        אחרי צירוף לקבוצה אפשר לעצור. השלבים הבאים נשארים פתוחים למי
        שרוצה לתת למחשב הזה הגדרה משלו, שגוברת על זו של הקבוצה.
      */}
      {groupName !== null && (step === "schedules" || step === "whitelist") && (
        <div className="setup-group-note">
          <span>
            המחשב בקבוצה <b>{groupName}</b> וההגדרות שלה כבר חלות עליו. מה שתקבע כאן
            יחול רק על המחשב הזה, ויגבר על הגדרת הקבוצה.
          </span>
          <button onClick={() => setStep("done")}>מספיק לי הגדרות הקבוצה</button>
        </div>
      )}

      {/* ─────────────────────────────── זמני גלישה */}

      {step === "schedules" && (
        <div className="panel">
          <div className="panel-head"><h2>באילו שעות המחשב חסום לגלישה?</h2></div>
          <DeviceSchedules deviceId={device.id} />
        </div>
      )}

      {/* ─────────────────────────────── רשימה לבנה */}

      {step === "whitelist" && (
        <div className="panel">
          <div className="panel-head"><h2>לאפשר גלישה רק לאתרים מאושרים?</h2></div>

          <p className="panel-body muted small" style={{ paddingBottom: 0 }}>
            כשהרשימה הלבנה פעילה, נפתחים רק האתרים שאישרת וכל השאר חסום. אם המחשב
            אמור לגלוש חופשי דרך ספק סינון, משאירים אותה כבויה וממשיכים.
          </p>

          <DeviceWhitelist deviceId={device.id} />
        </div>
      )}

      {/* ─────────────────────────────── רשתות */}

      {step === "networks" && (
        <>
          <p className="muted small scope-note">
            כאן קובעים מה קורה כשמחשב מתחבר לרשת Wi-Fi או לנקודה חמה שעוד לא אושרה.
            ההגדרה חלה על כל המחשבים בחשבון. בתחתית אפשר לאשר או לחסום רשת למחשב
            הזה בלבד.
          </p>

          <Networks />

          <section style={{ marginTop: 22 }}>
            <h3>רק ל{label}</h3>
            <DeviceNetworks deviceId={device.id} />
          </section>
        </>
      )}

      {/* ─────────────────────────────── יוטיוב ו-AI */}

      {step === "content" && (
        <>
          <p className="muted small scope-note">
            חסימת תמונות וסרטונים: יוטיוב בשמע בלבד, הסתרת תמונות ממוזערות, וסינון
            תמונות ומילים בתשובות של מנועי AI.
            {groupName !== null
              ? ` למחשבי הקבוצה ${groupName} אפשר לקבוע הגדרה נפרדת בלשונית "הגדרות גלישה".`
              : ""}
          </p>

          <Egress section="content" />
        </>
      )}

      {/* ─────────────────────────────── עקיפות */}

      {step === "bypass" && (
        <>
          <p className="muted small scope-note">
            חסימת VPN ותוכנות שמאפשרות לגלוש בלי שהסינון רואה.
          </p>

          <Egress section="bypass" />
        </>
      )}

      {/* ─────────────────────────────── סיום */}

      {step === "done" && (
        <div className="panel">
          <div className="panel-head"><h2>{label} מוגדר</h2></div>

          <div className="panel-body">
            <p className="muted small">
              ההגדרות נשמרו, והמחשב מקבל אותן בדיווח הבא שלו, בדרך כלל תוך שלוש
              דקות. כל הגדרה אפשר לשנות בכל עת בלשונית "הגדרות גלישה", ואת המצב של
              המחשב רואים בלוח הבקרה שלו.
            </p>

            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <button className="primary" onClick={() => onClose(true)}>ללוח הבקרה של המחשב</button>
              <button onClick={() => onClose(false)}>חזרה לרשימת המחשבים</button>
            </div>
          </div>
        </div>
      )}

      {step !== "done" && (
        <div className="setup-nav">
          {index > 0 && <button disabled={busy} onClick={() => go(-1)}>הקודם</button>}

          <div className="spacer" />

          <span className="muted small">שלב {index + 1} מתוך {steps.length}</span>

          <button
            className="primary"
            disabled={busy || (step === "name" && !name.trim())}
            onClick={() => void next()}
          >
            {busy ? "שומר…" : step === "name" || step === "group" ? "שמור והמשך" : "המשך"}
          </button>
        </div>
      )}
    </div>
  );
}
