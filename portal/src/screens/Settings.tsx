import { useState } from "react";

import { ApiError, api } from "../api";
import { ACCOUNT_TYPE_LABEL, AccountTypePicker, type AccountType } from "../components/AccountTypePicker";
import { DeviceUninstall } from "../components/DeviceUninstall";
import { SupportLink } from "../components/SupportLink";
import { ScopePicker, SubTabs, deviceLabel, type Fleet } from "../fleet";
import { ROLE_LABEL, type Me } from "../types";
import { Notifications } from "./Notifications";
import { Security } from "./Security";

/**
 * הגדרות החשבון: כל מה שאינו "מה מותר למחשב לגלוש".
 *
 * חמישה נושאים, ולכל אחד לשונית. שתי ההסרות יושבות זו ליד זו
 * בכוונה: "להסיר את התוכנה" ו"להסיר את המחשב מהחשבון" נשמעות
 * אותו דבר והן שתי פעולות שונות, וכשהן היו בשני קצוות של דף
 * המחשב לא הייתה דרך לדעת במה לבחור.
 */

export type SettingsTopic = "notifications" | "security" | "uninstall" | "retire" | "account";

const TOPICS: ReadonlyArray<{ key: SettingsTopic; label: string }> = [
  { key: "notifications", label: "התראות" },
  { key: "security", label: "אבטחה" },
  { key: "uninstall", label: "הסרת התוכנה" },
  { key: "retire", label: "הסרת מחשב מהחשבון" },
  { key: "account", label: "החשבון" },
];

export function Settings({
  me,
  fleet,
  topic,
  onTopic,
  deviceId,
  onDevice,
  onAccountChanged,
}: {
  me: Me;
  onAccountChanged: () => void;
  fleet: Fleet;
  topic: SettingsTopic;
  onTopic: (next: SettingsTopic) => void;
  deviceId: string | null;
  onDevice: (id: string) => void;
}): JSX.Element {
  return (
    <>
      <div className="page-head">
        <h1>הגדרות</h1>
      </div>

      <SubTabs tabs={TOPICS} value={topic} onChange={onTopic} label="נושאי ההגדרות" />

      {topic === "notifications" && <Notifications />}

      {topic === "security" && <Security />}

      {topic === "uninstall" && (
        <>
          <Compare />
          <DeviceUninstall />
        </>
      )}

      {topic === "retire" && (
        <>
          <Compare />
          <Retire fleet={fleet} deviceId={deviceId} onDevice={onDevice} />
        </>
      )}

      {topic === "account" && <Account me={me} onChanged={onAccountChanged} />}
    </>
  );
}

/** שתי ההסרות, זו מול זו. */
function Compare(): JSX.Element {
  return (
    <div className="compare">
      <div>
        <b>הסרת התוכנה</b>
        <span>
          מוחקת את Filter+‎ מהמחשב עצמו, והמחשב חוזר לגלוש בלי הגנה. נעשית במחשב,
          עם קוד.
        </span>
      </div>

      <div>
        <b>הסרת מחשב מהחשבון</b>
        <span>
          מוחקת רק את השורה של המחשב מהרשימה כאן. התוכנה נשארת מותקנת במחשב
          וממשיכה לחסום. מתאים למחשב שיצא משימוש.
        </span>
      </div>
    </div>
  );
}

function Retire({
  fleet,
  deviceId,
  onDevice,
}: {
  fleet: Fleet;
  deviceId: string | null;
  onDevice: (id: string) => void;
}): JSX.Element {
  const devices = fleet.devices ?? [];
  const current = devices.find((d) => d.id === deviceId) ?? devices[0] ?? null;

  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function retire() {
    if (current === null) return;

    if (!window.confirm(
      `להסיר את ${deviceLabel(current)} מהחשבון? התוכנה תמשיך לפעול במחשב עצמו.`)) {
      return;
    }

    setBusy(true);
    setError(null);
    setNote(null);

    try {
      const result = await api.post<{ note: string }>(
        `/api/portal/v1/devices/${current.id}/retire`);

      setNote(result.note);
      await fleet.reload();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "ההסרה נכשלה");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel">
      <div className="panel-head">
        <h2>הסרת מחשב מהחשבון</h2>
      </div>

      <div className="panel-body">
        {note !== null && <p className="ok">{note}</p>}
        {error !== null && <p className="error">{error}</p>}

        {fleet.devices === null ? (
          <p className="muted">טוען…</p>
        ) : current === null ? (
          <p className="muted">אין מחשבים בחשבון.</p>
        ) : (
          <>
            <ScopePicker
              fleet={fleet}
              kinds={["device"]}
              value={{ kind: "device", id: current.id }}
              onChange={(next) => { if (next.kind === "device") onDevice(next.id); }}
              label="המחשב להסרה"
            />

            <p className="muted small">
              המחשב יורד מהרשימה, וההיסטוריה שלו נשמרת. אם התוכנה
              עדיין מותקנת בו, היא ממשיכה לפעול לפי ההגדרות האחרונות שקיבלה, ואי
              אפשר יהיה לנהל אותה מכאן. כדי להסיר גם את התוכנה, עושים זאת קודם,
              בלשונית "הסרת התוכנה".
            </p>

            <p className="muted small">
              התקנה חדשה על אותו מחשב תרשום אותו מחדש, עם ההגדרות של קישור
              ההתקנה החדש.
            </p>

            <div>
              <button className="danger" disabled={busy} onClick={() => void retire()}>
                {busy ? "מסיר…" : `הסר את ${deviceLabel(current)} מהחשבון`}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function Account({ me, onChanged }: { me: Me; onChanged: () => void }): JSX.Element {
  const [type, setType] = useState<string>(me.tenantType ?? "");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function saveType() {
    setBusy(true);
    setError(null);
    setNote(null);

    try {
      await api.patch("/api/portal/v1/account/type", { accountType: type });
      setNote(`סוג החשבון עודכן: ${ACCOUNT_TYPE_LABEL[type] ?? type}.`);
      onChanged();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "העדכון נכשל");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      {/*
        סוג החשבון, רק למי שיש לו חשבון. מנהל פלטפורמה אינו שייך
        לדייר, ואין לו מה לבחור.
      */}
      {me.tenantId !== null && (
        <div className="panel" style={{ marginBottom: 16 }}>
          <div className="panel-head">
            <h2>סוג החשבון</h2>
          </div>

          <div className="panel-body">
            <p className="muted small">
              הסוג קובע מי הנאמן: מי שמחזיק את המפתח, ויכול להקל הגדרות, לאשר רשתות
              ולהנפיק קוד הסרה. שינוי הסוג אינו משנה את ההגדרות של מחשבים שכבר
              מותקנים; הוא חל על מתקינים שיוכנו מעכשיו.
            </p>

            {note !== null && <p className="ok">{note}</p>}
            {error !== null && <p className="error">{error}</p>}

            <AccountTypePicker
              value={type}
              disabled={busy}
              name="settings-account-type"
              onChange={(next: AccountType) => setType(next)}
            />

            <div>
              <button
                className="primary"
                disabled={busy || type === "" || type === (me.tenantType ?? "")}
                onClick={() => void saveType()}
              >
                {busy ? "שומר…" : "שמור סוג חשבון"}
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head">
          <h2>פרטי החשבון</h2>
        </div>

        <dl className="kv">
          {me.tenantName !== null && (
            <>
              <dt>שם החשבון</dt>
              <dd>{me.tenantName}</dd>
            </>
          )}

          <dt>מנהל החשבון</dt>
          <dd>{me.displayName ?? "—"}</dd>

          <dt>דוא"ל לכניסה</dt>
          <dd dir="ltr" style={{ textAlign: "right" }}>{me.email}</dd>

          <dt>הרשאה</dt>
          <dd>{ROLE_LABEL[me.role]}</dd>
        </dl>

        <p className="panel-body muted small">
          לחשבון יש מנהל אחד. כדי שאדם נוסף יקבל את ההתראות, מוסיפים את הכתובת
          שלו בלשונית "התראות", תחת כתובות נוספות.
        </p>
      </div>

      <div className="panel">
        <div className="panel-head">
          <h2>סגירת החשבון</h2>
        </div>

        <div className="panel-body">
          <p className="muted small">
            סגירת חשבון נעשית בפנייה אלינו, ולא בלחיצה כאן, כדי שמי שהשיג גישה
            לחשבון לא יוכל למחוק אותו ואת ההגנה יחד איתו. לפני הסגירה צריך להסיר
            את התוכנה מהמחשבים: סגירת החשבון אינה מסירה אותה.
          </p>

          <SupportLink prefix="לסגירת החשבון:" />
        </div>
      </div>
    </>
  );
}
