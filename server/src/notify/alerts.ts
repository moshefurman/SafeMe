import type { TxClient } from "../db/client.ts";
import {
  deviceAlertMessage,
  resolvedAlertMessage,
  silentDeviceMessage,
  type Mailer,
  type Message,
} from "./mailer.ts";
import {
  decideDelivery,
  localHour,
  recipientsFor,
  type AlertChannel,
  type AlertKind as SettingKind,
  type NotificationSettings,
} from "./settings.ts";

/**
 * פתיחה, סגירה ומסירה של התראות. מקום אחד לכל הסוגים.
 *
 * עד כאן היה מסלול אחד — מחשב ששתק — שפתח התראה ושלח מייל בעצמו,
 * וארבעה סוגים שמסך ההגדרות הציע ואיש לא מימש. כל סוג שיתווסף כאן
 * מקבל בחינם את מה שההורה כבר הגדיר: ערוץ, שעות שקט, נמענים
 * מאומתים, ואת הכלל שכשל בשליחה אינו מאבד את ההתראה.
 *
 * שני מחזורי חיים:
 *
 *   condition  מצב שנמשך. נפתח כשהוא מתחיל, נסגר כשהוא נגמר, ובינתיים
 *              לא נפתח שוב. מחשב ששתק, חיבור לא מסונן, נעילה.
 *   event      דבר שקרה. נפתח, נשלח, ונסגר מיד — כדי שהפעם הבאה
 *              תהיה התראה חדשה ולא תיבלע באינדקס הייחודי. חבלה,
 *              רשת חדשה.
 */

export type AlertKind =
  | "device.silent"
  | "device.unfiltered"
  | "device.tamper"
  | "device.lockout"
  | "network.new";

export interface KindInfo {
  /** העמודה בהגדרות ההתראה שקובעת את הערוץ. */
  setting: SettingKind;
  lifecycle: "condition" | "event";
  /** מה קרה, לנושא ולסיכום. */
  headline: string;
  /** מה זה אומר, ומה יקרה מעצמו. */
  explanation: readonly string[];
  /** נוסח הסגירה. חסר = לא מודיעים על סגירה. */
  resolved?: { headline: string; detail: string } | undefined;
}

export const KINDS: Record<AlertKind, KindInfo> = {
  "device.silent": {
    setting: "on_device_silent",
    lifecycle: "condition",
    headline: "הפסיק לדווח",
    explanation: [
      "מחשב שאינו מדווח עשוי להיות כבוי — או שההגנה עליו הופסקה.",
      "כשהוא יחזור לדווח, Filter+‎ יבדוק ביומן האירועים של Windows אם",
      "המחשב היה דלוק בזמן הזה, ויציג את התשובה במרכז הניהול.",
    ],
  },
  "device.unfiltered": {
    setting: "on_unfiltered",
    lifecycle: "condition",
    headline: "מחובר בלי סינון",
    explanation: [
      "המחשב דיווח שהוא יוצא לאינטרנט שלא דרך ספק סינון מאושר.",
      "זה קורה כשמחליפים רשת, כשמתחברים דרך נקודה חמה, או כשהסינון",
      "אצל הספק הופסק. כשהחיבור יחזור לספק מאושר, ההתראה תיסגר מעצמה.",
    ],
  },
  "device.tamper": {
    setting: "on_tamper",
    lifecycle: "event",
    headline: "חשד לחבלה",
    explanation: [
      "ההגנה זיהתה ניסיון לעצור או לשנות אותה. הפרטים למעלה אומרים",
      "אם הניסיון נחסם או הצליח. ניסיון שנחסם הוא מידע; הצלחה היא",
      "סימן שהמחשב אינו מוגן ושכדאי לבדוק אותו.",
    ],
  },
  "device.lockout": {
    setting: "on_lockout",
    lifecycle: "condition",
    headline: "ננעל",
    explanation: [
      "הגלישה במחשב חסומה. הנעילה משתחררת מעצמה כשהחיבור חוזר להיות",
      "מסונן, או ידנית ממרכז הניהול.",
    ],
    resolved: {
      headline: "שוחרר מנעילה",
      detail: "המחשב שוחרר מנעילה והגלישה בו חזרה לפעול.",
    },
  },
  "network.new": {
    setting: "on_new_network",
    lifecycle: "event",
    headline: "רשת חדשה",
    explanation: [
      "המחשב נראה על רשת שלא ראית קודם. השורה למעלה אומרת מה נעשה",
      "איתה לפי ההגדרות: אושרה, נחסמה, או ממתינה להחלטה שלך.",
    ],
  },
};

export interface Notify {
  mailer: Mailer;
  portalUrl: string;
}

/**
 * כמה זמן לא שולחים שוב על אותו מחשב ואותו סוג.
 *
 * מחשב שמרצד בין מסונן ללא מסונן כל דקה יפתח ויסגור התראה כל דקה.
 * ההתראות נרשמות כולן; המייל יוצא על הראשונה, ושוב אחרי שעה אם
 * זה נמשך. הורה שקיבל שישים מיילים בשעה למד להתעלם מהשישים ואחד.
 */
export const COOLDOWN_MINUTES = 60;

export interface RaiseInput {
  deviceId: string;
  kind: AlertKind;
  /** מה קרה, בנוסח להורה. נשמר ומופיע במייל. */
  detail: string;
  now?: Date | undefined;
}

export type Delivery =
  /** נשלח עכשיו */
  | "sent"
  /** ממתין: סיכום יומי, שעות שקט, או ניסיון חוזר אחרי כשל */
  | "deferred"
  /** ההורה ביקש לא לשלוח את הסוג הזה */
  | "off"
  /** נשלח על אותו מחשב לפני פחות משעה */
  | "cooldown"
  /** אין למי לשלוח, או שלא ביקשו לשלוח */
  | "none";

export interface RaiseResult {
  /** האם נפתחה התראה חדשה. false = כבר הייתה פתוחה. */
  opened: boolean;
  delivery: Delivery;
}

interface AlertRow {
  id: string;
  tenant_id: string;
}

/**
 * פותח התראה ומוסר אותה.
 *
 * מחזיר opened=false כשכבר יש התראה פתוחה מאותו סוג לאותו מחשב —
 * זה הכלל שמונע 576 מיילים על מחשב שמנותק יומיים, והוא נאכף
 * באינדקס ולא בקוד, כדי שיחזיק גם מול שני מופעים של השרת.
 */
export async function raiseAlert(
  tx: TxClient,
  notify: Notify | null,
  input: RaiseInput,
): Promise<RaiseResult> {
  const now = input.now ?? new Date();
  const info = KINDS[input.kind];

  const inserted = await tx.query<AlertRow>(
    `INSERT INTO alerts (device_id, tenant_id, kind, state, first_seen_at, detail)
     SELECT $1, d.tenant_id, $2, 'open', $3, $4
       FROM devices d WHERE d.id = $1
     ON CONFLICT (device_id, kind) WHERE state <> 'resolved'
     DO NOTHING
     RETURNING id, tenant_id`,
    [input.deviceId, input.kind, now, input.detail.slice(0, 500)],
  );

  const alert = inserted.rows[0];

  if (!alert) return { opened: false, delivery: "none" };

  let delivery: Delivery = "none";

  if (notify) {
    delivery = await deliver(tx, notify, alert, input, now);
  }

  // אירוע נסגר מיד. הסימון "ממתין" שורד את הסגירה, ולכן הסיכום
  // עדיין יזכיר אותו — כדבר שקרה, לא כמצב.
  if (info.lifecycle === "event") {
    await tx.query(
      "UPDATE alerts SET state = 'resolved', resolved_at = $2 WHERE id = $1",
      [alert.id, now],
    );
  }

  return { opened: true, delivery };
}

async function deliver(
  tx: TxClient,
  notify: Notify,
  alert: AlertRow,
  input: RaiseInput,
  now: Date,
): Promise<Delivery> {
  const info = KINDS[input.kind];
  const context = await loadContext(tx, alert.tenant_id);

  if (context === null) return "none";

  const decision = decideDelivery(context.settings, info.setting, localHour(now));

  if (decision.send === "never") return "off";

  if (decision.send === "digest") {
    await tx.query("UPDATE alerts SET deferred = true WHERE id = $1", [alert.id]);
    return "deferred";
  }

  const recent = await tx.query(
    `SELECT 1 FROM alerts
      WHERE device_id = $1 AND kind = $2 AND id <> $3
        AND last_notified_at > $4::timestamptz - make_interval(mins => $5)
      LIMIT 1`,
    [input.deviceId, input.kind, alert.id, now, COOLDOWN_MINUTES],
  );

  if (recent.rowCount) return "cooldown";

  const name = await deviceName(tx, input.deviceId);

  const message = input.kind === "device.silent"
    ? silentDeviceMessage({
        to: "",
        deviceName: name,
        silenceText: input.detail,
        portalUrl: notify.portalUrl,
      })
    : deviceAlertMessage({
        to: "",
        deviceName: name,
        headline: info.headline,
        detail: input.detail,
        explanation: info.explanation,
        portalUrl: notify.portalUrl,
      });

  const ok = await sendToAll(notify.mailer, message, context.recipients);

  if (!ok) {
    /*
     * כשל בשליחה אינו מאבד את ההתראה. היא מסומנת כממתינה, ועובד
     * הסיכום ינסה שוב בסבב הבא — כשהספק יחזור, או כשהמפתח יתוקן.
     */
    await tx.query("UPDATE alerts SET deferred = true WHERE id = $1", [alert.id]);
    return "deferred";
  }

  await markNotified(tx, [alert.id], now);

  return "sent";
}

export interface ResolveInput {
  deviceId: string;
  kind: AlertKind;
  /** האם להודיע על הסגירה, כשהסוג תומך בכך והפתיחה נשלחה. */
  notice: boolean;
  now?: Date | undefined;
}

/**
 * סוגר התראה פתוחה, אם יש.
 *
 * הסגירה היא מה שמאפשר לפעם הבאה להישלח. בלעדיה ההתראה הראשונה
 * הייתה גם האחרונה: המחשב חוזר, שותק שוב, והאינדקס הייחודי אומר
 * "כבר יש" — בשקט.
 */
export async function resolveAlert(
  tx: TxClient,
  notify: Notify | null,
  input: ResolveInput,
): Promise<{ resolved: boolean }> {
  const now = input.now ?? new Date();

  const r = await tx.query<{
    id: string;
    tenant_id: string;
    notify_count: number;
    first_seen_at: Date;
  }>(
    `UPDATE alerts SET state = 'resolved', resolved_at = $3
      WHERE device_id = $1 AND kind = $2 AND state <> 'resolved'
      RETURNING id, tenant_id, notify_count, first_seen_at`,
    [input.deviceId, input.kind, now],
  );

  const row = r.rows[0];

  if (!row) return { resolved: false };

  const info = KINDS[input.kind];

  /*
   * הודעת סגירה יוצאת רק על מה שכבר הודיעו עליו.
   *
   * התראה שלא נשלחה — ערוץ כבוי, שעות שקט, ממתינה לסיכום — אינה
   * מצדיקה "נגמר" על דבר שההורה לא שמע שהתחיל. הסיכום יגיד את
   * שניהם יחד.
   */
  if (input.notice && notify && info.resolved && row.notify_count > 0) {
    const context = await loadContext(tx, row.tenant_id);

    if (context !== null) {
      const decision = decideDelivery(context.settings, info.setting, localHour(now));

      if (decision.send === "now") {
        const message = resolvedAlertMessage({
          to: "",
          deviceName: await deviceName(tx, input.deviceId),
          headline: info.resolved.headline,
          detail: info.resolved.detail,
          openedAt: row.first_seen_at,
          portalUrl: notify.portalUrl,
        });

        await sendToAll(notify.mailer, message, context.recipients);
      }
    }
  }

  return { resolved: true };
}

// ---------------------------------------------------------------- משותף

export interface TenantContext {
  settings: NotificationSettings;
  lastDigestAt: Date | null;
  /** הראשית והנוספות המאומתות, בלי כפילויות. */
  recipients: string[];
}

interface SettingsRow {
  primary_email: string | null;
  on_device_silent: AlertChannel | null;
  on_unfiltered: AlertChannel | null;
  on_new_network: AlertChannel | null;
  on_tamper: AlertChannel | null;
  on_lockout: AlertChannel | null;
  weekly_digest: boolean | null;
  quiet_from: number | null;
  quiet_to: number | null;
  last_digest_at: Date | null;
  extras: string[] | null;
}

/**
 * ההגדרות והנמענים של דייר.
 *
 * LEFT JOIN, ונפילה אחורה לכתובת הבעלים. דייר בלי שורת הגדרות אמור
 * להיות בלתי אפשרי — יש טריגר — אבל אם זה יקרה, ההתראה חייבת לצאת.
 * JOIN רגיל היה הופך תקלת נתונים להשתקה שקטה של כל ההתראות בחשבון,
 * וזה בדיוק הכשל שהמוצר קיים כדי למנוע.
 *
 * מחזיר null רק כשאין שום כתובת. אז באמת אין למי.
 */
export async function loadContext(
  tx: TxClient,
  tenantId: string,
): Promise<TenantContext | null> {
  const r = await tx.query<SettingsRow>(
    `SELECT COALESCE(s.primary_email, o.email) AS primary_email,
            s.on_device_silent, s.on_unfiltered, s.on_new_network,
            s.on_tamper, s.on_lockout, s.weekly_digest,
            s.quiet_from, s.quiet_to, s.last_digest_at,
            (SELECT array_agg(email) FROM notification_recipients
              WHERE tenant_id = $1 AND verified_at IS NOT NULL) AS extras
       FROM tenants t
       LEFT JOIN notification_settings s ON s.tenant_id = t.id
       LEFT JOIN LATERAL (
         SELECT email FROM users
          WHERE tenant_id = t.id AND role = 'tenant_owner'
          ORDER BY created_at LIMIT 1
       ) o ON true
      WHERE t.id = $1`,
    [tenantId],
  );

  const row = r.rows[0];

  if (!row || !row.primary_email) return null;

  return {
    settings: {
      primaryEmail: row.primary_email,
      channels: {
        on_device_silent: row.on_device_silent ?? "immediate",
        on_unfiltered: row.on_unfiltered ?? "immediate",
        on_new_network: row.on_new_network ?? "immediate",
        on_tamper: row.on_tamper ?? "immediate",
        on_lockout: row.on_lockout ?? "immediate",
      },
      weeklyDigest: row.weekly_digest ?? true,
      quietFrom: row.quiet_from,
      quietTo: row.quiet_to,
    },
    lastDigestAt: row.last_digest_at,
    recipients: recipientsFor(row.primary_email, row.extras ?? []),
  };
}

export async function deviceName(tx: TxClient, deviceId: string): Promise<string> {
  const r = await tx.query<{ name: string }>(
    `SELECT COALESCE(display_name, machine_name, 'מחשב ללא שם') AS name
       FROM devices WHERE id = $1`,
    [deviceId],
  );

  return r.rows[0]?.name ?? "מחשב ללא שם";
}

/**
 * שולח לכל הנמענים. מחזיר האם כולם קיבלו.
 *
 * כשל אצל נמען אחד אינו עוצר את השאר: הכתובת הראשית חשובה יותר
 * מכתובת נוספת שנדחתה, ואסור שהשנייה תפיל את הראשונה.
 */
export async function sendToAll(
  mailer: Mailer,
  message: Message,
  recipients: readonly string[],
): Promise<boolean> {
  let ok = true;

  for (const to of recipients) {
    try {
      await mailer.send({ ...message, to });
    } catch {
      ok = false;
    }
  }

  return ok;
}

/** מסמן שנשלח. מצב סגור נשאר סגור. */
export async function markNotified(
  tx: TxClient,
  alertIds: readonly string[],
  now: Date,
): Promise<void> {
  if (alertIds.length === 0) return;

  await tx.query(
    `UPDATE alerts
        SET state = CASE WHEN state = 'resolved' THEN state ELSE 'notified'::alert_state END,
            last_notified_at = $2,
            notify_count = notify_count + 1,
            deferred = false
      WHERE id = ANY($1::uuid[])`,
    [alertIds, now],
  );
}
