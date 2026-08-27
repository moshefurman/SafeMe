import type pg from "pg";

import type { BlockRule } from "./blocklist.ts";
import {
  decideNetwork,
  describeDecision,
  fingerprintOf,
  type NetworkAction,
  type NetworkApproval,
  type NetworkPolicy,
} from "./decide.ts";

/**
 * מעקב אחר הרשת שהמכשיר מחובר אליה.
 *
 * שלוש פעולות בכל פעימה: לזהות את הרשת, לרשום אותה אם היא חדשה,
 * ולנהל את הסשן. הסשן נפתח בהתחברות ונסגר במעבר לרשת אחרת — שורה
 * לכל חיבור, לא לכל פעימה. זה אותו שיעור שלמדנו בטלמטריה.
 */

/*
 * השדות מקבלים גם undefined במפורש.
 *
 * exactOptionalPropertyTypes מבחין בין "שדה חסר" לבין "שדה עם ערך
 * undefined", ומה שמגיע מ-zod הוא השני. בלי ההבחנה הזו הטיפוס נראה
 * נכון ואינו מתאים.
 */
export interface AdapterInput {
  name: string;
  ssid?: string | null | undefined;
  gateway?: string | null | undefined;
  gatewayMac?: string | null | undefined;
  isVirtualVpn?: boolean | undefined;

  /** האם הרשת פתוחה, בלי הצפנה. */
  isOpen?: boolean | null | undefined;
}

export interface NetworkOutcome {
  action: NetworkAction;
  reason: string;
  /** שם הרשת, לתצוגה בסוכן. */
  ssid: string | null;
  /** האם זו רשת חדשה שנרשמה עכשיו. */
  isNew: boolean;
}

interface NetworkRow {
  id: string;
  approval: NetworkApproval;
}

/**
 * בוחר את המתאם שדרכו המכשיר יוצא לאינטרנט.
 *
 * מתאם וירטואלי מדולג: הוא לא הרשת אלא מנהרה מעליה, ורישומו היה
 * מחליף את זהות הרשת האמיתית בזהות ה-VPN.
 */
export function primaryAdapter(adapters: readonly AdapterInput[]): AdapterInput | null {
  return adapters.find((a) => !a.isVirtualVpn && a.gateway) ?? null;
}

/**
 * מזהה, רושם, ומכריע.
 *
 * מחזיר null כשאין מתאם מזוהה — מכשיר בלי חיבור אינו מצב חריג,
 * ואין מה לרשום עליו.
 */
export async function trackNetwork(
  tx: { query: pg.ClientBase["query"] },
  device: { deviceId: string; tenantId: string },
  adapters: readonly AdapterInput[],
  detectedProvider: string | null,
): Promise<NetworkOutcome | null> {
  const adapter = primaryAdapter(adapters);

  if (adapter === null) return null;

  const identity = {
    ssid: adapter.ssid ?? null,
    gatewayIp: adapter.gateway ?? null,
    gatewayMac: adapter.gatewayMac ?? null,
  };

  const fingerprint = fingerprintOf(identity);

  const policyRow = await tx.query<{ network_policy: NetworkPolicy }>(
    "SELECT network_policy FROM tenants WHERE id = $1",
    [device.tenantId],
  );

  const policy = policyRow.rows[0]?.network_policy ?? "balanced";

  const ruleRows = await tx.query<BlockRule>(
    `SELECT id, kind, pattern, note, enabled
       FROM network_block_rules
      WHERE tenant_id = $1 AND enabled
      ORDER BY created_at`,
    [device.tenantId],
  );

  const existing = await tx.query<NetworkRow>(
    "SELECT id, approval FROM known_networks WHERE tenant_id = $1 AND fingerprint = $2",
    [device.tenantId, fingerprint],
  );

  const known = existing.rows[0] ?? null;

  /*
   * הרשת הראשונה של הדייר מאושרת מאליה.
   *
   * זה תוקן אחרי שנפל בשטח: התקנה ראשונה חסמה את הרשת שממנה היא
   * עצמה הורדה. ההורה עמד מול מחשב חסום, והדרך לאשר עברה בפורטל
   * שהמחשב כבר לא יכול היה להגיע אליו.
   *
   * ההיגיון פשוט: מי שמתקין עומד פיזית מול המחשב, ברשת שהוא בחר.
   * עצם ההתקנה הוא אישור לרשת הזו. כל רשת אחרת אחריה תישאל.
   */
  const firstEver = known === null && await isFirstNetwork(tx, device.tenantId);

  const decision = decideNetwork({
    ...identity,
    policy,
    approval: known?.approval ?? null,
    detectedProvider,
    blockRules: ruleRows.rows,
    isOpen: adapter.isOpen ?? null,
  });

  /*
   * כלל שתפס נרשם.
   *
   * המונה מראה להורה איזה כלל עובד ואיזה סתם יושב שם, וזה ההבדל
   * בין רשימה שמתחזקים לבין רשימה שגדלה לנצח.
   */
  if (decision.blockedBy) {
    await tx.query(
      `UPDATE network_block_rules
          SET hit_count = hit_count + 1, last_hit_at = now()
        WHERE id = $1`,
      [decision.blockedBy.rule.id],
    );
  }

  // רשת חדשה נרשמת גם כשהיא נחסמת. ההורה צריך לראות מה נחסם, ולא
  // רק שמשהו נחסם.
  const approval: NetworkApproval = decision.autoApprove || firstEver
    ? "approved"
    : decision.blockedBy
      ? "blocked"
      : (known?.approval ?? "pending");

  const upserted = await tx.query<{ id: string }>(
    `INSERT INTO known_networks
       (tenant_id, fingerprint, ssid, gateway_ip, gateway_mac,
        approval, hotspot_confidence, hotspot_reasons, detected_provider,
        decided_at, blocked_by_rule)
     VALUES ($1, $2, $3, $4, $5, $6::network_approval, $7, $8, $9,
             CASE WHEN $6 <> 'pending' THEN now() ELSE NULL END, $10::uuid)
     ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET
       last_seen_at = now(),
       ssid = COALESCE(EXCLUDED.ssid, known_networks.ssid),
       gateway_ip = COALESCE(EXCLUDED.gateway_ip, known_networks.gateway_ip),
       detected_provider = EXCLUDED.detected_provider,
       hotspot_confidence = EXCLUDED.hotspot_confidence,
       hotspot_reasons = EXCLUDED.hotspot_reasons,
       approval = CASE
         -- חסימה מכלל דורסת מצב קודם; החלטה ידנית של ההורה לא
         WHEN $10::uuid IS NOT NULL THEN 'blocked'::network_approval
         ELSE known_networks.approval
       END,
       blocked_by_rule = $10::uuid
     RETURNING id`,
    [
      device.tenantId,
      fingerprint,
      identity.ssid,
      identity.gatewayIp,
      identity.gatewayMac,
      approval,
      decision.hotspot.confidence,
      JSON.stringify(decision.hotspot.reasons),
      detectedProvider,
      decision.blockedBy?.rule.id ?? null,
    ],
  );

  const networkId = upserted.rows[0]!.id;

  await manageSession(tx, device, networkId, firstEver ? "allow" : decision.action);

  return {
    action: firstEver ? "allow" : decision.action,
    reason: firstEver
      ? "הרשת שממנה בוצעה ההתקנה. אושרה אוטומטית."
      : describeDecision(decision, identity.ssid),
    ssid: identity.ssid,
    isNew: known === null,
  };
}

/**
 * האם לדייר אין עדיין אף רשת.
 *
 * נבדק ולא נגזר מ-known === null: מכשיר שני שמתחבר לרשת חדשה אינו
 * "התקנה ראשונה", וגם הוא היה מקבל אישור אוטומטי בלי הבדיקה הזו.
 */
async function isFirstNetwork(
  tx: { query: pg.ClientBase["query"] },
  tenantId: string,
): Promise<boolean> {
  const r = await tx.query<{ n: string }>(
    "SELECT count(*) AS n FROM known_networks WHERE tenant_id = $1",
    [tenantId],
  );

  return Number(r.rows[0]?.n ?? 0) === 0;
}

/**
 * פותח סשן חדש או ממשיך קיים.
 *
 * מעבר לרשת אחרת סוגר את הסשן הפתוח. זו הנקודה היחידה שבה נכתבת
 * שורה חדשה, ולכן ההיסטוריה נשארת קריאה: כמה עשרות שורות בחודש
 * במקום עשרות אלפים.
 */
async function manageSession(
  tx: { query: pg.ClientBase["query"] },
  device: { deviceId: string; tenantId: string },
  networkId: string,
  action: NetworkAction,
): Promise<void> {
  const open = await tx.query<{ id: string; network_id: string }>(
    `SELECT id, network_id FROM network_sessions
      WHERE device_id = $1 AND ended_at IS NULL
      ORDER BY started_at DESC LIMIT 1`,
    [device.deviceId],
  );

  const current = open.rows[0];

  if (current?.network_id === networkId) {
    // אותה רשת. התוצאה עשויה להשתנות — הורה שאישר באמצע הסשן.
    await tx.query(
      "UPDATE network_sessions SET outcome = $2 WHERE id = $1",
      [current.id, outcomeOf(action)],
    );

    return;
  }

  if (current) {
    await tx.query("UPDATE network_sessions SET ended_at = now() WHERE id = $1", [current.id]);
  }

  await tx.query(
    `INSERT INTO network_sessions (device_id, tenant_id, network_id, outcome)
     VALUES ($1, $2, $3, $4)`,
    [device.deviceId, device.tenantId, networkId, outcomeOf(action)],
  );
}

function outcomeOf(action: NetworkAction): string {
  return action === "allow" ? "allowed" : action === "block" ? "blocked" : "pending";
}
