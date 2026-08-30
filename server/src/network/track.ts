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
 * מעקב אחר הרשת שהמחשב מחובר אליה.
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
  approved_isp: string | null;
}

/**
 * בוחר את המתאם שדרכו המחשב יוצא לאינטרנט.
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
 * מחזיר null כשאין מתאם מזוהה — מחשב בלי חיבור אינו מצב חריג,
 * ואין מה לרשום עליו.
 */
export async function trackNetwork(
  tx: { query: pg.ClientBase["query"] },
  device: { deviceId: string; tenantId: string },
  adapters: readonly AdapterInput[],
  detectedProvider: string | null,
  /**
   * ספק האינטרנט שמאחורי הרשת.
   *
   * key ריק פירושו שהסוכן לא הצליח לקרוא. במקרה כזה שום דבר לא
   * משתנה — לא הרשומה ולא האישור. זו נקודת הכשל הרגישה כאן:
   * הקריאה נכשלת בדיוק כשהרשת חסומה, ומשפחה לא אמורה לאבד את
   * אישור הרשת בגלל שהמחשב שלה כבר נחסם.
   */
  isp: { key: string | null; name: string | null },
  /*
   * מצב האכיפה במחשב.
   *
   * ההכרעה אינה תלויה בו — רשת שצריך לחסום היא רשת שצריך לחסום —
   * אבל **הרישום** תלוי: במצב תצפית שום דבר לא נחסם בפועל, ורישום
   * "נחסם" הוא דיווח על מה שלא קרה.
   */
  enforcementMode: string = "enforce",
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
    `SELECT id, approval, approved_isp
       FROM known_networks
      WHERE tenant_id = $1 AND fingerprint = $2`,
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
    isp: isp.key,
    approvedIsp: known?.approved_isp ?? null,
  });

  /*
   * האם האישור נשלל בגלל שהספק התחלף.
   *
   * מזוהה כאן ולא נלמד מהתוצאה: "ממתינה לאישור" יכולה להגיע גם
   * מרשת חדשה, ורק בצירוף אישור קיים היא אומרת שהקו מאחורי הנתב
   * הוחלף.
   */
  const ispChanged =
    known?.approval === "approved" &&
    decision.action === "await_approval";

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
        decided_at, blocked_by_rule, isp_key, isp_name, approved_isp)
     VALUES ($1, $2, $3, $4, $5, $6::network_approval, $7, $8, $9,
             CASE WHEN $6 <> 'pending' THEN now() ELSE NULL END, $10::uuid,
             $11, $12,
             -- רשת שנרשמת כמאושרת, מאושרת עבור הספק שנצפה עכשיו
             CASE WHEN $6 <> 'pending' THEN $11 ELSE NULL END)
     ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET
       last_seen_at = now(),
       ssid = COALESCE(EXCLUDED.ssid, known_networks.ssid),
       gateway_ip = COALESCE(EXCLUDED.gateway_ip, known_networks.gateway_ip),
       detected_provider = EXCLUDED.detected_provider,
       hotspot_confidence = EXCLUDED.hotspot_confidence,
       hotspot_reasons = EXCLUDED.hotspot_reasons,

       -- ספק שלא נקרא אינו מוחק את מה שידוע
       isp_key  = COALESCE(EXCLUDED.isp_key,  known_networks.isp_key),
       isp_name = COALESCE(EXCLUDED.isp_name, known_networks.isp_name),

       approval = CASE
         -- חסימה מכלל דורסת מצב קודם; החלטה ידנית של ההורה לא
         WHEN $10::uuid IS NOT NULL THEN 'blocked'::network_approval
         -- הקו מאחורי הנתב הוחלף. האישור ניתן לצירוף, ולא לנתב לבדו.
         WHEN $13 THEN 'pending'::network_approval
         ELSE known_networks.approval
       END,

       /*
        * האילוץ דורש ש-pending יהיה בדיוק כשאין זמן החלטה, ולכן
        * שלילת האישור חייבת לנקות גם אותו.
        */
       decided_at = CASE WHEN $13 THEN NULL ELSE known_networks.decided_at END,
       decided_by = CASE WHEN $13 THEN NULL ELSE known_networks.decided_by END,

       /*
        * ורישום הספק שאושר.
        *
        * רשת שאושרה לפני שהשדה היה קיים נושאת NULL, ואין מול מה
        * להשוות. היא מקבלת את הספק הנוכחי בפעימה הראשונה שקוראת
        * אותו — קו הבסיס נקבע, ומכאן והלאה החלפה תיתפס. הרחבה של
        * הגנה אינה אמורה לנעול רטרואקטיבית מי שכבר אישר.
        */
       approved_isp = CASE
         WHEN $13 THEN NULL
         WHEN known_networks.approval = 'approved' AND known_networks.approved_isp IS NULL
           THEN COALESCE($11, known_networks.approved_isp)
         ELSE known_networks.approved_isp
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
      isp.key,
      isp.name,
      ispChanged,
    ],
  );

  const networkId = upserted.rows[0]!.id;

  await manageSession(
    tx, device, networkId, firstEver ? "allow" : decision.action, enforcementMode, isp);

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
 * נבדק ולא נגזר מ-known === null: מחשב שני שמתחבר לרשת חדשה אינו
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
  enforcementMode: string,
  isp: { key: string | null; name: string | null },
): Promise<void> {
  const open = await tx.query<{ id: string; network_id: string; isp_key: string | null }>(
    `SELECT id, network_id, isp_key FROM network_sessions
      WHERE device_id = $1 AND ended_at IS NULL
      ORDER BY started_at DESC LIMIT 1`,
    [device.deviceId],
  );

  const current = open.rows[0];

  /*
   * החלפת קו מאחורי אותו נתב סוגרת סשן ופותחת חדש.
   *
   * זו כל התועלת שבשמירת הספק בהיסטוריה: השאלה שנשאלת היא "מתי
   * זה השתנה", ולה יש תשובה רק אם יש שתי שורות. סשן אחד ארוך
   * שערך הספק בו התחלף באמצע מוחק בדיוק את הרגע שמחפשים.
   *
   * ורק כשהספק נקרא בשני הצדדים. קריאה שנכשלה אינה החלפה, וסשן
   * חדש בכל כשל קריאה היה ממלא את ההיסטוריה ברעש.
   */
  const sameNetwork = current?.network_id === networkId;

  const ispSwitched =
    isp.key !== null && current?.isp_key != null && current.isp_key !== isp.key;

  if (sameNetwork && !ispSwitched) {
    // אותה רשת. התוצאה עשויה להשתנות — הורה שאישר באמצע הסשן.
    await tx.query(
      `UPDATE network_sessions
          SET outcome = $2,
              -- סשן שנפתח לפני שהספק נקרא מקבל אותו כשהוא מתברר
              isp_key  = COALESCE(isp_key,  $3),
              isp_name = COALESCE(isp_name, $4)
        WHERE id = $1`,
      [current.id, outcomeOf(action, enforcementMode), isp.key, isp.name],
    );

    return;
  }

  if (current) {
    await tx.query("UPDATE network_sessions SET ended_at = now() WHERE id = $1", [current.id]);
  }

  await tx.query(
    `INSERT INTO network_sessions (device_id, tenant_id, network_id, outcome, isp_key, isp_name)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [
      device.deviceId,
      device.tenantId,
      networkId,
      outcomeOf(action, enforcementMode),
      isp.key,
      isp.name,
    ],
  );
}

/**
 * מה לרשום שקרה בפועל.
 *
 * הפורטל הציג "חסום" בזמן שהמשתמש גלש באותה רשת בלי הפרעה. שניהם
 * היו נכונים מבחינתם: ההכרעה אמרה לחסום, והאכיפה במצב תצפית לא
 * חסמה דבר. מה שנשבר הוא הדיווח — הוא הציג כוונה כעובדה.
 *
 * זה אינו פגם קוסמטי. מוצר שמדווח על חסימה שלא קרתה מלמד את ההורה
 * שאי אפשר להאמין למה שכתוב, וברגע שזה נלמד — גם חסימה אמיתית לא
 * תיקרא.
 */
function outcomeOf(action: NetworkAction, enforcementMode: string): string {
  if (action === "allow") return "allowed";

  const enforcing = enforcementMode === "enforce";

  if (action === "block") return enforcing ? "blocked" : "observed";

  return "pending";
}
