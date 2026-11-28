import { createHash, randomBytes } from "node:crypto";

import type { FastifyBaseLogger, FastifyReply, FastifyRequest } from "fastify";
import type pg from "pg";

import { withPlatform } from "../db/client.ts";
import type { Mailer, Message } from "../notify/mailer.ts";

/**
 * שער הנאמן.
 *
 * כל מסלול שמקל על ההגנה קורא ל-gate() לפני שהוא מבצע. השער מחליט
 * אחת משלוש:
 *
 *   אין נאמן פעיל, או שהבקשה אינה של בעל חשבון: הפעולה ממשיכה.
 *
 *   מצב inform: הפעולה ממשיכה, והנאמנים מקבלים הודעה אחרי שהצליחה.
 *
 *   מצב approve: הפעולה נעצרת. נוצרת בקשה, הנאמנים מקבלים קישור,
 *   ובעל החשבון מקבל תשובה שאומרת שזה ממתין. כשנאמן מאשר, בעל
 *   החשבון מבצע את אותה פעולה שוב, והשער מזהה אותה ונותן לה לעבור.
 *
 * למה בעל החשבון מבצע שוב, ולא השרת בשמו. האפשרות השנייה הייתה
 * שהשרת ישחזר את הבקשה ברגע האישור, וזה מחייב לזייף הפעלה של
 * משתמש שאינו מחובר. כאן כל ביצוע עובר את אותן בדיקות הפעלה,
 * CSRF והרשאה כמו תמיד, והאישור הוא רק מה שחסר לו.
 *
 * האישור תקף לפעולה אחת בדיוק: אותה שיטה, אותו נתיב, אותו גוף.
 * אישור להוסיף אתר אחד לרשימה הלבנה אינו אישור להוסיף אחר.
 */

export type TrusteeMode = "inform" | "approve";

interface Deps {
  pool: pg.Pool;
  mailer: Mailer;
  portalUrl: string;
  log: FastifyBaseLogger;
}

let deps: Deps | null = null;

export function initTrusteeGate(next: Deps): void {
  deps = next;
}

const SYSTEM = { userId: "system", reason: "שער הנאמן" };

export function hashToken(raw: string): string {
  return createHash("sha256").update(raw, "utf8").digest("hex");
}

export function newToken(): string {
  return randomBytes(24).toString("base64url");
}

/** גיבוב יציב של גוף הבקשה: סדר המפתחות אינו משנה. */
export function bodyHash(method: string, path: string, body: unknown): string {
  const stable = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(stable);

    if (value !== null && typeof value === "object") {
      return Object.fromEntries(
        Object.entries(value as Record<string, unknown>)
          .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
          .map(([k, v]) => [k, stable(v)]),
      );
    }

    return value;
  };

  return createHash("sha256")
    .update(`${method} ${path}\n${JSON.stringify(stable(body ?? {}))}`, "utf8")
    .digest("hex");
}

/** טבלה שעוד לא נוצרה. הקוד עולה לפני שהמיגרציה רצה, ואז אין נאמנים. */
function missingTable(error: unknown): boolean {
  return (error as { code?: string }).code === "42P01";
}

export interface ActiveTrustee {
  id: string;
  name: string;
  email: string;
}

export interface TrusteeState {
  mode: TrusteeMode;
  trustees: ActiveTrustee[];
  tenantName: string;
}

/**
 * הנאמנים הפעילים של חשבון.
 *
 * פעיל הוא מי שאישר את התפקיד ושהסרתו עוד לא נכנסה לתוקף. מי
 * שהסרתו נכנסה לתוקף נמחק כאן, בקריאה: אין צורך בתהליך רקע, כי
 * הרגע שבו זה משנה הוא בדיוק הרגע שבו מישהו שואל.
 */
export async function loadTrusteeState(pool: pg.Pool, tenantId: string): Promise<TrusteeState> {
  try {
    return await withPlatform(pool, SYSTEM, async (tx) => {
      await tx.query(
        `DELETE FROM trustees
          WHERE tenant_id = $1
            AND removal_effective_at IS NOT NULL
            AND removal_effective_at <= now()`,
        [tenantId],
      );

      const settings = await tx.query<{ mode: TrusteeMode }>(
        "SELECT mode FROM trustee_settings WHERE tenant_id = $1",
        [tenantId],
      );

      const rows = await tx.query<ActiveTrustee>(
        `SELECT id, name, email FROM trustees
          WHERE tenant_id = $1 AND verified_at IS NOT NULL
          ORDER BY created_at`,
        [tenantId],
      );

      const tenant = await tx.query<{ name: string }>(
        "SELECT name FROM tenants WHERE id = $1",
        [tenantId],
      );

      return {
        mode: settings.rows[0]?.mode ?? "approve",
        trustees: rows.rows,
        tenantName: tenant.rows[0]?.name ?? "החשבון",
      };
    });
  } catch (error) {
    if (missingTable(error)) return { mode: "approve", trustees: [], tenantName: "החשבון" };

    throw error;
  }
}

async function send(message: Message): Promise<boolean> {
  if (deps === null) return false;

  try {
    await deps.mailer.send(message);

    return true;
  } catch (error) {
    deps.log.warn({ err: error, to: message.to }, "שליחת הודעה לנאמן נכשלה");

    return false;
  }
}

/** ההודעה לנאמן על בקשה שממתינה לו. */
export function requestMessage(input: {
  to: string;
  trusteeName: string;
  tenantName: string;
  requesterName: string;
  summary: string;
  link: string;
}): Message {
  return {
    to: input.to,
    subject: `Filter+‎ · בקשה לאישורך: ${input.summary}`,
    body: [
      `שלום ${input.trusteeName},`,
      "",
      `אתה הנאמן של ${input.tenantName} ב-Filter+‎.`,
      `${input.requesterName} מבקש:`,
      "",
      `    ${input.summary}`,
      "",
      "הפעולה לא תתבצע בלי אישורך. לאישור או לדחייה:",
      input.link,
      "",
      "אין מועד אחרון: הבקשה ממתינה עד שתענה. אם אינך בטוח, אל תאשר.",
      "",
      "— Filter+‎",
    ].join("\n"),
  };
}

/** ההודעה לנאמן על הקלה שכבר בוצעה, במצב שבו הוא רק מיודע. */
function informMessage(input: {
  to: string;
  trusteeName: string;
  tenantName: string;
  requesterName: string;
  summary: string;
}): Message {
  return {
    to: input.to,
    subject: `Filter+‎ · שינוי בהגנה: ${input.summary}`,
    body: [
      `שלום ${input.trusteeName},`,
      "",
      `אתה הנאמן של ${input.tenantName} ב-Filter+‎.`,
      `${input.requesterName} ביצע עכשיו:`,
      "",
      `    ${input.summary}`,
      "",
      "ההודעה לידיעתך בלבד. בחשבון הזה הנאמן מקבל הודעות ואינו נדרש לאשר.",
      "",
      "— Filter+‎",
    ].join("\n"),
  };
}

export async function notifyTrustees(
  state: TrusteeState,
  build: (trustee: ActiveTrustee) => Message,
): Promise<number> {
  let sent = 0;

  for (const trustee of state.trustees) {
    if (await send(build(trustee))) sent++;
  }

  return sent;
}

/**
 * השער עצמו.
 *
 * מחזיר true כשהבקשה נעצרה והתשובה כבר נשלחה: המסלול צריך לצאת.
 * מחזיר false כשהפעולה רשאית להמשיך.
 */
export async function trusteeGate(
  request: FastifyRequest,
  reply: FastifyReply,
  summary: string,
): Promise<boolean> {
  if (deps === null) return false;

  const session = request.portal?.session;

  // רק בעל חשבון. צוות החברה פועל דרך המוקד, עם תיעוד משלו.
  if (!session || session.user.role !== "tenant_owner" || !session.user.tenantId) return false;

  const tenantId = session.user.tenantId;
  const state = await loadTrusteeState(deps.pool, tenantId);

  if (state.trustees.length === 0) return false;

  const requester = session.user.displayName ?? session.user.email;

  if (state.mode === "inform") {
    // אחרי שהתשובה יצאה, ורק אם הפעולה הצליחה. הודעה על הקלה
    // שנכשלה הייתה מלמדת את הנאמן להתעלם מההודעות.
    reply.raw.once("finish", () => {
      if (reply.statusCode >= 400) return;

      void notifyTrustees(state, (t) => informMessage({
        to: t.email,
        trusteeName: t.name,
        tenantName: state.tenantName,
        requesterName: requester,
        summary,
      }));
    });

    return false;
  }

  const method = request.method.toUpperCase();
  const path = request.url.split("?")[0]!;
  const hash = bodyHash(method, path, request.body);

  const { pool, portalUrl } = deps;

  const outcome = await withPlatform(pool, SYSTEM, async (tx) => {
    // אישור שכבר ניתן לפעולה הזו בדיוק: מנוצל פעם אחת, והפעולה עוברת
    const approved = await tx.query<{ id: string }>(
      `UPDATE trustee_requests
          SET status = 'executed', executed_at = now()
        WHERE id = (
          SELECT id FROM trustee_requests
           WHERE tenant_id = $1 AND body_hash = $2 AND status = 'approved'
           ORDER BY decided_at DESC LIMIT 1
           FOR UPDATE SKIP LOCKED
        )
      RETURNING id`,
      [tenantId, hash],
    );

    if (approved.rows[0]) return { kind: "pass" as const };

    // בקשה זהה שכבר ממתינה: לא נוצרת עוד אחת, ולא נשלח עוד דוא"ל
    const pending = await tx.query<{ id: string }>(
      `SELECT id FROM trustee_requests
        WHERE tenant_id = $1 AND body_hash = $2 AND status = 'pending' LIMIT 1`,
      [tenantId, hash],
    );

    if (pending.rows[0]) return { kind: "waiting" as const, token: null };

    const token = newToken();

    await tx.query(
      `INSERT INTO trustee_requests
         (tenant_id, requested_by, summary, method, path, body, body_hash, decide_hash)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        tenantId, session.user.userId, summary, method, path,
        JSON.stringify(request.body ?? {}), hash, hashToken(token),
      ],
    );

    await tx.query(
      `INSERT INTO audit_log (actor_type, actor_id, action, tenant_id, payload)
       VALUES ('tenant_user', $1, 'trustee.request.created', $2, $3)`,
      [session.user.userId, tenantId, JSON.stringify({ summary, method, path })],
    );

    return { kind: "waiting" as const, token };
  });

  if (outcome.kind === "pass") return false;

  if (outcome.token !== null) {
    const token = outcome.token;

    await notifyTrustees(state, (t) => requestMessage({
      to: t.email,
      trusteeName: t.name,
      tenantName: state.tenantName,
      requesterName: requester,
      summary,
      link: `${portalUrl}/trustee?token=${token}&by=${t.id}`,
    }));
  }

  const names = state.trustees.map((t) => t.name).join(", ");

  await reply.code(409).send({
    error: outcome.token !== null
      ? `הפעולה דורשת אישור של הנאמן (${names}). נשלחה אליו בקשה, והפעולה תתאפשר אחרי שיאשר.`
      : `הפעולה כבר ממתינה לאישור הנאמן (${names}). אפשר לשלוח לו תזכורת בהגדרות, תחת נאמן.`,
    trusteePending: true,
  });

  return true;
}

/**
 * על מה הפעולה חלה, במילים שהנאמן מבין.
 *
 * הנאמן אינו רואה את מרכז הניהול. "למחוק שעות חסימה" בלי שם המחשב
 * הוא בקשה שאי אפשר לשקול, ולכן השם נכנס לתיאור עצמו.
 */
export async function targetLabel(
  tenantId: string,
  target: { deviceId?: string; groupId?: string; networkId?: string },
): Promise<string> {
  if (deps === null) return "";

  try {
    return await withPlatform(deps.pool, SYSTEM, async (tx) => {
      if (target.deviceId) {
        const r = await tx.query<{ name: string }>(
          `SELECT COALESCE(NULLIF(display_name, ''), machine_name, 'מחשב ללא שם') AS name
             FROM devices WHERE id = $1 AND tenant_id = $2`,
          [target.deviceId, tenantId],
        );

        return r.rows[0] ? `במחשב "${r.rows[0].name}"` : "במחשב";
      }

      if (target.groupId) {
        const r = await tx.query<{ name: string }>(
          "SELECT name FROM device_groups WHERE id = $1 AND tenant_id = $2",
          [target.groupId, tenantId],
        );

        return r.rows[0] ? `בקבוצה "${r.rows[0].name}"` : "בקבוצה";
      }

      if (target.networkId) {
        const r = await tx.query<{ ssid: string | null }>(
          "SELECT ssid FROM known_networks WHERE id = $1 AND tenant_id = $2",
          [target.networkId, tenantId],
        );

        return `"${r.rows[0]?.ssid?.trim() || "רשת ללא שם"}"`;
      }

      return "";
    });
  } catch {
    // התיאור הוא נוחות. כישלון בו אינו אמור לעצור את השער.
    return "";
  }
}
