import { randomBytes } from "node:crypto";

import type pg from "pg";

import { withPlatform } from "../db/client.ts";
import { buildEnvelope, type Signer, type SignedEnvelope } from "../crypto/signing.ts";
import { hwidHashHex } from "../crypto/challenge.ts";

/**
 * הנפקת היתר להורדת רצפת המדיניות, ומסירתו.
 *
 * הרצפה נקבעת בהתקנה ונחתמת, והסוכן דוחה כל מדיניות שמקלה ממנה.
 * זו ההגנה החזקה במוצר: גם שרת שנפרץ אינו יכול לכבות אכיפה, כי
 * הרצפה אינה מגיעה ממנו אלא נשמרת אצלו מוגנת.
 *
 * ההיתר הוא הפתח היחיד, והוא חתום במפתח **נפרד** ממפתח המדיניות.
 * זו כל ההפרדה: מי שמשיג את היכולת לחתום מדיניות אינו משיג בכך את
 * היכולת להוריד רצפות, והסוכן אוכף את ההפרדה בעצמו.
 */

const SYSTEM = {
  userId: "00000000-0000-0000-0000-000000000000",
  reason: "היתר הקלה",
};

/**
 * חלון קצר.
 *
 * ההיתר נמסר בפעימה הבאה, ולכן שעה מספיקה בהרבה. חלון ארוך הופך
 * היתר שנלכד ברשת לכלי שאפשר להשתמש בו מאוחר יותר — והוא נועד
 * לפעולה אחת, עכשיו.
 */
const VALID_MINUTES = 60;

export interface FloorSpec {
  mode: string;
  onRedAction: string;
  minScoreForGreen: number;
  minScoreForYellow: number;
  requireProvider: string[];
}

/**
 * מנפיק היתר ושומר אותו כממתין למסירה.
 *
 * ה-nonce נשמר כי הסוכן דוחה שימוש חוזר, והשרת חייב לזכור מה
 * הנפיק — גם כדי לא להנפיק פעמיים, וגם כדי לענות "מי אישר להוריד
 * רצפה במחשב הזה", שאלה שתישאל בדיוק כשמשהו השתבש.
 */
export async function issueLooseningGrant(
  pool: pg.Pool,
  signer: Signer,
  input: {
    deviceId: string;
    tenantId: string;
    hwid: string;
    from: FloorSpec;
    to: FloorSpec;
    approvedBy: string;
    reason?: string | undefined;
  },
): Promise<{ nonce: string; expiresAt: Date }> {
  const nonce = randomBytes(16).toString("base64url");
  const now = new Date();
  const expires = new Date(now.getTime() + VALID_MINUTES * 60_000);

  await withPlatform(pool, { userId: input.approvedBy, reason: "הנפקת היתר" }, async (tx) => {
    /*
     * היתר ממתין קודם מבוטל.
     *
     * שני היתרים פתוחים לאותו מחשב פירושם שהשני נמסר אחרי הראשון
     * ומתייחס לרצפה שכבר השתנתה — כלומר הוא ייכשל באימות, וייראה
     * כמו ניסיון חבלה.
     */
    await tx.query(
      "DELETE FROM loosening_grants WHERE device_id = $1 AND delivered_at IS NULL",
      [input.deviceId],
    );

    await tx.query(
      `INSERT INTO loosening_grants
         (device_id, tenant_id, nonce, from_floor, to_floor, reason, approved_by, expires_at)
       VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6, $7, $8)`,
      [
        input.deviceId,
        input.tenantId,
        nonce,
        JSON.stringify(input.from),
        JSON.stringify(input.to),
        input.reason ?? null,
        input.approvedBy,
        expires,
      ],
    );
  });

  return { nonce, expiresAt: expires };
}

/**
 * ההיתר הממתין למחשב, אם יש, כמעטפה חתומה.
 *
 * נקרא בכל פעימה. מסומן כנמסר מיד עם ההחזרה — היתר שנשלח ולא הגיע
 * יפוג מעצמו תוך שעה, וזה עדיף על שליחה חוזרת שתגיע אחרי שהרצפה
 * כבר השתנתה ותיראה כמו ניסיון חבלה.
 */
export async function pendingLooseningGrant(
  pool: pg.Pool,
  signer: Signer,
  device: { deviceId: string; tenantId: string; hwid: string },
): Promise<SignedEnvelope | null> {
  const row = await withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{
      nonce: string;
      from_floor: FloorSpec;
      to_floor: FloorSpec;
      reason: string | null;
      expires_at: Date;
      issued_at: Date;
      approved_by: string | null;
    }>(
      `UPDATE loosening_grants SET delivered_at = now()
        WHERE id = (
          SELECT id FROM loosening_grants
           WHERE device_id = $1 AND delivered_at IS NULL AND expires_at > now()
           ORDER BY issued_at DESC LIMIT 1
        )
    RETURNING nonce, from_floor, to_floor, reason, expires_at, issued_at, approved_by`,
      [device.deviceId],
    );

    const grant = r.rows[0] ?? null;

    if (grant === null) return null;

    /*
     * מי אישר, בשם ולא במזהה.
     *
     * הסוכן כותב את זה ליומן האירועים של המחשב, וזה מה שהורה או
     * טכנאי יקראו שם. מזהה UUID לא אומר להם דבר.
     */
    const who = grant.approved_by === null
      ? null
      : await tx.query<{ email: string }>(
          "SELECT email FROM users WHERE id = $1", [grant.approved_by]);

    return { ...grant, approvedBy: who?.rows[0]?.email ?? null };
  });

  if (row === null) return null;

  /*
   * הצורה חייבת להתאים למה שהסוכן מפענח.
   *
   * שמות השדות הם מה ש-LooseningGrant ב-C# מצפה להם, והפענוח שם
   * אינו רגיש לרישיות — אבל שדה שיישכח יגיע כברירת מחדל ויכשיל
   * את האימות בלי הסבר.
   */
  const built = await buildEnvelope(signer, {
    hwidHash: hwidHashHex(device.hwid),
    nonce: row.nonce,
    issuedUtc: row.issued_at.toISOString(),
    expiresUtc: row.expires_at.toISOString(),
    fromFloor: row.from_floor,
    toFloor: row.to_floor,
    approvedBy: row.approvedBy,
    reason: row.reason,
  });

  return built.envelope;
}

/**
 * הסוכן דיווח שהחיל היתרים. הרצפה הרשומה מתעדכנת לפי זה בלבד.
 *
 * לא ברגע ההנפקה ולא ברגע המסירה: הסוכן מאמת את ההיתר בעצמו
 * ורשאי לדחות אותו, ורצפה שנרשמה כמונמכת בעוד המחשב סירב הייתה
 * מכשילה כל היתר עתידי — כולם היו יוצאים מרצפה שאינה קיימת.
 *
 * מחזיר את הרצפה החדשה כשמשהו השתנה, ו-null כשהרשימה כבר ידועה.
 * הרשימה מגיעה בכל פעימה, ולכן רוב הקריאות חוזרות ריקות.
 */
export async function markGrantsApplied(
  pool: pg.Pool,
  device: { deviceId: string; nonces: string[] },
): Promise<FloorSpec | null> {
  if (device.nonces.length === 0) return null;

  return withPlatform(pool, SYSTEM, async (tx) => {
    const r = await tx.query<{ to_floor: FloorSpec; issued_at: Date }>(
      `UPDATE loosening_grants SET applied_at = now()
        WHERE device_id = $1 AND nonce = ANY($2::text[]) AND applied_at IS NULL
    RETURNING to_floor, issued_at`,
      [device.deviceId, device.nonces],
    );

    if (r.rows.length === 0) return null;

    /*
     * האחרון שהונפק הוא הרצפה הנוכחית.
     *
     * אם כמה היתרים דווחו יחד — מחשב שהיה כבוי — מי שהונפק אחרון
     * יצא מהרצפה שההיתרים הקודמים הביאו אליה, והוא הקובע.
     */
    const latest = r.rows
      .sort((a, b) => b.issued_at.getTime() - a.issued_at.getTime())[0]!;

    await tx.query(
      "UPDATE devices SET policy_floor = $2::jsonb WHERE id = $1",
      [device.deviceId, JSON.stringify(latest.to_floor)],
    );

    return latest.to_floor;
  });
}
