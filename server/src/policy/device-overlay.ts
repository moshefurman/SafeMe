import type pg from "pg";

import { withTenant } from "../db/client.ts";
import type { Signer } from "../crypto/signing.ts";

import {
  blockUntilApproved,
  bodyVersion,
  deletePolicyRow,
  loadGlobalPolicy,
  loadTenantPolicy,
  publishAtNextVersion,
  republishTenantPolicy,
  sameBody,
  type PolicyRow,
} from "./compose.ts";
import { assignPolicy } from "./publish.ts";
import { loadSchedules, loadGroupSchedules, toRules, type ScheduleRow } from "./schedules.ts";
import {
  buildWhitelistRule,
  learningActive,
  loadWhitelist,
  loadGroupWhitelist,
  whitelistSystemDomains,
  type WhitelistState,
} from "./whitelist.ts";

/**
 * השכבה של מחשב אחד: מה שחל עליו ולא על שאר המחשבים של הדייר.
 *
 * היום יש בה שני דברים — שעות חסימה ורשימה לבנה — והיא מורכבת
 * במקום אחד בלבד, כאן.
 *
 * קודם היו שני מרכיבים: אחד במסלולי שעות הגלישה, שרץ בכל שמירה,
 * ואחד בהרכבה של עליית השרת. הם נכתבו בנפרד ונפרדו בשקט: הראשון
 * לא נשא את דגל חסימת הרשתות ובחר מספר גרסה חלש יותר, והשני מחק
 * את השיוך כשלא נשארו שעות. כל שמירה ואחריה אתחול הפיקו שתי
 * מדיניות שונות לאותו מחשב. תכונה שלישית שהייתה נוספת לאחד מהם
 * ונשכחת בשני הייתה נמחקת בכל עליית שרת.
 *
 * הכללים, וכל אחד מהם נלמד מתקלה בשטח:
 *
 *   · הבסיס הוא מדיניות הדייר או הגלובלית — לעולם לא שורה שמשויכת
 *     למחשב. הרכבה מעל העותק של עצמך היא מזלג, והמחשב מתנתק מכל
 *     שינוי עתידי בבסיס.
 *   · מספר הגרסה אינו יורד. הסוכן דוחה מדיניות שמספרה נמוך ממה
 *     שבידיו.
 *   · מחשב שאין לו מה לשאת מעל הבסיס אינו מחזיק שיוך כלל, והשורה
 *     שלו נמחקת — שורה בלי שיוך נראית בדיוק כמו מדיניות דייר.
 *   · מה שלא השתנה אינו מתפרסם. ההרכבה רצה בכל עליית שרת.
 */

export interface OverlayResult {
  /**
   * published — פורסמה שכבה חדשה ושויכה.
   * unchanged — השכבה הקיימת כבר נכונה.
   * removed   — המחשב חזר לבסיס, והשיוך נמחק.
   * none      — אין שכבה ולא נדרשת.
   */
  action: "published" | "unchanged" | "removed" | "none";

  /** הגרסה שהמחשב אמור להחזיק אחרי הפעולה, כשהיא ידועה. */
  version: number | null;
}

interface Inputs {
  schedules: ScheduleRow[];
  whitelist: WhitelistState;
  browserOverride: Record<string, unknown> | null;
  assigned: PolicyRow | null;
  heldVersion: number;
}

const NO_WHITELIST: WhitelistState = { enabled: false, learningUntil: null, domains: [] };

let warnedMissingTables = false;

/**
 * הרשימה הלבנה של המחשב — או "אין", אם הטבלאות עוד לא קיימות.
 *
 * המיגרציות מורצות ביד (deploy/render.md), ולכן קוד חדש עלול לעלות
 * לפני מיגרציה 0040. בלי הענף הזה כל שמירה של שעות חסימה הייתה
 * נופלת ב-500 וההרכבה בעלייה הייתה נכשלת לכל מחשב — תכונה קיימת
 * נשברת בגלל תכונה שעוד לא הופעלה.
 *
 * נקרא בטרנזקציה משלו, כי שאילתה שנכשלה מבטלת את כל מה שסביבה.
 * וההודעה נכתבת בקול: ענף שקט כאן היה מסתיר מיגרציה שנשכחה.
 */
async function loadWhitelistTolerant(
  pool: pg.Pool,
  tenantId: string,
  deviceId: string,
): Promise<WhitelistState> {
  try {
    return await withTenant(pool, tenantId, (tx) => loadWhitelist(tx, deviceId));
  } catch (error) {
    if ((error as { code?: string }).code !== "42P01") throw error;

    if (!warnedMissingTables) {
      warnedMissingTables = true;
      console.error(
        "  ✗ טבלאות הרשימה הלבנה חסרות. יש להריץ את מיגרציה 0040 (node scripts/migrate.ts).\n" +
        "    עד אז מדיניות המחשבים מורכבת בלי רשימה לבנה.",
      );
    }

    return NO_WHITELIST;
  }
}

async function loadInputs(pool: pg.Pool, tenantId: string, deviceId: string): Promise<Inputs> {
  const whitelist = await loadWhitelistTolerant(pool, tenantId, deviceId);

  return withTenant(pool, tenantId, async (tx) => {
    const deviceSchedules = await loadSchedules(tx, deviceId);

    /*
     * הגדרות קבוצה: דריסה, לא מיזוג.
     *
     * אם למחשב יש שעות חסימה משלו — רק הן חלות. אם אין — חלות
     * שעות הקבוצה. אותו כלל לרשימה הלבנה. הורה שרוצה להחזיר מחשב
     * להגדרות הקבוצה מאפס את ההגדרות האישיות שלו.
     */
    const groupId = await tx.query<{ group_id: string | null }>(
      "SELECT group_id FROM devices WHERE id = $1",
      [deviceId],
    );
    const gid = groupId.rows[0]?.group_id ?? null;

    let schedules: ScheduleRow[];
    let effectiveWhitelist = whitelist;

    if (gid !== null && deviceSchedules.length === 0) {
      schedules = await loadGroupSchedules(tx, gid);
    } else {
      schedules = deviceSchedules;
    }

    if (gid !== null && !whitelist.enabled && !learningActive(whitelist)) {
      try {
        const groupWl = await loadGroupWhitelist(tx, gid);

        if (groupWl.enabled) {
          effectiveWhitelist = {
            enabled: true,
            learningUntil: null,
            domains: groupWl.domains,
          };
        }
      } catch (error) {
        if ((error as { code?: string }).code !== "42P01") throw error;
      }
    }

    let browserOverride: Record<string, unknown> | null = null;
    if (gid !== null) {
      try {
        const br = await tx.query<{ settings: Record<string, unknown> }>(
          "SELECT settings FROM group_browser_settings WHERE group_id = $1",
          [gid],
        );
        if (br.rows.length > 0 && Object.keys(br.rows[0]!.settings).length > 0) {
          browserOverride = br.rows[0]!.settings;
        }
      } catch (error) {
        if ((error as { code?: string }).code !== "42P01") throw error;
      }
    }

    const assigned = await tx.query<PolicyRow>(
      `SELECT p.id, p.version, p.body
         FROM device_policy_assignments a
         JOIN policies p ON p.id = a.policy_id
        WHERE a.device_id = $1`,
      [deviceId],
    );

    const reported = await tx.query<{ policy_version: number | null }>(
      "SELECT policy_version FROM device_state WHERE device_id = $1",
      [deviceId],
    );

    const row = assigned.rows[0] ?? null;

    return {
      schedules,
      whitelist: effectiveWhitelist,
      browserOverride,
      assigned: row,
      heldVersion: Math.max(
        reported.rows[0]?.policy_version ?? 0,
        row === null ? 0 : bodyVersion(row),
      ),
    };
  });
}

/**
 * האם המחשב צריך שכבה משלו.
 *
 * שעות חסימה — כל שורה, גם מושבתת, כפי שהיה תמיד. רשימה לבנה —
 * כשהיא פעילה, או כשחלון למידה פתוח ברגע זה: למידה רשאית לרוץ
 * לפני ההפעלה, והסוכן חייב לקבל את סוף החלון כדי לדעת ללמוד.
 *
 * חלון שעבר אינו סיבה. לא נדרש פרסום ברגע שהוא נגמר — הסוכן משווה
 * את הזמן בעצמו — אבל בהרכבה הבאה הוא כבר אינו נחשב.
 */
function needsOverlay(inputs: Inputs, now: Date): boolean {
  return inputs.schedules.length > 0
    || inputs.whitelist.enabled
    || learningActive(inputs.whitelist, now)
    || inputs.browserOverride !== null;
}

/**
 * מרכיב את המדיניות של מחשב אחד ומביא את המסד למצב הנכון.
 *
 * נקרא אחרי כל שינוי בשעות החסימה או ברשימה הלבנה של המחשב, ועל
 * כל מחשב רלוונטי אחרי כל שינוי בבסיס או במדיניות הדייר. בטוח
 * לקריאה חוזרת: כשאין מה לשנות, דבר אינו מתפרסם.
 */
export async function composeDeviceOverlay(
  pool: pg.Pool,
  signer: Signer,
  input: {
    tenantId: string;
    deviceId: string;
    /** מזהה המשתמש ששינה, או null לפרסום של המערכת. חייב להיות uuid. */
    publishedBy?: string | null;
    now?: Date;
  },
): Promise<OverlayResult> {
  const { tenantId, deviceId } = input;
  const now = input.now ?? new Date();
  const inputs = await loadInputs(pool, tenantId, deviceId);

  /*
   * הבסיס להרכבה הוא המדיניות הרשמית, ולא מה שהמחשב מקבל היום.
   *
   * כאן הייתה תקלה שקטה וחמורה. הבסיס נבחר פעם מתוך כל מה שהמחשב
   * רואה, כולל העותק שהוא עצמו קיבל בפעם הקודמת — וכך כל שמירה
   * יצרה עותק של עותק. מרגע שמחשב קיבל שעות גלישה הוא התנתק
   * לצמיתות מהבסיס: כלל זיהוי חדש נכנס לבסיס, הכלים הראו אותו,
   * והמחשב המשיך לקבל שורה משלו שאיש לא חידש. נצפה בשטח — מחשב
   * על גרסה 16 בשיוך ישיר בזמן שהבסיס כבר ב-13 עם כללים חדשים.
   *
   * מדיניות הדייר או הבסיס הן מקור האמת. השיוך הוא שכבה מעליהן
   * ולעולם לא הבסיס שלהן.
   */
  const base =
    (await loadTenantPolicy(pool, tenantId)) ?? (await loadGlobalPolicy(pool, tenantId));

  if (!needsOverlay(inputs, now)) {
    if (inputs.assigned === null) return { action: "none", version: null };

    return removeOverlay(pool, signer, {
      tenantId,
      deviceId,
      publishedBy: input.publishedBy ?? null,
      assigned: inputs.assigned,
      heldVersion: inputs.heldVersion,
      base,
    });
  }

  /*
   * בלי בסיס מרכיבים מעל גוף ריק, כפי ששעות הגלישה עשו תמיד.
   *
   * זה מצב של התקנה שעוד לא פרסמה תבנית — השרת מפרסם אחת בעלייה,
   * ולכן בפועל הוא קיים רק בבדיקות. השכבה תורכב מחדש מעל הבסיס
   * ברגע שיתפרסם.
   */
  const baseBody = base?.body ?? {};
  const enforcement = (baseBody["enforcement"] ?? {}) as Record<string, unknown>;
  const allowed = (enforcement["allowedNetworks"] ?? {}) as Record<string, unknown>;

  const composed: Record<string, unknown> = {
    ...baseBody,
    enforcement: {
      ...enforcement,
      allowedNetworks: {
        ...allowed,
        blockUntilApproved: await blockUntilApproved(pool, tenantId),
      },
      schedules: toRules(inputs.schedules),
      whitelist: buildWhitelistRule({
        enabled: inputs.whitelist.enabled,
        domains: inputs.whitelist.domains.map((d) => d.domain),
        learningUntil: inputs.whitelist.learningUntil,
        systemDomains: whitelistSystemDomains(),
        now,
      }),
      ...(inputs.browserOverride !== null ? { browser: inputs.browserOverride } : {}),
    },
  };

  /*
   * מה שהמחשב מחזיק עכשיו.
   *
   * ההרכבה רצה בכל עליית שרת, ולכן היא חייבת לדעת לא לעשות כלום.
   * בלי הבדיקה הזו כל אתחול היה מפרסם גרסה חדשה וזהה, וכל מחשב
   * היה מוריד אותה — תעבורה, מספרים מטפסים, ושום שינוי אמיתי.
   */
  if (inputs.assigned !== null && sameBody(inputs.assigned.body, composed)) {
    return { action: "unchanged", version: bodyVersion(inputs.assigned) };
  }

  const published = await publishAtNextVersion(pool, signer, {
    tenantId,
    body: composed,
    publishedBy: input.publishedBy ?? null,
  });

  await assignPolicy(pool, tenantId, deviceId, published.id);

  /*
   * השורה הקודמת נמחקת, אחרי שהשיוך כבר עבר לחדשה.
   *
   * בלי המחיקה היא נשארת בטבלה עם tenant_id ובלי שיוך — כלומר
   * נראית בדיוק כמו מדיניות דייר, ועם מספר גרסה גבוה. כל בחירה של
   * "מדיניות הדייר" הייתה נוחתת עליה: שעות החסימה של מחשב אחד
   * הופכות לבסיס של כל המחשבים, ולמה שמסך ההגדרות מציג כהגדרת
   * החשבון. כך נוצרו בזמנו שאריות המזלג שההרכבה נאלצה לנקות.
   */
  if (inputs.assigned !== null) await deletePolicyRow(pool, tenantId, inputs.assigned.id);

  return { action: "published", version: published.version };
}

/**
 * מחזיר מחשב לבסיס: מוחק את השיוך ואת השורה שלו.
 *
 * מחיקת השיוך היא הפעולה הנכונה, ולא פרסום עותק זהה לבסיס: כל עוד
 * יש שיוך, המחשב תלוי בהרכבה הזו לנצח. בלעדיו הוא מקבל את הבסיס
 * ישירות, וזה מה שנכון כשאין לו כלום מעליו.
 */
async function removeOverlay(
  pool: pg.Pool,
  signer: Signer,
  input: {
    tenantId: string;
    deviceId: string;
    publishedBy: string | null;
    assigned: PolicyRow;
    heldVersion: number;
    base: PolicyRow | null;
  },
): Promise<OverlayResult> {
  const { tenantId, deviceId } = input;
  const fallbackVersion = input.base === null ? 0 : bodyVersion(input.base);

  /*
   * המספר שהמחשב ייפול אליו חייב להיות גבוה ממה שבידיו.
   *
   * השכבה נושאת תמיד מספר גבוה מהבסיס — היא פורסמה אחריו. ברגע
   * שהשיוך נמחק המחשב מקבל את מדיניות הדייר או הבסיס, שמספרן
   * נמוך יותר, והסוכן דוחה אותה: PolicyStore מסרב לגרסה ישנה
   * מהפעילה. הוא נשאר על השכבה שכבר אינה קיימת בשרת.
   *
   * לשעות חסימה זה כמעט לא הורגש, כי שכבה ריקה משעות שקולה לבסיס.
   * לרשימה לבנה זה ההבדל בין "כיביתי" ל"המחשב עדיין חסום ואין לי
   * איך לשחרר אותו": הכיבוי היה נשמר בשרת ולא מגיע לעולם.
   *
   * לכן מדיניות הדייר מתפרסמת מחדש במספר שעובר את מה שהמחשב
   * מחזיק. התוכן שלה אינו משתנה — רק המספר — ושאר המחשבים של
   * הדייר ימשכו אותה פעם אחת.
   *
   * הפרסום קודם למחיקה, ובכוונה. המספר הבא נגזר ממה שבטבלה, וכל
   * עוד השורה של המחשב שם הוא בהכרח גבוה ממנה. אחרי המחיקה היא
   * כבר אינה נספרת, והמספר היה עלול לצאת נמוך ממה שהמחשב מחזיק —
   * בדיוק מה שהפרסום הזה בא למנוע.
   */
  let version: number | null = fallbackVersion;

  if (fallbackVersion <= input.heldVersion) {
    version = await republishTenantPolicy(pool, signer, tenantId, {
      force: true,
      publishedBy: input.publishedBy,
    });

    /*
     * בלי בסיס גלובלי אין מה לפרסם, והמחשב יישאר על מה שבידיו עד
     * שהשרת יפרסם תבנית. זה מצב של בדיקות בלבד, אבל הוא נאמר.
     */
    if (version === null) {
      console.error(
        `  ✗ המחשב ${deviceId} חוזר לבסיס, ואין מדיניות בסיס לפרסם במספר שיעבור את ${input.heldVersion}.`,
      );
    }
  }

  await withTenant(pool, tenantId, (tx) =>
    tx.query("DELETE FROM device_policy_assignments WHERE device_id = $1", [deviceId]));

  /*
   * השורה עצמה נמחקת, לא רק השיוך.
   *
   * מדיניות מחשב נכתבת עם tenant_id, ולכן מרגע שהשיוך נמחק היא
   * נראית בדיוק כמו מדיניות דייר — עם מספר גרסה גבוה. כל בחירה של
   * "מדיניות הדייר" לפי הגרסה הגבוהה הייתה נוחתת עליה.
   *
   * זה בדיוק מה שקרה: שאריות של מזלג ישן נבחרו כמדיניות הדייר,
   * וההרכבה שנועדה לתקן את הפיצול הרכיבה מעליהן.
   */
  await deletePolicyRow(pool, tenantId, input.assigned.id);

  return { action: "removed", version };
}
