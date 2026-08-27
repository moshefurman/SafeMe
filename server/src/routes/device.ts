import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type pg from "pg";
import { z } from "zod";
import { withPlatform, withTenant } from "../db/client.ts";
import { hashEnrollToken, issueDeviceToken, verifyDeviceToken } from "../auth/device-token.ts";
import { buildEnvelope, envelopeFromStored, type Signer } from "../crypto/signing.ts";
import type { Config } from "../config.ts";
import { sampleReason, type DeviceSnapshot } from "../telemetry/retention.ts";
import { severityFor } from "../telemetry/severity.ts";
import { buildUpdateOffer } from "../updates/offer.ts";
import { hwidHashHex } from "../crypto/challenge.ts";

/**
 * ממשק המכשיר. שישה מסלולים שהסוכן ב-Windows מדבר איתם.
 *
 * כל המסלולים פרט ל-health ול-enroll דורשים אסימון מכשיר תקף,
 * ופועלים בהקשר הדייר של אותו מכשיר בלבד.
 */

const SYSTEM_ACTOR = {
  userId: "00000000-0000-0000-0000-000000000000",
  reason: "רישום מכשיר",
};

// ---------------------------------------------------------------- סכמות

const enrollBody = z.object({
  enrollToken: z.string().min(8),
  hwid: z.string().min(10).max(64),
  machineName: z.string().max(128).optional(),
  osVersion: z.string().max(128).optional(),
  agentVersion: z.string().max(32).optional(),
  installId: z.string().uuid().optional(),
});

const adapterSchema = z.object({
  name: z.string().max(128),
  ssid: z.string().max(64).nullish(),
  gateway: z.string().max(64).nullish(),
  localIp: z.string().max(64).nullish(),
  isVirtualVpn: z.boolean().optional(),
});

const heartbeatBody = z.object({
  hwid: z.string(),
  agentVersion: z.string().max(32).optional(),
  policyVersion: z.number().int().nonnegative().optional(),
  sentUtc: z.string().datetime({ offset: true }).optional(),
  sequence: z.number().int().nonnegative(),
  status: z.enum(["unknown", "safe", "lowFilter", "unfiltered", "blocked"]),
  score: z.number().int().min(0).max(100),
  activeAdapters: z.array(adapterSchema).max(16).default([]),
  publicIp: z.string().max(64).nullish(),
  detectedProvider: z.string().max(64).nullish(),
  failedProbes: z.array(z.string().max(64)).max(64).default([]),
  tamperEvents: z
    .array(
      z.object({
        kind: z.string().max(64),
        utc: z.string().datetime({ offset: true }).optional(),
        detail: z.string().max(1024).nullish(),
      }),
    )
    .max(50)
    .default([]),
  wfpFilterCount: z.number().int().nonnegative().optional(),
  uptimeSec: z.number().int().nonnegative().optional(),
  lockoutActive: z.boolean().default(false),
});

const eventsBody = z.array(
  z.object({
    kind: z.string().max(64),
    utc: z.string().datetime({ offset: true }).optional(),
    detail: z.string().max(1024).nullish(),
  }),
).max(200);

/** שמות הפקודות כפי שהסוכן מצפה להם ב-RemoteCommand.Type. */
const TYPE_MAP: Record<string, string> = {
  lockout: "Lockout",
  release_lockout: "ReleaseLockout",
  run_audit: "RunAudit",
  refresh_policy: "RefreshPolicy",
};

/** הסוכן שולח camelCase, בסיס הנתונים משתמש ב-snake_case. */
const STATUS_MAP: Record<string, string> = {
  unknown: "unknown",
  safe: "safe",
  lowFilter: "low_filter",
  unfiltered: "unfiltered",
  blocked: "blocked",
};

/**
 * ממיר את כל ערכי הארגומנטים למחרוזות.
 *
 * RemoteCommand.Args בסוכן הוא Dictionary<string, string>. jsonb מחזיר
 * מספרים כמספרים, ו-System.Text.Json זורק כשהוא פוגש מספר במקום
 * מחרוזת. בלי ההמרה הזו כל פקודת נעילה הייתה מפילה את הפעימה בסוכן —
 * וזה היה מתגלה רק בשטח.
 */
function stringifyArgs(args: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};

  for (const [key, value] of Object.entries(args)) {
    if (value === null || value === undefined) continue;
    out[key] = typeof value === "string" ? value : String(value);
  }

  return out;
}

// ---------------------------------------------------------------- הקשר בקשה

export interface DeviceContext {
  deviceId: string;
  tenantId: string;
  hwid: string;
}

declare module "fastify" {
  interface FastifyRequest {
    device?: DeviceContext;
  }
}

export interface DeviceRoutesDeps {
  pool: pg.Pool;
  signer: Signer;
  looseningSigner: Signer;
  uninstallSigner: Signer;
  updateSigner: Signer;
  config: Config;
}

// ---------------------------------------------------------------- מסלולים

export async function registerDeviceRoutes(
  app: FastifyInstance,
  deps: DeviceRoutesDeps,
): Promise<void> {
  const { pool, signer, looseningSigner, uninstallSigner, updateSigner, config } = deps;

  /** אימות אסימון מכשיר. נכשל בשקט אחיד כדי לא לדלוף מידע לתוקף. */
  async function requireDevice(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    const header = request.headers.authorization;

    if (!header?.startsWith("Bearer ")) {
      await reply.code(401).send({ error: "נדרש אסימון מכשיר" });
      return;
    }

    const claims = await verifyDeviceToken(config.DEVICE_TOKEN_SECRET, header.slice(7).trim());

    if (!claims) {
      await reply.code(401).send({ error: "אסימון מכשיר אינו תקף" });
      return;
    }

    // כותרת ה-HWID חייבת להתאים לאסימון. אסימון שהועתק למכונה אחרת נדחה.
    const hwidHeader = request.headers["x-safeme-hwid"];

    if (typeof hwidHeader !== "string" || hwidHeader !== claims.hwid) {
      await reply.code(401).send({ error: "אי התאמה בין האסימון למזהה החומרה" });
      return;
    }

    const active = await withTenant(pool, claims.tenantId, async (tx) => {
      const r = await tx.query(
        `SELECT 1 FROM device_tokens
         WHERE jti = $1 AND revoked_at IS NULL AND expires_at > now()`,
        [claims.jti],
      );
      return r.rows.length === 1;
    });

    if (!active) {
      await reply.code(401).send({ error: "האסימון בוטל או פג תוקפו" });
      return;
    }

    request.device = {
      deviceId: claims.deviceId,
      tenantId: claims.tenantId,
      hwid: claims.hwid,
    };
  }

  // ---------------------------------------------------------------- health

  app.get("/api/v1/health", async () => ({
    ok: true,
    serverUtc: new Date().toISOString(),
  }));

  // ---------------------------------------------------------------- enroll

  app.post("/api/v1/enroll", async (request, reply) => {
    const parsed = enrollBody.safeParse(request.body);

    if (!parsed.success) {
      return reply.code(400).send({ error: "בקשת רישום אינה תקינה" });
    }

    const body = parsed.data;
    const tokenHash = hashEnrollToken(body.enrollToken);

    const result = await withPlatform(pool, SYSTEM_ACTOR, async (tx) => {
      const tokenRow = await tx.query<{
        id: string;
        tenant_id: string;
        install_profile: string;
        enforcement_mode: string;
        policy_floor: unknown;
      }>(
        `SELECT id, tenant_id, install_profile, enforcement_mode, policy_floor
         FROM enroll_tokens
         WHERE token_hash = $1
           AND revoked_at IS NULL
           AND expires_at > now()
           AND uses < max_uses
         FOR UPDATE`,
        [tokenHash],
      );

      const token = tokenRow.rows[0];
      if (!token) return { kind: "bad-token" as const };

      // רישום חוזר של אותו מכשיר אינו יוצר כפילות. זה קורה בשגרה
      // אחרי התקנה מחדש, ואין סיבה להכשיל אותו.
      const device = await tx.query<{ id: string; policy_floor: unknown }>(
        `INSERT INTO devices
           (tenant_id, hwid, machine_name, os_version, agent_version,
            install_profile, enforcement_mode, policy_floor)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (tenant_id, hwid) DO UPDATE SET
           machine_name  = EXCLUDED.machine_name,
           os_version    = EXCLUDED.os_version,
           agent_version = EXCLUDED.agent_version,
           status        = 'active'
         RETURNING id, policy_floor`,
        [
          token.tenant_id,
          body.hwid,
          body.machineName ?? null,
          body.osVersion ?? null,
          body.agentVersion ?? null,
          token.install_profile,
          token.enforcement_mode,
          JSON.stringify(token.policy_floor),
        ],
      );

      await tx.query("UPDATE enroll_tokens SET uses = uses + 1 WHERE id = $1", [token.id]);

      await tx.query(
        `INSERT INTO device_state (device_id, tenant_id) VALUES ($1, $2)
         ON CONFLICT (device_id) DO NOTHING`,
        [device.rows[0]!.id, token.tenant_id],
      );

      return {
        kind: "ok" as const,
        deviceId: device.rows[0]!.id,
        tenantId: token.tenant_id,
        installProfile: token.install_profile,
        enforcementMode: token.enforcement_mode,
        policyFloor: device.rows[0]!.policy_floor,
      };
    });

    if (result.kind === "bad-token") {
      return reply.code(403).send({ error: "אסימון הרישום אינו תקף, נוצל או פג תוקפו" });
    }

    const issued = await issueDeviceToken(
      config.DEVICE_TOKEN_SECRET,
      config.DEVICE_TOKEN_TTL_DAYS,
      { deviceId: result.deviceId, tenantId: result.tenantId, hwid: body.hwid },
    );

    await withTenant(pool, result.tenantId, async (tx) =>
      tx.query(
        `INSERT INTO device_tokens (device_id, tenant_id, jti, expires_at)
         VALUES ($1, $2, $3, $4)`,
        [result.deviceId, result.tenantId, issued.jti, issued.expiresAt],
      ),
    );

    // רצפת המדיניות נשלחת חתומה. המכשיר מאמת אותה ושומר אותה מוגנת,
    // ומכאן והלאה דוחה כל מדיניות שנמוכה ממנה. ראה 3.2.3.
    const floor = await buildEnvelope(signer, {
      hwid: body.hwid,
      floor: result.policyFloor,
      issuedUtc: new Date().toISOString(),
    });

    return reply.send({
      deviceId: result.deviceId,
      deviceToken: issued.token,
      installProfile: result.installProfile,
      enforcementMode: result.enforcementMode,
      policyFloor: floor.envelope,
      uninstallKeyMode: "Rsa",
      serverPublicKeyPem: await signer.publicKeyPem(),
      // מפתח שלישי ונפרד. קוד ההסרה מאומת בו בלבד, כדי שמי שיכול
      // לחתום מדיניות לא יוכל בכך גם להסיר מכשירים.
      uninstallPublicKeyPem: await uninstallSigner.publicKeyPem(),
      // מפתח נפרד. הסוכן מאמת בו היתרי הקלה בלבד, ולעולם לא
      // מקבל הקלה מתחת לרצפה שנחתמה במפתח המדיניות.
      looseningPublicKeyPem: await looseningSigner.publicKeyPem(),
      // מפתח רביעי ונפרד. עדכון הוא הרצת קוד ב-SYSTEM, ולכן הוא
      // מאומת במפתח שאינו חותם דבר אחר.
      updatePublicKeyPem: await updateSigner.publicKeyPem(),
      signingKid: signer.kid,
    });
  });

  // ---------------------------------------------------------------- policy

  app.get("/api/v1/policy", { preHandler: requireDevice }, async (request, reply) => {
    const device = request.device!;

    const policy = await withTenant(pool, device.tenantId, async (tx) => {
      const r = await tx.query<{
        id: string;
        version: number;
        etag: string;
        signed_bytes: Buffer;
        signature: Buffer;
        signing_kid: string;
      }>(
        `SELECT p.id, p.version, p.etag, p.signed_bytes, p.signature, p.signing_kid
         FROM policies p
         LEFT JOIN device_policy_assignments a ON a.policy_id = p.id AND a.device_id = $1
         WHERE a.device_id IS NOT NULL
            OR p.tenant_id = $2
            OR p.tenant_id IS NULL
         ORDER BY (a.device_id IS NOT NULL) DESC,
                  (p.tenant_id IS NOT NULL) DESC,
                  p.version DESC
         LIMIT 1`,
        [device.deviceId, device.tenantId],
      );

      return r.rows[0] ?? null;
    });

    if (!policy) {
      return reply.code(404).send({ error: "טרם הוגדרה מדיניות עבור המכשיר" });
    }

    if (request.headers["if-none-match"] === policy.etag) {
      return reply.code(304).send();
    }

    return reply
      .header("ETag", policy.etag)
      .send(envelopeFromStored(policy.signing_kid, policy.signed_bytes, policy.signature));
  });

  // ---------------------------------------------------------------- heartbeat

  app.post("/api/v1/heartbeat", { preHandler: requireDevice }, async (request, reply) => {
    const device = request.device!;
    const parsed = heartbeatBody.safeParse(request.body);

    if (!parsed.success) {
      return reply.code(400).send({ error: "פעימה אינה תקינה" });
    }

    const body = parsed.data;
    const status = STATUS_MAP[body.status] ?? "unknown";
    const ssid = body.activeAdapters.find((a) => a.ssid)?.ssid ?? null;

    const outcome = await withTenant(pool, device.tenantId, async (tx) => {
      // פעימה ישנה שהגיעה באיחור לא תדרוס מצב עדכני יותר
      // המצב הקודם נשלף באותה שאילתה שדורסת אותו, דרך צילום שנלקח
      // לפני העדכון. בלי זה היה צריך סבב נוסף לבסיס הנתונים בכל
      // פעימה — בדיוק העלות שהדגימה באה לחסוך.
      const state = await tx.query<{
        prev_status: string;
        prev_score: number | null;
        prev_provider: string | null;
        prev_lockout: boolean;
        prev_policy_version: number | null;
        prev_sample_at: Date | null;
      }>(
        `UPDATE device_state SET
           last_seen_at = now(),
           last_status  = $2::security_status,
           last_score   = $3,
           detected_provider = $4,
           public_ip    = NULLIF($5, '')::inet,
           wifi_ssid    = $6,
           lockout_active = $7,
           wfp_filter_count = $8,
           policy_version = $9,
           heartbeat_seq = GREATEST(device_state.heartbeat_seq, $10),
           -- פעימה מחזירה לתקינות, אך אינה מוחקת סימון חבלה:
           -- מכשיר שהוכח שחובל אינו נקי רק מפני שהוא מדווח שוב.
           health = CASE WHEN device_state.health = 'tampered'
                        THEN device_state.health
                        ELSE 'healthy'::dead_man_state END,
           updated_at   = now()
         FROM (
           SELECT last_status, last_score, detected_provider,
                  lockout_active, policy_version, last_sample_at
           FROM device_state WHERE device_id = $1
         ) AS prev
         WHERE device_state.device_id = $1 AND device_state.heartbeat_seq <= $10
         RETURNING prev.last_status        AS prev_status,
                   prev.last_score         AS prev_score,
                   prev.detected_provider  AS prev_provider,
                   prev.lockout_active     AS prev_lockout,
                   prev.policy_version     AS prev_policy_version,
                   prev.last_sample_at     AS prev_sample_at`,
        [
          device.deviceId,
          status,
          body.score,
          body.detectedProvider ?? null,
          body.publicIp ?? "",
          ssid,
          body.lockoutActive,
          body.wfpFilterCount ?? null,
          body.policyVersion ?? null,
          body.sequence,
        ],
      );

      // ---- היסטוריה: נשמרת רק כשיש בה מידע ----
      //
      // device_state לעיל כבר מחזיקה את המצב החי, וזה מה שהדשבורד
      // קורא. שורה כאן נכתבת רק בשינוי מצב או אחת לשעה. ראה
      // src/telemetry/retention.ts ומיגרציה 0014.
      const row = state.rows[0];

      const prev: DeviceSnapshot | null = row
        ? {
            status: row.prev_status,
            score: row.prev_score,
            provider: row.prev_provider,
            lockoutActive: row.prev_lockout,
            policyVersion: row.prev_policy_version,
            lastSampleAt: row.prev_sample_at,
          }
        : null;

      const reason = sampleReason(
        prev,
        {
          status,
          score: body.score,
          provider: body.detectedProvider ?? null,
          lockoutActive: body.lockoutActive,
          policyVersion: body.policyVersion ?? null,
          hasTamperEvents: body.tamperEvents.length > 0,
        },
        new Date(),
      );

      if (reason !== null) {
        // ההכנסה וסימון זמן הדגימה באותה שאילתה: אם אחת מהן תיכשל
        // ייווצר פער שבו סימן החיים השעתי לא יופעל שוב לעולם.
        await tx.query(
          `WITH sample AS (
             INSERT INTO heartbeats
               (device_id, tenant_id, sent_at, sequence, status, score,
                policy_version, lockout_active, payload)
             VALUES ($1, $2, $3, $4, $5::security_status, $6, $7, $8, $9)
             RETURNING device_id
           )
           UPDATE device_state SET last_sample_at = now()
           WHERE device_id = (SELECT device_id FROM sample)`,
          [
            device.deviceId,
            device.tenantId,
            body.sentUtc ?? null,
            body.sequence,
            status,
            body.score,
            body.policyVersion ?? null,
            body.lockoutActive,
            JSON.stringify({
              adapters: body.activeAdapters,
              failedProbes: body.failedProbes,
              uptimeSec: body.uptimeSec ?? null,
              agentVersion: body.agentVersion ?? null,
              sampleReason: reason,
            }),
          ],
        );
      }

      for (const event of body.tamperEvents) {
        await tx.query(
          // החומרה נגזרת מהסוג ואינה קבועה. אירוע שמשמעותו שההגנה
          // לא פעלה בפועל חייב לבלוט מול ניסיון שנחסם.
          `INSERT INTO events (device_id, tenant_id, kind, severity, detail, occurred_at)
           VALUES ($1, $2, $3, $4, $5, COALESCE($6::timestamptz, now()))`,
          [
            device.deviceId,
            device.tenantId,
            event.kind,
            severityFor(event.kind),
            event.detail ?? null,
            event.utc ?? null,
          ],
        );
      }

      const policy = await tx.query<{ etag: string }>(
        `SELECT etag FROM policies
         WHERE tenant_id = $1 OR tenant_id IS NULL
         ORDER BY (tenant_id IS NOT NULL) DESC, version DESC LIMIT 1`,
        [device.tenantId],
      );

      // פקודות ישנות פוקעות לפני האיסוף, כדי שמכשיר שחזר אחרי
      // שבוע לא ייחסם בגלל בקשה ששכחו ממנה
      await tx.query(
        `UPDATE device_commands SET status = 'expired'
         WHERE device_id = $1 AND status = 'pending' AND expires_at <= now()`,
        [device.deviceId],
      );

      // איסוף וסימון כנמסר באותה שאילתה: פקודה לא תימסר פעמיים
      const commands = await tx.query<{
        id: string;
        type: string;
        args: Record<string, string>;
        reason: string | null;
      }>(
        `UPDATE device_commands SET status = 'delivered', delivered_at = now()
         WHERE id IN (
           SELECT id FROM device_commands
           WHERE device_id = $1 AND status = 'pending'
           ORDER BY created_at
           LIMIT 10
           FOR UPDATE SKIP LOCKED
         )
         RETURNING id, type::text AS type, args, reason`,
        [device.deviceId],
      );

      // ---- הצעת עדכון ----
      //
      // ההצעה אינה רק "יש גרסה חדשה". היא גם ההיתר היחיד שבגללו
      // השמירה הכפולה תסבול עצירה של השירות בלי לזעוק חבלה, ולכן
      // היא חתומה במפתח נפרד, קשורה למכשיר, ובעלת תוקף קצר.
      const update = await buildUpdateOffer(
        tx,
        updateSigner,
        { deviceId: device.deviceId, hwidHash: hwidHashHex(body.hwid) },
        body.agentVersion ?? null,
        new Date(),
      );

      return {
        stale: state.rows.length === 0,
        policyEtag: policy.rows[0]?.etag ?? null,
        commands: commands.rows,
        update,
      };
    });

    return reply.send({
      ok: true,
      serverUtc: new Date().toISOString(),
      policyEtag: outcome.policyEtag,
      licenseValid: true,

      // מעטפה חתומה במפתח העדכונים, או null כשאין מה להציע.
      // הסוכן מאמת אותה במפתח שקיבל ברישום, ולעולם לא במפתח אחר.
      update: outcome.update,
      commands: outcome.commands.map((c) => ({
        id: c.id,
        // הסוכן מצפה ל-PascalCase, בסיס הנתונים שומר snake_case
        type: TYPE_MAP[c.type] ?? c.type,
        args: stringifyArgs({ ...c.args, ...(c.reason ? { reason: c.reason } : {}) }),
      })),
      ...(outcome.stale ? { note: "התקבלה פעימה ישנה; המצב לא עודכן" } : {}),
    });
  });

  // ---------------------------------------------------------------- audit

  app.post("/api/v1/audit", { preHandler: requireDevice }, async (request, reply) => {
    const device = request.device!;
    const report = request.body;

    await withTenant(pool, device.tenantId, async (tx) =>
      tx.query(
        `INSERT INTO events (device_id, tenant_id, kind, severity, detail, occurred_at)
         VALUES ($1, $2, 'audit.report', 'info', $3, now())`,
        [device.deviceId, device.tenantId, JSON.stringify(report).slice(0, 1024)],
      ),
    );

    return reply.send({ ok: true });
  });

  // ---------------------------------------------------------------- events

  app.post("/api/v1/events", { preHandler: requireDevice }, async (request, reply) => {
    const device = request.device!;
    const parsed = eventsBody.safeParse(request.body);

    if (!parsed.success) {
      return reply.code(400).send({ error: "רשימת אירועים אינה תקינה" });
    }

    await withTenant(pool, device.tenantId, async (tx) => {
      for (const event of parsed.data) {
        await tx.query(
          `INSERT INTO events (device_id, tenant_id, kind, severity, detail, occurred_at)
           VALUES ($1, $2, $3, 'warning', $4, COALESCE($5::timestamptz, now()))`,
          [device.deviceId, device.tenantId, event.kind, event.detail ?? null, event.utc ?? null],
        );
      }
    });

    return reply.send({ ok: true, accepted: parsed.data.length });
  });
}
