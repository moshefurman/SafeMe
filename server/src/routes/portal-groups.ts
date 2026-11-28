import type { FastifyInstance } from "fastify";
import { targetLabel, trusteeGate } from "../auth/trustee.ts";
import type pg from "pg";
import { z } from "zod";

import { withTenant, withPlatform } from "../db/client.ts";
import { createGuards } from "../auth/guards.ts";
import { can, isPlatformRole } from "../auth/rbac.ts";
import type { ActiveSession } from "../auth/session.ts";
import type { Config } from "../config.ts";
import type { Signer } from "../crypto/signing.ts";
import { composeDeviceOverlay } from "../policy/device-overlay.ts";
import { loadGroupSchedules, describeSchedule } from "../policy/schedules.ts";
import {
  MAX_APPROVED_DOMAINS,
  checkDomainsAllowed,
  loadGroupWhitelist,
  normalizeDomain,
  whitelistSystemDomains,
} from "../policy/whitelist.ts";

const HHMM = /^([01][0-9]|2[0-3]):[0-5][0-9]$/;

const groupBody = z.object({ name: z.string().trim().min(1).max(60) });

const memberBody = z.object({ deviceId: z.string().uuid() });

const scheduleBody = z.object({
  days: z.array(z.number().int().min(0).max(6)).max(7).default([]),
  from: z.string().regex(HHMM, "שעה בפורמט HH:mm"),
  to: z.string().regex(HHMM, "שעה בפורמט HH:mm"),
  label: z.string().trim().max(60).optional(),
});

const enabledBody = z.object({ enabled: z.boolean() });

const domainsBody = z.object({
  domains: z.array(z.string().max(2048)).min(1).max(100),
});

const displayNameBody = z.object({ displayName: z.string().trim().min(1).max(60) });

const browserSettingsBody = z.object({
  youtubeAudioOnly: z.boolean(),
  youtubeHideThumbnails: z.boolean(),
  youtubeAllowedChannels: z.array(z.string().trim().min(1).max(200)).max(100).default([]),
  aiSafeMode: z.boolean(),
  aiBlockedKeywords: z.array(z.string().trim().min(1).max(200)).max(1000).default([]),
});

const NOTE = "המחשבים יקבלו את השינוי בפעימה הבאה, בדרך כלל תוך שלוש דקות.";

const SYSTEM = {
  userId: "00000000-0000-0000-0000-000000000000",
  reason: "רישום ביומן ביקורת",
};

async function audit(
  pool: pg.Pool,
  session: ActiveSession,
  entry: { action: string; targetId?: string; tenantId?: string | null; payload?: unknown },
): Promise<void> {
  await withPlatform(pool, SYSTEM, async (tx) => {
    await tx.query(
      `INSERT INTO audit_log
         (actor_type, actor_id, action, target_type, target_id, tenant_id, payload)
       VALUES ($1, $2, $3, 'group', $4, $5, $6)`,
      [
        isPlatformRole(session.user.role) ? "platform_user" : "tenant_user",
        session.user.userId,
        entry.action,
        entry.targetId ?? null,
        entry.tenantId ?? session.user.tenantId,
        JSON.stringify(entry.payload ?? {}),
      ],
    );
  });
}

interface Deps {
  pool: pg.Pool;
  config: Config;
  signer: Signer;
  fetch?: typeof fetch | undefined;
}

export async function registerGroupRoutes(
  app: FastifyInstance,
  deps: Deps,
): Promise<void> {
  const { pool, config, signer } = deps;
  const guards = createGuards(pool, config);
  const base = [guards.requireSession, guards.requirePlatformMfa];
  const checkOptions = deps.fetch === undefined ? {} : { fetch: deps.fetch };

  async function ownsGroup(tenantId: string, groupId: string): Promise<boolean> {
    return withTenant(pool, tenantId, async (tx) => {
      const r = await tx.query(
        "SELECT 1 FROM device_groups WHERE id = $1 AND tenant_id = $2",
        [groupId, tenantId],
      );
      return (r.rowCount ?? 0) > 0;
    });
  }

  async function recomposeGroupDevices(
    tenantId: string,
    groupId: string,
    publishedBy: string,
  ): Promise<void> {
    const members = await withTenant(pool, tenantId, async (tx) => {
      const r = await tx.query<{ id: string }>(
        "SELECT id FROM devices WHERE group_id = $1 AND status = 'active'",
        [groupId],
      );
      return r.rows;
    });

    for (const { id } of members) {
      await composeDeviceOverlay(pool, signer, { tenantId, deviceId: id, publishedBy });
    }
  }

  // ---------------------------------------------------------------- CRUD קבוצות

  app.get(
    "/api/portal/v1/groups",
    { preHandler: [...base, guards.requirePermission("devices.viewOwn")] },
    async (request, reply) => {
      const tenantId = request.portal!.session.user.tenantId;
      if (!tenantId) return reply.send({ groups: [] });

      const rows = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query<{
          id: string;
          name: string;
          member_count: string;
          created_at: Date;
        }>(
          `SELECT g.id, g.name, g.created_at,
                  count(d.id)::text AS member_count
             FROM device_groups g
             LEFT JOIN devices d ON d.group_id = g.id AND d.status = 'active'
            WHERE g.tenant_id = $1
            GROUP BY g.id
            ORDER BY g.name`,
          [tenantId],
        );
        return r.rows;
      });

      return reply.send({
        groups: rows.map((r) => ({
          id: r.id,
          name: r.name,
          memberCount: Number(r.member_count),
          createdAt: r.created_at,
        })),
      });
    },
  );

  app.post(
    "/api/portal/v1/groups",
    { preHandler: [...base, guards.requirePermission("devices.lockout")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;
      if (!tenantId) return reply.code(400).send({ error: "החשבון אינו משויך לדייר" });

      const parsed = groupBody.safeParse(request.body);
      if (!parsed.success) return reply.code(400).send({ error: "שם הקבוצה אינו תקין" });

      try {
        const id = await withTenant(pool, tenantId, async (tx) => {
          const r = await tx.query<{ id: string }>(
            `INSERT INTO device_groups (tenant_id, name) VALUES ($1, $2) RETURNING id`,
            [tenantId, parsed.data.name],
          );
          return r.rows[0]!.id;
        });

        await audit(pool, session, {
          action: "group.created",
          targetId: id,
          payload: { name: parsed.data.name },
        });

        return reply.send({ ok: true, id });
      } catch (error) {
        if ((error as { code?: string }).code === "23505") {
          return reply.code(409).send({ error: "שם הקבוצה כבר קיים" });
        }
        throw error;
      }
    },
  );

  app.get<{ Params: { id: string } }>(
    "/api/portal/v1/groups/:id",
    { preHandler: [...base, guards.requirePermission("devices.viewOwn")] },
    async (request, reply) => {
      const tenantId = request.portal!.session.user.tenantId;
      if (!tenantId) return reply.code(404).send({ error: "הקבוצה אינה קיימת" });

      if (!z.string().uuid().safeParse(request.params.id).success) {
        return reply.code(404).send({ error: "הקבוצה אינה קיימת" });
      }

      const result = await withTenant(pool, tenantId, async (tx) => {
        const g = await tx.query<{ id: string; name: string; created_at: Date }>(
          "SELECT id, name, created_at FROM device_groups WHERE id = $1",
          [request.params.id],
        );
        if (g.rows.length === 0) return null;

        const members = await tx.query<{
          id: string;
          display_name: string | null;
          machine_name: string | null;
          last_status: string;
        }>(
          `SELECT d.id, d.display_name, d.machine_name, COALESCE(s.last_status, 'unknown') AS last_status
             FROM devices d
             LEFT JOIN device_state s ON s.device_id = d.id
            WHERE d.group_id = $1 AND d.status = 'active'
            ORDER BY d.display_name, d.machine_name`,
          [request.params.id],
        );

        return { group: g.rows[0]!, members: members.rows };
      });

      if (!result) return reply.code(404).send({ error: "הקבוצה אינה קיימת" });

      return reply.send({
        id: result.group.id,
        name: result.group.name,
        createdAt: result.group.created_at,
        members: result.members.map((m) => ({
          id: m.id,
          displayName: m.display_name,
          machineName: m.machine_name,
          lastStatus: m.last_status,
        })),
      });
    },
  );

  app.patch<{ Params: { id: string } }>(
    "/api/portal/v1/groups/:id",
    { preHandler: [...base, guards.requirePermission("devices.lockout")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;
      if (!tenantId) return reply.code(400).send({ error: "החשבון אינו משויך לדייר" });

      const parsed = groupBody.safeParse(request.body);
      if (!parsed.success) return reply.code(400).send({ error: "שם הקבוצה אינו תקין" });

      if (!await ownsGroup(tenantId, request.params.id)) {
        return reply.code(404).send({ error: "הקבוצה אינה קיימת" });
      }

      if (GATED_GROUP_ROUTES.has(`${request.method} ${request.routeOptions.url}`)) {
        const where = await targetLabel(tenantId, { groupId: request.params.id });
        const before = await previousBrowserSettings(pool, tenantId, request.params.id);
        const what = groupGateSummary(request.method, request.routeOptions.url ?? "", request.body, where, before);

        if (what !== null && await trusteeGate(request, reply, what)) return reply;
      }

      try {
        await withTenant(pool, tenantId, (tx) =>
          tx.query("UPDATE device_groups SET name = $2 WHERE id = $1", [request.params.id, parsed.data.name]));

        await audit(pool, session, {
          action: "group.renamed",
          targetId: request.params.id,
          payload: { name: parsed.data.name },
        });

        return reply.send({ ok: true });
      } catch (error) {
        if ((error as { code?: string }).code === "23505") {
          return reply.code(409).send({ error: "שם הקבוצה כבר קיים" });
        }
        throw error;
      }
    },
  );

  app.delete<{ Params: { id: string } }>(
    "/api/portal/v1/groups/:id",
    { preHandler: [...base, guards.requirePermission("devices.lockout")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;
      if (!tenantId) return reply.code(400).send({ error: "החשבון אינו משויך לדייר" });

      if (!await ownsGroup(tenantId, request.params.id)) {
        return reply.code(404).send({ error: "הקבוצה אינה קיימת" });
      }

      if (GATED_GROUP_ROUTES.has(`${request.method} ${request.routeOptions.url}`)) {
        const where = await targetLabel(tenantId, { groupId: request.params.id });
        const before = await previousBrowserSettings(pool, tenantId, request.params.id);
        const what = groupGateSummary(request.method, request.routeOptions.url ?? "", request.body, where, before);

        if (what !== null && await trusteeGate(request, reply, what)) return reply;
      }

      const memberIds = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query<{ id: string }>(
          "SELECT id FROM devices WHERE group_id = $1 AND status = 'active'",
          [request.params.id],
        );
        await tx.query("DELETE FROM device_groups WHERE id = $1", [request.params.id]);
        return r.rows.map((x) => x.id);
      });

      for (const deviceId of memberIds) {
        await composeDeviceOverlay(pool, signer, { tenantId, deviceId, publishedBy: session.user.userId });
      }

      await audit(pool, session, {
        action: "group.deleted",
        targetId: request.params.id,
        payload: { affectedDevices: memberIds.length },
      });

      return reply.send({ ok: true });
    },
  );

  // ---------------------------------------------------------------- שיוך מחשבים

  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/groups/:id/members",
    { preHandler: [...base, guards.requirePermission("devices.lockout")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;
      if (!tenantId) return reply.code(400).send({ error: "החשבון אינו משויך לדייר" });

      const parsed = memberBody.safeParse(request.body);
      if (!parsed.success) return reply.code(400).send({ error: "בקשה לא תקינה" });

      if (!await ownsGroup(tenantId, request.params.id)) {
        return reply.code(404).send({ error: "הקבוצה אינה קיימת" });
      }

      if (GATED_GROUP_ROUTES.has(`${request.method} ${request.routeOptions.url}`)) {
        const where = await targetLabel(tenantId, { groupId: request.params.id });
        const before = await previousBrowserSettings(pool, tenantId, request.params.id);
        const what = groupGateSummary(request.method, request.routeOptions.url ?? "", request.body, where, before);

        if (what !== null && await trusteeGate(request, reply, what)) return reply;
      }

      const updated = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query(
          "UPDATE devices SET group_id = $2 WHERE id = $1 AND tenant_id = $3 AND status = 'active'",
          [parsed.data.deviceId, request.params.id, tenantId],
        );
        return (r.rowCount ?? 0) > 0;
      });

      if (!updated) return reply.code(404).send({ error: "המחשב אינו קיים" });

      await composeDeviceOverlay(pool, signer, {
        tenantId, deviceId: parsed.data.deviceId, publishedBy: session.user.userId,
      });

      await audit(pool, session, {
        action: "group.member_added",
        targetId: request.params.id,
        payload: { deviceId: parsed.data.deviceId },
      });

      return reply.send({ ok: true, note: NOTE });
    },
  );

  app.delete<{ Params: { id: string; deviceId: string } }>(
    "/api/portal/v1/groups/:id/members/:deviceId",
    { preHandler: [...base, guards.requirePermission("devices.lockout")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;
      if (!tenantId) return reply.code(400).send({ error: "החשבון אינו משויך לדייר" });

      {
        const device = await targetLabel(tenantId, { deviceId: request.params.deviceId });
        const group = await targetLabel(tenantId, { groupId: request.params.id });

        if (await trusteeGate(request, reply,
          `להוציא את המחשב ${device.replace(/^במחשב /, "")} מהקבוצה ${group.replace(/^בקבוצה /, "")}, כך שהגדרות הקבוצה לא יחולו עליו`)) return reply;
      }

      const updated = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query(
          "UPDATE devices SET group_id = NULL WHERE id = $1 AND group_id = $2 AND tenant_id = $3",
          [request.params.deviceId, request.params.id, tenantId],
        );
        return (r.rowCount ?? 0) > 0;
      });

      if (!updated) return reply.code(404).send({ error: "המחשב אינו חבר בקבוצה" });

      await composeDeviceOverlay(pool, signer, {
        tenantId, deviceId: request.params.deviceId, publishedBy: session.user.userId,
      });

      await audit(pool, session, {
        action: "group.member_removed",
        targetId: request.params.id,
        payload: { deviceId: request.params.deviceId },
      });

      return reply.send({ ok: true, note: NOTE });
    },
  );

  // ---------------------------------------------------------------- שעות חסימה לקבוצה

  app.get<{ Params: { id: string } }>(
    "/api/portal/v1/groups/:id/schedules",
    { preHandler: [...base, guards.requirePermission("devices.viewOwn")] },
    async (request, reply) => {
      const tenantId = request.portal!.session.user.tenantId;
      if (!tenantId) return reply.send({ schedules: [] });

      const rows = await withTenant(pool, tenantId, (tx) =>
        loadGroupSchedules(tx, request.params.id));

      return reply.send({
        schedules: rows.map((row) => ({
          id: row.id,
          days: row.days,
          from: row.from_time.slice(0, 5),
          to: row.to_time.slice(0, 5),
          label: row.label,
          enabled: row.enabled,
          description: describeSchedule(row),
        })),
      });
    },
  );

  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/groups/:id/schedules",
    { preHandler: [...base, guards.requirePermission("devices.lockout")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;
      if (!tenantId) return reply.code(400).send({ error: "החשבון אינו משויך לדייר" });

      const parsed = scheduleBody.safeParse(request.body);
      if (!parsed.success) {
        return reply.code(400).send({ error: parsed.error.issues[0]?.message ?? "בקשה לא תקינה" });
      }

      if (parsed.data.from === parsed.data.to) {
        return reply.code(400).send({ error: "שעת ההתחלה והסיום זהות, ולכן לא ייחסם דבר." });
      }

      if (!await ownsGroup(tenantId, request.params.id)) {
        return reply.code(404).send({ error: "הקבוצה אינה קיימת" });
      }

      if (GATED_GROUP_ROUTES.has(`${request.method} ${request.routeOptions.url}`)) {
        const where = await targetLabel(tenantId, { groupId: request.params.id });
        const before = await previousBrowserSettings(pool, tenantId, request.params.id);
        const what = groupGateSummary(request.method, request.routeOptions.url ?? "", request.body, where, before);

        if (what !== null && await trusteeGate(request, reply, what)) return reply;
      }

      const id = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query<{ id: string }>(
          `INSERT INTO group_schedules
             (group_id, tenant_id, days, from_time, to_time, label, created_by)
           VALUES ($1, $2, $3::smallint[], $4::time, $5::time, $6, $7)
           RETURNING id`,
          [
            request.params.id,
            tenantId,
            parsed.data.days,
            parsed.data.from,
            parsed.data.to,
            parsed.data.label ?? null,
            session.user.userId,
          ],
        );
        return r.rows[0]!.id;
      });

      await recomposeGroupDevices(tenantId, request.params.id, session.user.userId);

      await audit(pool, session, {
        action: "group.schedule.added",
        targetId: request.params.id,
        payload: { from: parsed.data.from, to: parsed.data.to, days: parsed.data.days },
      });

      return reply.send({ ok: true, id, note: NOTE });
    },
  );

  app.delete<{ Params: { id: string; scheduleId: string } }>(
    "/api/portal/v1/groups/:id/schedules/:scheduleId",
    { preHandler: [...base, guards.requirePermission("devices.lockout")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;
      if (!tenantId) return reply.code(400).send({ error: "החשבון אינו משויך לדייר" });

      {
        const where = await targetLabel(tenantId, { groupId: request.params.id });

        if (await trusteeGate(request, reply, `למחוק שעות חסימה ${where}`)) return reply;
      }

      const removed = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query(
          "DELETE FROM group_schedules WHERE id = $1 AND group_id = $2 AND tenant_id = $3",
          [request.params.scheduleId, request.params.id, tenantId],
        );
        return (r.rowCount ?? 0) > 0;
      });

      if (!removed) return reply.code(404).send({ error: "שעות החסימה אינן קיימות" });

      await recomposeGroupDevices(tenantId, request.params.id, session.user.userId);

      await audit(pool, session, {
        action: "group.schedule.removed",
        targetId: request.params.id,
        payload: { scheduleId: request.params.scheduleId },
      });

      return reply.send({ ok: true, note: NOTE });
    },
  );

  // ---------------------------------------------------------------- רשימה לבנה לקבוצה

  app.get<{ Params: { id: string } }>(
    "/api/portal/v1/groups/:id/whitelist",
    { preHandler: [...base, guards.requirePermission("devices.viewOwn")] },
    async (request, reply) => {
      const tenantId = request.portal!.session.user.tenantId;
      if (!tenantId || !z.string().uuid().safeParse(request.params.id).success) {
        return reply.send({ enabled: false, domains: [], systemDomains: whitelistSystemDomains(), maxDomains: MAX_APPROVED_DOMAINS });
      }

      const state = await withTenant(pool, tenantId, (tx) =>
        loadGroupWhitelist(tx, request.params.id));

      return reply.send({
        enabled: state.enabled,
        domains: state.domains.map((d) => ({
          id: d.id,
          domain: d.domain,
          source: d.source,
          createdAt: d.created_at,
        })),
        systemDomains: whitelistSystemDomains(),
        maxDomains: MAX_APPROVED_DOMAINS,
      });
    },
  );

  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/groups/:id/whitelist",
    { preHandler: [...base, guards.requirePermission("policy.tighten")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;
      if (!tenantId) return reply.code(400).send({ error: "החשבון אינו משויך לדייר" });

      const parsed = enabledBody.safeParse(request.body);
      if (!parsed.success) return reply.code(400).send({ error: "בקשה לא תקינה" });

      if (!parsed.data.enabled && !can(session.user.role, "networks.approve")) {
        return reply.code(403).send({ error: "אין הרשאה לפעולה זו.", mfaRequired: false });
      }

      if (!await ownsGroup(tenantId, request.params.id)) {
        return reply.code(404).send({ error: "הקבוצה אינה קיימת" });
      }

      if (GATED_GROUP_ROUTES.has(`${request.method} ${request.routeOptions.url}`)) {
        const where = await targetLabel(tenantId, { groupId: request.params.id });
        const before = await previousBrowserSettings(pool, tenantId, request.params.id);
        const what = groupGateSummary(request.method, request.routeOptions.url ?? "", request.body, where, before);

        if (what !== null && await trusteeGate(request, reply, what)) return reply;
      }

      await withTenant(pool, tenantId, (tx) =>
        tx.query(
          `INSERT INTO group_whitelist (group_id, tenant_id, enabled, updated_by)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (group_id) DO UPDATE
              SET enabled = EXCLUDED.enabled, updated_at = now(), updated_by = EXCLUDED.updated_by`,
          [request.params.id, tenantId, parsed.data.enabled, session.user.userId],
        ));

      await recomposeGroupDevices(tenantId, request.params.id, session.user.userId);

      await audit(pool, session, {
        action: parsed.data.enabled ? "group.whitelist.enabled" : "group.whitelist.disabled",
        targetId: request.params.id,
      });

      return reply.send({ ok: true, enabled: parsed.data.enabled, note: NOTE });
    },
  );

  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/groups/:id/whitelist/domains",
    { preHandler: [...base, guards.requirePermission("networks.approve")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;
      if (!tenantId) return reply.code(400).send({ error: "החשבון אינו משויך לדייר" });

      const parsed = domainsBody.safeParse(request.body);
      if (!parsed.success) {
        return reply.code(400).send({ error: "יש לשלוח בין אתר אחד למאה אתרים בכל פעם." });
      }

      if (!await ownsGroup(tenantId, request.params.id)) {
        return reply.code(404).send({ error: "הקבוצה אינה קיימת" });
      }

      if (GATED_GROUP_ROUTES.has(`${request.method} ${request.routeOptions.url}`)) {
        const where = await targetLabel(tenantId, { groupId: request.params.id });
        const before = await previousBrowserSettings(pool, tenantId, request.params.id);
        const what = groupGateSummary(request.method, request.routeOptions.url ?? "", request.body, where, before);

        if (what !== null && await trusteeGate(request, reply, what)) return reply;
      }

      const groupId = request.params.id;

      interface Result { input: string; domain: string; ok: boolean; reason?: string; already?: boolean }

      const results: Result[] = [];
      const candidates: string[] = [];
      const seen = new Set<string>();

      const existing = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query<{ domain: string }>(
          "SELECT domain FROM group_whitelist_domains WHERE group_id = $1",
          [groupId],
        );
        return new Set(r.rows.map((x) => x.domain));
      });

      for (const input of parsed.data.domains) {
        const domain = normalizeDomain(input, { stripWww: true });

        if (domain === null) {
          results.push({
            input, domain: input.trim(), ok: false,
            reason: "זה אינו שם של אתר. יש לכתוב שם כמו example.co.il, או להדביק קישור.",
          });
          continue;
        }

        if (seen.has(domain)) continue;
        seen.add(domain);

        if (existing.has(domain)) {
          results.push({ input, domain, ok: true, already: true });
          continue;
        }

        candidates.push(domain);
        results.push({ input, domain, ok: false });
      }

      if (existing.size + candidates.length > MAX_APPROVED_DOMAINS) {
        return reply.code(400).send({
          error: `אפשר לאשר עד ${MAX_APPROVED_DOMAINS} אתרים לקבוצה. כרגע מאושרים ${existing.size}, והבקשה מוסיפה ${candidates.length}.`,
        });
      }

      const verdicts = await checkDomainsAllowed(candidates, checkOptions);
      const allowed: string[] = [];

      for (const result of results) {
        const verdict = verdicts.get(result.domain);
        if (verdict === undefined) continue;

        if (verdict.ok) {
          result.ok = true;
          allowed.push(result.domain);
        } else {
          result.reason = verdict.reason;
        }
      }

      if (allowed.length > 0) {
        await withTenant(pool, tenantId, (tx) =>
          tx.query(
            `INSERT INTO group_whitelist_domains (group_id, tenant_id, domain, source, created_by)
             SELECT $1, $2, d, 'manual', $3 FROM unnest($4::text[]) AS d
             ON CONFLICT (group_id, domain) DO NOTHING`,
            [groupId, tenantId, session.user.userId, allowed],
          ));

        await recomposeGroupDevices(tenantId, groupId, session.user.userId);
      }

      await audit(pool, session, {
        action: "group.whitelist.domains_added",
        targetId: groupId,
        payload: { added: allowed, rejected: results.filter((r) => !r.ok).map((r) => ({ domain: r.domain, reason: r.reason })) },
      });

      return reply.send({
        ok: true, added: allowed.length, results,
        ...(allowed.length > 0 ? { note: NOTE } : {}),
      });
    },
  );

  app.delete<{ Params: { id: string; domainId: string } }>(
    "/api/portal/v1/groups/:id/whitelist/domains/:domainId",
    { preHandler: [...base, guards.requirePermission("policy.tighten")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;
      if (!tenantId) return reply.code(400).send({ error: "החשבון אינו משויך לדייר" });

      if (!z.string().uuid().safeParse(request.params.domainId).success) {
        return reply.code(404).send({ error: "האתר אינו ברשימה" });
      }

      const removed = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query<{ domain: string }>(
          `DELETE FROM group_whitelist_domains
            WHERE id = $1 AND group_id = $2 AND tenant_id = $3
        RETURNING domain`,
          [request.params.domainId, request.params.id, tenantId],
        );
        return r.rows[0]?.domain ?? null;
      });

      if (removed === null) return reply.code(404).send({ error: "האתר אינו ברשימה" });

      await recomposeGroupDevices(tenantId, request.params.id, session.user.userId);

      await audit(pool, session, {
        action: "group.whitelist.domain_removed",
        targetId: request.params.id,
        payload: { domain: removed },
      });

      return reply.send({ ok: true, note: NOTE });
    },
  );

  // ---------------------------------------------------------------- הגדרות דפדפן לקבוצה

  app.get<{ Params: { id: string } }>(
    "/api/portal/v1/groups/:id/browser",
    { preHandler: [...base, guards.requirePermission("devices.viewOwn")] },
    async (request, reply) => {
      const tenantId = request.portal!.session.user.tenantId;
      if (!tenantId) {
        return reply.send({
          youtubeAudioOnly: false,
          youtubeHideThumbnails: false,
          youtubeAllowedChannels: [],
          aiSafeMode: false,
          aiBlockedKeywords: [],
        });
      }

      const row = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query<{ settings: Record<string, unknown> }>(
          "SELECT settings FROM group_browser_settings WHERE group_id = $1",
          [request.params.id],
        );
        return r.rows[0]?.settings ?? null;
      });

      const s = row ?? {};
      return reply.send({
        youtubeAudioOnly: s["youtubeAudioOnly"] === true,
        youtubeHideThumbnails: s["youtubeHideThumbnails"] === true,
        youtubeAllowedChannels: Array.isArray(s["youtubeAllowedChannels"])
          ? (s["youtubeAllowedChannels"] as unknown[]).filter((x): x is string => typeof x === "string")
          : [],
        aiSafeMode: s["aiSafeMode"] === true,
        aiBlockedKeywords: Array.isArray(s["aiBlockedKeywords"])
          ? (s["aiBlockedKeywords"] as unknown[]).filter((x): x is string => typeof x === "string")
          : [],
      });
    },
  );

  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/groups/:id/browser",
    { preHandler: [...base, guards.requirePermission("devices.lockout")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;
      if (!tenantId) return reply.code(400).send({ error: "החשבון אינו משויך לדייר" });

      const parsed = browserSettingsBody.safeParse(request.body);
      if (!parsed.success) {
        return reply.code(400).send({ error: parsed.error.issues[0]?.message ?? "בקשה לא תקינה" });
      }

      if (!await ownsGroup(tenantId, request.params.id)) {
        return reply.code(404).send({ error: "הקבוצה אינה קיימת" });
      }

      if (GATED_GROUP_ROUTES.has(`${request.method} ${request.routeOptions.url}`)) {
        const where = await targetLabel(tenantId, { groupId: request.params.id });
        const before = await previousBrowserSettings(pool, tenantId, request.params.id);
        const what = groupGateSummary(request.method, request.routeOptions.url ?? "", request.body, where, before);

        if (what !== null && await trusteeGate(request, reply, what)) return reply;
      }

      const settings = {
        youtubeAudioOnly: parsed.data.youtubeAudioOnly,
        youtubeHideThumbnails: parsed.data.youtubeHideThumbnails,
        youtubeAllowedChannels: parsed.data.youtubeAllowedChannels,
        aiSafeMode: parsed.data.aiSafeMode,
        aiBlockedKeywords: parsed.data.aiBlockedKeywords,
      };

      await withTenant(pool, tenantId, (tx) =>
        tx.query(
          `INSERT INTO group_browser_settings (group_id, tenant_id, settings, updated_by)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (group_id) DO UPDATE
              SET settings = EXCLUDED.settings, updated_at = now(), updated_by = EXCLUDED.updated_by`,
          [request.params.id, tenantId, JSON.stringify(settings), session.user.userId],
        ));

      await recomposeGroupDevices(tenantId, request.params.id, session.user.userId);

      await audit(pool, session, {
        action: "group.browser.updated",
        targetId: request.params.id,
        payload: settings,
      });

      return reply.send({ ok: true, ...settings, note: NOTE });
    },
  );

  // ---------------------------------------------------------------- איפוס הגדרות מחשב + שם

  app.post<{ Params: { id: string } }>(
    "/api/portal/v1/devices/:id/reset-settings",
    { preHandler: [...base, guards.requirePermission("devices.lockout")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;
      if (!tenantId) return reply.code(400).send({ error: "החשבון אינו משויך לדייר" });

      if (!z.string().uuid().safeParse(request.params.id).success) {
        return reply.code(404).send({ error: "המחשב אינו קיים" });
      }

      const deviceId = request.params.id;

      {
        const where = await targetLabel(tenantId, { deviceId });

        if (await trusteeGate(request, reply, `למחוק את ההגדרות האישיות ${where} (שעות חסימה ורשימה לבנה)`)) return reply;
      }

      const deleted = await withTenant(pool, tenantId, async (tx) => {
        const owns = await tx.query("SELECT 1 FROM devices WHERE id = $1 AND tenant_id = $2", [deviceId, tenantId]);
        if ((owns.rowCount ?? 0) === 0) return null;

        const s = await tx.query("DELETE FROM device_schedules WHERE device_id = $1 AND tenant_id = $2", [deviceId, tenantId]);
        const wd = await tx.query("DELETE FROM device_whitelist_domains WHERE device_id = $1 AND tenant_id = $2", [deviceId, tenantId]);
        await tx.query("DELETE FROM device_whitelist WHERE device_id = $1", [deviceId]);

        return { schedules: s.rowCount ?? 0, domains: wd.rowCount ?? 0 };
      });

      if (deleted === null) return reply.code(404).send({ error: "המחשב אינו קיים" });

      await composeDeviceOverlay(pool, signer, { tenantId, deviceId, publishedBy: session.user.userId });

      await audit(pool, session, {
        action: "device.settings_reset",
        targetId: deviceId,
        payload: deleted,
      });

      return reply.send({ ok: true, ...deleted, note: NOTE });
    },
  );

  app.patch<{ Params: { id: string } }>(
    "/api/portal/v1/devices/:id/display-name",
    { preHandler: [...base, guards.requirePermission("devices.lockout")] },
    async (request, reply) => {
      const session = request.portal!.session;
      const tenantId = session.user.tenantId;
      if (!tenantId) return reply.code(400).send({ error: "החשבון אינו משויך לדייר" });

      const parsed = displayNameBody.safeParse(request.body);
      if (!parsed.success) return reply.code(400).send({ error: "חובה לתת למחשב כינוי, עד 60 תווים" });

      const updated = await withTenant(pool, tenantId, async (tx) => {
        const r = await tx.query(
          "UPDATE devices SET display_name = $2 WHERE id = $1 AND tenant_id = $3",
          [request.params.id, parsed.data.displayName || null, tenantId],
        );
        return (r.rowCount ?? 0) > 0;
      });

      if (!updated) return reply.code(404).send({ error: "המחשב אינו קיים" });

      return reply.send({ ok: true });
    },
  );
}

/*
 * מסלולי הקבוצה שעוברים דרך הנאמן, אחרי בדיקת הבעלות על הקבוצה.
 *
 * הבדיקה משותפת לכמה מסלולים, ולכן השער יושב אחריה פעם אחת ושואל
 * כאן אם המסלול הזה מקל, ומה בדיוק הוא מבקש.
 */
const GATED_GROUP_ROUTES = new Set([
  "DELETE /api/portal/v1/groups/:id",
  "POST /api/portal/v1/groups/:id/whitelist",
  "POST /api/portal/v1/groups/:id/whitelist/domains",
  "POST /api/portal/v1/groups/:id/browser",
]);

/** הגדרות הסינון השמורות של קבוצה, כדי לדעת מה באמת נכבה בשמירה. */
async function previousBrowserSettings(
  pool: pg.Pool,
  tenantId: string,
  groupId: string,
): Promise<Record<string, unknown>> {
  try {
    return await withTenant(pool, tenantId, async (tx) => {
      const r = await tx.query<{ settings: Record<string, unknown> }>(
        "SELECT settings FROM group_browser_settings WHERE group_id = $1 AND tenant_id = $2",
        [groupId, tenantId],
      );

      return r.rows[0]?.settings ?? {};
    });
  } catch {
    return {};
  }
}

function groupGateSummary(
  method: string,
  route: string,
  body: unknown,
  where: string,
  before: Record<string, unknown>,
): string | null {
  const data = (body ?? {}) as Record<string, unknown>;

  if (method === "DELETE") {
    return `למחוק את הקבוצה ${where.replace(/^בקבוצה /, "")}, כך שההגדרות שלה לא יחולו על המחשבים שבה`;
  }

  if (route.endsWith("/whitelist")) {
    return data["enabled"] === false
      ? `לכבות את הרשימה הלבנה ${where}, כך שהגלישה לא תוגבל לאתרים מאושרים`
      : null;
  }

  if (route.endsWith("/whitelist/domains")) {
    const domains = Array.isArray(data["domains"]) ? (data["domains"] as unknown[]).map(String) : [];

    return `להוסיף לרשימה הלבנה ${where} את: ${domains.slice(0, 8).join(", ")}`
      + (domains.length > 8 ? ` ועוד ${domains.length - 8}` : "");
  }

  if (route.endsWith("/browser")) {
    // רק מה שהיה פעיל ועכשיו נכבה. הגוף נושא את כל השדות בכל שמירה,
    // ו"כבוי" שלא השתנה אינו הקלה.
    const off = [
      before["youtubeAudioOnly"] === true && data["youtubeAudioOnly"] === false ? "יוטיוב בשמע בלבד" : null,
      before["youtubeHideThumbnails"] === true && data["youtubeHideThumbnails"] === false ? "הסתרת תמונות ביוטיוב" : null,
      before["aiSafeMode"] === true && data["aiSafeMode"] === false ? "סינון במנועי AI" : null,
    ].filter((x): x is string => x !== null);

    return off.length > 0 ? `לכבות ${where} את: ${off.join(", ")}` : null;
  }

  return null;
}
