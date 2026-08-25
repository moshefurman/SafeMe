import { createHash } from "node:crypto";
import type pg from "pg";
import { withPlatform, withTenant } from "../db/client.ts";
import { buildEnvelope, type Signer } from "../crypto/signing.ts";

/**
 * פרסום מדיניות.
 *
 * הנקודה המרכזית: החתימה מתבצעת **פעם אחת** על הבתים שנשמרים במאגר,
 * ואותם בתים בדיוק נשלחים למכשיר. השרת לעולם אינו מסדר את המדיניות
 * מחדש בזמן ההגשה, ולכן אין דרך שהבתים ישתנו בין החתימה למסירה.
 *
 * זה מה שמאפשר לסוכן ב-C# לאמת חתימה של שרת ב-TypeScript.
 */

export interface PublishInput {
  /** null = תבנית גלובלית שחלה על כל מי שאין לו מדיניות ייעודית */
  tenantId: string | null;
  version: number;
  body: unknown;
  publishedBy?: string | null;
}

export interface PublishedPolicy {
  id: string;
  version: number;
  etag: string;
  byteLength: number;
}

function computeEtag(bytes: Buffer): string {
  return `W/"${createHash("sha256").update(bytes).digest("hex").slice(0, 16)}"`;
}

export async function publishPolicy(
  pool: pg.Pool,
  signer: Signer,
  input: PublishInput,
): Promise<PublishedPolicy> {
  const { envelope, bytes, signature } = await buildEnvelope(signer, input.body);
  const etag = computeEtag(bytes);

  const insert = async (tx: { query: pg.ClientBase["query"] }) => {
    const r = await tx.query<{ id: string; version: number }>(
      `INSERT INTO policies
         (tenant_id, version, body, signed_bytes, signature, signing_kid, etag, published_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING id, version`,
      [
        input.tenantId,
        input.version,
        JSON.stringify(input.body),
        bytes,
        signature,
        envelope.kid,
        etag,
        input.publishedBy ?? null,
      ],
    );

    return r.rows[0]!;
  };

  // מדיניות גלובלית אינה שייכת לדייר, ולכן נכתבת בהקשר פלטפורמה
  const row = input.tenantId
    ? await withTenant(pool, input.tenantId, insert)
    : await withPlatform(
        pool,
        { userId: input.publishedBy ?? "system", reason: "פרסום מדיניות גלובלית" },
        insert,
      );

  return { id: row.id, version: row.version, etag, byteLength: bytes.length };
}

/** משייך מדיניות למכשיר מסוים, מעל ברירת המחדל של הדייר. */
export async function assignPolicy(
  pool: pg.Pool,
  tenantId: string,
  deviceId: string,
  policyId: string,
): Promise<void> {
  await withTenant(pool, tenantId, async (tx) => {
    await tx.query(
      `INSERT INTO device_policy_assignments (device_id, tenant_id, policy_id)
       VALUES ($1, $2, $3)
       ON CONFLICT (device_id) DO UPDATE SET policy_id = EXCLUDED.policy_id,
                                             assigned_at = now()`,
      [deviceId, tenantId, policyId],
    );
  });
}
