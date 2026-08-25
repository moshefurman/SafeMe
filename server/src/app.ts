import Fastify, { type FastifyInstance } from "fastify";
import type pg from "pg";
import { createPool } from "./db/client.ts";
import { createSigner, type Signer } from "./crypto/signing.ts";
import { registerDeviceRoutes } from "./routes/device.ts";
import { registerPortalAuthRoutes } from "./routes/portal-auth.ts";
import { registerPortalDeviceRoutes } from "./routes/portal-devices.ts";
import { registerSignupRoutes } from "./routes/portal-signup.ts";
import { registerSigningKey } from "./policy/keys.ts";
import { loadConfig, type Config } from "./config.ts";

export interface App {
  fastify: FastifyInstance;
  pool: pg.Pool;
  signer: Signer;
  config: Config;
  close(): Promise<void>;
}

export interface BuildOptions {
  config?: Config;
  pool?: pg.Pool;
  signer?: Signer;
  logger?: boolean;
  /** לדילוג על רישום המפתח, לבדיקות שאינן נוגעות במאגר. */
  skipKeyRegistration?: boolean;
}

export async function buildApp(options: BuildOptions = {}): Promise<App> {
  const config = options.config ?? loadConfig();
  const pool = options.pool ?? createPool({ connectionString: config.DATABASE_URL_APP });
  const signer = options.signer ?? createSigner(config);

  const fastify = Fastify({
    logger: options.logger ?? config.NODE_ENV !== "test",
    // הסוכן שולח דוחות ביקורת שיכולים להיות גדולים, אך לא בלי גבול
    bodyLimit: 512 * 1024,
    trustProxy: true,
  });

  // שגיאה לא צפויה לא אמורה לחשוף מבנה פנימי למכשיר בשטח
  fastify.setErrorHandler((error: unknown, request, reply) => {
    request.log.error({ err: error }, "בקשה נכשלה");

    const fastifyError = error as { statusCode?: number; message?: string };
    const raw = fastifyError.statusCode ?? 500;
    const status = raw >= 400 && raw <= 599 ? raw : 500;
    const message = status >= 500 ? "שגיאה פנימית בשרת" : fastifyError.message ?? "בקשה שגויה";

    void reply.code(status).send({ error: message });
  });

  // המפתח הציבורי חייב להיות רשום לפני שאפשר לפרסם מדיניות שנחתמה בו,
  // ולפני שאפשר להפיץ אותו למכשירים ברישום.
  if (!options.skipKeyRegistration) {
    const key = await registerSigningKey(pool, signer, {
      purpose: "policy",
      kmsKeyId: config.SIGNER_KMS_KEY_ID ?? "local",
    });

    if (key.registered) {
      fastify.log.info(
        { kid: signer.kid, retired: key.retired },
        "נרשם מפתח חתימת מדיניות",
      );
    }
  }

  await registerDeviceRoutes(fastify, { pool, signer, config });
  await registerPortalAuthRoutes(fastify, { pool, config });
  await registerPortalDeviceRoutes(fastify, { pool, config });
  await registerSignupRoutes(fastify, { pool, config });

  return {
    fastify,
    pool,
    signer,
    config,
    close: async () => {
      await fastify.close();
      if (!options.pool) await pool.end();
    },
  };
}
