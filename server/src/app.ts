import Fastify, { type FastifyInstance } from "fastify";
import type pg from "pg";
import { createPool } from "./db/client.ts";
import { createLooseningSigner, createSigner, type Signer } from "./crypto/signing.ts";
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
  /** חותם היתרי ההקלה. מפתח נפרד ממפתח המדיניות, ראה config. */
  looseningSigner: Signer;
  config: Config;
  close(): Promise<void>;
}

export interface BuildOptions {
  config?: Config;
  pool?: pg.Pool;
  signer?: Signer;
  looseningSigner?: Signer;
  logger?: boolean;
  /** לדילוג על רישום המפתח, לבדיקות שאינן נוגעות במאגר. */
  skipKeyRegistration?: boolean;
}

export async function buildApp(options: BuildOptions = {}): Promise<App> {
  const config = options.config ?? loadConfig();
  const pool = options.pool ?? createPool({ connectionString: config.DATABASE_URL_APP });
  const signer = options.signer ?? createSigner(config);
  const looseningSigner = options.looseningSigner ?? createLooseningSigner(config);

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
    // ---- ההפרדה בין המפתחות, לפני כל כתיבה ----
    //
    // הבדיקה האמיתית, ולא זו שב-config. שם מושווים מזהים; כאן
    // מושווים המפתחות עצמם. שני כינויים ב-KMS יכולים להצביע לאותו
    // מפתח, ואז המזהים שונים אך ההפרדה אינה קיימת — והיא כל ההגנה
    // מאחורי "להחמיר כן, להסיר לא".
    //
    // רצה לפני הרישום ולא אחריו: תצורה שגויה לא אמורה להשאיר אחריה
    // מפתח רשום למחצה.
    const policyPem = await signer.publicKeyPem();
    const looseningPem = await looseningSigner.publicKeyPem();

    if (policyPem === looseningPem) {
      throw new Error(
        "מפתח המדיניות ומפתח ההיתרים הם אותו מפתח בפועל, למרות מזהים שונים. " +
          "בדוק אם שני הכינויים ב-KMS מצביעים לאותו מפתח.",
      );
    }

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

    const grantKey = await registerSigningKey(pool, looseningSigner, {
      purpose: "loosening",
      kmsKeyId: config.SIGNER_LOOSENING_KMS_KEY_ID ?? "local",
    });

    if (grantKey.registered) {
      fastify.log.info(
        { kid: looseningSigner.kid, retired: grantKey.retired },
        "נרשם מפתח חתימת היתרי הקלה",
      );
    }
  }

  await registerDeviceRoutes(fastify, { pool, signer, looseningSigner, config });
  await registerPortalAuthRoutes(fastify, { pool, config });
  await registerPortalDeviceRoutes(fastify, { pool, config });
  await registerSignupRoutes(fastify, { pool, config });

  return {
    fastify,
    pool,
    signer,
    looseningSigner,
    config,
    close: async () => {
      await fastify.close();
      if (!options.pool) await pool.end();
    },
  };
}
