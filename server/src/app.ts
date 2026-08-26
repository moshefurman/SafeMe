import Fastify, { type FastifyInstance } from "fastify";
import type pg from "pg";
import { createPool } from "./db/client.ts";
import {
  createLooseningSigner,
  createSigner,
  createUninstallSigner,
  createUpdateSigner,
  type Signer,
} from "./crypto/signing.ts";
import { registerDeviceRoutes } from "./routes/device.ts";
import { registerPortalAuthRoutes } from "./routes/portal-auth.ts";
import { registerPortalDeviceRoutes } from "./routes/portal-devices.ts";
import { registerSignupRoutes } from "./routes/portal-signup.ts";
import { registerDownloadRoutes } from "./routes/download.ts";
import { registerSigningKey } from "./policy/keys.ts";
import { loadConfig, type Config } from "./config.ts";

export interface App {
  fastify: FastifyInstance;
  pool: pg.Pool;
  signer: Signer;
  /** חותם היתרי ההקלה. מפתח נפרד ממפתח המדיניות, ראה config. */
  looseningSigner: Signer;
  /** חותם קודי ההסרה. מפתח שלישי ונפרד. */
  uninstallSigner: Signer;
  /** חותם עדכוני הסוכן. הרביעי, והחזק מכולם. */
  updateSigner: Signer;
  config: Config;
  close(): Promise<void>;
}

export interface BuildOptions {
  config?: Config;
  pool?: pg.Pool;
  signer?: Signer;
  looseningSigner?: Signer;
  uninstallSigner?: Signer;
  updateSigner?: Signer;
  logger?: boolean;
  /** לדילוג על רישום המפתח, לבדיקות שאינן נוגעות במאגר. */
  skipKeyRegistration?: boolean;
}

export async function buildApp(options: BuildOptions = {}): Promise<App> {
  const config = options.config ?? loadConfig();
  const pool = options.pool ?? createPool({ connectionString: config.DATABASE_URL_APP });
  const signer = options.signer ?? createSigner(config);
  const looseningSigner = options.looseningSigner ?? createLooseningSigner(config);
  const uninstallSigner = options.uninstallSigner ?? createUninstallSigner(config);
  const updateSigner = options.updateSigner ?? createUpdateSigner(config);

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
    // ---- שלושת המפתחות ----
    //
    // כל מפתח הוא סמכות אחת: לחתום מדיניות, להקל אותה, או להסיר
    // מכשיר. ההפרדה ביניהם היא מה שמונע ממי שהשיג אחת לקבל גם את
    // האחרות.
    const authorities = [
      {
        purpose: "policy" as const,
        signer,
        kmsKeyId: config.SIGNER_KMS_KEY_ID ?? "local",
        label: "מדיניות",
      },
      {
        purpose: "loosening" as const,
        signer: looseningSigner,
        kmsKeyId: config.SIGNER_LOOSENING_KMS_KEY_ID ?? "local",
        label: "היתרי הקלה",
      },
      {
        purpose: "uninstall" as const,
        signer: uninstallSigner,
        kmsKeyId: config.SIGNER_UNINSTALL_KMS_KEY_ID ?? "local",
        label: "קודי הסרה",
      },
      {
        purpose: "update" as const,
        signer: updateSigner,
        kmsKeyId: config.SIGNER_UPDATE_KMS_KEY_ID ?? "local",
        label: "עדכוני סוכן",
      },
    ];

    // הבדיקה האמיתית, ולא זו שב-config. שם מושווים מזהים; כאן
    // מושווים המפתחות עצמם, כי שני כינויים ב-KMS יכולים להצביע
    // לאותו מפתח — ואז המזהים שונים אך ההפרדה אינה קיימת.
    //
    // רצה לפני כל רישום, כדי שתצורה שגויה לא תשאיר מפתח רשום למחצה.
    const pems = await Promise.all(authorities.map((a) => a.signer.publicKeyPem()));

    for (let i = 0; i < pems.length; i++) {
      for (let j = i + 1; j < pems.length; j++) {
        if (pems[i] === pems[j]) {
          throw new Error(
            `מפתח ${authorities[i]!.label} ומפתח ${authorities[j]!.label} הם אותו מפתח ` +
              "בפועל, למרות מזהים שונים. בדוק אם שני הכינויים מצביעים לאותו מפתח.",
          );
        }
      }
    }

    for (const authority of authorities) {
      const registered = await registerSigningKey(pool, authority.signer, {
        purpose: authority.purpose,
        kmsKeyId: authority.kmsKeyId,
      });

      if (registered.registered) {
        fastify.log.info(
          { kid: authority.signer.kid, retired: registered.retired },
          `נרשם מפתח חתימת ${authority.label}`,
        );
      }
    }
  }

  await registerDeviceRoutes(fastify, {
    pool,
    signer,
    looseningSigner,
    uninstallSigner,
    updateSigner,
    config,
  });
  await registerPortalAuthRoutes(fastify, { pool, config });
  await registerPortalDeviceRoutes(fastify, { pool, config });
  await registerSignupRoutes(fastify, { pool, config });
  await registerDownloadRoutes(fastify, { pool, config });

  return {
    fastify,
    pool,
    signer,
    looseningSigner,
    uninstallSigner,
    updateSigner,
    config,
    close: async () => {
      await fastify.close();
      if (!options.pool) await pool.end();
    },
  };
}
