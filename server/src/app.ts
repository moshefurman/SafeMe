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
import { registerNetworkRoutes } from "./routes/portal-networks.ts";
import { registerEgressRoutes } from "./routes/portal-egress.ts";
import { registerGoogleRoutes } from "./routes/portal-google.ts";
import { registerProviderRoutes } from "./routes/portal-providers.ts";
import { registerNotificationRoutes } from "./routes/portal-notifications.ts";
import { registerMailRoutes } from "./routes/portal-mail.ts";
import { registerUninstallRoutes } from "./routes/portal-uninstall.ts";
import { registerScheduleRoutes } from "./routes/portal-schedules.ts";
import { registerPlatformTenantRoutes } from "./routes/platform-tenants.ts";
import { registerBillingRoutes } from "./routes/portal-billing.ts";
import { LiveMailer } from "./notify/live-mailer.ts";
import { registerSigningKey } from "./policy/keys.ts";
import { ensureBaselinePolicy } from "./policy/baseline.ts";
import { isPlatformRole } from "./auth/rbac.ts";
import {
  KmsDeviceSecretDeriver,
  LocalDeviceSecretDeriver,
  createKmsMacClient,
} from "./crypto/device-secret.ts";
import { loadConfig, type Config } from "./config.ts";
import { startDeadManWorker } from "./workers/deadman-worker.ts";
import { startEmailChangeWorker } from "./workers/email-change-worker.ts";
import { createMailer, type Mailer } from "./notify/mailer.ts";

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
  mailer?: Mailer;
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

  // שגיאה לא צפויה לא אמורה לחשוף מבנה פנימי למחשב בשטח
  fastify.setErrorHandler((error: unknown, request, reply) => {
    request.log.error({ err: error }, "בקשה נכשלה");

    const fastifyError = error as { statusCode?: number; message?: string };
    const raw = fastifyError.statusCode ?? 500;
    const status = raw >= 400 && raw <= 599 ? raw : 500;
    const message = status >= 500 ? "שגיאה פנימית בשרת" : fastifyError.message ?? "בקשה שגויה";

    /*
     * למנהל פלטפורמה מוצג גם מה קרה.
     *
     * "שגיאה פנימית בשרת" לבדה היא מבוי סתום: היא נכונה, היא לא
     * חושפת דבר לתוקף, ואי אפשר לעשות איתה כלום. מי שמאבחן נאלץ
     * לצאת ליומני הפריסה ולחזור — וזה בדיוק מה שקרה כאן.
     *
     * הפירוט נחשף רק למי שממילא רואה את כל הדיירים ואת יומן
     * הביקורת, ולכן אינו מוסיף לו ידיעה שלא הייתה לו. להורה
     * ולסוכן ההודעה נשארת כפי שהייתה.
     */
    const detail = status >= 500 && isPlatformRole(request.portal?.session.user.role ?? "tenant_member")
      ? { detail: error instanceof Error ? error.message : String(error) }
      : {};

    void reply.code(status).send({ error: message, ...detail });
  });

  // המפתח הציבורי חייב להיות רשום לפני שאפשר לפרסם מדיניות שנחתמה בו,
  // ולפני שאפשר להפיץ אותו למחשבים ברישום.
  if (!options.skipKeyRegistration) {
    // ---- שלושת המפתחות ----
    //
    // כל מפתח הוא סמכות אחת: לחתום מדיניות, להקל אותה, או להסיר
    // מחשב. ההפרדה ביניהם היא מה שמונע ממי שהשיג אחת לקבל גם את
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

    /*
     * תבנית מדיניות גלובלית, אם אין.
     *
     * בלעדיה מחשב שנרשם לחשבון חדש מקבל 404 ורץ בלי הגדרות
     * כלל. אחרי רישום המפתחות, כי הפרסום דורש חותם רשום.
     *
     * כשל אינו מפיל את העלייה: שרת בלי תבנית עדיף על שרת שאינו
     * עולה, והוא ינסה שוב בהפעלה הבאה.
     */
    try {
      const baseline = await ensureBaselinePolicy(pool, signer, config.PORTAL_URL);

      if (baseline.created) {
        fastify.log.info({ version: baseline.version }, "נוצרה מדיניות בסיס גלובלית");
      }
    } catch (error) {
      fastify.log.error({ err: error }, "יצירת מדיניות הבסיס נכשלה");
    }
  }

  /*
   * גוזר סוד ההסרה, אם הוגדר.
   *
   * בלעדיו כל קוד הסרה נשאר חתימת RSA בת שש מאות תווים — עובד
   * בהדבקה, בלתי אפשרי בטלפון. זה אינו כשל אלא פשרה מודעת:
   * פריסה בלי KMS עדיין מתפקדת.
   */
  const deriver = config.DEVICE_SECRET_KMS_KEY_ID
    ? new KmsDeviceSecretDeriver(
        config.DEVICE_SECRET_KMS_KEY_ID,
        await createKmsMacClient())
    : config.DEVICE_SECRET_MASTER
      ? new LocalDeviceSecretDeriver(config.DEVICE_SECRET_MASTER)
      : undefined;

  /*
   * בדיקה שהגזירה באמת עובדת, בעלייה ולא ברישום הראשון.
   *
   * הרשאה חסרה או מפתח שגוי היו מתגלים רק כשמשפחה מתקינה — ואז
   * הסוכן היה נרשם במצב Rsa בשקט, ומקבל קוד של שש מאות תווים
   * שאי אפשר להכתיב בטלפון. הכול היה נראה תקין עד השיחה הראשונה
   * למוקד.
   *
   * זה בדיוק הדפוס שחזר כאן שוב ושוב: מנגנון שנופל בשקט ואין לו
   * דרך להיראות. עדיף לדעת בעלייה.
   *
   * כשל אינו מפיל את השרת: קוד ארוך עדיף על שרת שאינו עולה.
   */
  if (deriver) {
    try {
      const probe = await deriver.derive("self-check");

      if (probe.length < 32) throw new Error(`אורך לא צפוי: ${probe.length}`);

      fastify.log.info("גזירת סוד ההסרה פעילה. קודי הסרה יהיו קצרים.");
    } catch (error) {
      fastify.log.error(
        { err: error },
        "גזירת סוד ההסרה אינה עובדת. מחשבים חדשים יקבלו קוד ארוך שאי אפשר להכתיב בטלפון.",
      );
    }
  } else {
    fastify.log.warn(
      "לא הוגדר מפתח לגזירת סוד ההסרה. קודי ההסרה יהיו ארוכים, ולא ניתן להכתיב אותם בטלפון.",
    );
  }

  /*
   * גוף בינארי, ליומנים שמגיעים מהמחשבים.
   *
   * Fastify מפענח JSON בלבד כברירת מחדל ומחזיר 415 על כל דבר אחר.
   * היומן נשלח דחוס — מאות קילובייטים של שורות חוזרות מתכווצים פי
   * עשרה — ועטיפה ב-base64 בתוך JSON הייתה מנפחת אותו בשליש בדיוק
   * בכיוון הלא נכון.
   *
   * המפענח מחזיר את הבתים כפי שהתקבלו, בלי לפרש. הגבול נאכף
   * ברמת המסלול.
   */
  fastify.addContentTypeParser(
    "application/octet-stream",
    { parseAs: "buffer" },
    (_request, body, done) => { done(null, body); },
  );

  await registerDeviceRoutes(fastify, {
    pool,
    deriver,
    signer,
    looseningSigner,
    uninstallSigner,
    updateSigner,
    config,
  });
  /*
   * הדוור קורא את הגדרותיו מהמסד ורושם את תוצאת השליחה.
   *
   * בלי הרישום, "האם הדואר עובד" הייתה שאלה שאפשר לענות עליה רק
   * בדיעבד — כשהתראה אמיתית לא הגיעה.
   *
   * נוצר כאן ולא למטה: מסלולי האימות צריכים אותו לאיפוס סיסמה,
   * והם נרשמים ראשונים. const בתחום זמני מת אינו שגיאת הידור —
   * הוא קריסה בעלייה.
   */
  const mailer = options.mailer ?? new LiveMailer(pool, config.RESEND_API_KEY);

  await registerPortalAuthRoutes(fastify, { pool, config, mailer });
  await registerPortalDeviceRoutes(fastify, { pool, config });
  await registerSignupRoutes(fastify, { pool, config });
  await registerNetworkRoutes(fastify, { pool, config, signer });
  await registerEgressRoutes(fastify, { pool, config, signer });
  await registerGoogleRoutes(fastify, { pool, config });
  await registerProviderRoutes(fastify, { pool, config, signer });
  await registerPlatformTenantRoutes(fastify, { pool, config });
  await registerBillingRoutes(fastify, { pool, config });
  await registerDownloadRoutes(fastify, { pool, config });

  await registerNotificationRoutes(fastify, { pool, config, mailer });
  await registerMailRoutes(fastify, { pool, config, mailer });
  await registerUninstallRoutes(fastify, { pool, config, uninstallSigner, deriver });
  await registerScheduleRoutes(fastify, { pool, config, signer });

  // הסורק שמזהה מחשבים ששתקו.
  //
  // נעילת ייעוץ בבסיס הנתונים מבטיחה שרק מופע אחד סורק בכל רגע,
  // גם כשרצים כמה מופעים של השרת.
  const stopDeadMan = options.skipKeyRegistration
    ? () => {}
    : startDeadManWorker(pool, fastify.log, {
        mailer,
        portalUrl: config.PORTAL_URL,
      });

  /*
   * מחיל בקשות להחלפת כתובת התראות שהחלון שלהן נגמר.
   *
   * בלעדיו ההשהיה אינה השהיה אלא ביטול שקט: הבקשה יושבת במסד לנצח,
   * וההורה בטוח שהכתובת השתנתה.
   */
  const stopEmailChange = options.skipKeyRegistration
    ? () => {}
    : startEmailChangeWorker(pool, fastify.log);

  return {
    fastify,
    pool,
    signer,
    looseningSigner,
    uninstallSigner,
    updateSigner,
    config,
    close: async () => {
      stopDeadMan();
      stopEmailChange();
      await fastify.close();
      if (!options.pool) await pool.end();
    },
  };
}
