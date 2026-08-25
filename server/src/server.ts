import { buildApp } from "./app.ts";

/** נקודת הכניסה בייצור. */
const app = await buildApp();

try {
  await app.fastify.listen({ port: app.config.PORT, host: app.config.HOST });
} catch (error) {
  app.fastify.log.error(error);
  process.exit(1);
}

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => {
    void app.close().then(() => process.exit(0));
  });
}
