import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import type { FastifyInstance } from "fastify";

const DIR = join(import.meta.dirname, "../../extension");

export async function registerExtensionRoutes(
  fastify: FastifyInstance,
): Promise<void> {
  const crxPath = join(DIR, "safeme-audio.crx");
  const xmlPath = join(DIR, "update.xml");

  if (!existsSync(crxPath) || !existsSync(xmlPath)) {
    fastify.log.warn("extension/ missing — /extension/* routes disabled");
    return;
  }

  const crx = readFileSync(crxPath);
  const xml = readFileSync(xmlPath, "utf8");

  fastify.get("/extension/update.xml", async (_req, reply) => {
    return reply
      .header("content-type", "application/xml")
      .header("cache-control", "public, max-age=3600")
      .send(xml);
  });

  fastify.get("/extension/safeme-audio.crx", async (_req, reply) => {
    return reply
      .header("content-type", "application/x-chrome-extension")
      .header("cache-control", "public, max-age=86400")
      .send(crx);
  });
}
