import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import type { RaspAgent } from "../agent.js";
import type { NormalizedRequest } from "../types.js";

/**
 * Registers a Fastify plugin that inspects every incoming request.
 * In "block" mode, detected threats receive a 403 reply.
 * In "monitor" mode (default), the request passes through regardless.
 *
 * Usage:
 *   await fastify.register(createFastifyPlugin(agent))
 */
export function createFastifyPlugin(agent: RaspAgent) {
  return async function raspPlugin(fastify: FastifyInstance): Promise<void> {
    fastify.addHook(
      "onRequest",
      async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
        try {
          const normalized: NormalizedRequest = {
            method: request.method,
            path: request.url.split("?")[0] ?? request.url,
            query: (request.query as Record<string, unknown>) ?? {},
            headers: request.headers as Record<string, string | string[] | undefined>,
            body: request.body,
            sourceIp: extractSourceIp(request),
          };

          const detection = agent.inspect(normalized);

          if (detection && agent["cfg"].mode === "block") {
            return reply.status(403).send({
              error: "Request blocked by RASP",
              eventType: detection.eventType,
            });
          }
        } catch {
          // Fail open.
        }
      }
    );
  };
}

function extractSourceIp(req: FastifyRequest): string | undefined {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") return forwarded.split(",")[0]?.trim();
  if (Array.isArray(forwarded)) return forwarded[0]?.split(",")[0]?.trim();
  return req.socket?.remoteAddress;
}
