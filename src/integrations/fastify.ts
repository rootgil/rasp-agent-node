/**
 * Fastify integration.
 *
 * Uses `onRequest` for early context + query/header inspection, then
 * `preHandler` to re-inspect with the parsed body (POST/PUT/PATCH).
 */
import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import type { RaspAgent } from "../agent.js";
import type { NormalizedRequest } from "../types.js";

type RaspRequest = FastifyRequest & {
  __raspCtx?: import("../runtime-context.js").RequestContext | null;
  __raspBlocked?: boolean;
};

function normalize(request: FastifyRequest): NormalizedRequest {
  const rawQuery = request.query as Record<string, unknown>;
  const query =
    rawQuery && Object.keys(rawQuery).length > 0
      ? rawQuery
      : parseQueryFromUrl(request.url);

  return {
    method: request.method,
    path: request.url.split("?")[0] ?? request.url,
    query,
    headers: request.headers as Record<string, string | string[] | undefined>,
    body: request.body,
    sourceIp: extractSourceIp(request),
  };
}

export function createFastifyPlugin(agent: RaspAgent) {
  const raspPlugin = async function raspPlugin(fastify: FastifyInstance): Promise<void> {
    // Early hook: bind request context. Inspect immediately only when no body
    // is expected — body-bearing methods are inspected once in preHandler.
    fastify.addHook(
      "onRequest",
      async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
        try {
          const normalized = normalize(request);
          const ctx = agent.beginRequest(normalized);
          (request as RaspRequest).__raspCtx = ctx;

          const method = request.method.toUpperCase();
          if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) return;

          const detection = agent.inspect(normalized);
          if (detection && agent.mode === "block") {
            (request as RaspRequest).__raspBlocked = true;
            return reply.status(403).send({
              error: "Request blocked by RASP",
              eventType: detection.eventType,
            });
          }
        } catch {
          // Fail-open.
        }
      }
    );

    // After body parsing: re-inspect so POST bodies are visible to detectors.
    fastify.addHook(
      "preHandler",
      async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
        try {
          if ((request as RaspRequest).__raspBlocked) return;
          const method = request.method.toUpperCase();
          if (!["POST", "PUT", "PATCH", "DELETE"].includes(method)) return;
          if (request.body == null) return;

          const normalized = normalize(request);
          const detection = agent.inspect(normalized);
          if (detection && agent.mode === "block") {
            return reply.status(403).send({
              error: "Request blocked by RASP",
              eventType: detection.eventType,
            });
          }
        } catch {
          // Fail-open.
        }
      }
    );

    fastify.addHook(
      "onResponse",
      async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
        try {
          const normalized = normalize(request);
          const r = request as RaspRequest & {
            user?: unknown;
            auth?: unknown;
          };
          agent.endRequest(r.__raspCtx ?? null, normalized, {
            statusCode: reply.statusCode,
            durationMs: Math.round(reply.elapsedTime),
            authenticated: r.user != null || r.auth != null,
          });
        } catch {
          // Fail-open.
        }
      }
    );
  };

  (raspPlugin as typeof raspPlugin & { [key: symbol]: boolean })[
    Symbol.for("skip-override")
  ] = true;

  return raspPlugin;
}

function extractSourceIp(req: FastifyRequest): string | undefined {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") return forwarded.split(",")[0]?.trim();
  if (Array.isArray(forwarded)) return forwarded[0]?.split(",")[0]?.trim();
  return req.socket?.remoteAddress;
}

function parseQueryFromUrl(url: string): Record<string, unknown> {
  try {
    const qIndex = url.indexOf("?");
    if (qIndex === -1) return {};
    const params = new URLSearchParams(url.slice(qIndex + 1));
    const result: Record<string, string> = {};
    for (const [k, v] of params.entries()) {
      result[k] = v;
    }
    return result;
  } catch {
    return {};
  }
}
