/**
 * Fastify integration.
 *
 * Exposes {@link createFastifyPlugin}, a factory that returns a Fastify
 * plugin attaching an `onRequest` hook bound to a {@link RaspAgent}.
 *
 * Behaviour mirrors the Express integration:
 *  - The request is normalised and inspected.
 *  - `monitor` mode lets the request continue regardless of the result.
 *  - `block` mode replies `403 { error, eventType }` and short-circuits
 *    the route handler.
 *  - Any thrown error is swallowed (fail-open).
 *
 * @example
 * ```ts
 * import Fastify from "fastify";
 * import { RaspAgent, createFastifyPlugin } from "@queno/agent-node";
 *
 * const agent = new RaspAgent({ apiKey, projectId, agentId });
 * agent.start();
 *
 * const fastify = Fastify();
 * await fastify.register(createFastifyPlugin(agent));
 * ```
 *
 * @remarks The hook fires at `onRequest`, before body parsing. If body
 * inspection is required, switch the hook to `preHandler` in this file or
 * register a separate hook downstream.
 */
import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import type { RaspAgent } from "../agent.js";
import type { NormalizedRequest } from "../types.js";

export function createFastifyPlugin(agent: RaspAgent) {
  const raspPlugin = async function raspPlugin(fastify: FastifyInstance): Promise<void> {
    fastify.addHook(
      "onRequest",
      async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
        try {
          const rawQuery = request.query as Record<string, unknown>;
          const query =
            rawQuery && Object.keys(rawQuery).length > 0
              ? rawQuery
              : parseQueryFromUrl(request.url);

          const normalized: NormalizedRequest = {
            method: request.method,
            path: request.url.split("?")[0] ?? request.url,
            query,
            headers: request.headers as Record<string, string | string[] | undefined>,
            body: request.body,
            sourceIp: extractSourceIp(request),
          };

          const ctx = agent.beginRequest(normalized);
          (request as FastifyRequest & { __raspCtx?: unknown }).__raspCtx = ctx;

          const detection = agent.inspect(normalized);

          if (detection && agent.mode === "block") {
            return reply.status(403).send({
              error: "Request blocked by RASP",
              eventType: detection.eventType,
            });
          }
        } catch {
          // Fail-open - see file-level note.
        }
      }
    );

    // Response-phase observation for traffic profiling + auth confirmation.
    fastify.addHook(
      "onResponse",
      async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
        try {
          const normalized: NormalizedRequest = {
            method: request.method,
            path: request.url.split("?")[0] ?? request.url,
            query: (request.query as Record<string, unknown>) ?? {},
            headers: request.headers as Record<string, string | string[] | undefined>,
            body: request.body,
            sourceIp: undefined,
          };
          const r = request as FastifyRequest & {
            user?: unknown;
            auth?: unknown;
            __raspCtx?: import("../runtime-context.js").RequestContext | null;
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

  // Mark as non-encapsulated so the onRequest/onResponse hooks apply to ALL
  // routes in the Fastify instance, not only those registered inside this
  // plugin scope. Equivalent to wrapping with `fastify-plugin` without
  // adding a package dependency.
  (raspPlugin as typeof raspPlugin & { [key: symbol]: boolean })[
    Symbol.for("skip-override")
  ] = true;

  return raspPlugin;
}

/**
 * Best-effort source IP resolution; see the Express integration for the
 * trust caveat.
 */
function extractSourceIp(req: FastifyRequest): string | undefined {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") return forwarded.split(",")[0]?.trim();
  if (Array.isArray(forwarded)) return forwarded[0]?.split(",")[0]?.trim();
  return req.socket?.remoteAddress;
}

/**
 * Parse query parameters from a raw URL string.
 *
 * Used as a fallback when `request.query` is not yet populated in the
 * `onRequest` hook (Fastify v5 populates it lazily after route matching).
 */
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
