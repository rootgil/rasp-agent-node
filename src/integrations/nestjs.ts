/**
 * NestJS integration.
 *
 * Exposes {@link createNestMiddleware}, a factory that returns a NestJS
 * middleware **class** bound to a {@link RaspAgent} instance.
 *
 * Behaviour matches the Express adapter (Nest's middleware contract is
 * Express-compatible by default):
 *  - The request is normalised and inspected.
 *  - `monitor` mode lets the request continue.
 *  - `block` mode replies `403 { error, eventType }` and skips the next
 *    handler.
 *  - Any thrown error is swallowed (fail-open).
 *
 * @example
 * ```ts
 * import { MiddlewareConsumer, Module, NestModule } from "@nestjs/common";
 * import { RaspAgent, createNestMiddleware } from "@queno/agent-node";
 *
 * const agent = new RaspAgent({ apiKey, projectId, agentId });
 * agent.start();
 *
 * @Module({})
 * export class AppModule implements NestModule {
 *   configure(consumer: MiddlewareConsumer) {
 *     consumer.apply(createNestMiddleware(agent)).forRoutes("*");
 *   }
 * }
 * ```
 */
import type { NestMiddleware } from "@nestjs/common";
import type { Request, Response, NextFunction } from "express";
import type { RaspAgent } from "../agent.js";
import type { NormalizedRequest } from "../types.js";

/**
 * Build a Nest middleware class bound to a {@link RaspAgent}.
 *
 * A class is returned (rather than an instance) because Nest itself
 * instantiates middlewares from its DI container.
 */
export function createNestMiddleware(agent: RaspAgent): new () => NestMiddleware {
  class RaspNestMiddleware implements NestMiddleware {
    use(req: Request, res: Response, next: NextFunction): void {
      try {
        const normalized: NormalizedRequest = {
          method: req.method,
          path: req.path,
          query: req.query as Record<string, unknown>,
          headers: req.headers as Record<string, string | string[] | undefined>,
          body: req.body,
          sourceIp: extractSourceIp(req),
        };

        const ctx = agent.beginRequest(normalized);

        const detection = agent.inspect(normalized);

        if (detection && agent.mode === "block") {
          res.status(403).json({
            error: "Request blocked by RASP",
            eventType: detection.eventType,
          });
          return;
        }

        const start = Date.now();
        res.on("finish", () => {
          const r = req as Request & { user?: unknown; auth?: unknown };
          agent.endRequest(ctx, normalized, {
            statusCode: res.statusCode,
            durationMs: Date.now() - start,
            authenticated: r.user != null || r.auth != null,
          });
        });
      } catch {
        // Fail-open - see file-level note.
      }
      next();
    }
  }

  return RaspNestMiddleware;
}

/**
 * Best-effort source IP resolution; see the Express integration for the
 * trust caveat.
 */
function extractSourceIp(req: Request): string | undefined {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") return forwarded.split(",")[0]?.trim();
  if (Array.isArray(forwarded)) return forwarded[0]?.split(",")[0]?.trim();
  return (req.socket as { remoteAddress?: string } | undefined)?.remoteAddress;
}
