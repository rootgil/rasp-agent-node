import type { NestMiddleware } from "@nestjs/common";
import type { Request, Response, NextFunction } from "express";
import type { RaspAgent } from "../agent.js";
import type { NormalizedRequest } from "../types.js";

/**
 * NestJS middleware class factory.
 * Inject or instantiate RaspAgent and pass it to the factory.
 *
 * Usage in AppModule:
 *
 *   export class AppModule implements NestModule {
 *     configure(consumer: MiddlewareConsumer) {
 *       consumer.apply(createNestMiddleware(agent)).forRoutes('*');
 *     }
 *   }
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

        const detection = agent.inspect(normalized);

        if (detection && agent["cfg"].mode === "block") {
          res.status(403).json({
            error: "Request blocked by RASP",
            eventType: detection.eventType,
          });
          return;
        }
      } catch {
        // Fail open.
      }
      next();
    }
  }

  return RaspNestMiddleware;
}

function extractSourceIp(req: Request): string | undefined {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") return forwarded.split(",")[0]?.trim();
  if (Array.isArray(forwarded)) return forwarded[0]?.split(",")[0]?.trim();
  return (req.socket as { remoteAddress?: string } | undefined)?.remoteAddress;
}
