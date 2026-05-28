import type { Request, Response, NextFunction } from "express";
import type { RaspAgent } from "../agent.js";
import type { NormalizedRequest } from "../types.js";

/**
 * Returns an Express middleware that inspects every incoming request.
 * In "block" mode, detected threats receive a 403 response.
 * In "monitor" mode (default), the request passes through regardless.
 */
export function createExpressMiddleware(agent: RaspAgent) {
  return function raspMiddleware(req: Request, res: Response, next: NextFunction): void {
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
      // Fail open — never crash the host application.
    }

    next();
  };
}

function extractSourceIp(req: Request): string | undefined {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") return forwarded.split(",")[0]?.trim();
  if (Array.isArray(forwarded)) return forwarded[0]?.split(",")[0]?.trim();
  return req.socket?.remoteAddress;
}
