/**
 * Express integration.
 *
 * Exposes {@link createExpressMiddleware}, a factory that returns a standard
 * `(req, res, next)` middleware bound to a {@link RaspAgent} instance.
 *
 * Behaviour:
 *  - Every request is normalised into a {@link NormalizedRequest} and run
 *    through `agent.inspect`.
 *  - In `monitor` mode the request always passes through, even on detection.
 *  - In `block` mode a detected request is short-circuited with `403`
 *    `{ error: "Request blocked by RASP", eventType }`.
 *  - Any thrown error inside the middleware is swallowed so the agent never
 *    takes down the host application (fail-open).
 *
 * @example
 * ```ts
 * import express from "express";
 * import { RaspAgent, createExpressMiddleware } from "@rasp/agent-node";
 *
 * const agent = new RaspAgent({ apiKey, projectId, agentId, mode: "monitor" });
 * agent.start();
 *
 * const app = express();
 * app.use(express.json());
 * app.use(createExpressMiddleware(agent));
 * ```
 */
import type { Request, Response, NextFunction } from "express";
import type { RaspAgent } from "../agent.js";
import type { NormalizedRequest } from "../types.js";

/**
 * Build an Express middleware bound to a {@link RaspAgent}.
 *
 * The middleware must be registered **after** body parsing
 * (`express.json()`, `express.urlencoded()`) so `req.body` is populated
 * when detectors run.
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
      // Fail-open — see file-level note.
    }

    next();
  };
}

/**
 * Best-effort source IP resolution:
 *  1. First entry of `X-Forwarded-For`, when present (string or array).
 *  2. Fallback to `req.socket.remoteAddress`.
 *
 * No trust validation is performed — operators relying on `X-Forwarded-For`
 * must terminate it at a known proxy.
 */
function extractSourceIp(req: Request): string | undefined {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") return forwarded.split(",")[0]?.trim();
  if (Array.isArray(forwarded)) return forwarded[0]?.split(",")[0]?.trim();
  return req.socket?.remoteAddress;
}
