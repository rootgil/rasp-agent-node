/**
 * Banking API Express application factory.
 *
 * Extracted so the app can be imported without starting a listening server,
 * enabling automated E2E tests via supertest.
 */
import express, { type Express } from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createExpressMiddleware } from "@queno/agent-node";
import type { RaspAgent } from "@queno/agent-node";

import { requestLogger } from "./logger.js";
import authRouter         from "./routes/auth.js";
import usersRouter        from "./routes/users.js";
import accountsRouter     from "./routes/accounts.js";
import transactionsRouter from "./routes/transactions.js";
import documentsRouter    from "./routes/documents.js";
import adminRouter        from "./routes/admin.js";

/**
 * Build and return the configured Express application.
 * When `agent` is provided the RASP middleware is registered on every request.
 * When omitted the app runs without any RASP instrumentation - used for the
 * performance baseline so the benchmark measures a clean reference.
 * Does NOT call app.listen() - the caller decides whether to listen or use
 * supertest directly.
 */
export function createBankingApp(agent?: RaspAgent): Express {
  const app = express();

  app.use((_req, res, next) => {
    res.setHeader("X-RASP-Example", "dev-only-do-not-deploy");
    next();
  });

  app.use(express.json({ limit: "64kb" }));
  app.use(express.urlencoded({ extended: false, limit: "64kb" }));

  app.use(requestLogger);

  if (agent) {
    app.use(createExpressMiddleware(agent));
  }

  app.use("/api/auth",         authRouter);
  app.use("/api/users",        usersRouter);
  app.use("/api/accounts",     accountsRouter);
  app.use("/api/transactions", transactionsRouter);
  app.use("/api/documents",    documentsRouter);
  app.use("/api/admin",        adminRouter);

  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  app.use(express.static(path.join(__dirname, "public")));

  app.get("/health", (_req, res) => {
    res.json({
      status: "ok",
      service: "banking-api-example",
      agentActive: agent != null,
      mode: agent?.mode ?? "disabled",
      bootMode: agent?.cfg.mode ?? "disabled",
      channel: agent?.cfg.channel ?? "n/a",
      hmac: Boolean(agent?.cfg.hmacSecret),
      selfProtect: agent?.cfg.selfProtect ?? false,
      policyVersion: agent?.policyVersion ?? null,
    });
  });

  return app;
}
