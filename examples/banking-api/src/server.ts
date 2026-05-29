/**
 * Banking API - RASP example server.
 *
 * DEV ONLY. This app exists solely to exercise the RASP agent against
 * realistic-looking attack payloads. It must never be deployed to a
 * production environment.
 *
 * Safety guarantees:
 *  - Refuses to start when NODE_ENV=production.
 *  - Listens only on 127.0.0.1 (no external exposure).
 *  - Routes accept malformed input but never execute dangerous operations.
 *  - All data is in-memory / hardcoded - no real DB, no real filesystem.
 */
import "dotenv/config";
import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";

// ── Dev-only guard ────────────────────────────────────────────────────────────
if (process.env["NODE_ENV"] === "production") {
  console.error(
    "FATAL: banking-api-example must not run in production. Exiting."
  );
  process.exit(1);
}

// ── RASP agent ────────────────────────────────────────────────────────────────
// Import directly from the agent source so no build step is needed.
import { RaspAgent, createExpressMiddleware } from "../../../src/index.js";

const agent = new RaspAgent({
  apiKey:       process.env["RASP_API_KEY"]    ?? "rasp_demo_key_abc123",
  projectId:    process.env["RASP_PROJECT_ID"] ?? "proj_banking_local",
  agentId:      process.env["RASP_AGENT_ID"]   ?? "agent_banking_local",
  framework:    "express",
  agentVersion: "0.1.0",
  auditLogPath: "./rasp-audit.log",
  // policyPublicKey: process.env["RASP_POLICY_PUBLIC_KEY"] ?? undefined,
  // Enforcement mode + release channel (Addendum D). Driven by env so the same
  // build can be flipped between monitor/block and stable/early/edge.
  mode:         (process.env["RASP_MODE"] as "monitor" | "block") ?? "monitor",
  channel:      (process.env["RASP_CHANNEL"] as "stable" | "early" | "edge") ?? "stable",
  // Payload integrity (Addendum E.5): when set, every batch is HMAC-signed.
  // Must match the agent's hmacSecret in the dashboard (or the collector's
  // global HMAC_SECRET fallback).
  hmacSecret:   process.env["RASP_HMAC_SECRET"] || undefined,
  // Runtime self-protection (Addendum E.7): anti-debug + hook-integrity checks.
  selfProtect:  process.env["RASP_SELF_PROTECT"] === "true",
});

agent.start();

// ── Express app ───────────────────────────────────────────────────────────────
import authRouter         from "./routes/auth.js";
import usersRouter        from "./routes/users.js";
import accountsRouter     from "./routes/accounts.js";
import transactionsRouter from "./routes/transactions.js";
import documentsRouter    from "./routes/documents.js";
import adminRouter        from "./routes/admin.js";

const app = express();

// Security banner on every response
app.use((_req, res, next) => {
  res.setHeader("X-RASP-Example", "dev-only-do-not-deploy");
  next();
});

app.use(express.json({ limit: "64kb" }));
app.use(express.urlencoded({ extended: false, limit: "64kb" }));

// RASP middleware - must come after body parsers
app.use(createExpressMiddleware(agent));

// Routes
app.use("/api/auth",         authRouter);
app.use("/api/users",        usersRouter);
app.use("/api/accounts",     accountsRouter);
app.use("/api/transactions", transactionsRouter);
app.use("/api/documents",    documentsRouter);
app.use("/api/admin",        adminRouter);

// Serve the frontend
const __dirname = path.dirname(fileURLToPath(import.meta.url));
app.use(express.static(path.join(__dirname, "public")));

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    service: "banking-api-example",
    mode: agent.mode,
    bootMode: agent.cfg.mode,
    channel: agent.cfg.channel,
    hmac: Boolean(agent.cfg.hmacSecret),
    selfProtect: agent.cfg.selfProtect,
    policyVersion: agent.policyVersion,
  });
});

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = Number(process.env["PORT"]) || 3000;
const HOST = "127.0.0.1";

const server = app.listen(PORT, HOST, () => {
  console.log("");
  console.log("  ⚠  RASP EXAMPLE APP - DEV ONLY. DO NOT DEPLOY.");
  console.log(`     Listening on http://${HOST}:${PORT}`);
  console.log(`     RASP boot mode: ${agent.cfg.mode} (effective mode syncs via heartbeat/policy)`);
  console.log(`     Channel     : ${agent.cfg.channel}`);
  console.log(`     HMAC signing: ${agent.cfg.hmacSecret ? "on" : "off"}`);
  console.log(`     Self-protect: ${agent.cfg.selfProtect ? "on" : "off"}`);
  console.log(`     Policy ver. : ${agent.policyVersion}`);
  console.log(`     Collector   : ${process.env["RASP_COLLECTOR_URL"] ?? "https://collector.rasp.dev"}`);
  console.log(`     Audit log   : ${agent.cfg.auditLogPath}`);
  console.log("");
  console.log(`     Open http://${HOST}:${PORT} in your browser to start testing.`);
  console.log("");
});

// ── Graceful shutdown ─────────────────────────────────────────────────────────
async function shutdown(signal: string) {
  console.log(`\n[${signal}] Shutting down...`);
  server.close();
  await agent.stop();
  process.exit(0);
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT",  () => shutdown("SIGINT"));
