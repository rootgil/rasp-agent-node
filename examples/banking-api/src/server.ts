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
import { RaspAgent } from "@queno/agent-node";
import { createBankingApp } from "./app.js";
import { printBanner } from "./logger.js";

// ── Dev-only guard ────────────────────────────────────────────────────────────
if (process.env["NODE_ENV"] === "production") {
  console.error(
    "FATAL: banking-api-example must not run in production. Exiting."
  );
  process.exit(1);
}

// ── RASP agent ────────────────────────────────────────────────────────────────
// Set RASP_ENABLED=false to start without the agent (used for perf baseline).
const raspEnabled = process.env["RASP_ENABLED"] !== "false";

const agent = raspEnabled
  ? new RaspAgent({
      apiKey:       process.env["RASP_API_KEY"]    ?? "rasp_demo_key_abc123",
      projectId:    process.env["RASP_PROJECT_ID"] ?? "proj_banking_local",
      agentId:      process.env["RASP_AGENT_ID"]   ?? "agent_banking_local",
      framework:    "express",
      agentVersion: "0.1.0",
      auditLogPath: "./rasp-audit.log",
      mode:         (process.env["RASP_MODE"] as "monitor" | "block") ?? "monitor",
      channel:      (process.env["RASP_CHANNEL"] as "stable" | "early" | "edge") ?? "stable",
      hmacSecret:   process.env["RASP_HMAC_SECRET"] || undefined,
      selfProtect:  process.env["RASP_SELF_PROTECT"] === "true",
    })
  : undefined;

if (agent) agent.start();

const app = createBankingApp(agent);

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = Number(process.env["PORT"]) || 3000;
const HOST = "127.0.0.1";

const server = app.listen(PORT, HOST, () => {
  if (agent) {
    printBanner(PORT, HOST, agent.cfg.mode);
    console.log(`  RASP boot mode: ${agent.cfg.mode} (effective mode syncs via heartbeat/policy)`);
    console.log(`  Channel        : ${agent.cfg.channel}`);
    console.log(`  HMAC signing   : ${agent.cfg.hmacSecret ? "on" : "off"}`);
    console.log(`  Self-protect   : ${agent.cfg.selfProtect ? "on" : "off"}`);
    console.log(`  Policy ver.    : ${agent.policyVersion ?? "none"}`);
    console.log(`  Collector      : ${process.env["RASP_COLLECTOR_URL"] ?? "https://collector.rasp.dev"}`);
    console.log(`  Audit log      : ${agent.cfg.auditLogPath}`);
  } else {
    printBanner(PORT, HOST, "disabled");
    console.log("  RASP agent  : DISABLED (baseline mode - no instrumentation)");
  }
});

// ── Graceful shutdown ─────────────────────────────────────────────────────────
async function shutdown(signal: string) {
  console.log(`\n[${signal}] Shutting down...`);
  server.close();
  if (agent) await agent.stop();
  process.exit(0);
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT",  () => shutdown("SIGINT"));
