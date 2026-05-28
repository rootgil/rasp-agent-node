/**
 * Runtime configuration validation for the RASP agent.
 *
 * Wraps user-supplied {@link RaspConfig} in a Zod schema that:
 *  - enforces required fields (`apiKey`, `projectId`, `agentId`),
 *  - applies safe defaults for everything else,
 *  - rejects degenerate values (e.g. 0 ms intervals).
 *
 * {@link validateConfig} is the only sanctioned way to produce a
 * {@link ValidatedRaspConfig} — every other module relies on the post-parse
 * defaults being present.
 */
import { z } from "zod";
import type { RaspConfig } from "./types.js";

/**
 * Collector base URL.
 *
 * Per `AGENTS.md` "Security Rules", the agent must not perform arbitrary
 * outbound network calls — only this endpoint is allowed.
 *
 * `RASP_COLLECTOR_URL` is intentionally only read here so that example apps
 * and local test environments can point the agent at a local collector without
 * modifying source code. In production the env var is not set and the
 * hard-coded default is used.
 */
export const COLLECTOR_URL =
  process.env.RASP_COLLECTOR_URL ?? "https://collector.rasp.dev";

/**
 * Zod schema mirroring {@link RaspConfig}.
 *
 * Each default here matches the documented behaviour in `types.ts` and the
 * lower bounds protect against pathological values (e.g. a 100 ms heartbeat
 * that would DOS the collector).
 */
const RaspConfigSchema = z.object({
  apiKey: z.string().min(1, "apiKey is required"),
  projectId: z.string().min(1, "projectId is required"),
  agentId: z.string().min(1, "agentId is required"),
  agentVersion: z.string().optional(),
  mode: z.enum(["monitor", "block"]).default("monitor"),
  heartbeatIntervalMs: z.number().int().min(5_000).default(30_000),
  flushIntervalMs: z.number().int().min(1_000).default(5_000),
  bufferMaxSize: z.number().int().min(1).default(50),
  transportTimeoutMs: z.number().int().min(500).default(5_000),
  auditLog: z.boolean().default(true),
  auditLogPath: z.string().default("./rasp-audit.log"),
  auditLogMaxBytes: z.number().int().min(1).default(10 * 1024 * 1024),
  framework: z.string().optional(),
  runtime: z.string().default("node"),
  discoveryFlushIntervalMs: z.number().int().min(5_000).default(60_000),
});

/**
 * Fully resolved configuration with all defaults applied.
 *
 * Internal modules (`agent.ts`, `transport/*`, `redaction/*`) accept this
 * stricter type rather than the user-facing optional-heavy {@link RaspConfig}.
 */
export type ValidatedRaspConfig = z.infer<typeof RaspConfigSchema>;

/**
 * Validate a raw user config and return a fully resolved one.
 *
 * @param raw - The configuration object passed to `new RaspAgent(...)`.
 * @returns The same configuration with all defaults applied.
 * @throws {Error} If validation fails. The error message has the form
 *   `[rasp-agent] Invalid configuration — field1: msg1; field2: msg2`.
 */
export function validateConfig(raw: RaspConfig): ValidatedRaspConfig {
  const result = RaspConfigSchema.safeParse(raw);
  if (!result.success) {
    const fields = result.error.flatten().fieldErrors;
    const msg = Object.entries(fields)
      .map(([k, v]) => `${k}: ${v?.join(", ")}`)
      .join("; ");
    throw new Error(`[rasp-agent] Invalid configuration — ${msg}`);
  }
  return result.data;
}
