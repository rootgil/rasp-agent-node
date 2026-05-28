import { z } from "zod";
import type { RaspConfig } from "./types.js";

const RaspConfigSchema = z.object({
  collectorUrl: z.string().url("collectorUrl must be a valid URL"),
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
});

export type ValidatedRaspConfig = z.infer<typeof RaspConfigSchema>;

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
