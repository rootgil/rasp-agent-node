/**
 * Builds a minimal RaspAgent suitable for test-lab usage.
 *
 * Defaults chosen to keep tests deterministic:
 *  - auditLog disabled (no temp files)
 *  - very short heartbeat / flush intervals so async events settle quickly
 *  - selfProtect off
 *  - no instrumentDb (DB tests enable it explicitly)
 *
 * The caller is responsible for calling agent.stop() in afterAll/afterEach.
 */
import { RaspAgent } from "../../src/agent.js";
import type { RaspConfig } from "../../src/types.js";

export interface TestAgentOptions {
  collectorUrl: string;
  mode?: RaspConfig["mode"];
  instrumentDb?: boolean;
  extra?: Partial<RaspConfig>;
}

export function buildTestAgent(opts: TestAgentOptions): RaspAgent {
  return new RaspAgent({
    apiKey: "test_key_lab",
    projectId: "proj_test",
    agentId: "agent_test",
    agentVersion: "0.0.0-test",
    auditLog: false,
    selfProtect: false,
    mode: opts.mode ?? "monitor",
    instrumentDb: opts.instrumentDb ?? false,
    heartbeatIntervalMs: 60_000,
    flushIntervalMs: 500,
    bufferMaxSize: 10,
    transportTimeoutMs: 3_000,
    ...opts.extra,
  });
}

/**
 * Flush the microtask + I/O queue so async promise handlers fire.
 * Use after operations that enqueue events asynchronously.
 */
export function flushAsync(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}
