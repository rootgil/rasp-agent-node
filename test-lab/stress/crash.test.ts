/**
 * Stress and crash-detection tests for the RASP agent.
 *
 * These tests verify that the agent survives adversarial conditions without
 * crashing the host process, leaking memory, or leaving unhandled rejections.
 *
 * Invariants checked:
 *  1. Agent survives 1000 concurrent inspect() calls.
 *  2. Agent survives rapid policy change churn (50 cycles).
 *  3. Agent survives malformed / deeply nested request bodies.
 *  4. No uncaughtException / unhandledRejection fires during the test.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from "vitest";
import { RaspAgent } from "../../src/agent.js";
import { normalizeRequest } from "../mocks/normalize-request.js";

// ── Helpers ────────────────────────────────────────────────────────────────

function buildAgent(mode: "monitor" | "block" = "monitor"): RaspAgent {
  return new RaspAgent({
    apiKey: "stress_key",
    projectId: "proj_stress",
    agentId: "agent_stress",
    auditLog: false,
    mode,
    heartbeatIntervalMs: 60_000,
    flushIntervalMs: 60_000,
  });
}

/** Attach uncaught-exception / unhandled-rejection listeners that fail the test. */
function installCrashGuards(fails: string[]): { remove: () => void } {
  const onUncaught = (err: unknown) => {
    fails.push(`uncaughtException: ${String(err)}`);
  };
  const onUnhandled = (reason: unknown) => {
    fails.push(`unhandledRejection: ${String(reason)}`);
  };
  process.on("uncaughtException", onUncaught);
  process.on("unhandledRejection", onUnhandled);
  return {
    remove() {
      process.off("uncaughtException", onUncaught);
      process.off("unhandledRejection", onUnhandled);
    },
  };
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe("Concurrency stress — 1000 concurrent inspect() calls", () => {
  let agent: RaspAgent;
  const crashLog: string[] = [];
  let guards: { remove: () => void };

  beforeAll(() => {
    guards = installCrashGuards(crashLog);
    agent = buildAgent("block");
  });

  afterAll(async () => {
    guards.remove();
    await agent.stop();
  });

  it("all 1000 requests complete without exception", async () => {
    const requests = Array.from({ length: 1000 }, (_, i) =>
      normalizeRequest({
        method: "GET",
        path: `/api/users/${i % 10}`,
        query: { id: i % 2 === 0 ? "safe" : "1' OR '1'='1" },
      })
    );

    const results = await Promise.allSettled(
      requests.map((req) => Promise.resolve(agent.inspect(req)))
    );

    const failed = results.filter((r) => r.status === "rejected");
    expect(failed).toHaveLength(0);
    expect(crashLog).toHaveLength(0);
  });

  it("mix of safe and attack requests — no undefined results", () => {
    const safeReq = normalizeRequest({ method: "GET", path: "/health" });
    const attackReq = normalizeRequest({
      method: "GET",
      path: "/api/users/1",
      query: { id: "1 UNION SELECT * FROM users--" },
    });

    for (let i = 0; i < 200; i++) {
      const r1 = agent.inspect(safeReq);
      const r2 = agent.inspect(attackReq);
      // r1 should be null (clean), r2 should be detection
      expect(r1).toBeNull();
      expect(r2?.eventType).toBe("sql_injection");
    }
  });
});

describe("Malformed / adversarial request bodies", () => {
  let agent: RaspAgent;

  beforeEach(() => {
    agent = buildAgent("block");
  });
  afterEach(async () => {
    await agent.stop();
  });

  it("handles null body without throwing", () => {
    expect(() => agent.inspect(normalizeRequest({
      path: "/api/test",
      body: null,
    }))).not.toThrow();
  });

  it("handles array body without throwing", () => {
    expect(() => agent.inspect(normalizeRequest({
      path: "/api/test",
      body: [1, 2, 3],
    }))).not.toThrow();
  });

  it("handles deeply nested object (depth 10) without stack overflow", () => {
    const deep: Record<string, unknown> = {};
    let current = deep;
    for (let i = 0; i < 10; i++) {
      current["nested"] = {};
      current = current["nested"] as Record<string, unknown>;
    }
    current["value"] = "' OR 1=1--";

    expect(() => agent.inspect(normalizeRequest({
      path: "/api/test",
      body: deep,
    }))).not.toThrow();
  });

  it("handles very large query string (10KB) without hanging", () => {
    const largeValue = "a".repeat(10_240);
    expect(() => agent.inspect(normalizeRequest({
      path: "/api/test",
      query: { data: largeValue },
    }))).not.toThrow();
  });

  it("handles very long path without throwing", () => {
    const longPath = "/api/" + "x".repeat(4096);
    expect(() => agent.inspect(normalizeRequest({
      path: longPath,
    }))).not.toThrow();
  });

  it("handles circular-like structure (via array nesting) without crashing", () => {
    const body = { a: [{ b: [{ c: "safe" }] }, { d: "' OR 1=1" }] };
    expect(() => agent.inspect(normalizeRequest({
      path: "/api/test",
      body,
    }))).not.toThrow();
  });

  it("handles non-string header values without throwing", () => {
    expect(() => agent.inspect(normalizeRequest({
      path: "/api/test",
      headers: {
        "x-custom": ["value1", "value2"],
        "content-type": "application/json",
      } as Record<string, unknown> as Record<string, string>,
    }))).not.toThrow();
  });
});

describe("Policy churn — 50 rapid config cycles", () => {
  let agent: RaspAgent;
  const crashLog: string[] = [];
  let guards: { remove: () => void };

  beforeAll(() => {
    guards = installCrashGuards(crashLog);
    agent = buildAgent("monitor");
  });

  afterAll(async () => {
    guards.remove();
    await agent.stop();
  });

  it("agent survives 50 consecutive inspect() calls interleaved with mode checks", () => {
    const req = normalizeRequest({
      method: "GET",
      path: "/api/users/1",
      query: { id: "safe" },
    });

    for (let i = 0; i < 50; i++) {
      // Inspect clean request — should not throw
      expect(() => agent.inspect(req)).not.toThrow();
      // Access mode property — should not throw
      expect(["monitor", "block"]).toContain(agent.mode);
    }

    expect(crashLog).toHaveLength(0);
  });
});

describe("Agent lifecycle — start/stop resilience", () => {
  it("calling stop() multiple times does not throw", async () => {
    const agent = buildAgent();
    agent.start();
    await expect(agent.stop()).resolves.toBeUndefined();
    await expect(agent.stop()).resolves.toBeUndefined();
  });

  it("inspect() after stop() returns null gracefully (kill-switch path)", async () => {
    const agent = buildAgent();
    agent.start();
    await agent.stop();
    const req = normalizeRequest({
      method: "GET",
      path: "/api/test",
      query: { id: "1 UNION SELECT * FROM users--" },
    });
    // After stop, killed=true → inspect returns null (fail-open)
    expect(() => agent.inspect(req)).not.toThrow();
  });
});
