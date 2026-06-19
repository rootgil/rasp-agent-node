/**
 * Compatibility test: RASP agent + Datadog dd-trace.
 *
 * Verifies that:
 *  1. dd-trace and the RASP agent can both initialise in the same process.
 *  2. DB hooks installed by the RASP agent are not overwritten by dd-trace.
 *  3. The RASP agent still detects attacks after dd-trace is active.
 *
 * dd-trace is a devDependency only - this test is skipped when the package
 * is not installed (nightly CI installs it; regular CI does not).
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  instrumentDatabaseDrivers,
  verifyHookIntegrity,
  __resetInstrumentationForTests,
} from "../../src/db-hooks/instrument.js";
import { RaspAgent } from "../../src/agent.js";
import { normalizeRequest } from "../mocks/normalize-request.js";

let ddTrace: typeof import("dd-trace") | null = null;

try {
  // Dynamic import so the test file loads even without dd-trace installed.
  ddTrace = (await import("dd-trace")).default;
} catch {
  ddTrace = null;
}

const itIfDdTrace = ddTrace ? it : it.skip;

describe("RASP agent + Datadog dd-trace coexistence", () => {
  let agent: RaspAgent;

  beforeAll(() => {
    __resetInstrumentationForTests();

    if (ddTrace) {
      // Initialise dd-trace in test mode (no actual Datadog agent needed)
      ddTrace.init({
        startupLogs: false,
        logInjection: false,
        runtimeMetrics: false,
        profiling: false,
      } as Parameters<typeof ddTrace.init>[0]);
    }

    // Install RASP DB hooks AFTER dd-trace init (worst case for conflicts)
    instrumentDatabaseDrivers();

    agent = new RaspAgent({
      apiKey: "test_key",
      projectId: "proj_test",
      agentId: "agent_compat_dd",
      auditLog: false,
      mode: "block",
      instrumentDb: true,
    });
    agent.start();
  });

  afterAll(async () => {
    await agent.stop();
    __resetInstrumentationForTests();
  });

  itIfDdTrace("dd-trace and RASP agent both start without error", () => {
    expect(ddTrace).not.toBeNull();
    expect(agent).toBeDefined();
  });

  itIfDdTrace("DB hook integrity remains intact after dd-trace initialisation", () => {
    const tampered = verifyHookIntegrity();
    expect(tampered).toEqual([]);
  });

  itIfDdTrace("RASP agent still detects SQLi after dd-trace is active", () => {
    const req = normalizeRequest({
      method: "GET",
      path: "/api/users/1",
      query: { id: "1' OR '1'='1" },
    });
    const result = agent.inspect(req);
    expect(result).not.toBeNull();
    expect(result?.eventType).toBe("sql_injection");
  });

  itIfDdTrace("clean requests still pass after dd-trace is active", () => {
    const req = normalizeRequest({
      method: "GET",
      path: "/api/health",
    });
    expect(agent.inspect(req)).toBeNull();
  });

  it.skip("dd-trace not installed - skipping compatibility tests (install dd-trace as devDep to enable)", () => {
    // Intentionally empty - marker for CI logs
  });
});
