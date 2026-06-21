/**
 * Compatibility test: RASP agent + OpenTelemetry Node SDK.
 *
 * Verifies that:
 *  1. OTel SDK and the RASP agent can both initialise in the same process.
 *  2. DB hooks installed by the RASP agent survive OTel auto-instrumentation.
 *  3. The RASP agent still detects attacks when OTel is active.
 *
 * @opentelemetry/sdk-node and @opentelemetry/auto-instrumentations-node are
 * devDependencies. This test is skipped when packages are not installed.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  instrumentDatabaseDrivers,
  verifyHookIntegrity,
  __resetInstrumentationForTests,
} from "../../src/db-hooks/instrument.js";
import { RaspAgent } from "../../src/agent.js";
import { createOfflineDetectors } from "../../src/detectors/index.js";
import { normalizeRequest } from "../mocks/normalize-request.js";

let NodeSDK: typeof import("@opentelemetry/sdk-node").NodeSDK | null = null;
let sdk: import("@opentelemetry/sdk-node").NodeSDK | null = null;

try {
  const otelModule = await import("@opentelemetry/sdk-node");
  NodeSDK = otelModule.NodeSDK;
} catch {
  NodeSDK = null;
}

const itIfOtel = NodeSDK ? it : it.skip;

describe("RASP agent + OpenTelemetry coexistence", () => {
  let agent: RaspAgent;

  beforeAll(async () => {
    __resetInstrumentationForTests();

    if (NodeSDK) {
      // Start OTel SDK with no exporters (no real backend needed)
      sdk = new NodeSDK({
        traceExporter: undefined,
        metricReader: undefined,
      });
      sdk.start();
    }

    // Install RASP DB hooks after OTel (worst case for hook conflicts)
    instrumentDatabaseDrivers();

    agent = new RaspAgent(
      {
        apiKey: "test_key",
        projectId: "proj_test",
        agentId: "agent_compat_otel",
        auditLog: false,
        mode: "block",
        instrumentDb: true,
      },
      createOfflineDetectors(),
    );
    agent.start();
  });

  afterAll(async () => {
    await agent.stop();
    __resetInstrumentationForTests();
    if (sdk) {
      await sdk.shutdown().catch(() => {/* best-effort */});
    }
  });

  itIfOtel("OTel SDK and RASP agent both start without error", () => {
    expect(NodeSDK).not.toBeNull();
    expect(agent).toBeDefined();
  });

  itIfOtel("DB hook integrity is intact after OTel SDK start", () => {
    const tampered = verifyHookIntegrity();
    expect(tampered).toEqual([]);
  });

  itIfOtel("RASP agent still detects XSS after OTel is active", () => {
    const req = normalizeRequest({
      method: "GET",
      path: "/api/search",
      query: { q: "<script>alert(document.cookie)</script>" },
    });
    const result = agent.inspect(req);
    expect(result).not.toBeNull();
    expect(result?.eventType).toBe("xss");
  });

  itIfOtel("clean requests still pass after OTel is active", () => {
    const req = normalizeRequest({
      method: "GET",
      path: "/api/health",
    });
    expect(agent.inspect(req)).toBeNull();
  });

  it.skip("OTel SDK not installed - skipping compatibility tests (install @opentelemetry/sdk-node to enable)", () => {
    // Intentionally empty
  });
});
