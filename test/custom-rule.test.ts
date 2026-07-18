import { describe, it, expect } from "vitest";
import { CustomRuleDetector } from "../src/detectors/custom-rule.js";
import { pickPrimaryDetection, severityRank } from "../src/detectors/base.js";
import { RaspAgent } from "../src/agent.js";
import type { DetectionResult, NormalizedRequest } from "../src/types.js";

function req(overrides: Partial<NormalizedRequest> = {}): NormalizedRequest {
  return {
    method: "GET",
    path: "/api/users",
    query: {},
    headers: {},
    body: undefined,
    ...overrides,
  };
}

describe("severity helpers", () => {
  it("ranks critical above high above medium above low", () => {
    expect(severityRank("critical")).toBeGreaterThan(severityRank("high"));
    expect(severityRank("high")).toBeGreaterThan(severityRank("medium"));
    expect(severityRank("medium")).toBeGreaterThan(severityRank("low"));
  });

  it("pickPrimaryDetection keeps first on equal severity", () => {
    const a: DetectionResult = {
      detectorName: "first",
      eventType: "a",
      severity: "medium",
      description: "a",
    };
    const b: DetectionResult = {
      detectorName: "second",
      eventType: "b",
      severity: "medium",
      description: "b",
    };
    expect(pickPrimaryDetection([a, b])?.detectorName).toBe("first");
  });
});

describe("CustomRuleDetector", () => {
  it("skips invalid regex and disabled rules at construction", () => {
    const det = new CustomRuleDetector([
      { id: "bad", pattern: "(" },
      { id: "off", pattern: "x", enabled: false },
      { id: "ok", pattern: "evil" },
    ]);
    expect(det.size).toBe(1);
  });

  it("matches a body value against a rule", () => {
    const det = new CustomRuleDetector([
      { id: "r1", pattern: "drop\\s+table", target: "body", severity: "high" },
    ]);
    const result = det.detect(req({ body: { q: "DROP TABLE users" } }));
    expect(result).not.toBeNull();
    expect(result?.detectorName).toBe("r1");
    expect(result?.severity).toBe("high");
  });

  it("returns null when nothing matches", () => {
    const det = new CustomRuleDetector([{ id: "r1", pattern: "evil", target: "path" }]);
    expect(det.detect(req({ path: "/safe" }))).toBeNull();
  });

  it("respects the target scope", () => {
    const det = new CustomRuleDetector([{ id: "r1", pattern: "secret", target: "headers" }]);
    // Present in query, not headers → no match because target is headers.
    expect(det.detect(req({ query: { x: "secret" } }))).toBeNull();
    // Header rules match names only (never values — Authorization/Cookie stay out of scope).
    expect(det.detect(req({ headers: { "x-test": "secret" } }))).toBeNull();
    expect(det.detect(req({ headers: { "x-secret-probe": "1" } }))).not.toBeNull();
  });

  it("detectAll returns every matching rule; detect picks highest severity", () => {
    const det = new CustomRuleDetector([
      {
        id: "brute-force",
        pattern: "login",
        target: "path",
        severity: "medium",
        eventType: "brute_force",
      },
      {
        id: "nosql-injection",
        pattern: "\\$ne",
        target: "body",
        severity: "high",
        eventType: "nosql_injection",
      },
    ]);

    const attack = req({
      path: "/api/login",
      body: { filter: "user[$ne]=null" },
    });

    const all = det.detectAll(attack);
    expect(all.map((m) => m.detectorName)).toEqual(["brute-force", "nosql-injection"]);

    const primary = det.detect(attack);
    expect(primary?.detectorName).toBe("nosql-injection");
    expect(primary?.severity).toBe("high");
    expect(primary?.eventType).toBe("nosql_injection");
  });
});

describe("RaspAgent.inspect multi-match", () => {
  it("returns highest-severity rule when medium is registered first", () => {
    const agent = new RaspAgent(
      {
        apiKey: "test_key",
        projectId: "proj_test",
        agentId: "agent_test",
        auditLog: false,
        mode: "monitor",
      },
      [
        new CustomRuleDetector([
          {
            id: "brute-force",
            pattern: "attack",
            target: "any",
            severity: "medium",
            eventType: "brute_force",
          },
          {
            id: "nosql-injection",
            pattern: "attack",
            target: "any",
            severity: "high",
            eventType: "nosql_injection",
          },
        ]),
      ]
    );

    const result = agent.inspect(req({ path: "/x", query: { q: "attack" } }));
    expect(result?.detectorName).toBe("nosql-injection");
    expect(result?.severity).toBe("high");
    expect(result?.eventType).toBe("nosql_injection");
  });
});
