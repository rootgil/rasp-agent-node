import { describe, it, expect } from "vitest";
import { CustomRuleDetector } from "../src/detectors/custom-rule.js";
import type { NormalizedRequest } from "../src/types.js";

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
    expect(det.detect(req({ headers: { "x-test": "secret" } }))).not.toBeNull();
  });
});
