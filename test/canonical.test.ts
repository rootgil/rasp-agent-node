import { describe, it, expect } from "vitest";
import { stableStringify, canonicalPolicyBytes, type SignablePolicy } from "../src/policy/canonical.js";

describe("stableStringify", () => {
  it("sorts object keys recursively", () => {
    const a = stableStringify({ b: 1, a: { d: 2, c: 3 } });
    const b = stableStringify({ a: { c: 3, d: 2 }, b: 1 });
    expect(a).toBe(b);
    expect(a).toBe('{"a":{"c":3,"d":2},"b":1}');
  });

  it("treats null and undefined as null", () => {
    expect(stableStringify(null)).toBe("null");
    expect(stableStringify(undefined)).toBe("null");
  });

  it("preserves array order", () => {
    expect(stableStringify([3, 1, 2])).toBe("[3,1,2]");
  });
});

describe("canonicalPolicyBytes", () => {
  const base: SignablePolicy = {
    projectId: "p1",
    version: 2,
    channel: "stable",
    mode: "block",
    detectionRules: [{ id: "r1", pattern: "x" }],
    redactionConfig: null,
    dataResidency: null,
    targetAgentVersion: null,
  };

  it("is deterministic regardless of input key order", () => {
    const reordered: SignablePolicy = {
      targetAgentVersion: null,
      dataResidency: null,
      version: 2,
      mode: "block",
      channel: "stable",
      redactionConfig: null,
      detectionRules: [{ id: "r1", pattern: "x" }],
      projectId: "p1",
    };
    expect(canonicalPolicyBytes(base).toString("utf8")).toBe(
      canonicalPolicyBytes(reordered).toString("utf8")
    );
  });

  it("changes when a signed field changes", () => {
    const bumped = { ...base, version: 3 };
    expect(canonicalPolicyBytes(base).toString("utf8")).not.toBe(
      canonicalPolicyBytes(bumped).toString("utf8")
    );
  });
});
