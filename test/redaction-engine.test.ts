/**
 * Integration tests for RedactionEngine + fingerprintMatch (post-remediation).
 *
 * matchedValue raw strings must never leave the process. handleDetection now
 * emits matchedValueFingerprint / matchedValueKind only; if a buggy path still
 * sets matchedValue, the key denylist replaces it with [REDACTED].
 */
import { describe, it, expect } from "vitest";
import { RedactionEngine } from "../src/redaction/engine.js";
import { fingerprintMatch, redactValueString } from "../src/redaction/patterns.js";

function makePayload(overrides: Record<string, unknown> = {}) {
  return {
    projectId: "proj_test",
    agentId: "agent_test",
    agentVersion: "0.1.0",
    runtime: "node",
    framework: "express",
    eventType: "xss",
    severity: "high",
    action: "monitor",
    method: "GET",
    path: "/api/transactions",
    sourceIp: "127.0.0.1",
    timestamp: "2026-01-01T00:00:00.000Z",
    metadata: {
      redacted: true,
      matchedRule: "xss",
      detectorDescription: "Cross-site scripting attempt detected",
      location: "query.search",
      ...fingerprintMatch("<script>alert('alice@acme.io')</script>"),
    },
    ...overrides,
  };
}

const engine = new RedactionEngine();

describe("fingerprintMatch telemetry (preferred path)", () => {
  const payload = makePayload();
  const { redacted } = engine.redact(payload);
  const meta = (redacted as typeof payload).metadata;

  it("keeps fingerprint and kind, never raw match", () => {
    expect(meta.matchedValueFingerprint).toMatch(/^[0-9a-f]{16}$/);
    expect(meta.matchedValueKind).toBe("other");
    expect("matchedValue" in meta).toBe(false);
  });

  it("never leaks the raw email address", () => {
    expect(JSON.stringify(redacted)).not.toContain("alice@acme.io");
  });

  it("hashes the source IP", () => {
    expect(JSON.stringify(redacted)).not.toContain("127.0.0.1");
  });
});

describe("defense-in-depth: raw matchedValue key is fully redacted", () => {
  const payload = makePayload({
    metadata: {
      redacted: true,
      matchedRule: "xss",
      matchedValue: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig",
    },
  });
  const { redacted, redactedFields } = engine.redact(payload);
  const meta = (redacted as typeof payload).metadata;

  it("replaces matchedValue wholesale", () => {
    expect(meta.matchedValue).toBe("[REDACTED]");
    expect(redactedFields).toContain("metadata.matchedValue");
  });

  it("never leaks Bearer token", () => {
    expect(JSON.stringify(redacted)).not.toContain("eyJhbGci");
    expect(JSON.stringify(redacted)).not.toContain("Bearer eyJ");
  });
});

describe("Bearer / JWT / API key value scrubbing", () => {
  it("scrubs Bearer tokens", () => {
    const { value, redacted } = redactValueString(
      "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def"
    );
    expect(redacted).toBe(true);
    expect(value).toContain("Bearer [REDACTED]");
    expect(value).not.toContain("eyJhbGci");
  });

  it("scrubs sk_live API keys", () => {
    const { value, redacted } = redactValueString("key=sk_live_abc123xyz789abcdef");
    expect(redacted).toBe(true);
    expect(value).toContain("[API_KEY REDACTED]");
    expect(value).not.toContain("sk_live_");
  });
});

describe("policy cannot disable value redaction", () => {
  const locked = RedactionEngine.fromConfig({
    mode: "denylist",
    valueRedaction: false,
  } as never);
  const { redacted } = locked.redact({
    email: "alice@example.com",
  });
  it("still masks emails when policy asks for valueRedaction:false", () => {
    expect(JSON.stringify(redacted)).toMatch(/\[EMAIL:/);
    expect(JSON.stringify(redacted)).not.toContain("alice@example.com");
  });
});

describe("password key denylist", () => {
  const { redacted, redactedFields } = engine.redact({
    projectId: "p",
    metadata: { redacted: true, password: "supersecret" },
  });
  it("redacts password keys", () => {
    expect((redacted as { metadata: { password: string } }).metadata.password).toBe(
      "[REDACTED]"
    );
    expect(redactedFields).toContain("metadata.password");
  });
});
