/**
 * Integration tests for RedactionEngine.redact() with realistic handleDetection
 * payloads - mirrors the "Data privacy" button cases in the banking-api example UI.
 *
 * These tests verify that PII embedded inside an attack payload's matchedValue
 * is masked before the event would leave the process, and that the raw sensitive
 * value never appears in the redacted output.
 */
import { describe, it, expect } from "vitest";
import { RedactionEngine } from "../src/redaction/engine.js";

/** Minimal event payload mirroring what handleDetection assembles (agent.ts L337-357). */
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
      matchedValue: "",
    },
    ...overrides,
  };
}

const engine = new RedactionEngine();

// ---------------------------------------------------------------------------
// Case 1 - Email inside an XSS payload (mirrors banking-api "Data privacy" btn 1)
// ---------------------------------------------------------------------------
describe("email in XSS matchedValue", () => {
  const payload = makePayload({
    metadata: {
      redacted: true,
      matchedRule: "xss",
      matchedValue: "<script>alert('alice@acme.io')</script>",
    },
  });

  const { redacted, redactedFields } = engine.redact(payload);
  const meta = (redacted as typeof payload).metadata;

  it("masks the email as [EMAIL:<hash>]", () => {
    expect(meta.matchedValue).toMatch(/\[EMAIL:[0-9a-f]{16}\]/);
  });

  it("never leaks the raw email address", () => {
    expect(JSON.stringify(redacted)).not.toContain("alice@acme.io");
  });

  it("reports metadata.matchedValue in redactedFields", () => {
    expect(redactedFields).toContain("metadata.matchedValue");
  });

  it("hashes the source IP", () => {
    expect(JSON.stringify(redacted)).not.toContain("127.0.0.1");
    expect(redactedFields).toContain("sourceIp");
  });
});

// ---------------------------------------------------------------------------
// Case 2 - Luhn-valid credit card inside a SQLi payload (btn 2)
// ---------------------------------------------------------------------------
describe("credit card in SQLi matchedValue", () => {
  const payload = makePayload({
    eventType: "sql_injection",
    metadata: {
      redacted: true,
      matchedRule: "sql-injection",
      matchedValue: "1' UNION SELECT 4111111111111111--",
    },
  });

  const { redacted, redactedFields } = engine.redact(payload);
  const meta = (redacted as typeof payload).metadata;

  it("masks the card keeping last 4 digits", () => {
    expect(meta.matchedValue).toContain("****-****-****-1111");
  });

  it("never leaks the raw card number", () => {
    expect(JSON.stringify(redacted)).not.toContain("4111111111111111");
  });

  it("reports metadata.matchedValue in redactedFields", () => {
    expect(redactedFields).toContain("metadata.matchedValue");
  });
});

// ---------------------------------------------------------------------------
// Case 3 - Canadian SIN inside a SQLi payload
// ---------------------------------------------------------------------------
describe("SIN in SQLi matchedValue", () => {
  const payload = makePayload({
    eventType: "sql_injection",
    metadata: {
      redacted: true,
      matchedRule: "sql-injection",
      matchedValue: "1' OR '046-454-286'='046-454-286",
    },
  });

  const { redacted, redactedFields } = engine.redact(payload);
  const meta = (redacted as typeof payload).metadata;

  it("masks the SIN as [SIN REDACTED]", () => {
    expect(meta.matchedValue).toContain("[SIN REDACTED]");
  });

  it("never leaks the raw SIN digits", () => {
    expect(JSON.stringify(redacted)).not.toContain("046-454-286");
  });

  it("reports metadata.matchedValue in redactedFields", () => {
    expect(redactedFields).toContain("metadata.matchedValue");
  });
});

// ---------------------------------------------------------------------------
// Case 4 - RAMQ health ID inside a SQLi payload
// ---------------------------------------------------------------------------
describe("RAMQ health ID in SQLi matchedValue", () => {
  const payload = makePayload({
    eventType: "sql_injection",
    metadata: {
      redacted: true,
      matchedRule: "sql-injection",
      matchedValue: "1' UNION SELECT MULL56072112--",
    },
  });

  const { redacted, redactedFields } = engine.redact(payload);
  const meta = (redacted as typeof payload).metadata;

  it("masks the RAMQ ID as [HEALTH_ID REDACTED]", () => {
    expect(meta.matchedValue).toContain("[HEALTH_ID REDACTED]");
  });

  it("never leaks the raw RAMQ string", () => {
    expect(JSON.stringify(redacted)).not.toContain("MULL56072112");
  });

  it("reports metadata.matchedValue in redactedFields", () => {
    expect(redactedFields).toContain("metadata.matchedValue");
  });
});

// ---------------------------------------------------------------------------
// Case 5 - IPv4 address in source IP field
// ---------------------------------------------------------------------------
describe("IPv4 address in sourceIp", () => {
  const payload = makePayload({ sourceIp: "192.168.1.42" });
  const { redacted, redactedFields } = engine.redact(payload);

  it("hashes the IP (does not pass through in default mode)", () => {
    expect(JSON.stringify(redacted)).not.toContain("192.168.1.42");
  });

  it("reports sourceIp in redactedFields", () => {
    expect(redactedFields).toContain("sourceIp");
  });
});

// ---------------------------------------------------------------------------
// Case 6 - Key-based redaction: field named "password"
// ---------------------------------------------------------------------------
describe("key-based redaction: password field", () => {
  const payload = makePayload({
    eventType: "sql_injection",
    metadata: {
      redacted: true,
      matchedRule: "sql-injection",
      matchedValue: "' OR '1'='1",
      password: "s3cr3t_passw0rd",
    },
  });

  const { redacted, redactedFields } = engine.redact(payload);
  const meta = (redacted as Record<string, unknown>).metadata as Record<string, unknown>;

  it("replaces password field with [REDACTED]", () => {
    expect(meta.password).toBe("[REDACTED]");
  });

  it("never leaks the raw password value", () => {
    expect(JSON.stringify(redacted)).not.toContain("s3cr3t_passw0rd");
  });

  it("reports metadata.password in redactedFields", () => {
    expect(redactedFields).toContain("metadata.password");
  });
});

// ---------------------------------------------------------------------------
// Allowlist mode tests
// ---------------------------------------------------------------------------

describe("allowlist mode: drops non-approved metadata fields", () => {
  const engineAL = new RedactionEngine({ mode: "allowlist" });
  const payload = makePayload({
    metadata: {
      redacted: true,
      matchedRule: "xss",
      detectorDescription: "Cross-site scripting",
      location: "query.search",
      matchedValue: "<script>",
    },
  });

  const { redacted, redactedFields } = engineAL.redact(payload);
  const meta = (redacted as typeof payload).metadata;

  it("preserves structural sub-keys (matchedRule, redacted)", () => {
    expect(meta.matchedRule).toBe("xss");
    expect(meta.redacted).toBe(true);
  });

  it("drops detectorDescription from the payload", () => {
    expect("detectorDescription" in meta).toBe(false);
  });

  it("drops location from the payload", () => {
    expect("location" in meta).toBe(false);
  });

  it("drops matchedValue (not in allowKeyPatterns)", () => {
    expect("matchedValue" in meta).toBe(false);
  });

  it("reports dropped fields in redactedFields", () => {
    expect(redactedFields).toContain("metadata.detectorDescription");
    expect(redactedFields).toContain("metadata.location");
    expect(redactedFields).toContain("metadata.matchedValue");
  });

  it("never emits [REDACTED] sentinel for dropped fields", () => {
    expect(JSON.stringify(redacted)).not.toContain("[REDACTED]");
  });
});

describe("allowlist mode: denylist key is dropped (not [REDACTED])", () => {
  const engineAL = new RedactionEngine({ mode: "allowlist" });
  const payload = makePayload({
    metadata: {
      redacted: true,
      matchedRule: "sql-injection",
      matchedValue: "1' OR 1=1",
      password: "s3cr3t",
    },
  });

  const { redacted, redactedFields } = engineAL.redact(payload);
  const meta = (redacted as typeof payload).metadata;

  it("drops password field entirely (not [REDACTED])", () => {
    expect("password" in meta).toBe(false);
    expect(JSON.stringify(redacted)).not.toContain("s3cr3t");
  });

  it("reports metadata.password in redactedFields", () => {
    expect(redactedFields).toContain("metadata.password");
  });
});

describe("allowlist mode: allowKeyPatterns preserves extra field", () => {
  const engineAL = new RedactionEngine({
    mode: "allowlist",
    allowKeyPatterns: [/^matchedValue$/],
  });
  const payload = makePayload({
    metadata: {
      redacted: true,
      matchedRule: "xss",
      matchedValue: "<script>alert(1)</script>",
      location: "query.q",
    },
  });

  const { redacted } = engineAL.redact(payload);
  const meta = (redacted as typeof payload).metadata;

  it("keeps matchedValue because it matches allowKeyPatterns", () => {
    expect(meta.matchedValue).toBe("<script>alert(1)</script>");
  });

  it("still drops location (not in allowKeyPatterns)", () => {
    expect("location" in meta).toBe(false);
  });
});

describe("allowlist mode: non-approved root-level custom object dropped entirely", () => {
  const engineAL = new RedactionEngine({ mode: "allowlist" });
  const payload = {
    ...makePayload(),
    customerData: { name: "Alice", account: "123" },
  };

  const { redacted, redactedFields } = engineAL.redact(payload);

  it("drops customerData key entirely", () => {
    expect("customerData" in (redacted as Record<string, unknown>)).toBe(false);
  });

  it("reports customerData in redactedFields", () => {
    expect(redactedFields).toContain("customerData");
  });
});

describe("allowlist mode: value redaction still applies to approved fields", () => {
  const engineAL = new RedactionEngine({
    mode: "allowlist",
    allowKeyPatterns: [/^matchedValue$/],
  });
  const payload = makePayload({
    metadata: {
      redacted: true,
      matchedRule: "xss",
      matchedValue: "contact alice@example.com",
    },
  });

  const { redacted } = engineAL.redact(payload);
  const meta = (redacted as typeof payload).metadata;

  it("hashes email inside an approved field", () => {
    expect(meta.matchedValue).toMatch(/\[EMAIL:[0-9a-f]{16}\]/);
    expect(meta.matchedValue).not.toContain("alice@example.com");
  });
});
