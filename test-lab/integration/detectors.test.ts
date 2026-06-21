/**
 * Table-driven integration tests for all 10 built-in detectors.
 *
 * Each test loads fixture payloads from test-lab/fixtures/payloads/ and
 * verifies that agent.inspect() returns the expected eventType and severity.
 * No HTTP, no collector, no async - purely synchronous.
 */
import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { RaspAgent } from "../../src/agent.js";
import { createOfflineDetectors } from "../../src/detectors/index.js";
import { requestFromFixture } from "../mocks/normalize-request.js";
import { normalizeRequest } from "../mocks/normalize-request.js";
import sqliPayloads         from "../fixtures/payloads/sqli.json" assert { type: "json" };
import xssPayloads          from "../fixtures/payloads/xss.json" assert { type: "json" };
import pathTraversalPayloads from "../fixtures/payloads/path-traversal.json" assert { type: "json" };
import cmdPayloads          from "../fixtures/payloads/command-injection.json" assert { type: "json" };
import ssrfPayloads         from "../fixtures/payloads/ssrf.json" assert { type: "json" };
import nosqlPayloads        from "../fixtures/payloads/nosql.json" assert { type: "json" };
import sstitPayloads        from "../fixtures/payloads/template-injection.json" assert { type: "json" };
import protoPollPayloads    from "../fixtures/payloads/prototype-pollution.json" assert { type: "json" };
import suspHeaderPayloads   from "../fixtures/payloads/suspicious-headers.json" assert { type: "json" };
import bolaJwts             from "../fixtures/payloads/bola-jwts.json" assert { type: "json" };

type Fixture = {
  description: string;
  request: {
    method: string;
    path: string;
    query: Record<string, unknown>;
    headers: Record<string, string>;
    body: unknown;
  };
  expectedEventType: string;
  expectedSeverity: string;
};

let agent: RaspAgent;

beforeEach(() => {
  agent = new RaspAgent(
    {
      apiKey: "test_key",
      projectId: "proj_test",
      agentId: "agent_test",
      auditLog: false,
      mode: "block",
    },
    createOfflineDetectors(),
  );
});

afterAll(async () => {
  await agent?.stop();
});

function runFixtures(fixtures: Fixture[]) {
  fixtures.forEach((f) => {
    it(f.description, () => {
      const req = requestFromFixture(f.request);
      const result = agent.inspect(req);
      expect(result, `Expected detection for: ${f.description}`).not.toBeNull();
      expect(result?.eventType).toBe(f.expectedEventType);
      expect(result?.severity).toBe(f.expectedSeverity);
    });
  });
}

describe("SQL Injection detector", () => runFixtures(sqliPayloads as Fixture[]));
describe("XSS detector", () => runFixtures(xssPayloads as Fixture[]));
describe("Path Traversal detector", () => runFixtures(pathTraversalPayloads as Fixture[]));
describe("Command Injection detector", () => runFixtures(cmdPayloads as Fixture[]));
describe("SSRF detector", () => runFixtures(ssrfPayloads as Fixture[]));
describe("NoSQL Injection detector", () => runFixtures(nosqlPayloads as Fixture[]));
describe("Template Injection detector", () => runFixtures(sstitPayloads as Fixture[]));
describe("Prototype Pollution detector", () => runFixtures(protoPollPayloads as Fixture[]));
describe("Suspicious Headers detector", () => runFixtures(suspHeaderPayloads as unknown as Fixture[]));

describe("BOLA detector", () => {
  it("flags JWT sub mismatch: user 1 accessing resource 2", () => {
    const req = normalizeRequest({
      method: "GET",
      path: "/api/users/2",
      headers: { authorization: `Bearer ${bolaJwts.user1.token}` },
    });
    const result = agent.inspect(req);
    expect(result).not.toBeNull();
    expect(result?.eventType).toBe("bola");
    expect(result?.severity).toBe("high");
  });

  it("does NOT flag when JWT sub matches resource ID", () => {
    const req = normalizeRequest({
      method: "GET",
      path: "/api/users/1",
      headers: { authorization: `Bearer ${bolaJwts.user1.token}` },
    });
    const result = agent.inspect(req);
    expect(result).toBeNull();
  });

  it("does NOT flag legitimate requests without JWT", () => {
    const req = normalizeRequest({
      method: "GET",
      path: "/api/users/1",
      headers: {},
    });
    const result = agent.inspect(req);
    expect(result).toBeNull();
  });
});

describe("Clean requests - no false positives", () => {
  it("does not flag a normal GET request", () => {
    const req = normalizeRequest({ method: "GET", path: "/api/health" });
    expect(agent.inspect(req)).toBeNull();
  });

  it("does not flag a normal POST with clean body", () => {
    const req = normalizeRequest({
      method: "POST",
      path: "/api/auth/login",
      headers: { "content-type": "application/json" },
      body: { email: "alice@example.com", password: "correct-horse-battery" },
    });
    expect(agent.inspect(req)).toBeNull();
  });
});
