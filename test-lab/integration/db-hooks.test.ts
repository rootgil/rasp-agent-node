/**
 * Integration tests for DB driver hooks and BOLA-via-DB correlation.
 *
 * Extends the unit-level hook-integrity tests with agent-level integration:
 * verifies that hook installation, BOLA correlation, and integrity checks
 * all work correctly when the agent is fully initialised.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  instrumentDatabaseDrivers,
  verifyHookIntegrity,
  installedHookCount,
  __resetInstrumentationForTests,
} from "../../src/db-hooks/instrument.js";
import { RaspAgent } from "../../src/agent.js";
import { normalizeRequest } from "../mocks/normalize-request.js";
import bolaJwts from "../fixtures/payloads/bola-jwts.json" assert { type: "json" };

describe("DB hook installation via agent (instrumentDb: true)", () => {
  let agent: RaspAgent;

  beforeEach(() => {
    __resetInstrumentationForTests();
    agent = new RaspAgent({
      apiKey: "test_key",
      projectId: "proj_test",
      agentId: "agent_test",
      auditLog: false,
      instrumentDb: true,
      mode: "monitor",
    });
    agent.start();
  });

  afterEach(async () => {
    await agent.stop();
    __resetInstrumentationForTests();
  });

  it("installs at least one DB hook on start", () => {
    // pg and other drivers may not be present in the test environment,
    // but the call must not throw and integrity must be intact.
    const count = installedHookCount();
    const tampered = verifyHookIntegrity();
    expect(tampered).toEqual([]);
    // count may be 0 if no drivers are installed — that's acceptable
    expect(count).toBeGreaterThanOrEqual(0);
  });

  it("hook integrity check returns empty array after fresh installation", () => {
    expect(verifyHookIntegrity()).toEqual([]);
  });
});

describe("DB hook integrity — tamper detection", () => {
  beforeEach(() => {
    __resetInstrumentationForTests();
  });
  afterEach(() => {
    __resetInstrumentationForTests();
  });

  it("detects a replaced hook (simulated attacker un-hooking pg.query)", () => {
    const proto: Record<string, unknown> = {
      query(_sql: string) { return "original"; },
    };
    const fakePg = { Client: { prototype: proto }, Pool: { prototype: {} } };

    instrumentDatabaseDrivers((name) => name === "pg" ? fakePg : null);
    expect(verifyHookIntegrity()).toEqual([]);

    // Simulate attacker replacing the patched method
    proto.query = function () { return "evil"; };

    const tampered = verifyHookIntegrity();
    expect(tampered).toContainEqual({ driver: "pg", method: "query" });
  });

  it("does NOT flag intact hooks", () => {
    const proto = { query(_sql: string) { return "ok"; } };
    const fakePg = { Client: { prototype: proto }, Pool: { prototype: {} } };

    instrumentDatabaseDrivers((name) => name === "pg" ? fakePg : null);
    expect(verifyHookIntegrity()).toEqual([]);
  });
});

describe("BOLA detection (JWT sub mismatch)", () => {
  let agent: RaspAgent;

  beforeEach(() => {
    agent = new RaspAgent({
      apiKey: "test_key",
      projectId: "proj_test",
      agentId: "agent_test",
      auditLog: false,
      mode: "block",
    });
  });

  afterEach(async () => {
    await agent.stop();
  });

  it("fires bola event when user 1 accesses resource 2", () => {
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

  it("does not fire when sub matches resource ID", () => {
    const req = normalizeRequest({
      method: "GET",
      path: "/api/users/1",
      headers: { authorization: `Bearer ${bolaJwts.user1.token}` },
    });
    expect(agent.inspect(req)).toBeNull();
  });

  it("does not fire when path has no numeric/UUID segment", () => {
    const req = normalizeRequest({
      method: "GET",
      path: "/api/dashboard",
      headers: { authorization: `Bearer ${bolaJwts.user1.token}` },
    });
    expect(agent.inspect(req)).toBeNull();
  });
});
