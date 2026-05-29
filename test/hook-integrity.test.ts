import { describe, it, expect, beforeEach } from "vitest";
import {
  instrumentDatabaseDrivers,
  verifyHookIntegrity,
  installedHookCount,
  __resetInstrumentationForTests,
} from "../src/db-hooks/instrument.js";

describe("DB hook integrity", () => {
  beforeEach(() => {
    __resetInstrumentationForTests();
  });

  it("installs hooks and reports intact integrity", () => {
    const proto = { query(_sql: string) { return "ok"; } };
    const fakePg = { Client: { prototype: proto }, Pool: { prototype: {} } };

    instrumentDatabaseDrivers((name) => (name === "pg" ? fakePg : null));

    expect(installedHookCount()).toBeGreaterThan(0);
    expect(verifyHookIntegrity()).toEqual([]);
  });

  it("detects a hook that was overwritten (un-hooked)", () => {
    const proto: Record<string, unknown> = { query(_sql: string) { return "ok"; } };
    const fakePg = { Client: { prototype: proto } };

    instrumentDatabaseDrivers((name) => (name === "pg" ? fakePg : null));
    expect(verifyHookIntegrity()).toEqual([]);

    // Simulate an attacker replacing the patched method.
    proto.query = function () { return "evil"; };

    const tampered = verifyHookIntegrity();
    expect(tampered).toContainEqual({ driver: "pg", method: "query" });
  });
});
