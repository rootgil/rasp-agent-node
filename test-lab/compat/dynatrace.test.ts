/**
 * Compatibility test: RASP agent + Dynatrace OneAgent.
 *
 * Skipped: Dynatrace OneAgent requires a host-level installation and a valid
 * Dynatrace environment, making it unsuitable for standard CI runners.
 * Tests are documented here as a reference for manual compatibility
 * validation in a dedicated Dynatrace environment.
 *
 * To run manually:
 *   1. Install Dynatrace OneAgent on the test host (follow Dynatrace docs)
 *   2. Ensure DT_TENANT and DT_API_TOKEN are set
 *   3. Start the test process with OneAgent attached
 *   4. Run: vitest run test-lab/compat/dynatrace.test.ts
 *
 * Expected behaviour: no hook conflicts, agent still detects attacks.
 * See CONFLICTS.md for documented results.
 */
import { describe, it } from "vitest";

describe.skip("RASP agent + Dynatrace OneAgent coexistence (manual — requires host-level installation)", () => {
  it("Dynatrace and RASP agent both start without error", () => {
    // Manual: start process with OneAgent attached, then new RaspAgent({ ... })
  });

  it("DB hook integrity is intact after Dynatrace patches drivers", () => {
    // Manual: instrumentDatabaseDrivers() after OneAgent → verifyHookIntegrity() === []
  });

  it("RASP agent still detects attacks when Dynatrace is active", () => {
    // Manual: agent.inspect({ ... sqli payload ... }) → detection
  });
});
