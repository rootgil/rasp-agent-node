/**
 * Compatibility test: RASP agent + New Relic Node.js agent.
 *
 * Skipped: New Relic requires a valid license key and account to run, making
 * it unsuitable for open CI. Tests are documented here as a reference for
 * manual compatibility validation.
 *
 * To run manually:
 *   1. Install newrelic: npm install --no-save newrelic
 *   2. Set NEW_RELIC_LICENSE_KEY and NEW_RELIC_APP_NAME env vars
 *   3. Run: vitest run test-lab/compat/newrelic.test.ts
 *
 * Expected behaviour: no hook conflicts, agent still detects attacks.
 * See CONFLICTS.md for documented results.
 */
import { describe, it } from "vitest";

describe.skip("RASP agent + New Relic coexistence (manual — requires licence key)", () => {
  it("New Relic and RASP agent both start without error", () => {
    // Manual: require('newrelic'); then new RaspAgent({ ... })
  });

  it("DB hook integrity is intact after New Relic patches drivers", () => {
    // Manual: instrumentDatabaseDrivers() after NR init → verifyHookIntegrity() === []
  });

  it("RASP agent still detects attacks when New Relic is active", () => {
    // Manual: agent.inspect({ ... sqli payload ... }) → detection
  });
});
