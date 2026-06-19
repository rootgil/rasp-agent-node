# APM Compatibility Matrix

Results of running RASP agent alongside third-party APM agents.

Updated after each nightly CI run. Manual entries marked with *.

## Results

| APM | Version | Hook collision | Memory delta | Tracing context broken | Status | Last tested |
|---|---|---|---|---|---|---|
| Datadog dd-trace | TBD | TBD | TBD | TBD | tested nightly | - |
| OpenTelemetry SDK | TBD | TBD | TBD | TBD | tested nightly | - |
| New Relic | TBD | TBD | TBD | TBD | skipped (licence) | - |
| Dynatrace OneAgent | TBD | TBD | TBD | TBD | skipped (host install) | - |

## How to interpret results

- **Hook collision**: whether DB hooks installed by the RASP agent were overwritten by the APM.
  - `none` = hooks intact after APM init (`verifyHookIntegrity()` returns `[]`)
  - `partial` = some hooks overwritten but agent degraded gracefully
  - `full` = hooks overwritten, BOLA-via-DB correlation disabled
- **Memory delta**: approximate RSS increase observed when both agents run vs RASP alone.
- **Tracing context broken**: whether OTel/APM spans were missing or malformed when RASP middleware runs.
- **Status**:
  - `ok` = fully compatible, no issues
  - `degraded` = minor conflict, documented workaround available
  - `incompatible` = known hard conflict, not supported
  - `skipped` = not tested in automated CI (requires licence or manual setup)

## Known workarounds

_None yet - table will be populated after first nightly runs._

## Testing methodology

For APMs tested in nightly CI:
1. APM initialised first (worst-case ordering for RASP hook conflicts).
2. RASP `instrumentDatabaseDrivers()` called after APM init.
3. `verifyHookIntegrity()` called to check for hook collisions.
4. 10 attack payloads sent through RASP middleware - all must be detected.
5. Memory measured via `process.memoryUsage().rss` before and after.

For manual entries (New Relic, Dynatrace): follow the instructions in the
respective test files (`newrelic.test.ts`, `dynatrace.test.ts`).
