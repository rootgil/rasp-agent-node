# Testing — agent-node

Manual test commands to run locally when the CI fails or when you want to re-run a specific suite.

---

## Prerequisites

- Node ≥ 18
- `npm ci` — install dependencies
- k6 — only required for benchmarks

---

## Reproduce the full CI in one command

```sh
npm run test:ci
```

Equivalent to: `typecheck` + `test:unit` + `test:lab`

---

## Individual CI steps

Mirror of [`.github/workflows/ci.yml`](.github/workflows/ci.yml):

```sh
# 1. TypeScript type check
npm run typecheck

# 2. Unit tests (test/)
npm run test:unit

# 3. Integration tests (test-lab/integration/)
NODE_ENV=test npm run test:lab

# 4. Build
npm run build
```

---

## Optional suites (not run by CI)

```sh
# E2E — test-lab/e2e/banking-api.test.ts
npm run test:e2e

# Stress — test-lab/stress/crash.test.ts
npm run test:stress

# Compat — Datadog, Dynatrace, NewRelic, OpenTelemetry
npm run test:compat
```

---

## Run a single test file

```sh
npx vitest run test/redaction-engine.test.ts
npx vitest run test/redaction-patterns.test.ts
npx vitest run test/canonical.test.ts
npx vitest run test/policy-rejection.test.ts
npx vitest run test/custom-rule.test.ts
npx vitest run test/self-protect.test.ts
npx vitest run test/hook-integrity.test.ts

npx vitest run test-lab/integration/express-middleware.test.ts
npx vitest run test-lab/integration/fastify-plugin.test.ts
npx vitest run test-lab/integration/nest-middleware.test.ts
npx vitest run test-lab/integration/detectors.test.ts
npx vitest run test-lab/integration/db-hooks.test.ts

npx vitest run test-lab/compat/datadog.test.ts
npx vitest run test-lab/compat/dynatrace.test.ts
npx vitest run test-lab/compat/newrelic.test.ts
npx vitest run test-lab/compat/opentelemetry.test.ts
```

---

## Watch mode (fast iteration)

```sh
npm run test:watch
```

---

## Benchmark — p99 regression gate

Reproduces the `benchmark-regression` CI job.

### 1. Start banking-api WITH the agent (port 3000)

```sh
NODE_ENV=test RASP_MODE=monitor PORT=3000 \
node --import tsx/esm examples/banking-api/src/server.ts &
sleep 3
```

### 2. Run the with-agent benchmark

```sh
mkdir -p benchmarks/output
k6 run benchmarks/k6/with-agent.js --env BASE_URL=http://127.0.0.1:3000
# writes benchmarks/output/with-agent.json
```

### 3. Compare against the committed baseline (5% gate, same as CI)

```sh
node benchmarks/compare-p99.js \
  benchmarks/baselines/p99-baseline.json \
  benchmarks/output/with-agent.json
```

- overhead `> 1%` → WARN (exit 0)
- overhead `> 5%` → FAIL (exit 1)

### Optional — full local comparison with a fresh baseline

Start the app without the agent, capture a fresh baseline, then compare both runs:

```sh
# Start WITHOUT agent (port 3001)
RASP_ENABLED=false PORT=3001 \
node --import tsx/esm examples/banking-api/src/server.ts &
sleep 3

# Capture baseline
k6 run benchmarks/k6/baseline.js --env BASE_URL=http://127.0.0.1:3001
# writes benchmarks/output/baseline.json

# Compare fresh baseline vs with-agent
node benchmarks/compare-p99.js \
  benchmarks/output/baseline.json \
  benchmarks/output/with-agent.json
```

---

## Update the committed baseline

Run after a successful with-agent benchmark to promote the current p99 as the new reference:

```sh
node benchmarks/update-baseline.js
# then commit benchmarks/baselines/p99-baseline.json
```
