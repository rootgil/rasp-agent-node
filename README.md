# @queno/agent-node

> Runtime Application Self-Protection for Node.js - Express · Fastify · NestJS

[![npm version](https://img.shields.io/badge/npm-0.1.2-blue)](https://www.npmjs.com/package/@queno/agent-node)
[![node](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)
[![license](https://img.shields.io/badge/license-MIT-green)](./LICENSE)
[![build](https://img.shields.io/badge/build-passing-brightgreen)](#)

`@queno/agent-node` is a lightweight RASP agent that installs inside your Node.js application and **detects, redacts, audits, and optionally blocks** runtime attacks - without a proxy, without a WAF, and without crashing your app.

It instruments Express, Fastify, and NestJS middleware to inspect each incoming request against 10 built-in attack detectors. Sensitive data is redacted **before leaving the process**, a tamper-evident audit log is written locally, and security events are forwarded to the RASP collector.

---

## Features

- **10 built-in detectors** - SQL injection, XSS, Command injection, Path traversal, NoSQL injection, SSRF, Prototype pollution, Template injection, Suspicious headers, BOLA/IDOR
- **Local redaction engine** - key-based denylist + value-based (email, card, SIN/RAMQ, IP). Redaction happens *before* telemetry leaves the process
- **Local JSONL audit log** - metadata-only, never raw sensitive values, with automatic rotation
- **Monitor and block modes** - monitor by default; block must be explicitly enabled or pushed via signed policy
- **Signed policy distribution** - Ed25519 signed configuration from the dashboard (mode, custom rules, redaction config). Agents verify before applying
- **Passive API discovery** - observes endpoints at runtime, normalizes routes, flushes inventory to the collector
- **Self-protection (optional)** - AES-256-GCM in-memory secret store, anti-debug detection, DB hook integrity
- **Fail-open** - any internal error is swallowed; the agent never crashes the host application
- **Single runtime dependency** - only `zod`. No axios, no winston, no lodash

---

## Requirements

| Requirement | Version |
|---|---|
| Node.js | **≥ 18** |
| TypeScript | ≥ 5 (optional) |
| Framework | Express ≥ 4, Fastify ≥ 4, or NestJS ≥ 10 |

> Node ≥ 18 is required for native `crypto` (AES-GCM, Ed25519, HMAC), native `fetch`, and `AsyncLocalStorage`.

---

## Installation

```bash
# npm
npm install @queno/agent-node

# pnpm
pnpm add @queno/agent-node

# yarn
yarn add @queno/agent-node
```

Install the peer dependency for your framework - only what you need:

```bash
# Express
npm install express

# Fastify
npm install fastify

# NestJS
npm install @nestjs/common @nestjs/core
```

---

## Quickstart

Before you start: create a **Project** and an **Agent** in the RASP dashboard, then copy the `apiKey`, `projectId`, and `agentId`.

### Express

```typescript
import express from "express";
import { RaspAgent, createExpressMiddleware } from "@queno/agent-node";

// 1. Create and start the agent
const agent = new RaspAgent({
  apiKey:    process.env.RASP_API_KEY!,
  projectId: process.env.RASP_PROJECT_ID!,
  agentId:   process.env.RASP_AGENT_ID!,
  framework: "express",
  mode:      "monitor", // "monitor" | "block"
});
agent.start();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// 2. Mount the RASP middleware AFTER body parsers
app.use(createExpressMiddleware(agent));

// 3. Your routes
app.get("/api/users/:id", (req, res) => {
  // In block mode, the middleware already replied 403 if an attack was detected
  res.json({ id: req.params.id });
});

// 4. Drain on shutdown
process.on("SIGTERM", async () => {
  await agent.stop(); // flushes event buffer + closes audit log
  process.exit(0);
});

app.listen(3000);
```

### Fastify

```typescript
import Fastify from "fastify";
import { RaspAgent, createFastifyPlugin } from "@queno/agent-node";

const agent = new RaspAgent({
  apiKey:    process.env.RASP_API_KEY!,
  projectId: process.env.RASP_PROJECT_ID!,
  agentId:   process.env.RASP_AGENT_ID!,
  framework: "fastify",
});
agent.start();

const fastify = Fastify({ logger: true });

// Register as a Fastify plugin
await fastify.register(createFastifyPlugin(agent));

fastify.get("/api/items", async () => ({ items: [] }));

await fastify.listen({ port: 3000 });

process.on("SIGTERM", async () => {
  await fastify.close();
  await agent.stop();
});
```

> **Note:** The Fastify plugin hooks into `onRequest` (before body parsing). To inspect request bodies, add a `preHandler` hook after plugin registration.

### NestJS

```typescript
// rasp.module.ts
import { Module, NestModule, MiddlewareConsumer } from "@nestjs/common";
import { RaspAgent, createNestMiddleware } from "@queno/agent-node";

export const raspAgent = new RaspAgent({
  apiKey:    process.env.RASP_API_KEY!,
  projectId: process.env.RASP_PROJECT_ID!,
  agentId:   process.env.RASP_AGENT_ID!,
  framework: "nestjs",
});
raspAgent.start();

@Module({ imports: [/* your modules */] })
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(createNestMiddleware(raspAgent))
      .forRoutes("*");
  }
}
```

```typescript
// main.ts - graceful shutdown
import { raspAgent } from "./rasp.module";

process.on("SIGTERM", async () => {
  await raspAgent.stop();
});
```

---

## Configuration

Pass a `RaspConfig` object to the `RaspAgent` constructor. All fields except `apiKey`, `projectId`, and `agentId` are optional with safe defaults.

| Option | Type | Default | Min | Description |
|---|---|---|---|---|
| `apiKey` * | `string` | - | - | API key generated in the dashboard |
| `projectId` * | `string` | - | - | Project ID |
| `agentId` * | `string` | - | - | Agent ID (registered in the dashboard) |
| `mode` | `"monitor" \| "block"` | `"monitor"` | - | Initial mode. Can be overridden by a signed policy |
| `channel` | `"stable" \| "early" \| "edge"` | `"stable"` | - | Policy and version distribution channel |
| `heartbeatIntervalMs` | `number` | `30000` | `5000` | Heartbeat interval |
| `flushIntervalMs` | `number` | `5000` | `1000` | Event buffer flush interval |
| `bufferMaxSize` | `number` | `50` | `1` | Flush also triggers at this buffer size |
| `transportTimeoutMs` | `number` | `5000` | `500` | HTTP timeout to the collector |
| `auditLog` | `boolean` | `true` | - | Enable local JSONL audit log |
| `auditLogPath` | `string` | `"./rasp-audit.log"` | - | Local audit log path |
| `auditLogMaxBytes` | `number` | `10485760` | `1` | Rotation size (10 MB default) |
| `discoveryFlushIntervalMs` | `number` | `60000` | `5000` | API discovery flush interval |
| `hmacSecret` | `string` | - | - | HMAC-SHA256 secret if `HMAC_REQUIRED=true` on the collector |
| `instrumentDb` | `boolean` | `false` | - | Enable DB driver monkey-patching for BOLA correlation (`pg`, `mysql2`, `mongoose`, `knex`, `sequelize`, Prisma) |
| `selfProtect` | `boolean` | `false` | - | Enable anti-debug, hook integrity checks, extended SecureStore |
| `policyPublicKey` | `string` | Dev key (built-in) | - | Ed25519 PEM public key. **Override in production** |
| `agentVersion` | `string` | - | - | Reported in heartbeats |
| `framework` | `string` | - | - | Free-form tag reported in heartbeats |
| `tls` | `object` | - | - | TLS/mTLS: `caCert`, `clientCert`, `clientKey`, `collectorFingerprints`, `rejectUnauthorized` |

### Environment variables

Two environment variables are read from `process.env` by `src/config.ts`:

| Variable | Default | Description |
|---|---|---|
| `RASP_COLLECTOR_URL` | `https://collector.rasp.dev` | Override the collector URL (dev/staging) |
| `RASP_POLICY_PUBLIC_KEY` | Built-in dev key | Override the trusted Ed25519 public key |

All other options are passed directly via `RaspConfig` - not read from the environment.

---

## Modes

### Monitor (default)

All requests pass through. Detections are reported as events to the collector and visible in the dashboard. **No impact on your application's responses.**

```typescript
const agent = new RaspAgent({ ..., mode: "monitor" });
```

### Block

When an attack is detected, the middleware replies with `HTTP 403` and does **not** call `next()`:

```json
{ "error": "Request blocked by RASP", "eventType": "sql_injection" }
```

```typescript
const agent = new RaspAgent({ ..., mode: "block" });
```

> **Important:** Always read `agent.mode` at runtime - the mode may change via a signed policy pushed from the dashboard. Do not rely on the boot config value.

### Kill-switch

If the dashboard activates a kill-switch (per-agent or global), the agent's `inspect()` becomes a no-op on the next heartbeat. The agent stops sending telemetry but continues heartbeating to detect when the kill-switch is lifted. **Recovery is automatic.**

---

## Detectors

| # | Detector | Severity | Targets |
|---|---|---|---|
| 1 | SQL injection | critical | query, body, path |
| 2 | XSS | high | query, body |
| 3 | Command injection | critical | query, body, path |
| 4 | Path traversal | high | query, body, path |
| 5 | NoSQL injection | high | query, body |
| 6 | SSRF | high | query, body |
| 7 | Prototype pollution | critical | query, body |
| 8 | Template injection | high | query, body |
| 9 | Suspicious headers | medium/high | headers |
| 10 | BOLA / IDOR | high | path, JWT `sub` |

Detection is **synchronous** on the request path. All telemetry side-effects (redaction, audit, buffer, transport) are **async fire-and-forget**.

---

## Security & Privacy

### Redaction before transport

The redaction engine runs **before** any event enters the transport buffer. If redaction throws, the event is **dropped** (fail-closed) and logged locally with `dropped: true`. No raw sensitive value ever leaves the process.

**Default key redaction:** `authorization`, `cookie`, `password`, `secret`, `token`, `api_key`, `ssn`, `credit_card`, `cvv`, `pin`, `x-api-key` and more.

**Value-based redaction:** emails → `[EMAIL:<hash>]`, Luhn-valid cards → `****-****-****-XXXX`, SIN → `[SIN REDACTED]`, RAMQ → `[HEALTH_ID REDACTED]`, SQL literals → `[STRING]`/`[INT]`.

### Local audit log

Every redaction action is journaled locally as JSONL (`./rasp-audit.log` by default). Contents: timestamp, eventType, severity, redactedFields - **never raw values**. The log never leaves the customer's environment.

### Secrets in memory

`apiKey` and `hmacSecret` are stored encrypted in memory using `SecureStore` (AES-256-GCM, per-process random key). They never appear in heap dumps or crash logs.

### Signed policy

The agent verifies every policy with Ed25519 before applying it. Policies are monotonically versioned - replay attacks are rejected. Without a valid signature, the agent keeps its last known-good policy.

### Transport hardening

- **HMAC-SHA256** payload signing (`X-RASP-Signature` header) - opt-in via `hmacSecret`
- **TLS certificate pinning** - via `tls.collectorFingerprints` (SHA-256 DER)
- **mTLS** - via `tls.clientCert` + `tls.clientKey`

### Fail-open (never crash your app)

Every exception inside the agent - in detectors, transport, audit log - is caught and swallowed. The agent never propagates errors to the host application.

---

## Extension

### Custom detector

```typescript
import { RaspAgent, Detector, NormalizedRequest, DetectionResult } from "@queno/agent-node";

const myDetector: Detector = {
  name: "my-detector",
  detect(req: NormalizedRequest): DetectionResult | null {
    if (req.path.startsWith("/internal")) {
      return {
        eventType:    "unauthorized_internal_access",
        severity:     "high",
        detectorName: "my-detector",
        matchedValue: req.path,
        matchedField: "path",
      };
    }
    return null;
  },
};

const agent = new RaspAgent(
  { apiKey, projectId, agentId },
  { extraDetectors: [myDetector] },
);
```

### Prisma instrumentation (BOLA DB correlation)

```typescript
import { PrismaClient } from "@prisma/client";
import { instrumentPrismaClient } from "@queno/agent-node";

const prisma = new PrismaClient({
  log: [{ emit: "event", level: "query" }], // required
});
instrumentPrismaClient(prisma);

const agent = new RaspAgent({ ..., instrumentDb: true });
```

Also supports `pg`, `mysql2`, `sequelize`, `mongoose`, and `knex` via `instrumentDatabaseDrivers()` (called automatically when `instrumentDb: true`).

---

## Self-protection

When `selfProtect: true`:

- **Anti-debug** - warns if `--inspect`/`--debug` args or a V8 inspector is detected
- **Hook integrity** - polls every 30s to detect tampering of installed DB driver hooks
- **SecureStore** - always active regardless of this flag: `apiKey` and `hmacSecret` are encrypted in-process

---

## API discovery

The agent passively observes HTTP endpoints at runtime and normalizes routes (`:id` substitution for numeric, UUID, and CUID-like segments). Observations are flushed every 60 seconds (configurable) to `POST /v1/discovery` on the collector.

Discover shadow APIs, zombie endpoints (no traffic in 30 days), and get an auth coverage heatmap in the dashboard. Export your live API inventory as an OpenAPI spec.

---

## Development warning

> **⚠ The default `policyPublicKey` is a development key** bundled in `src/config.ts`. It works out of the box with the RASP platform seed data. **Before production deployment, override it** with your actual Ed25519 public key via `RaspConfig.policyPublicKey` or `RASP_POLICY_PUBLIC_KEY`.

---

## Architecture overview

```
Host application
└── RASP middleware (Express / Fastify / NestJS)
    ├── inspect(req)
    │   ├── EndpointObserver.observe()   ← passive API discovery
    │   ├── Detectors[0..N].detect()     ← first-match, sync
    │   └── handleDetection() [async]
    │       ├── RedactionEngine.redact() ← fail-closed on error
    │       ├── AuditLog.write()         ← local JSONL, never sent
    │       └── EventBuffer.enqueue()    ← batch flush → collector
    └── endRequest(outcome)
        ├── EndpointObserver.observeOutcome()
        └── correlateBola()              ← DB query correlation (opt-in)

EventBuffer → POST /v1/events  → rasp-collector → PostgreSQL
Heartbeat   → POST /v1/heartbeat (kill-switch, policy version, upgrade)
            ← GET  /v1/policy   (Ed25519 signed, verified locally)
Discovery   → POST /v1/discovery (batched, 60s)
```

---

## Testing

### Unit tests (every PR)

```bash
npm run test:unit      # test/ — redaction, policy, hooks, self-protect
npm run test:lab       # test-lab/integration/ — detectors, Express/Fastify/NestJS, DB hooks
npm run typecheck      # tsc --noEmit
npm run test:ci        # typecheck + unit + lab (same as CI)
```

### E2E and stress (nightly / on-demand)

```bash
npm run test:e2e       # test-lab/e2e/ — banking-api via supertest + mock collector
npm run test:stress    # test-lab/stress/ — 1000 concurrent requests, crash detection
npm run test:compat    # test-lab/compat/ — Datadog + OTel coexistence (skipped if not installed)
```

### CI matrix

| Trigger | Jobs |
|---|---|
| Every push / PR | Typecheck · unit · integration · build on Node 18, 20, 22 |
| Nightly (02:00 UTC) | E2E, stress, k6 benchmarks, multi-OS Docker (Alpine/Debian), APM compat |

### Performance benchmarks (k6)

```bash
# Requires k6 installed (https://k6.io/docs/get-started/installation/)
# Start banking-api (port 3001 = baseline, 3000 = with agent), then:
npm run benchmark:compare
```

Thresholds: > 1 % P99 overhead → warning, > 5 % → CI fail.

### Test infrastructure layout

```
test-lab/
├── fixtures/payloads/    # JSON attack payloads for all 10 detectors
├── mocks/                # mock-collector, test-agent helpers, normalize-request
├── integration/          # detector table tests, framework middleware, DB hooks
├── e2e/                  # banking-api end-to-end via supertest
├── stress/               # concurrency + crash detection
└── compat/               # APM coexistence (Datadog, OTel, NR*, Dynatrace*)

benchmarks/
├── k6/                   # baseline.js + with-agent.js
├── compare-p99.js        # delta calculator (1% warn / 5% fail)
└── baselines/            # reference P99 JSON

* = skipped in automated CI (requires licence or host-level install)
```

Test coverage areas: redaction engine, redaction patterns (email/card/SIN/IP), policy rejection, canonical bytes, custom rules, self-protect, hook integrity, all 10 detectors, Express/Fastify/NestJS middleware, DB hooks, BOLA, E2E attack scenarios, stress/crash, APM compat.

---

## Further reading

- [`AGENTS.md`](./AGENTS.md) - architecture rules and security invariants for contributors
- [`examples/banking-api/README.md`](./examples/banking-api/README.md) - local test lab with attack payloads
- [`test-lab/compat/CONFLICTS.md`](./test-lab/compat/CONFLICTS.md) - APM compatibility matrix

---

## License

MIT
