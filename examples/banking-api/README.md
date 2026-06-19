# Banking API - RASP Test Lab

> **DEV ONLY.** This app is a test harness for the RASP agent.
> It must never be deployed outside `localhost`.

A minimal Express server that mimics a banking API.
Routes accept malformed/malicious input so the RASP agent can inspect it -
but they never execute dangerous operations (no real DB, no real filesystem).

## Prerequisites

| What | Where |
|---|---|
| Node.js ≥ 18 | - |
| pnpm | - |
| Collector running | `cd ../../.. && cd ../collector && pnpm dev` |
| DB seeded | `cd ../../.. && cd ../rasp && pnpm db:seed` |

## Setup

```bash
cd agent-node/examples/banking-api

cp .env.example .env
# Edit .env:
#   RASP_PROJECT_ID   → copy from the dashboard (project "banking-api")
#   RASP_MODE         → "monitor" or "block"
#   RASP_CHANNEL      → "stable" | "early" | "edge"  (optional)
#   RASP_HMAC_SECRET  → enable payload signing (optional)
#   RASP_SELF_PROTECT → "true" to enable anti-debug + hook integrity (optional)

pnpm install
pnpm dev
```

The startup banner reports the active mode, channel, HMAC signing, self-protect
and the applied policy version so you can confirm what is enabled.

Open **http://127.0.0.1:3000** in your browser.

## Playground

The web UI keeps the **original banking presets** (normal, attack, data privacy) and adds an editable request panel:

- **Presets** — same malicious requests as before (`/api/auth/login`, `/api/users`, `/api/transactions`, `/api/documents`, BOLA with JWT, etc.)
- **Editable request** — method, URL, JSON body
- **Send / Clear** — replay with your edits; Shift+click a preset loads without sending
- **Mode badge** — polls `/health` for MONITOR/BLOCK, channel, HMAC, policy version

**Rules flow:** toggle rules ON in the dashboard, then click **Publish now** on the Rules page. The agent picks up the signed policy on the next heartbeat (~30s).

## Endpoints

| Method | Path | Vulnerable to |
|---|---|---|
| `POST` | `/api/auth/login` | SQL injection (body) |
| `GET` | `/api/users/:id` | SQL injection (query), BOLA |
| `GET` | `/api/accounts/:id/balance` | BOLA |
| `GET` | `/api/transactions` | XSS, command injection (query) |
| `GET` | `/api/documents/:filename` | Path traversal |
| `DELETE` | `/api/admin/users/:id` | Auth bypass |
| `GET` | `/health` | - |

## Attack payloads (curl)

```bash
BASE=http://127.0.0.1:3000
KEY=rasp_demo_key_abc123   # not used by this app - demo only

# Normal request
curl "$BASE/api/users/1"

# SQL injection - query param
curl "$BASE/api/users/1?id=1'+OR+1%3D1--"

# SQL injection - body
curl -X POST "$BASE/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@acme.io","password":"'"'"' OR '"'"'1'"'"'='"'"'1"}'

# SQL injection - UNION SELECT
curl "$BASE/api/users/1?id=1+UNION+SELECT+username,password+FROM+users--"

# Blind SQL injection - SLEEP
curl "$BASE/api/users/1?id=1+AND+SLEEP(5)--"

# Path traversal
curl "$BASE/api/documents/..%2F..%2F..%2Fetc%2Fpasswd"

# XSS
curl "$BASE/api/transactions?search=%3Cscript%3Ealert(1)%3C%2Fscript%3E"

# Command injection
curl "$BASE/api/transactions?search=ping+127.0.0.1%3Bcat+%2Fetc%2Fpasswd"
```

## Test cases for the new features

### BOLA / IDOR via JWT (no DB needed)

The BOLA detector compares the JWT `sub` claim with the resource ID in the URL.
These demo tokens are **unsigned dev tokens** (the detector only reads `sub`,
it never verifies the signature):

```bash
JWT_USER1="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.demo"   # sub=1
JWT_USER2="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyIn0.demo"   # sub=2

# Legit: user 1 reads their own record → no event
curl "$BASE/api/users/1" -H "Authorization: Bearer $JWT_USER1"

# BOLA: user 1 reads user 2's record → "bola" event (severity high)
curl "$BASE/api/users/2" -H "Authorization: Bearer $JWT_USER1"

# Enumeration heuristic: >20 distinct IDs in 60s from one IP → "bola" event
for i in $(seq 1 25); do curl -s "$BASE/api/users/$i" >/dev/null; done
```

### Value-based redaction (Addendum B.2)

Embed PII inside an attack payload - the detector fires, and the agent
value-redacts the matched value before it leaves the process (you never see the
raw email/card in the dashboard event or in `rasp-audit.log`):

```bash
# Email inside an XSS payload → masked as [EMAIL:<hash>]
curl "$BASE/api/transactions?search=%3Cscript%3Ealert('alice@acme.io')%3C%2Fscript%3E"

# Luhn-valid card inside a SQLi payload → masked as ****-****-****-1111
curl "$BASE/api/users/1?id=1'+UNION+SELECT+4111111111111111--"
```

### HMAC payload integrity (Addendum E.5)

```bash
# 1. Set RASP_HMAC_SECRET in .env (matching the agent's secret in the dashboard).
# 2. On the collector, set HMAC_REQUIRED=true.
# 3. Restart both. Events are now signed with X-RASP-Signature and accepted.
# 4. Change RASP_HMAC_SECRET to a wrong value → the collector rejects the batch
#    (visible as transport errors; the app keeps running, fail-open).
```

### Self-protection (Addendum E.7)

```bash
# Enable it, then attach a debugger to trigger the anti-debug warning:
RASP_SELF_PROTECT=true node --import tsx/esm --inspect src/server.ts
# → console shows: [rasp:self-protect] debugger/inspector detected { reason: ... }
```

Secrets (API key, HMAC secret) are always held encrypted in memory regardless of
this flag - they never appear in a heap dump of the transport client.

### Channels, custom rules & kill-switch

- Set `RASP_CHANNEL=early` (or `edge`) to receive that channel's policy/version.
- Publish a **custom detection rule** or a **redaction policy** from the dashboard:
  on the next heartbeat the agent fetches the signed policy, verifies it, and the
  banner's policy version increments. A tampered signature is rejected (the agent
  keeps its last known-good policy - self-rollback).
- Trigger the **global kill-switch** from the backoffice: on the next heartbeat
  the agent goes passive (`inspect` becomes a no-op) and stops sending telemetry.

## What to observe

- **monitor mode** - attacks pass through (HTTP 200), events are sent to the collector and visible in the dashboard.
- **block mode** - attacks return `HTTP 403 { "error": "Request blocked by RASP", "eventType": "..." }`.
- **`rasp-audit.log`** - local JSONL file written by the agent for every redaction action.
- **Collector down** - the app continues to run normally (fail-open). Events are buffered and dropped.

## Security notes

- Listens on `127.0.0.1` only - not reachable from outside the machine.
- Refuses to start when `NODE_ENV=production`.
- All route data is static/hardcoded - no real DB, no real files are read.
- `.env` is in `.gitignore` - API keys stay local.
