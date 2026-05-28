# Banking API — RASP Test Lab

> **DEV ONLY.** This app is a test harness for the RASP agent.
> It must never be deployed outside `localhost`.

A minimal Express server that mimics a banking API.
Routes accept malformed/malicious input so the RASP agent can inspect it —
but they never execute dangerous operations (no real DB, no real filesystem).

## Prerequisites

| What | Where |
|---|---|
| Node.js ≥ 18 | — |
| pnpm | — |
| Collector running | `cd ../../.. && cd ../collector && pnpm dev` |
| DB seeded | `cd ../../.. && cd ../rasp && pnpm db:seed` |

## Setup

```bash
cd agent-node/examples/banking-api

cp .env.example .env
# Edit .env:
#   RASP_PROJECT_ID  → copy from the dashboard (project "banking-api")
#   RASP_MODE        → "monitor" or "block"

pnpm install
pnpm dev
```

Open **http://127.0.0.1:3000** in your browser.

## Endpoints

| Method | Path | Vulnerable to |
|---|---|---|
| `POST` | `/api/auth/login` | SQL injection (body) |
| `GET` | `/api/users/:id` | SQL injection (query), BOLA |
| `GET` | `/api/accounts/:id/balance` | BOLA |
| `GET` | `/api/transactions` | XSS, command injection (query) |
| `GET` | `/api/documents/:filename` | Path traversal |
| `DELETE` | `/api/admin/users/:id` | Auth bypass |
| `GET` | `/health` | — |

## Attack payloads (curl)

```bash
BASE=http://127.0.0.1:3000
KEY=rasp_demo_key_abc123   # not used by this app — demo only

# Normal request
curl "$BASE/api/users/1"

# SQL injection — query param
curl "$BASE/api/users/1?id=1'+OR+1%3D1--"

# SQL injection — body
curl -X POST "$BASE/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@acme.io","password":"'"'"' OR '"'"'1'"'"'='"'"'1"}'

# SQL injection — UNION SELECT
curl "$BASE/api/users/1?id=1+UNION+SELECT+username,password+FROM+users--"

# Blind SQL injection — SLEEP
curl "$BASE/api/users/1?id=1+AND+SLEEP(5)--"

# Path traversal
curl "$BASE/api/documents/..%2F..%2F..%2Fetc%2Fpasswd"

# XSS
curl "$BASE/api/transactions?search=%3Cscript%3Ealert(1)%3C%2Fscript%3E"

# Command injection
curl "$BASE/api/transactions?search=ping+127.0.0.1%3Bcat+%2Fetc%2Fpasswd"
```

## What to observe

- **monitor mode** — attacks pass through (HTTP 200), events are sent to the collector and visible in the dashboard.
- **block mode** — attacks return `HTTP 403 { "error": "Request blocked by RASP", "eventType": "..." }`.
- **`rasp-audit.log`** — local JSONL file written by the agent for every redaction action.
- **Collector down** — the app continues to run normally (fail-open). Events are buffered and dropped.

## Security notes

- Listens on `127.0.0.1` only — not reachable from outside the machine.
- Refuses to start when `NODE_ENV=production`.
- All route data is static/hardcoded — no real DB, no real files are read.
- `.env` is in `.gitignore` — API keys stay local.
