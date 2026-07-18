# AGENTS.md - rasp-agent-node

This repository contains the Node.js RASP agent.

## Scope

The agent is installed inside customer applications.

Responsibilities:
- observe HTTP requests
- detect suspicious runtime behavior
- detect API endpoints at runtime
- redact sensitive data before telemetry leaves the application
- write local redaction audit logs inside the customer environment
- support monitor and block modes
- send security events to the collector
- send heartbeat events
- avoid crashing the host application

## Architecture Rules

- Keep the package lightweight.
- Avoid heavy dependencies.
- Never crash the host application.
- Fail open by default if the collector is unavailable.
- Do not log sensitive data by default.
- All telemetry must pass through the redaction engine before buffering.
- If redaction fails, drop the event.
- Provide Express, Fastify, and NestJS integrations.
- Keep detectors isolated and testable.
- Keep transport logic separate from detection logic.
- On a single request, collect **all** detector/rule matches; emit one event with
  primary = highest severity (`matchedRule`) and full list in `matchedRules`.

## Local Redaction Audit Log

Every redaction action must be logged locally inside the customer environment.

Rules:
- Redaction audit logs are written locally by the agent.
- Redaction audit logs are never sent to the collector by default.
- Audit logs must never contain raw sensitive values.
- Audit logs must only contain metadata about the redaction action.
- If redaction fails, the event must be dropped and the failure must be logged locally.
- The local audit log path must be configurable.
- Log rotation must be supported to avoid filling customer disks.
- If audit logging fails, the host application must continue running.

## Security Rules

- Do not send raw passwords, tokens, API keys, or authorization headers.
- Do not send raw request bodies by default.
- Do not perform arbitrary outbound network calls.
- Only communicate with the configured collector URL.
- Monitor mode is the default.
- Block mode must be explicitly enabled.
- The agent must fail open by default.