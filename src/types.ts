/**
 * Public type definitions for `@rasp/agent-node`.
 *
 * These types form the contract between:
 *  - the customer application (RaspConfig, NormalizedRequest),
 *  - the framework integrations (Express/Fastify/NestJS adapters),
 *  - the bundled detectors (DetectionResult),
 *  - the collector backend (EventPayload, HeartbeatPayload, HeartbeatResponse),
 *  - the local redaction audit log (RedactionAuditEntry).
 */

/** Detection severity, ordered from worst to least severe. */
export type Severity = "critical" | "high" | "medium" | "low";

/**
 * Agent enforcement mode.
 *
 * - `monitor` (default): detections are recorded and reported but the request
 *   is allowed to continue.
 * - `block`: detections cause the integration to respond with HTTP 403.
 */
export type AgentMode = "monitor" | "block";

/**
 * Self-reported agent health, sent on every heartbeat.
 *
 * - `healthy`: agent is operating normally.
 * - `degraded`: agent is running but a non-fatal subsystem has issues.
 * - `error`: agent is in a broken state but still attempting to report.
 */
export type AgentStatus = "healthy" | "degraded" | "error";

/**
 * Runtime configuration accepted by {@link RaspAgent}.
 *
 * Only `apiKey`, `projectId` and `agentId` are mandatory. All other fields
 * have sensible defaults applied by the Zod schema in `config.ts`.
 */
export interface RaspConfig {
  /** Bearer API key issued by the RASP dashboard. Sent as `Authorization: Bearer <key>`. */
  apiKey: string;
  /** Project ID from the RASP dashboard. Scopes all telemetry to a tenant. */
  projectId: string;
  /** Stable identifier for this agent instance (e.g. hostname or pod name). */
  agentId: string;
  /** Free-form agent version string, echoed back in telemetry for debugging. */
  agentVersion?: string;
  /** Enforcement mode. Defaults to `monitor` — see {@link AgentMode}. */
  mode?: AgentMode;
  /** Heartbeat interval in ms. Min 5_000, default 30_000. */
  heartbeatIntervalMs?: number;
  /** Buffer flush interval in ms. Min 1_000, default 5_000. */
  flushIntervalMs?: number;
  /** Max events held in the buffer before a forced flush. Min 1, default 50. */
  bufferMaxSize?: number;
  /** HTTP request timeout to the collector in ms. Min 500, default 5_000. */
  transportTimeoutMs?: number;
  /** Whether to write the local redaction audit log. Default true. */
  auditLog?: boolean;
  /** Filesystem path for the local audit log. Default `./rasp-audit.log`. */
  auditLogPath?: string;
  /** Max audit log file size in bytes before rotation. Default 10 MB. */
  auditLogMaxBytes?: number;
  /** Framework hint included in telemetry (e.g. `express`, `fastify`, `nestjs`). */
  framework?: string;
  /** Runtime hint included in telemetry. Default `node`. */
  runtime?: string;
  /** Discovery flush interval in ms. Min 5_000, default 60_000. */
  discoveryFlushIntervalMs?: number;
}

/**
 * Framework-agnostic view of an incoming HTTP request.
 *
 * Integrations are responsible for mapping their native request object to this
 * shape before calling {@link RaspAgent.inspect}.
 */
export interface NormalizedRequest {
  /** HTTP verb (e.g. `GET`, `POST`). */
  method: string;
  /** Request path without the query string. */
  path: string;
  /** Parsed query parameters. */
  query: Record<string, unknown>;
  /** Raw HTTP headers as provided by the framework. */
  headers: Record<string, string | string[] | undefined>;
  /** Parsed request body, if available. May be undefined for streaming bodies. */
  body: unknown;
  /** Best-effort source IP, typically resolved from `X-Forwarded-For` or the socket. */
  sourceIp?: string;
}

/**
 * The outcome of a single detector run.
 *
 * Returned by {@link Detector.detect} when something suspicious is found, and
 * fed into {@link RaspAgent.inspect}'s event-building pipeline.
 */
export interface DetectionResult {
  /** Identifier of the detector that produced this result (e.g. `sql-injection`). */
  detectorName: string;
  /** Stable machine-readable event type used by the collector (e.g. `sql_injection`). */
  eventType: string;
  /** Severity assigned by the detector. */
  severity: Severity;
  /** Human-readable description of what was detected. */
  description: string;
  /**
   * The matched value or pattern. This may contain sensitive substrings — the
   * redaction engine MUST be run before the event leaves the process.
   */
  matchedValue?: string;
  /** Which field or location triggered the detection (e.g. `query/body`, `header:host`). */
  location?: string;
}

/**
 * Payload sent to the collector's `POST /v1/events` endpoint.
 *
 * Always passes through the redaction engine before being enqueued.
 */
export interface EventPayload {
  /** Project the event belongs to. */
  projectId: string;
  /** Stable identifier of the agent that produced the event. */
  agentId?: string;
  /** Version of the agent that produced the event. */
  agentVersion?: string;
  /** Runtime hint (e.g. `node`). */
  runtime?: string;
  /** Framework hint (e.g. `express`). */
  framework?: string;
  /** Stable machine-readable event type (see {@link DetectionResult.eventType}). */
  eventType: string;
  /** Severity of the detection. */
  severity: Severity;
  /** Mode in effect when the detection happened (`monitor` or `block`). */
  action: AgentMode;
  /** HTTP method of the originating request. */
  method?: string;
  /** Request path. */
  path?: string;
  /** Best-effort source IP. */
  sourceIp?: string;
  /** ISO-8601 timestamp set by the agent. */
  timestamp?: string;
  /**
   * Detection metadata.
   *
   * `redacted: true` is always present and signals that the redaction engine
   * has processed this payload. `auditLoggedLocally` indicates whether at
   * least one field was redacted (and therefore an audit log line was
   * written). Extra keys are detector-specific.
   */
  metadata: {
    redacted: true;
    matchedRule?: string;
    auditLoggedLocally?: boolean;
    [key: string]: unknown;
  };
}

/**
 * Payload sent to the collector's `POST /v1/heartbeat` endpoint.
 *
 * The heartbeat is the agent's liveness signal and the channel through which
 * the backend delivers the kill switch and policy version.
 */
export interface HeartbeatPayload {
  projectId: string;
  agentId: string;
  agentVersion?: string;
  runtime?: string;
  framework?: string;
  /** Self-reported health. */
  status: AgentStatus;
  /** Mode currently enforced by the agent. */
  mode: AgentMode;
  /** ISO-8601 timestamp set by the agent. */
  timestamp?: string;
}

/**
 * Response returned by the collector for `POST /v1/heartbeat`.
 *
 * The agent reacts to two fields:
 *  - `killSwitch: true` → the agent stops inspecting and shuts down its buffer.
 *  - `policyVersion` change → triggers `onPolicyChange` (reserved for future rule refresh).
 */
export interface HeartbeatResponse {
  ok: boolean;
  killSwitch: boolean;
  policyVersion: string;
}

/**
 * Auth status heuristic inferred from the presence/absence of an
 * `Authorization` header on the observed request.
 */
export type AuthStatus = "authenticated" | "unauthenticated" | "unknown";

/**
 * A single discovered endpoint entry, aggregated by {@link EndpointObserver}
 * and flushed by {@link DiscoveryBuffer}.
 */
export interface DiscoveryEntry {
  /** HTTP verb (upper-cased). */
  method: string;
  /** Normalised path pattern (e.g. `/api/users/:id`). */
  pathPattern: string;
  /** Auth heuristic for this endpoint. */
  authStatus: AuthStatus;
  /** True when request body/query keys matched sensitive-data patterns. */
  hasSensitiveData: boolean;
  /** Number of observations since the last flush. */
  observationCount: number;
}

/**
 * Payload sent to the collector's `POST /v1/discovery` endpoint.
 */
export interface DiscoveryPayload {
  projectId: string;
  agentId: string;
  /** ISO-8601 timestamp set by the agent at flush time. */
  timestamp?: string;
  /** Up to 500 entries per batch. */
  endpoints: DiscoveryEntry[];
}

/**
 * A single line written to the local redaction audit log.
 *
 * Serialised as one JSON object per line (JSONL). Contains only metadata —
 * never the raw redacted values.
 */
export interface RedactionAuditEntry {
  /** ISO-8601 timestamp. */
  ts: string;
  agentId: string;
  projectId: string;
  /** Event type that triggered redaction. */
  eventType: string;
  /** Dotted field paths that were replaced by `[REDACTED]`. */
  redactedFields: string[];
  /** True when the event was dropped (e.g. because redaction failed). */
  dropped: boolean;
  /** Free-form reason set when `dropped` is true. */
  dropReason?: string;
}
