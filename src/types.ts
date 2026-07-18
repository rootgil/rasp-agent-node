/**
 * Public type definitions for `@queno/agent-node`.
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
  /** Enforcement mode. Defaults to `monitor` - see {@link AgentMode}. */
  mode?: AgentMode;
  /** Stability channel for policy/version distribution. Default `stable`. */
  channel?: "stable" | "early" | "edge";
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
  /**
   * Pinned Ed25519 public key (PEM, SPKI) used to verify signed policies
   * distributed by the control plane. This is the trust anchor (Addendum
   * E.4.1). In production it is embedded in the package by default and may be
   * overridden here for sovereign/on-prem deployments. When absent, the agent
   * cannot apply any policy and stays on its boot configuration (fail-safe).
   */
  policyPublicKey?: string;
  /** Per-request HMAC secret used to sign telemetry batches (Addendum E.5). */
  hmacSecret?: string;
  /**
   * Instrument common database drivers (pg, mysql2, mongoose, sequelize, knex)
   * to enable BOLA-via-DB correlation (Addendum A.4). Off by default; enabling
   * monkey-patches driver query methods at agent start.
   */
  instrumentDb?: boolean;
  /**
   * Enable runtime self-protection (Addendum E.7): periodic DB-hook integrity
   * checks and basic anti-debug detection. Secrets are always held encrypted in
   * memory regardless of this flag. Defaults to `false`.
   */
  selfProtect?: boolean;
  /**
   * TLS options for certificate pinning + mutual TLS to the collector
   * (Addendum E.4.2). When set, the agent uses a pinned HTTPS transport.
   */
  tls?: {
    caCert?: string;
    clientCert?: string;
    clientKey?: string;
    collectorFingerprints?: string[];
    rejectUnauthorized?: boolean;
  };
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
   * The matched value or pattern. This may contain sensitive substrings - the
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
    /** Highest-severity rule/detector id for this request. */
    matchedRule?: string;
    /**
     * All rules/detectors that matched the same request (severity-ordered
     * primary is still `matchedRule` / top-level `eventType`/`severity`).
     */
    matchedRules?: Array<{
      id: string;
      eventType: string;
      severity: Severity;
      location?: string;
    }>;
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
  /**
   * Set to `"upgrade_failed"` when the new version could not initialize within
   * 60 seconds (Addendum D.4). The control plane records this and can trigger
   * a control-plane-initiated rollback.
   */
  upgradeStatus?: "upgrade_failed" | "upgrade_succeeded" | "rollback_loaded";
  /** Reason for the upgradeStatus, if any. */
  upgradeStatusReason?: string;
}

/**
 * Response returned by the collector for `POST /v1/heartbeat`.
 *
 * The agent reacts to three fields:
 *  - `killSwitch: true` → the agent stops inspecting and shuts down its buffer.
 *  - `policyVersion` change → triggers `onPolicyChange` (reserved for future rule refresh).
 *  - `mode` → the enforcement mode stored on the server; the agent applies it immediately.
 */
export interface HeartbeatResponse {
  ok: boolean;
  killSwitch: boolean;
  policyVersion: string;
  mode?: AgentMode;
  /** Version this agent should be running (canary cohort / pin). */
  targetVersion?: string | null;
  /** True when `targetVersion` differs from the running version. */
  upgradeAvailable?: boolean;
  /** Changelog for the target version (shown in logs). */
  changelog?: string | null;
  /** Expected impact/risk notes for the target version. */
  impact?: string | null;
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
  /**
   * Whether an auth middleware was observed populating the request
   * (e.g. `req.user`/`req.auth`). More reliable than the header heuristic.
   */
  authObserved?: boolean;
  /** Count of responses with status >= 400 since the last flush. */
  errorCount?: number;
  /** Sum of observed response durations (ms); used to derive an average. */
  sumDurationMs?: number;
  /** Number of responses timed (denominator for the average). */
  timedCount?: number;
  /** Inferred parameter schema: field name -> JSON type. */
  schemaFields?: Record<string, string>;
  /**
   * Sensitive field names detected on this endpoint (e.g. ["email","password"]).
   * Populated from the redaction pattern name of each matched key.
   * Used to build the data flow diagram on the dashboard (Addendum A.5).
   */
  sensitiveFields?: string[];
}

/**
 * Response-phase outcome fed back to the {@link EndpointObserver} so it can
 * build a traffic profile (error rate, latency) and confirm auth middleware
 * execution.
 */
export interface RequestOutcome {
  statusCode?: number;
  durationMs?: number;
  /** True if an auth middleware populated the request (req.user / req.auth). */
  authenticated?: boolean;
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
 * Serialised as one JSON object per line (JSONL). Contains only metadata -
 * never the raw redacted values.
 */
export interface RedactionAuditEntry {
  /** ISO-8601 timestamp. */
  ts: string;
  agentId: string;
  projectId: string;
  /** Event type that triggered the detection. */
  eventType: string;
  /** Severity of the detection. */
  severity?: string;
  /** Name of the detector that fired. */
  detectorName?: string;
  /** Dotted field paths that were replaced by `[REDACTED]`. */
  redactedFields: string[];
  /** True when the event was dropped (e.g. because redaction failed). */
  dropped: boolean;
  /** Free-form reason set when `dropped` is true. */
  dropReason?: string;
}
