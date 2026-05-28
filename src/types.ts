export type Severity = "critical" | "high" | "medium" | "low";
export type AgentMode = "monitor" | "block";
export type AgentStatus = "healthy" | "degraded" | "error";

export interface RaspConfig {
  /** Bearer API key issued by the RASP dashboard */
  apiKey: string;
  /** Project ID from the RASP dashboard */
  projectId: string;
  /** Unique identifier for this agent instance */
  agentId: string;
  /** Agent version string */
  agentVersion?: string;
  /** monitor (default) | block */
  mode?: AgentMode;
  /** Heartbeat interval in ms (default 30_000) */
  heartbeatIntervalMs?: number;
  /** Event buffer flush interval in ms (default 5_000) */
  flushIntervalMs?: number;
  /** Max events held in buffer before forced flush (default 50) */
  bufferMaxSize?: number;
  /** HTTP request timeout to collector in ms (default 5_000) */
  transportTimeoutMs?: number;
  /** Whether to write local redaction audit logs (default true) */
  auditLog?: boolean;
  /** Path for local redaction audit logs (default ./rasp-audit.log) */
  auditLogPath?: string;
  /** Max audit log file size in bytes before rotation (default 10 MB) */
  auditLogMaxBytes?: number;
  /** Framework hint used in telemetry */
  framework?: string;
  /** Runtime hint used in telemetry (default "node") */
  runtime?: string;
}

export interface NormalizedRequest {
  method: string;
  path: string;
  query: Record<string, unknown>;
  headers: Record<string, string | string[] | undefined>;
  body: unknown;
  sourceIp?: string;
}

export interface DetectionResult {
  detectorName: string;
  eventType: string;
  severity: Severity;
  /** Human-readable description of what was detected */
  description: string;
  /** The matched value or pattern (will be redacted before sending) */
  matchedValue?: string;
  /** Which field/location triggered the detection */
  location?: string;
}

export interface EventPayload {
  projectId: string;
  agentId?: string;
  agentVersion?: string;
  runtime?: string;
  framework?: string;
  eventType: string;
  severity: Severity;
  action: AgentMode;
  method?: string;
  path?: string;
  sourceIp?: string;
  timestamp?: string;
  metadata: {
    redacted: true;
    matchedRule?: string;
    auditLoggedLocally?: boolean;
    [key: string]: unknown;
  };
}

export interface HeartbeatPayload {
  projectId: string;
  agentId: string;
  agentVersion?: string;
  runtime?: string;
  framework?: string;
  status: AgentStatus;
  mode: AgentMode;
  timestamp?: string;
}

export interface HeartbeatResponse {
  ok: boolean;
  killSwitch: boolean;
  policyVersion: string;
}

export interface RedactionAuditEntry {
  ts: string;
  agentId: string;
  projectId: string;
  eventType: string;
  redactedFields: string[];
  dropped: boolean;
  dropReason?: string;
}
