/**
 * Types describing a policy as distributed by the control plane and applied by
 * the agent. The wire shape returned by `GET /v1/policy` is
 * {@link DistributedPolicy}; the agent verifies its signature, then applies the
 * embedded {@link CustomRuleSpec}s, {@link RedactionConfig} and
 * {@link DataResidencyConfig}.
 */
import type { AgentMode, Severity } from "../types.js";

/**
 * A customer-defined detection rule, evaluated by the generic
 * CustomRuleDetector. This is the codeable form of the Addendum requirement
 * "customers can create custom rules used in the RASP agent by policy".
 */
export interface CustomRuleSpec {
  /** Stable id, surfaced as the matched rule in telemetry. */
  id: string;
  /** Human-readable name. */
  name?: string;
  /** Machine-readable event type emitted on match (e.g. `custom_rule`). */
  eventType?: string;
  /** Severity assigned to a match. */
  severity?: Severity;
  /** Which part of the request to inspect. */
  target?: "path" | "query" | "body" | "headers" | "any";
  /** Regex source string, tested case-insensitively against stringified values. */
  pattern: string;
  /** Optional description for the audit trail. */
  description?: string;
  /** Whether the rule is active. Defaults to true. */
  enabled?: boolean;
}

/** How to handle IP addresses found in values. */
export type IpRedactionMode = "hash" | "mask" | "passthrough";

/** Redaction directives pushed via policy (Addendum B.2). */
export interface RedactionConfig {
  /** denylist (default), allowlist, metadata-only, local-only. */
  mode?: "denylist" | "allowlist" | "metadata-only" | "local-only";
  /** Extra field-name regexes to redact (denylist additions). */
  customKeyPatterns?: string[];
  /** Field-name regexes that are always allowed through (allowlist mode). */
  allowKeyPatterns?: string[];
  /** Whether to apply built-in value detectors (Luhn, SIN, email, etc.). */
  valueRedaction?: boolean;
  /** IP handling. Defaults to "hash". */
  ipMode?: IpRedactionMode;
}

/** Data residency directives (Addendum B.3). */
export interface DataResidencyConfig {
  /** Strip all payload data, send only event metadata. */
  metadataOnly?: boolean;
  /** Keep all telemetry local; never send to the collector. */
  localOnly?: boolean;
  /** Only export these event types to the collector (selective export). */
  exportEventTypes?: string[];
  /** Only export blocked detections (not informational/monitor). */
  exportBlockedOnly?: boolean;
}

/** Wire shape returned by `GET /v1/policy`. */
export interface DistributedPolicy {
  version: number;
  channel: string;
  mode: AgentMode;
  detectionRules: CustomRuleSpec[] | null;
  redactionConfig: RedactionConfig | null;
  dataResidency: DataResidencyConfig | null;
  targetAgentVersion: string | null;
  signature: string;
  signingKeyId: string | null;
}
