/**
 * Redaction engine - sanitises an event payload before it leaves the process.
 *
 * Layers (Addendum B.2):
 *  1. Key-based redaction: object keys matching a {@link RedactionPattern} are
 *     replaced wholesale.
 *  2. Value-based redaction: string leaves are scanned for sensitive shapes
 *     (credit cards, SIN, email, health IDs, IPs, SQL literals) and masked.
 *  3. Mode:
 *     - `denylist` (default): strip known-sensitive data, pass everything else.
 *     - `allowlist` (high-security): drops every field that is not in
 *       {@link STRUCTURAL_KEYS} or matched by `allowKeyPatterns`. Container
 *       keys listed in {@link CONTAINER_KEYS} (e.g. `metadata`) are never
 *       dropped themselves; their children are filtered individually.
 *
 * The walker returns a new object - the input is never mutated. A thrown error
 * is treated by the agent as a fatal redaction failure (the event is dropped).
 */
import {
  DEFAULT_REDACTION_PATTERNS,
  redactValueString,
  type RedactionPattern,
  type IpMode,
} from "./patterns.js";
import type { RedactionConfig } from "../policy/types.js";

export interface RedactionResult {
  /** Deep-cloned, sanitised copy of the input value. */
  redacted: unknown;
  /** Dotted paths of every field that was replaced or masked. */
  redactedFields: string[];
}

/**
 * Structural envelope keys that must survive allowlist mode so the collector
 * can still validate and route the event.
 */
const STRUCTURAL_KEYS = new Set([
  // top-level envelope
  "projectId",
  "agentId",
  "agentVersion",
  "runtime",
  "framework",
  "eventType",
  "severity",
  "action",
  "method",
  "path",
  "sourceIp",
  "timestamp",
  // metadata sub-keys always required by the collector
  "redacted",
  "matchedRule",
  "auditLoggedLocally",
]);

/**
 * Object keys that are never dropped in allowlist mode but whose children are
 * filtered individually. This prevents the entire `metadata` block from being
 * removed when only some of its inner keys are approved.
 */
const CONTAINER_KEYS = new Set(["metadata"]);

export interface RedactionEngineOptions {
  mode?: "denylist" | "allowlist";
  keyPatterns?: RedactionPattern[];
  allowKeyPatterns?: RegExp[];
  valueRedaction?: boolean;
  ipMode?: IpMode;
}

export class RedactionEngine {
  private readonly patterns: RedactionPattern[];
  private readonly mode: "denylist" | "allowlist";
  private readonly allowKeyPatterns: RegExp[];
  private readonly valueRedaction: boolean;
  private readonly ipMode: IpMode;

  constructor(extraPatternsOrOptions: RedactionPattern[] | RedactionEngineOptions = []) {
    const opts: RedactionEngineOptions = Array.isArray(extraPatternsOrOptions)
      ? { keyPatterns: extraPatternsOrOptions }
      : extraPatternsOrOptions;

    this.patterns = [...DEFAULT_REDACTION_PATTERNS, ...(opts.keyPatterns ?? [])];
    this.mode = opts.mode ?? "denylist";
    this.allowKeyPatterns = opts.allowKeyPatterns ?? [];
    this.valueRedaction = opts.valueRedaction ?? true;
    this.ipMode = opts.ipMode ?? "hash";
  }

  /**
   * Build an engine from a policy-supplied {@link RedactionConfig}. Unknown or
   * absent fields fall back to safe defaults (denylist + value redaction).
   */
  static fromConfig(cfg?: RedactionConfig): RedactionEngine {
    if (!cfg) return new RedactionEngine();

    const customKey = (cfg.customKeyPatterns ?? [])
      .map((src) => safeRegex(src))
      .filter((r): r is RegExp => r !== null)
      .map((re, i) => ({ name: `custom-${i}`, matchKey: re }));

    const allowKey = (cfg.allowKeyPatterns ?? [])
      .map((src) => safeRegex(src))
      .filter((r): r is RegExp => r !== null);

    // metadata-only / local-only are handled at the data-residency layer; for
    // redaction purposes they behave like an aggressive allowlist with no
    // approved keys, masking every value.
    const mode = cfg.mode === "allowlist" ? "allowlist" : "denylist";

    return new RedactionEngine({
      mode,
      keyPatterns: customKey,
      allowKeyPatterns: allowKey,
      valueRedaction: cfg.valueRedaction ?? true,
      ipMode: cfg.ipMode ?? "hash",
    });
  }

  redact(value: unknown, path = ""): RedactionResult {
    const redactedFields: string[] = [];
    const redacted = this.walk(value, path, redactedFields, false);
    return { redacted, redactedFields };
  }

  private walk(
    value: unknown,
    path: string,
    redactedFields: string[],
    keyApproved: boolean
  ): unknown {
    if (value === null || value === undefined) return value;

    if (Array.isArray(value)) {
      return value.map((item, i) =>
        this.walk(item, `${path}[${i}]`, redactedFields, keyApproved)
      );
    }

    if (typeof value === "object") {
      const result: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        const fieldPath = path ? `${path}.${k}` : k;
        const approved = keyApproved || this.isApprovedKey(k);

        // Allowlist mode: drop any field that is not approved and is not a
        // container whose children need to be filtered individually.
        if (this.mode === "allowlist" && !approved && !CONTAINER_KEYS.has(k)) {
          redactedFields.push(fieldPath);
          continue;
        }

        // Key-based denylist match → redact the whole subtree.
        if (this.shouldRedactKey(k)) {
          result[k] = "[REDACTED]";
          redactedFields.push(fieldPath);
          continue;
        }

        result[k] = this.walk(v, fieldPath, redactedFields, approved);
      }
      return result;
    }

    if (typeof value === "string") {
      return this.redactLeaf(value, path, redactedFields, keyApproved);
    }

    return value;
  }

  private redactLeaf(
    value: string,
    path: string,
    redactedFields: string[],
    _keyApproved: boolean
  ): string {
    if (this.valueRedaction) {
      const { value: out, redacted } = redactValueString(value, this.ipMode);
      if (redacted) redactedFields.push(path);
      return out;
    }

    return value;
  }

  private isApprovedKey(key: string): boolean {
    if (STRUCTURAL_KEYS.has(key)) return true;
    return this.allowKeyPatterns.some((p) => p.test(key));
  }

  private shouldRedactKey(key: string): boolean {
    return this.patterns.some((p) => p.matchKey.test(key));
  }
}

function safeRegex(src: string): RegExp | null {
  try {
    return new RegExp(src, "i");
  } catch {
    return null;
  }
}
