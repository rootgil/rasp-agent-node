/**
 * Redaction engine — sanitises an event payload before it leaves the process.
 *
 * The engine performs a depth-first deep clone of the input. Any object key
 * matching one of the registered patterns is replaced with the literal
 * `[REDACTED]` string and its dotted path is appended to the returned
 * `redactedFields` list (used by the agent to write a local audit log).
 *
 * Design notes:
 *  - Matching is key-based only. The engine never inspects values, which
 *    avoids logging or memoising secrets.
 *  - The walker returns a new object — the input is never mutated.
 *  - The agent treats a thrown error here as a fatal redaction failure and
 *    drops the event entirely (see `RaspAgent.handleDetection`).
 */
import { DEFAULT_REDACTION_PATTERNS, type RedactionPattern } from "./patterns.js";

/** Output of {@link RedactionEngine.redact}. */
export interface RedactionResult {
  /** Deep-cloned, sanitised copy of the input value. */
  redacted: unknown;
  /** Dotted paths of every field that was replaced with `[REDACTED]`. */
  redactedFields: string[];
}

export class RedactionEngine {
  private readonly patterns: RedactionPattern[];

  /**
   * @param extraPatterns - Additional patterns appended to the bundled
   *   {@link DEFAULT_REDACTION_PATTERNS}. Useful for org-specific field
   *   names (e.g. `customer_dob`).
   */
  constructor(extraPatterns: RedactionPattern[] = []) {
    this.patterns = [...DEFAULT_REDACTION_PATTERNS, ...extraPatterns];
  }

  /**
   * Deep-clone `value` and redact sensitive keys.
   *
   * @param value - Any JSON-serialisable value (the event payload built by
   *   the agent).
   * @param path - Internal accumulator used for the dotted field path.
   *   Callers should leave it empty.
   * @returns The sanitised value and the list of redacted field paths.
   * @throws When the input cannot be safely walked (circular references,
   *   exotic objects). The agent catches this and drops the event.
   */
  redact(value: unknown, path = ""): RedactionResult {
    const redactedFields: string[] = [];
    const redacted = this.walk(value, path, redactedFields);
    return { redacted, redactedFields };
  }

  /**
   * Depth-first walker. Returns a new value tree where sensitive object
   * keys are replaced with `[REDACTED]` and accumulates the corresponding
   * dotted paths into `redactedFields`.
   */
  private walk(value: unknown, path: string, redactedFields: string[]): unknown {
    if (value === null || value === undefined) return value;

    if (Array.isArray(value)) {
      return value.map((item, i) => this.walk(item, `${path}[${i}]`, redactedFields));
    }

    if (typeof value === "object") {
      const result: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        const fieldPath = path ? `${path}.${k}` : k;
        if (this.shouldRedactKey(k)) {
          result[k] = "[REDACTED]";
          redactedFields.push(fieldPath);
        } else {
          result[k] = this.walk(v, fieldPath, redactedFields);
        }
      }
      return result;
    }

    return value;
  }

  /** True iff `key` matches at least one registered pattern. */
  private shouldRedactKey(key: string): boolean {
    return this.patterns.some((p) => p.matchKey.test(key));
  }
}
