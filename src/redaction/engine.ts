import { DEFAULT_REDACTION_PATTERNS, type RedactionPattern } from "./patterns.js";

export interface RedactionResult {
  redacted: unknown;
  redactedFields: string[];
}

export class RedactionEngine {
  private readonly patterns: RedactionPattern[];

  constructor(extraPatterns: RedactionPattern[] = []) {
    this.patterns = [...DEFAULT_REDACTION_PATTERNS, ...extraPatterns];
  }

  /**
   * Deep-clone and redact an arbitrary object.
   * Returns the sanitised copy and the list of field paths that were redacted.
   * Throws if the input cannot be safely processed.
   */
  redact(value: unknown, path = ""): RedactionResult {
    const redactedFields: string[] = [];
    const redacted = this.walk(value, path, redactedFields);
    return { redacted, redactedFields };
  }

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

  private shouldRedactKey(key: string): boolean {
    return this.patterns.some((p) => p.matchKey.test(key));
  }
}
