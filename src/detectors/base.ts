/**
 * Shared contract and helpers for all detectors.
 *
 * A detector inspects a {@link NormalizedRequest} and reports a single
 * {@link DetectionResult} when a signature matches. Detectors are intentionally
 * stateless or near-stateless (e.g. {@link BolaDetector} keeps a per-IP window)
 * so they can be reordered, disabled, or stress-tested in isolation.
 *
 * Hard contract:
 *  - `detect` must be cheap (it runs in the request hot path).
 *  - `detect` must **never** throw. The agent catches anyway as a safety net,
 *    but a thrown error short-circuits the detector for the request and is a
 *    silent loss of coverage.
 */
import type { DetectionResult, NormalizedRequest, Severity } from "../types.js";

/**
 * Implementation contract for a single detector.
 */
export interface Detector {
  /** Unique identifier, surfaced in `DetectionResult.detectorName`. */
  readonly name: string;
  /**
   * Inspect a request.
   *
   * @returns A {@link DetectionResult} on the first match, or `null` if the
   *   request looks clean to this detector.
   */
  detect(req: NormalizedRequest): DetectionResult | null;
  /**
   * Optional: return every match for this detector (e.g. all custom rules).
   * When absent, {@link RaspAgent.inspect} falls back to {@link detect}.
   */
  detectAll?(req: NormalizedRequest): DetectionResult[];
}

/** Higher rank = more severe. Used to pick the primary detection. */
const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

export function severityRank(severity: Severity): number {
  return SEVERITY_RANK[severity] ?? 0;
}

/**
 * Pick the highest-severity detection. On a tie, keep the first in array order
 * (detector registration order / rule order).
 */
export function pickPrimaryDetection(
  results: DetectionResult[]
): DetectionResult | null {
  if (results.length === 0) return null;
  let primary = results[0]!;
  for (let i = 1; i < results.length; i++) {
    const candidate = results[i]!;
    if (severityRank(candidate.severity) > severityRank(primary.severity)) {
      primary = candidate;
    }
  }
  return primary;
}

/**
 * Recursively flatten an arbitrary value into the list of string-castable
 * leaves it contains.
 *
 * Used by signature-based detectors to obtain a flat list of values to run
 * regexes against, regardless of whether the input is a string, an array, or
 * a deeply nested object.
 *
 * @param value - The value to flatten. Objects and arrays are traversed.
 * @param depth - Internal recursion guard. Defaults to 0.
 * @returns The list of leaf string values. Numbers and booleans are coerced;
 *   `null`, `undefined`, functions and other non-stringifiable values are
 *   skipped.
 *
 * @remarks Recursion depth is capped at 6 to bound CPU/memory in case the
 *   request contains an attacker-controlled deeply nested object.
 */
export function flattenValues(value: unknown, depth = 0): string[] {
  if (depth > 6) return [];
  if (typeof value === "string") return [value];
  if (typeof value === "number" || typeof value === "boolean") return [String(value)];
  if (Array.isArray(value)) return value.flatMap((v) => flattenValues(v, depth + 1));
  if (value !== null && typeof value === "object") {
    return Object.values(value as Record<string, unknown>).flatMap((v) =>
      flattenValues(v, depth + 1)
    );
  }
  return [];
}

/**
 * Like {@link flattenValues}, but also exposes the dotted path leading to
 * each string leaf.
 *
 * Used when a detector needs to match against **keys** as well as values
 * (NoSQL `$gt`, prototype-pollution `__proto__`, …).
 *
 * @returns A list of `[dottedPath, leafStringValue]` tuples. Non-string
 *   leaves are dropped.
 *
 * @remarks Depth is capped at 6, same rationale as {@link flattenValues}.
 */
export function flattenEntries(
  value: unknown,
  depth = 0,
  prefix = ""
): Array<[key: string, value: string]> {
  if (depth > 6) return [];
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return Object.entries(value as Record<string, unknown>).flatMap(([k, v]) => {
      const fullKey = prefix ? `${prefix}.${k}` : k;
      const nested = flattenEntries(v, depth + 1, fullKey);
      const self: Array<[string, string]> = typeof v === "string" ? [[fullKey, v]] : [];
      return [...self, ...nested];
    });
  }
  return [];
}
