import type { DetectionResult, NormalizedRequest } from "../types.js";

export interface Detector {
  readonly name: string;
  detect(req: NormalizedRequest): DetectionResult | null;
}

/**
 * Flatten a query/body object into an array of string values for pattern matching.
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
 * Flatten query/body into [key, value] pairs for pattern matching on keys too.
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
