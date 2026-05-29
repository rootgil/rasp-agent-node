/**
 * Path traversal signature detector.
 *
 * Scans `query`, `body` and `path` for `../` and `..\` sequences, their
 * URL-encoded (`%2e%2e%2f`) and double-encoded (`%252e%252e`) variants,
 * NUL-byte truncation, and references to canonical loot files
 * (`/etc/passwd`, `/etc/shadow`, `win.ini`, `boot.ini`).
 *
 * Severity: `high`.
 *
 * Implementation note: each value is also tried after a single pass of
 * `decodeURIComponent` to catch the simplest encoding bypasses without
 * paying for a full normalisation pipeline.
 */
import type { Detector } from "./base.js";
import { flattenValues } from "./base.js";
import type { DetectionResult, NormalizedRequest } from "../types.js";

const PATH_PATTERNS = [
  /\.\.[/\\]/,
  /[/\\]\.\./,
  /%2e%2e[%2f%5c]/i,
  /%252e%252e/i,
  /\.\.%2f/i,
  /\.\.%5c/i,
  /\x00/,
  /\/etc\/passwd/i,
  /\/etc\/shadow/i,
  /\/windows\/win\.ini/i,
  /\/winnt\/win\.ini/i,
  /boot\.ini/i,
];

export class PathTraversalDetector implements Detector {
  readonly name = "path-traversal";

  detect(req: NormalizedRequest): DetectionResult | null {
    const values = [
      ...flattenValues(req.query),
      ...flattenValues(req.body),
      req.path,
    ];

    for (const val of values) {
      const decoded = tryDecode(val);
      for (const pattern of PATH_PATTERNS) {
        if (pattern.test(val) || pattern.test(decoded)) {
          return {
            detectorName: this.name,
            eventType: "path_traversal",
            severity: "high",
            description: "Path traversal pattern detected",
            matchedValue: val.slice(0, 200),
            location: "query/body/path",
          };
        }
      }
    }
    return null;
  }
}

/**
 * Best-effort `decodeURIComponent`. Falls back to the original string when
 * the input contains malformed percent-escapes.
 */
function tryDecode(val: string): string {
  try {
    return decodeURIComponent(val);
  } catch {
    return val;
  }
}
