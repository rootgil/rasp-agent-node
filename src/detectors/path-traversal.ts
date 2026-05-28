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

function tryDecode(val: string): string {
  try {
    return decodeURIComponent(val);
  } catch {
    return val;
  }
}
