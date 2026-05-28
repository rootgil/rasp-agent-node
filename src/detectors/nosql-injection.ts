import type { Detector } from "./base.js";
import { flattenEntries, flattenValues } from "./base.js";
import type { DetectionResult, NormalizedRequest } from "../types.js";

/** MongoDB operator patterns injected as string values */
const NOSQL_STRING_PATTERNS = [
  /\$where\s*:/i,
  /\$regex\s*:/i,
  /\{\s*\$gt\s*:/i,
  /\{\s*\$lt\s*:/i,
  /\{\s*\$ne\s*:/i,
  /\{\s*\$in\s*:/i,
  /\{\s*\$nin\s*:/i,
  /\{\s*\$or\s*:/i,
  /\{\s*\$and\s*:/i,
  /\{\s*\$not\s*:/i,
  /\{\s*\$exists\s*:/i,
  /mapReduce\s*\(/i,
];

/** MongoDB operators injected as object keys */
const NOSQL_KEY_PATTERN = /^\$[a-z]+$/i;

export class NoSqlInjectionDetector implements Detector {
  readonly name = "nosql-injection";

  detect(req: NormalizedRequest): DetectionResult | null {
    // Check string values for serialised operator patterns
    const values = [...flattenValues(req.query), ...flattenValues(req.body)];
    for (const val of values) {
      for (const pattern of NOSQL_STRING_PATTERNS) {
        if (pattern.test(val)) {
          return {
            detectorName: this.name,
            eventType: "nosql_injection",
            severity: "high",
            description: "NoSQL injection pattern detected in value",
            matchedValue: val.slice(0, 200),
            location: "query/body",
          };
        }
      }
    }

    // Check object keys for $ operators (e.g. body: { password: { $gt: "" } })
    const entries = [...flattenEntries(req.query), ...flattenEntries(req.body)];
    for (const [key] of entries) {
      const leaf = key.split(".").pop() ?? "";
      if (NOSQL_KEY_PATTERN.test(leaf)) {
        return {
          detectorName: this.name,
          eventType: "nosql_injection",
          severity: "high",
          description: "NoSQL operator key detected in request object",
          matchedValue: key,
          location: "query/body",
        };
      }
    }

    return null;
  }
}
