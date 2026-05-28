import type { Detector } from "./base.js";
import { flattenEntries, flattenValues } from "./base.js";
import type { DetectionResult, NormalizedRequest } from "../types.js";

const POLLUTION_KEY_PATTERNS = [
  /^__proto__$/,
  /^constructor$/,
  /^prototype$/,
  /\.__proto__/,
  /\.constructor\.prototype/,
];

const POLLUTION_VALUE_PATTERNS = [
  /"__proto__"\s*:/,
  /"constructor"\s*:\s*\{/,
  /"prototype"\s*:\s*\{/,
];

export class PrototypePollutionDetector implements Detector {
  readonly name = "prototype-pollution";

  detect(req: NormalizedRequest): DetectionResult | null {
    // Check keys in query/body
    const entries = [...flattenEntries(req.query), ...flattenEntries(req.body)];
    for (const [key] of entries) {
      for (const pattern of POLLUTION_KEY_PATTERNS) {
        if (pattern.test(key)) {
          return {
            detectorName: this.name,
            eventType: "prototype_pollution",
            severity: "critical",
            description: "Prototype pollution key detected in request",
            matchedValue: key,
            location: "query/body key",
          };
        }
      }
    }

    // Check serialised string values that look like polluted JSON
    const values = [...flattenValues(req.query), ...flattenValues(req.body)];
    for (const val of values) {
      for (const pattern of POLLUTION_VALUE_PATTERNS) {
        if (pattern.test(val)) {
          return {
            detectorName: this.name,
            eventType: "prototype_pollution",
            severity: "critical",
            description: "Prototype pollution pattern detected in serialised value",
            matchedValue: val.slice(0, 200),
            location: "query/body value",
          };
        }
      }
    }

    return null;
  }
}
