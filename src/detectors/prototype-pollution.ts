/**
 * Prototype pollution signature detector.
 *
 * Two strategies:
 *
 * 1. **Key scan** — flags any nested key equal to `__proto__`, `constructor`
 *    or `prototype`, plus dotted forms like `a.__proto__` and
 *    `a.constructor.prototype` used by some merge utilities.
 *
 * 2. **Value scan** — flags string values that look like a JSON-encoded
 *    pollution payload (e.g. `"__proto__": { ... }`), which is what attackers
 *    send when the application later parses the field with `JSON.parse`.
 *
 * Severity: `critical` — prototype pollution typically chains into RCE,
 * authentication bypass, or arbitrary file read.
 */
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
