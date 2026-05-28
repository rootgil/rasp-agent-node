import type { Detector } from "./base.js";
import { flattenValues } from "./base.js";
import type { DetectionResult, NormalizedRequest } from "../types.js";

/** Internal / cloud-metadata destinations that should never be user-supplied */
const SSRF_PATTERNS = [
  // Loopback
  /https?:\/\/localhost/i,
  /https?:\/\/127\.\d+\.\d+\.\d+/,
  /https?:\/\/0\.0\.0\.0/,
  /https?:\/\/\[::1\]/,
  // RFC1918 private ranges
  /https?:\/\/10\.\d+\.\d+\.\d+/,
  /https?:\/\/172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/,
  /https?:\/\/192\.168\.\d+\.\d+/,
  // AWS metadata
  /https?:\/\/169\.254\.169\.254/,
  // GCP metadata
  /https?:\/\/metadata\.google\.internal/i,
  // Azure metadata
  /https?:\/\/169\.254\.169\.254\/metadata/i,
  // file:// protocol
  /^file:\/\//i,
  // gopher / dict / ftp abuse
  /^(gopher|dict|ftp):\/\//i,
];

export class SsrfDetector implements Detector {
  readonly name = "ssrf";

  detect(req: NormalizedRequest): DetectionResult | null {
    const values = [...flattenValues(req.query), ...flattenValues(req.body)];

    for (const val of values) {
      for (const pattern of SSRF_PATTERNS) {
        if (pattern.test(val)) {
          return {
            detectorName: this.name,
            eventType: "ssrf",
            severity: "high",
            description: "SSRF — request targets an internal or metadata endpoint",
            matchedValue: val.slice(0, 200),
            location: "query/body",
          };
        }
      }
    }
    return null;
  }
}
