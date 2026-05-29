/**
 * Server-Side Request Forgery (SSRF) signature detector.
 *
 * Flags request parameters carrying URLs that target destinations a
 * server-side fetch should rarely visit:
 *
 *  - Loopback addresses (`localhost`, `127.0.0.0/8`, `0.0.0.0`, `[::1]`).
 *  - RFC 1918 private ranges (`10/8`, `172.16/12`, `192.168/16`).
 *  - Cloud metadata endpoints (`169.254.169.254` for AWS/Azure,
 *    `metadata.google.internal` for GCP).
 *  - Dangerous protocols (`file://`, `gopher://`, `dict://`, `ftp://`).
 *
 * Severity: `high`.
 *
 * Known limits: matching is purely lexical. DNS-rebinding payloads
 * (`internal.attacker.com` resolving to `127.0.0.1`) and Unicode
 * homoglyphs in hostnames are not caught here - they need runtime DNS
 * inspection which is out of scope.
 */
import type { Detector } from "./base.js";
import { flattenValues } from "./base.js";
import type { DetectionResult, NormalizedRequest } from "../types.js";

const SSRF_PATTERNS = [
  /https?:\/\/localhost/i,
  /https?:\/\/127\.\d+\.\d+\.\d+/,
  /https?:\/\/0\.0\.0\.0/,
  /https?:\/\/\[::1\]/,
  /https?:\/\/10\.\d+\.\d+\.\d+/,
  /https?:\/\/172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/,
  /https?:\/\/192\.168\.\d+\.\d+/,
  /https?:\/\/169\.254\.169\.254/,
  /https?:\/\/metadata\.google\.internal/i,
  /https?:\/\/169\.254\.169\.254\/metadata/i,
  /^file:\/\//i,
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
            description: "SSRF - request targets an internal or metadata endpoint",
            matchedValue: val.slice(0, 200),
            location: "query/body",
          };
        }
      }
    }
    return null;
  }
}
