/**
 * Suspicious HTTP-header detector.
 *
 * Catches a handful of abuse patterns that don't fit elsewhere:
 *
 *  - Header floods (more than {@link MAX_HEADERS_COUNT} headers).
 *  - Oversized header values (> {@link MAX_HEADER_VALUE_LENGTH} bytes).
 *  - `Host` headers containing characters outside the legal hostname set
 *    (Host-header injection probes).
 *  - `X-Forwarded-For` values smuggling RFC1918 addresses (source-IP
 *    spoofing toward downstream services that trust the header).
 *  - CRLF (`\r` / `\n`) anywhere in a header value (HTTP response
 *    splitting / log injection).
 *
 * Severity is `medium` for the structural anomalies (count, size,
 * `X-Forwarded-For` spoof, host-header injection) and `high` for newline
 * injection, which is more directly weaponisable.
 */
import type { Detector } from "./base.js";
import type { DetectionResult, NormalizedRequest } from "../types.js";

/** Threshold above which a single header value is treated as suspicious. */
const MAX_HEADER_VALUE_LENGTH = 8192;
/** Threshold above which the header count is treated as suspicious. */
const MAX_HEADERS_COUNT = 100;

/**
 * Characters allowed in a legal `Host` header. Anything outside this set
 * triggers a host-header-injection finding.
 */
const HOST_INJECTION_PATTERN = /[^a-zA-Z0-9\-._:\[\]]/;

export class SuspiciousHeadersDetector implements Detector {
  readonly name = "suspicious-headers";

  detect(req: NormalizedRequest): DetectionResult | null {
    const headers = req.headers;
    const entries = Object.entries(headers);

    if (entries.length > MAX_HEADERS_COUNT) {
      return {
        detectorName: this.name,
        eventType: "suspicious_headers",
        severity: "medium",
        description: `Abnormal header count: ${entries.length}`,
        location: "headers",
      };
    }

    for (const [name, value] of entries) {
      const v = Array.isArray(value) ? value.join(", ") : value ?? "";

      if (v.length > MAX_HEADER_VALUE_LENGTH) {
        return {
          detectorName: this.name,
          eventType: "suspicious_headers",
          severity: "medium",
          description: `Oversized header value for '${name}' (${v.length} bytes)`,
          location: `header:${name}`,
        };
      }

      if (name.toLowerCase() === "host" && HOST_INJECTION_PATTERN.test(v)) {
        return {
          detectorName: this.name,
          eventType: "host_header_injection",
          severity: "medium",
          description: "Suspicious characters in Host header",
          matchedValue: v.slice(0, 200),
          location: "header:host",
        };
      }

      if (name.toLowerCase() === "x-forwarded-for") {
        const ips = v.split(",").map((s) => s.trim());
        for (const ip of ips) {
          if (isPrivateIp(ip)) {
            return {
              detectorName: this.name,
              eventType: "suspicious_headers",
              severity: "medium",
              description: "Private IP injected in X-Forwarded-For header",
              matchedValue: ip,
              location: "header:x-forwarded-for",
            };
          }
        }
      }

      if (/[\r\n]/.test(v)) {
        return {
          detectorName: this.name,
          eventType: "header_injection",
          severity: "high",
          description: `Newline injection detected in header '${name}'`,
          matchedValue: v.slice(0, 200),
          location: `header:${name}`,
        };
      }
    }

    return null;
  }
}

/**
 * True iff `ip` belongs to a loopback or RFC1918 private range.
 *
 * Used only to flag client-supplied `X-Forwarded-For` values pretending to
 * originate from a trusted internal host.
 */
function isPrivateIp(ip: string): boolean {
  return (
    /^127\./.test(ip) ||
    /^10\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    ip === "::1"
  );
}
