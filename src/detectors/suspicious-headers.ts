import type { Detector } from "./base.js";
import type { DetectionResult, NormalizedRequest } from "../types.js";

const MAX_HEADER_VALUE_LENGTH = 8192;
const MAX_HEADERS_COUNT = 100;

/** Headers that should never contain URLs pointing elsewhere (Host injection) */
const HOST_INJECTION_PATTERN = /[^a-zA-Z0-9\-._:\[\]]/;

export class SuspiciousHeadersDetector implements Detector {
  readonly name = "suspicious-headers";

  detect(req: NormalizedRequest): DetectionResult | null {
    const headers = req.headers;
    const entries = Object.entries(headers);

    // Abnormal number of headers
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

      // Oversized header value
      if (v.length > MAX_HEADER_VALUE_LENGTH) {
        return {
          detectorName: this.name,
          eventType: "suspicious_headers",
          severity: "medium",
          description: `Oversized header value for '${name}' (${v.length} bytes)`,
          location: `header:${name}`,
        };
      }

      // Host header injection
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

      // X-Forwarded-For with internal IP injection (trying to spoof source)
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

      // Newline injection (header splitting)
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

function isPrivateIp(ip: string): boolean {
  return (
    /^127\./.test(ip) ||
    /^10\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    ip === "::1"
  );
}
