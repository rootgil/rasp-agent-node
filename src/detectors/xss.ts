/**
 * Cross-Site Scripting (XSS) signature detector.
 *
 * Scans `query` and `body` values for the most common reflected/stored XSS
 * payload shapes: `<script>`, `javascript:` URLs, inline event handlers,
 * `<iframe>`, `<svg onload=…>`, IE `expression(…)`, and the canonical
 * `<img src=x onerror=…>` probe.
 *
 * Severity: `high`.
 *
 * Known limits: signature-based, no HTML parser - an attacker who breaks the
 * payload across multiple parameters or uses very unusual encoding may evade
 * detection. The request `path` is not scanned to limit false positives on
 * legitimate URLs containing the substring `script`.
 */
import type { Detector } from "./base.js";
import { flattenValues } from "./base.js";
import type { DetectionResult, NormalizedRequest } from "../types.js";

const XSS_PATTERNS = [
  /<script[\s>]/i,
  /<\/script>/i,
  /javascript\s*:/i,
  /data\s*:\s*text\/html/i,
  /on\w+\s*=\s*["']?[^"'>]*(alert|confirm|prompt|eval|fetch|document|window)/i,
  /<iframe[\s>]/i,
  /<svg[\s>].*?on\w+/is,
  /expression\s*\(/i,
  /vbscript\s*:/i,
  /<img[^>]+src\s*=\s*["']?\s*x[^>]*onerror/i,
];

export class XssDetector implements Detector {
  readonly name = "xss";

  detect(req: NormalizedRequest): DetectionResult | null {
    const values = [
      ...flattenValues(req.query),
      ...flattenValues(req.body),
    ];

    for (const val of values) {
      for (const pattern of XSS_PATTERNS) {
        if (pattern.test(val)) {
          return {
            detectorName: this.name,
            eventType: "xss",
            severity: "high",
            description: "Cross-site scripting (XSS) pattern detected",
            matchedValue: val.slice(0, 200),
            location: "query/body",
          };
        }
      }
    }
    return null;
  }
}
