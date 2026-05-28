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
