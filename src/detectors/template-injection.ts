import type { Detector } from "./base.js";
import { flattenValues } from "./base.js";
import type { DetectionResult, NormalizedRequest } from "../types.js";

const SSTI_PATTERNS = [
  // Twig / Jinja2 / Nunjucks / Pebble
  /\{\{.*\}\}/s,
  /\{%.*%\}/s,
  // ERB / EJS
  /<%[=\-]?.*%>/s,
  // Handlebars triple-stache
  /\{\{\{.*\}\}\}/s,
  // Thymeleaf
  /\$\{.*\}/s,
  // Velocity
  /#\{.*\}/s,
  // Freemarker
  /<#.*>/s,
  // Common math-eval probes
  /\$\{7\s*\*\s*7\}/,
  /\{\{7\s*\*\s*7\}\}/,
  /<%=\s*7\s*\*\s*7\s*%>/,
];

export class TemplateInjectionDetector implements Detector {
  readonly name = "template-injection";

  detect(req: NormalizedRequest): DetectionResult | null {
    const values = [...flattenValues(req.query), ...flattenValues(req.body)];

    for (const val of values) {
      for (const pattern of SSTI_PATTERNS) {
        if (pattern.test(val)) {
          return {
            detectorName: this.name,
            eventType: "template_injection",
            severity: "high",
            description: "Server-side template injection (SSTI) pattern detected",
            matchedValue: val.slice(0, 200),
            location: "query/body",
          };
        }
      }
    }
    return null;
  }
}
