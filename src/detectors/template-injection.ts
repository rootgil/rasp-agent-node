/**
 * Server-Side Template Injection (SSTI) signature detector.
 *
 * Looks for the canonical delimiter shapes of popular server-side template
 * engines:
 *  - `{{ … }}` / `{% … %}` — Twig, Jinja2, Nunjucks, Pebble.
 *  - `<% … %>` — ERB, EJS.
 *  - `{{{ … }}}` — Handlebars triple-stache.
 *  - `${ … }` — Thymeleaf (and JSP EL).
 *  - `#{ … }` — Velocity.
 *  - `<#… >` — Freemarker.
 *
 * Also matches the classic `7*7` math probe in each delimiter style — a
 * cheap, very high-signal indicator.
 *
 * Severity: `high`.
 *
 * Known limits: applications that legitimately echo back template-like
 * strings (CMS editors, code paste forms) may produce false positives.
 */
import type { Detector } from "./base.js";
import { flattenValues } from "./base.js";
import type { DetectionResult, NormalizedRequest } from "../types.js";

const SSTI_PATTERNS = [
  /\{\{.*\}\}/s,
  /\{%.*%\}/s,
  /<%[=\-]?.*%>/s,
  /\{\{\{.*\}\}\}/s,
  /\$\{.*\}/s,
  /#\{.*\}/s,
  /<#.*>/s,
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
