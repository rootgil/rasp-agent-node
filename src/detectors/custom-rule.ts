/**
 * Customer-defined rule detector.
 *
 * Evaluates {@link CustomRuleSpec}s pushed by the control plane via a signed
 * policy. This is the codeable form of the Addendum requirement that customers
 * can author detection rules that run inside the RASP agent. Rules are compiled
 * from regex source strings and matched against the chosen request target.
 *
 * Safety: rule compilation and matching are wrapped so a malformed pattern can
 * never crash the request hot path - a bad rule is simply skipped.
 *
 * Multi-match: {@link detectAll} returns every matching rule; {@link detect}
 * returns the highest-severity match (severity wins over rule order).
 */
import type { Detector } from "./base.js";
import { flattenValues, pickPrimaryDetection } from "./base.js";
import type { DetectionResult, NormalizedRequest } from "../types.js";
import type { CustomRuleSpec } from "../policy/types.js";

interface CompiledRule {
  spec: CustomRuleSpec;
  regex: RegExp;
}

export class CustomRuleDetector implements Detector {
  readonly name = "custom-rule";
  private readonly rules: CompiledRule[];

  constructor(specs: CustomRuleSpec[]) {
    this.rules = [];
    for (const spec of specs) {
      if (spec.enabled === false) continue;
      if (!spec.pattern) continue;
      if (spec.pattern.length > 200) continue;
      if (/(\+|\*)\{|\(.*\+.*\)[+*]|\(.*\*.*\)[+*]/.test(spec.pattern)) continue;
      try {
        this.rules.push({ spec, regex: new RegExp(spec.pattern, "i") });
      } catch {
        // Skip invalid regex - never throw at construction time.
      }
    }
  }

  /** Number of active compiled rules (useful for diagnostics/tests). */
  get size(): number {
    return this.rules.length;
  }

  private valuesFor(req: NormalizedRequest, target: CustomRuleSpec["target"]): string[] {
    switch (target) {
      case "path":
        return [req.path];
      case "query":
        return flattenValues(req.query);
      case "body":
        return flattenValues(req.body);
      case "headers":
        // Header *names* only — never match/exfiltrate Authorization/Cookie values.
        return Object.keys(req.headers);
      case "any":
      default:
        return [
          req.path,
          ...flattenValues(req.query),
          ...flattenValues(req.body),
          ...Object.keys(req.headers),
        ];
    }
  }

  private matchRule(
    { spec, regex }: CompiledRule,
    req: NormalizedRequest
  ): DetectionResult | null {
    const values = this.valuesFor(req, spec.target ?? "any");
    for (const val of values) {
      if (typeof val !== "string") continue;
      if (regex.test(val)) {
        return {
          detectorName: spec.id,
          eventType: spec.eventType ?? "custom_rule",
          severity: spec.severity ?? "medium",
          description: spec.description ?? spec.name ?? `Custom rule ${spec.id} matched`,
          // Fingerprinted in handleDetection; keep a short non-secret snippet for path/query only.
          matchedValue:
            spec.target === "headers" ? undefined : val.slice(0, 200),
          location: spec.target ?? "any",
        };
      }
    }
    return null;
  }

  /** Every custom rule that matches this request (policy array order). */
  detectAll(req: NormalizedRequest): DetectionResult[] {
    const matches: DetectionResult[] = [];
    for (const rule of this.rules) {
      const hit = this.matchRule(rule, req);
      if (hit) matches.push(hit);
    }
    return matches;
  }

  /** Highest-severity match, or null when nothing matches. */
  detect(req: NormalizedRequest): DetectionResult | null {
    return pickPrimaryDetection(this.detectAll(req));
  }
}
