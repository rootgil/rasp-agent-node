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
 */
import type { Detector } from "./base.js";
import { flattenValues } from "./base.js";
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
        return flattenValues(req.headers);
      case "any":
      default:
        return [
          req.path,
          ...flattenValues(req.query),
          ...flattenValues(req.body),
          ...flattenValues(req.headers),
        ];
    }
  }

  detect(req: NormalizedRequest): DetectionResult | null {
    for (const { spec, regex } of this.rules) {
      const values = this.valuesFor(req, spec.target ?? "any");
      for (const val of values) {
        if (typeof val !== "string") continue;
        if (regex.test(val)) {
          return {
            detectorName: spec.id,
            eventType: spec.eventType ?? "custom_rule",
            severity: spec.severity ?? "medium",
            description: spec.description ?? spec.name ?? `Custom rule ${spec.id} matched`,
            matchedValue: val.slice(0, 200),
            location: spec.target ?? "any",
          };
        }
      }
    }
    return null;
  }
}
