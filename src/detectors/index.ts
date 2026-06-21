/**
 * Default detector set bundled with the agent.
 *
 * Detection rules are now entirely policy-driven: the control plane publishes
 * a signed policy containing {@link CustomRuleSpec}[] which the agent compiles
 * into a {@link CustomRuleDetector} at runtime via {@link RaspAgent.applyPolicy}.
 *
 * The built-in detector classes (SqlInjectionDetector, XssDetector, …) are
 * kept and exported so callers can pass them via {@link RaspConfig.extraDetectors}
 * as an offline fallback, but they are no longer activated by default.
 */
export { type Detector } from "./base.js";

// Named re-exports so callers can compose their own detector chains.
export { SqlInjectionDetector } from "./sql-injection.js";
export { XssDetector } from "./xss.js";
export { CommandInjectionDetector } from "./command-injection.js";
export { PathTraversalDetector } from "./path-traversal.js";
export { NoSqlInjectionDetector } from "./nosql-injection.js";
export { SsrfDetector } from "./ssrf.js";
export { PrototypePollutionDetector } from "./prototype-pollution.js";
export { TemplateInjectionDetector } from "./template-injection.js";
export { SuspiciousHeadersDetector } from "./suspicious-headers.js";
export { BolaDetector } from "./bola.js";

import type { Detector } from "./base.js";
import { SqlInjectionDetector } from "./sql-injection.js";
import { XssDetector } from "./xss.js";
import { CommandInjectionDetector } from "./command-injection.js";
import { PathTraversalDetector } from "./path-traversal.js";
import { NoSqlInjectionDetector } from "./nosql-injection.js";
import { SsrfDetector } from "./ssrf.js";
import { PrototypePollutionDetector } from "./prototype-pollution.js";
import { TemplateInjectionDetector } from "./template-injection.js";
import { SuspiciousHeadersDetector } from "./suspicious-headers.js";
import { BolaDetector } from "./bola.js";

/**
 * Built-in signature detectors for offline / test usage without a signed policy.
 */
export function createOfflineDetectors(): Detector[] {
  return [
    new SqlInjectionDetector(),
    new XssDetector(),
    new CommandInjectionDetector(),
    new PathTraversalDetector(),
    new NoSqlInjectionDetector(),
    new SsrfDetector(),
    new PrototypePollutionDetector(),
    new TemplateInjectionDetector(),
    new SuspiciousHeadersDetector(),
    new BolaDetector(),
  ];
}

/**
 * Returns an empty detector chain.
 *
 * All detection is now driven by the signed policy distributed by the control
 * plane. The agent receives detection rules via its heartbeat, compiles them
 * into a {@link CustomRuleDetector}, and rebuilds its chain without a restart.
 *
 * Passing built-in detectors via {@link RaspConfig.extraDetectors} still works
 * as an explicit offline fallback.
 */
export function createDefaultDetectors() {
  return [];
}
