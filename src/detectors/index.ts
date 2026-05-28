/**
 * Default detector set bundled with the agent.
 *
 * Order matters: {@link RaspAgent.inspect} returns on the first non-null
 * detection, so detectors with higher signal/lower false-positive rates and
 * higher severity come first.
 */
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

export { type Detector } from "./base.js";

/**
 * Build a fresh array of the bundled detectors.
 *
 * Each call returns brand-new detector instances — important because a few
 * detectors (notably {@link BolaDetector}) carry per-IP state.
 */
export function createDefaultDetectors(): Detector[] {
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
