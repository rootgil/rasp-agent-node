/**
 * Public entry point for `@queno/agent-node`.
 *
 * Re-exports the runtime surface that customer applications are expected to
 * consume:
 *  - {@link RaspAgent} - the agent lifecycle object (start, stop, inspect).
 *  - {@link validateConfig} - Zod-backed config validator (throws on bad input).
 *  - Framework integrations: Express middleware, Fastify plugin, NestJS middleware.
 *  - Public types describing config, requests, detections, events and heartbeats.
 *  - The {@link Detector} contract and {@link createDefaultDetectors} factory so
 *    integrators can extend or replace the bundled detector set.
 *
 * Nothing else in `src/` is part of the supported API.
 */
export { RaspAgent } from "./agent.js";
export { validateConfig } from "./config.js";
export { createExpressMiddleware } from "./integrations/express.js";
export { createFastifyPlugin } from "./integrations/fastify.js";
export { createNestMiddleware } from "./integrations/nestjs.js";

export type {
  RaspConfig,
  NormalizedRequest,
  DetectionResult,
  EventPayload,
  HeartbeatPayload,
  HeartbeatResponse,
  DiscoveryEntry,
  DiscoveryPayload,
  AuthStatus,
  Severity,
  AgentMode,
  AgentStatus,
} from "./types.js";

export type { Detector } from "./detectors/index.js";
export { createDefaultDetectors } from "./detectors/index.js";
export { CustomRuleDetector } from "./detectors/custom-rule.js";
export {
  instrumentDatabaseDrivers,
  instrumentPrismaClient,
  verifyHookIntegrity,
} from "./db-hooks/instrument.js";

export {
  SecureStore,
  startSelfProtection,
  detectDebugger,
} from "./self-protect.js";
export type { SelfProtectionOptions } from "./self-protect.js";

export type {
  DistributedPolicy,
  CustomRuleSpec,
  RedactionConfig,
  DataResidencyConfig,
  IpRedactionMode,
} from "./policy/types.js";
