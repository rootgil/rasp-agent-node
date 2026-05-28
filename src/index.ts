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
  Severity,
  AgentMode,
  AgentStatus,
} from "./types.js";

export type { Detector } from "./detectors/index.js";
export { createDefaultDetectors } from "./detectors/index.js";
