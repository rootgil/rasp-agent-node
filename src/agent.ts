import { validateConfig, COLLECTOR_URL, type ValidatedRaspConfig } from "./config.js";
import type {
  RaspConfig,
  NormalizedRequest,
  EventPayload,
  DetectionResult,
} from "./types.js";
import { RedactionEngine } from "./redaction/engine.js";
import { AuditLog } from "./redaction/audit-log.js";
import { TransportClient } from "./transport/client.js";
import { EventBuffer } from "./transport/buffer.js";
import { HeartbeatScheduler } from "./transport/heartbeat.js";
import { createDefaultDetectors, type Detector } from "./detectors/index.js";

export class RaspAgent {
  readonly cfg: ValidatedRaspConfig;
  private readonly redaction: RedactionEngine;
  private readonly auditLog: AuditLog | null;
  private readonly client: TransportClient;
  private readonly buffer: EventBuffer;
  private readonly heartbeat: HeartbeatScheduler;
  private readonly detectors: Detector[];
  private killed = false;

  constructor(rawConfig: RaspConfig, extraDetectors: Detector[] = []) {
    this.cfg = validateConfig(rawConfig);

    this.redaction = new RedactionEngine();

    this.auditLog = this.cfg.auditLog
      ? new AuditLog(this.cfg.auditLogPath, this.cfg.auditLogMaxBytes)
      : null;

    this.client = new TransportClient({
      collectorUrl: COLLECTOR_URL,
      apiKey: this.cfg.apiKey,
      timeoutMs: this.cfg.transportTimeoutMs,
    });

    this.buffer = new EventBuffer(this.client, {
      flushIntervalMs: this.cfg.flushIntervalMs,
      maxSize: this.cfg.bufferMaxSize,
    });

    this.heartbeat = new HeartbeatScheduler(this.client, this.cfg, {
      onKillSwitch: () => this.handleKillSwitch(),
      onPolicyChange: (version) => this.handlePolicyChange(version),
    });

    this.detectors = [...createDefaultDetectors(), ...extraDetectors];
  }

  /**
   * Start the agent: begin heartbeat loop.
   * Call once during application bootstrap.
   */
  start(): void {
    this.heartbeat.start();
  }

  /**
   * Graceful shutdown: flush pending events and stop timers.
   */
  async stop(): Promise<void> {
    this.heartbeat.stop();
    await this.buffer.stop();
    this.auditLog?.close();
  }

  /**
   * Inspect an incoming request through all detectors.
   * Returns the first DetectionResult found, or null.
   * Must never throw — all errors are caught internally.
   */
  inspect(req: NormalizedRequest): DetectionResult | null {
    if (this.killed) return null;

    for (const detector of this.detectors) {
      let result: DetectionResult | null = null;
      try {
        result = detector.detect(req);
      } catch {
        // Detector failure — fail open, skip this detector.
        continue;
      }

      if (result) {
        this.handleDetection(result, req).catch(() => {});
        return result;
      }
    }
    return null;
  }

  /**
   * Build the event payload, redact it, audit-log locally, and enqueue for transport.
   */
  private async handleDetection(
    detection: DetectionResult,
    req: NormalizedRequest
  ): Promise<void> {
    const raw: Omit<EventPayload, "metadata"> & { metadata: Record<string, unknown> } = {
      projectId: this.cfg.projectId,
      agentId: this.cfg.agentId,
      agentVersion: this.cfg.agentVersion,
      runtime: this.cfg.runtime,
      framework: this.cfg.framework,
      eventType: detection.eventType,
      severity: detection.severity,
      action: this.cfg.mode,
      method: req.method,
      path: req.path,
      sourceIp: req.sourceIp,
      timestamp: new Date().toISOString(),
      metadata: {
        redacted: true,
        matchedRule: detection.detectorName,
        detectorDescription: detection.description,
        location: detection.location,
        matchedValue: detection.matchedValue,
      },
    };

    let redacted: unknown;
    let redactedFields: string[];

    try {
      const result = this.redaction.redact(raw);
      redacted = result.redacted;
      redactedFields = result.redactedFields;
    } catch (err) {
      this.auditLog?.write({
        ts: new Date().toISOString(),
        agentId: this.cfg.agentId,
        projectId: this.cfg.projectId,
        eventType: detection.eventType,
        redactedFields: [],
        dropped: true,
        dropReason: err instanceof Error ? err.message : "redaction_failed",
      });
      return;
    }

    const auditLoggedLocally = redactedFields.length > 0;

    if (auditLoggedLocally) {
      this.auditLog?.write({
        ts: new Date().toISOString(),
        agentId: this.cfg.agentId,
        projectId: this.cfg.projectId,
        eventType: detection.eventType,
        redactedFields,
        dropped: false,
      });
    }

    const event = redacted as EventPayload;
    (event.metadata as Record<string, unknown>)["auditLoggedLocally"] = auditLoggedLocally;

    this.buffer.enqueue(event);
  }

  private handleKillSwitch(): void {
    this.killed = true;
    this.buffer.stop().catch(() => {});
    this.auditLog?.close();
  }

  private handlePolicyChange(version: string): void {
    // Future: re-fetch rules from the platform.
    void version;
  }
}
