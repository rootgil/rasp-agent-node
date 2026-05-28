/**
 * {@link RaspAgent} — the entry point of the RASP runtime.
 *
 * Wires together five subsystems:
 *  1. Detectors        — pattern matchers run on every incoming request.
 *  2. Redaction engine — strips secrets/PII before anything leaves the process.
 *  3. Audit log        — local JSONL trace of every redaction action.
 *  4. Event buffer     — batches sanitised events to the collector.
 *  5. Heartbeat        — liveness signal + kill-switch / policy delivery channel.
 *
 * Invariants enforced here:
 *  - {@link RaspAgent.inspect} never throws (fail-open).
 *  - A detection is **never** enqueued before passing through the redaction
 *    engine; if redaction fails the event is dropped and audit-logged.
 *  - When the kill switch is received, inspection is disabled and the buffer
 *    is drained.
 */
import { validateConfig, COLLECTOR_URL, type ValidatedRaspConfig } from "./config.js";
import type {
  RaspConfig,
  NormalizedRequest,
  EventPayload,
  DetectionResult,
  AgentMode,
} from "./types.js";
import { RedactionEngine } from "./redaction/engine.js";
import { AuditLog } from "./redaction/audit-log.js";
import { TransportClient } from "./transport/client.js";
import { EventBuffer } from "./transport/buffer.js";
import { HeartbeatScheduler } from "./transport/heartbeat.js";
import { createDefaultDetectors, type Detector } from "./detectors/index.js";
import { EndpointObserver } from "./api-discovery/endpoint-observer.js";
import { DiscoveryBuffer } from "./api-discovery/discovery-buffer.js";

export class RaspAgent {
  /** Fully validated configuration with defaults applied. */
  readonly cfg: ValidatedRaspConfig;
  private readonly redaction: RedactionEngine;
  private readonly auditLog: AuditLog | null;
  private readonly client: TransportClient;
  private readonly buffer: EventBuffer;
  private readonly heartbeat: HeartbeatScheduler;
  private readonly detectors: Detector[];
  private readonly observer: EndpointObserver;
  private readonly discoveryBuffer: DiscoveryBuffer;
  /** Set to true after a kill-switch heartbeat — short-circuits {@link inspect}. */
  private killed = false;
  /**
   * Enforcement mode in effect. Initialised from `cfg.mode` and updated
   * whenever the collector returns a different mode in a heartbeat response.
   */
  private currentMode: AgentMode;

  /**
   * Build a new agent.
   *
   * The constructor validates the config (throws on bad input), instantiates
   * the subsystems and registers the default detectors. The heartbeat loop is
   * **not** started until {@link start} is called.
   *
   * @param rawConfig - User-supplied configuration. Validated via
   *   {@link validateConfig}; throws if required fields are missing.
   * @param extraDetectors - Optional custom detectors appended after the
   *   built-in set. They run in declaration order and the first non-null
   *   detection wins.
   */
  constructor(rawConfig: RaspConfig, extraDetectors: Detector[] = []) {
    this.cfg = validateConfig(rawConfig);
    this.currentMode = this.cfg.mode;

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
      onModeChange: (mode) => { this.currentMode = mode; },
      getMode: () => this.currentMode,
    });

    this.detectors = [...createDefaultDetectors(), ...extraDetectors];

    this.observer = new EndpointObserver();
    this.discoveryBuffer = new DiscoveryBuffer(this.client, this.observer, {
      projectId: this.cfg.projectId,
      agentId: this.cfg.agentId,
      flushIntervalMs: this.cfg.discoveryFlushIntervalMs,
    });
  }

  /**
   * Start the heartbeat loop. Idempotent.
   *
   * Call once during application bootstrap, after the framework middleware
   * has been registered. The buffer flush timer is already armed by the
   * constructor.
   */
  start(): void {
    this.heartbeat.start();
  }

  /**
   * Graceful shutdown.
   *
   * Stops the heartbeat timer, drains the buffer (final flush) and closes
   * the audit log file descriptor. Safe to await during process exit.
   */
  async stop(): Promise<void> {
    this.heartbeat.stop();
    await this.buffer.stop();
    await this.discoveryBuffer.stop();
    this.auditLog?.close();
  }

  /**
   * Run every detector against a normalised request.
   *
   * Detectors run in registration order; the first one returning a non-null
   * result wins. Detector exceptions are swallowed so that a bug in one
   * detector cannot take down the host application.
   *
   * @param req - Framework-agnostic request view.
   * @returns The first {@link DetectionResult} found, or `null` when the
   *   request is clean (or when the kill switch is active).
   *
   * @remarks Side-effects (redaction, audit log, buffering) happen in the
   *   background via {@link handleDetection}; this method itself returns
   *   synchronously.
   */
  inspect(req: NormalizedRequest): DetectionResult | null {
    if (this.killed) return null;

    // Observe passively before running detectors — fail open
    this.observer.observe(req);

    for (const detector of this.detectors) {
      let result: DetectionResult | null = null;
      try {
        result = detector.detect(req);
      } catch {
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
   * Build a raw event payload, redact it, audit-log locally and enqueue it.
   *
   * Control flow:
   *  1. Assemble the raw {@link EventPayload} from config + detection + request.
   *  2. Run it through the {@link RedactionEngine}. On failure → drop and
   *     audit-log with `dropped: true`.
   *  3. If any field was redacted → write a non-dropped audit-log line.
   *  4. Stamp `auditLoggedLocally` into the event metadata and enqueue.
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
      action: this.currentMode,
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

  /**
   * Handle a kill-switch heartbeat response.
   *
   * Disables inspection, drains the buffer and closes the audit log. The
   * heartbeat scheduler has already stopped itself by the time this is
   * called.
   */
  private handleKillSwitch(): void {
    this.killed = true;
    this.buffer.stop().catch(() => {});
    this.discoveryBuffer.stop().catch(() => {});
    this.auditLog?.close();
  }

  /**
   * Reserved for future dynamic policy refresh (rule deltas pushed via
   * heartbeat). Currently a no-op aside from acknowledging the version.
   */
  private handlePolicyChange(version: string): void {
    void version;
  }
}
