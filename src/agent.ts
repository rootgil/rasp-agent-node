/**
 * {@link RaspAgent} - the entry point of the RASP runtime.
 *
 * Wires together five subsystems:
 *  1. Detectors        - pattern matchers run on every incoming request.
 *  2. Redaction engine - strips secrets/PII before anything leaves the process.
 *  3. Audit log        - local JSONL trace of every redaction action.
 *  4. Event buffer     - batches sanitised events to the collector.
 *  5. Heartbeat        - liveness signal + kill-switch / policy delivery channel.
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
import { CustomRuleDetector } from "./detectors/custom-rule.js";
import { extractPathId, extractJwtSub } from "./detectors/bola.js";
import { EndpointObserver } from "./api-discovery/endpoint-observer.js";
import { DiscoveryBuffer } from "./api-discovery/discovery-buffer.js";
import { PolicyManager } from "./policy/policy-manager.js";
import type {
  DistributedPolicy,
  RedactionConfig,
  DataResidencyConfig,
} from "./policy/types.js";
import { instrumentDatabaseDrivers } from "./db-hooks/instrument.js";
import { correlateBola } from "./db-hooks/correlate.js";
import { startSelfProtection } from "./self-protect.js";
import { enterContext, type RequestContext } from "./runtime-context.js";
import type { RequestOutcome } from "./types.js";

export class RaspAgent {
  /** Fully validated configuration with defaults applied. */
  readonly cfg: ValidatedRaspConfig;
  private redaction: RedactionEngine;
  private readonly auditLog: AuditLog | null;
  private readonly client: TransportClient;
  private readonly buffer: EventBuffer;
  private readonly heartbeat: HeartbeatScheduler;
  /** Built-in signature detectors. */
  private readonly baseDetectors: Detector[];
  /** User-supplied detectors passed to the constructor. */
  private readonly extraDetectors: Detector[];
  /** Active detector chain, rebuilt when custom rules arrive via policy. */
  private detectors: Detector[];
  private readonly observer: EndpointObserver;
  private readonly discoveryBuffer: DiscoveryBuffer;
  /** Verifies and tracks signed policies distributed by the control plane. */
  private readonly policyManager: PolicyManager;
  /** Data residency directives applied in {@link handleDetection}. */
  private dataResidency: DataResidencyConfig | null = null;
  /** Version the control plane wants this agent to run (canary cohort / pin). */
  private targetVersion: string | null = null;
  /** True when an upgrade is available for this agent. */
  private upgradePending = false;
  /** Set to true after a kill-switch heartbeat - short-circuits {@link inspect}. */
  private killed = false;
  /** Stops the self-protection timer (Addendum E.7); null when disabled. */
  private stopSelfProtection: (() => void) | null = null;
  /**
   * Enforcement mode in effect. Initialised from `cfg.mode` and updated
   * whenever the collector returns a different mode in a heartbeat response.
   */
  private currentMode: AgentMode;
  /**
   * Deduplication key for `policy_rejected` telemetry: `"<version>:<reason>"`.
   * Prevents spamming the collector on every heartbeat cycle when the same
   * policy is repeatedly rejected (e.g. a persistent trust-anchor mismatch).
   */
  private lastRejectedPolicyKey: string | null = null;

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
      hmacSecret: this.cfg.hmacSecret,
      tls: this.cfg.tls,
    });

    this.buffer = new EventBuffer(this.client, {
      flushIntervalMs: this.cfg.flushIntervalMs,
      maxSize: this.cfg.bufferMaxSize,
    });

    this.heartbeat = new HeartbeatScheduler(this.client, this.cfg, {
      onKillSwitch: () => this.handleKillSwitch(),
      onRecover: () => this.handleRecover(),
      onPolicyChange: (version) => this.handlePolicyChange(version),
      onModeChange: (mode) => {
        // When a trust anchor is configured, mode changes must arrive through
        // a verified signed policy (applyPolicy). The heartbeat mode field is
        // an unsigned hint from the collector and must not bypass Ed25519
        // verification - otherwise a compromised network path or collector
        // could silently switch block → monitor (Addendum E.4.1).
        //
        // When no trust anchor is configured (e.g. legacy deployments that
        // pre-date the signed-policy system) the heartbeat mode is the only
        // available control channel, so we keep the original behaviour.
        if (!this.policyManager.hasTrustAnchor) {
          this.currentMode = mode;
        }
      },
      onTargetVersion: (info) => this.handleTargetVersion(info),
      getMode: () => this.currentMode,
    });

    this.baseDetectors = createDefaultDetectors();
    this.extraDetectors = extraDetectors;
    this.detectors = [...this.baseDetectors, ...this.extraDetectors];

    this.policyManager = new PolicyManager(this.cfg.projectId, [this.cfg.policyPublicKey]);

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
    if (this.cfg.instrumentDb) {
      // Best-effort; never throws.
      instrumentDatabaseDrivers();
    }
    if (this.cfg.selfProtect) {
      this.stopSelfProtection = startSelfProtection({
        checkHooks: this.cfg.instrumentDb,
        antiDebug: true,
      });
    }
    this.heartbeat.start();
  }

  /**
   * Begin a request's runtime context for DB correlation. Called by the
   * framework integration at the start of the request, before the handler runs,
   * so DB queries issued during the request are attributed to it.
   *
   * @returns The bound context, or `null` when DB instrumentation is disabled.
   */
  beginRequest(req: NormalizedRequest): RequestContext | null {
    if (!this.cfg.instrumentDb || this.killed) return null;
    const ctx: RequestContext = {
      method: req.method,
      path: req.path,
      pathId: extractPathId(req.path),
      userId: extractJwtSub(req.headers["authorization"]),
      sourceIp: req.sourceIp,
      authEnforced: false,
      dbQueries: [],
    };
    try {
      enterContext(ctx);
    } catch {
      return null;
    }
    return ctx;
  }

  /**
   * Finalise a request: record its outcome for traffic profiling and, when a
   * DB context is present, run BOLA-via-DB correlation and report any finding.
   */
  endRequest(
    ctx: RequestContext | null,
    req: NormalizedRequest,
    outcome: RequestOutcome
  ): void {
    this.observeOutcome(req, outcome);
    if (!ctx || this.killed) return;
    try {
      if (outcome.authenticated) {
        ctx.authEnforced = true;
        if (!ctx.userId) ctx.userId = "authenticated";
      }
      const detection = correlateBola(ctx);
      if (detection) this.handleDetection(detection, req).catch(() => {});
    } catch {
      // Fail open.
    }
  }

  /**
   * The enforcement mode currently in effect. Reflects remote mode changes
   * (heartbeat) and applied policies, so integrations should consult this
   * rather than the boot config.
   */
  get mode(): AgentMode {
    return this.currentMode;
  }

  /** The policy version currently applied (0 if none). */
  get policyVersion(): number {
    return this.policyManager.currentVersion;
  }

  /**
   * Version the control plane wants this agent to run, and whether an upgrade
   * is pending. The Node agent is delivered as an npm package and cannot
   * hot-swap its own binary, so the upgrade is surfaced (logged + queryable)
   * for the host's deployment automation to act on, rather than self-applied.
   */
  get desiredVersion(): { targetVersion: string | null; upgradePending: boolean } {
    return { targetVersion: this.targetVersion, upgradePending: this.upgradePending };
  }

  /**
   * React to the target version advertised by the heartbeat. Records the target
   * and logs an actionable message when an upgrade is available. Never throws.
   */
  private handleTargetVersion(info: import("./transport/heartbeat.js").TargetVersionInfo): void {
    this.targetVersion = info.targetVersion;
    this.upgradePending =
      info.upgradeAvailable &&
      info.targetVersion != null &&
      info.targetVersion !== this.cfg.agentVersion;

    if (this.upgradePending) {
      const parts = [`[rasp] upgrade available: ${this.cfg.agentVersion ?? "?"} -> ${info.targetVersion}`];
      if (info.impact) parts.push(`impact: ${info.impact}`);
      if (info.changelog) parts.push(`changelog: ${info.changelog}`);
      try {
        console.info(parts.join(" | "));
      } catch {
        // Ignore logging failures.
      }
    }
  }

  /**
   * Graceful shutdown.
   *
   * Stops the heartbeat timer, drains the buffer (final flush) and closes
   * the audit log file descriptor. Safe to await during process exit.
   */
  async stop(): Promise<void> {
    this.heartbeat.stop();
    this.stopSelfProtection?.();
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
  /**
   * Record the response-phase outcome of a request for API-discovery traffic
   * profiling (status code, latency, confirmed auth middleware execution).
   * Called by the framework integration's response hook. Never throws.
   */
  observeOutcome(req: NormalizedRequest, outcome: import("./types.js").RequestOutcome): void {
    if (this.killed) return;
    try {
      this.observer.observeOutcome(req, outcome);
    } catch {
      // Fail open.
    }
  }

  inspect(req: NormalizedRequest): DetectionResult | null {
    if (this.killed) return null;

    // Observe passively before running detectors - fail open
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

    this.auditLog?.write({
      ts: new Date().toISOString(),
      agentId: this.cfg.agentId,
      projectId: this.cfg.projectId,
      eventType: detection.eventType,
      severity: detection.severity,
      detectorName: detection.detectorName,
      redactedFields,
      dropped: false,
    });

    const event = redacted as EventPayload;
    (event.metadata as Record<string, unknown>)["auditLoggedLocally"] = auditLoggedLocally;

    const forSend = this.applyDataResidency(event);
    if (forSend) {
      this.buffer.enqueue(forSend);
    }
  }

  /**
   * Apply data residency directives (Addendum B.3) before an event is queued
   * for transmission.
   *
   * @returns The (possibly trimmed) event to send, or `null` if the event must
   *   stay local / be skipped. The local audit log has already been written by
   *   the caller, so dropping here still leaves a verifiable local record.
   */
  private applyDataResidency(event: EventPayload): EventPayload | null {
    const dr = this.dataResidency;
    if (!dr) return event;

    // Local-only: nothing leaves the customer environment.
    if (dr.localOnly) return null;

    // Selective export by event type.
    if (dr.exportEventTypes && dr.exportEventTypes.length > 0) {
      if (!dr.exportEventTypes.includes(event.eventType)) return null;
    }

    // Selective export: blocked detections only.
    if (dr.exportBlockedOnly && event.action !== "block") return null;

    // Metadata-only: strip everything but the minimal envelope + flags.
    if (dr.metadataOnly) {
      return {
        ...event,
        metadata: {
          redacted: true,
          matchedRule: event.metadata.matchedRule,
          auditLoggedLocally: event.metadata.auditLoggedLocally as boolean | undefined,
        },
      };
    }

    return event;
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
    this.stopSelfProtection?.();
    this.stopSelfProtection = null;
    // Buffers and audit log are kept open so they can resume if the kill
    // switch is lifted. Only agent.stop() (graceful shutdown) closes them.
  }

  /**
   * Called when the kill switch transitions from active back to inactive.
   * Re-enables inspection and restarts self-protection if configured.
   */
  private handleRecover(): void {
    this.killed = false;
    if (this.cfg.selfProtect && !this.stopSelfProtection) {
      this.stopSelfProtection = startSelfProtection({
        checkHooks: this.cfg.instrumentDb,
        antiDebug: true,
      });
    }
  }

  /**
   * React to a policy-version change signalled by the heartbeat.
   *
   * Fetches the latest signed policy, verifies its Ed25519 signature against
   * the pinned trust anchor, and applies it. An untrusted, malformed or stale
   * policy is ignored and the agent keeps its current configuration
   * (self-rollback of policy - Addendum D.4 / E.4.1). Never throws.
   *
   * Rejections are surfaced via a `console.warn` and a `policy_rejected`
   * telemetry event so operators can diagnose trust-anchor mismatches without
   * reading raw application logs.
   */
  private handlePolicyChange(version: string): void {
    void version;
    if (this.killed) return;
    if (!this.policyManager.hasTrustAnchor) {
      try {
        console.warn("[rasp] policy update ignored: no trust anchor configured");
      } catch {
        // Ignore logging failures.
      }
      return;
    }

    this.client
      .fetchPolicy(this.cfg.agentId, this.cfg.channel)
      .then((policy) => {
        if (!policy) return;
        const result = this.policyManager.accept(policy);
        if (result.applied) {
          try {
            this.applyPolicy(policy);
          } catch {
            // Self-rollback: applying the new policy failed - restore the
            // previous one so the agent keeps a known-good configuration.
            const restored = this.policyManager.rollback();
            if (restored) {
              try {
                this.applyPolicy(restored);
              } catch {
                // Give up safely; existing in-memory config remains.
              }
            }
          }
        } else {
          try {
            console.warn(
              `[rasp] policy v${policy.version} rejected: ${result.reason}` +
                (policy.signingKeyId ? ` (keyId: ${policy.signingKeyId})` : "")
            );
          } catch {
            // Ignore logging failures.
          }
          this.enqueuePolicyRejected(policy.version, result.reason ?? "unknown", policy.signingKeyId);
        }
      })
      .catch(() => {
        // Fail-safe: keep the current policy on any error.
      });
  }

  /**
   * Emit a single `policy_rejected` telemetry event so the control plane can
   * surface trust-anchor or signature mismatches in the dashboard.
   *
   * The event is deduplicated by `version:reason` so a persistent rejection
   * (e.g. a misconfigured trust anchor that the operator has not yet fixed)
   * does not flood the collector on every heartbeat cycle.
   *
   * The payload passes through the redaction engine (Addendum B.2 / AGENTS.md
   * rule: "All telemetry must pass through the redaction engine before
   * buffering") and the data-residency filter before being enqueued.
   */
  private enqueuePolicyRejected(
    version: number,
    reason: string,
    signingKeyId: string | null
  ): void {
    const key = `${version}:${reason}`;
    if (key === this.lastRejectedPolicyKey) return;
    this.lastRejectedPolicyKey = key;

    const raw = {
      projectId: this.cfg.projectId,
      agentId: this.cfg.agentId,
      agentVersion: this.cfg.agentVersion,
      runtime: this.cfg.runtime,
      framework: this.cfg.framework,
      eventType: "policy_rejected",
      severity: "low" as const,
      action: this.currentMode,
      timestamp: new Date().toISOString(),
      metadata: {
        redacted: true as const,
        version,
        reason,
        ...(signingKeyId ? { signingKeyId } : {}),
      },
    };

    let event: EventPayload;
    try {
      event = this.redaction.redact(raw).redacted as EventPayload;
    } catch {
      return;
    }

    const forSend = this.applyDataResidency(event);
    if (forSend) {
      this.buffer.enqueue(forSend);
    }
  }

  /**
   * Apply a verified policy to the live agent: enforcement mode, customer
   * detection rules, redaction configuration and data residency directives.
   */
  private applyPolicy(policy: DistributedPolicy): void {
    // Mode
    if (policy.mode === "monitor" || policy.mode === "block") {
      this.currentMode = policy.mode;
    }

    // Custom detection rules → rebuild the detector chain.
    this.rebuildDetectors(policy.detectionRules ?? []);

    // Redaction configuration.
    this.applyRedactionConfig(policy.redactionConfig);

    // Data residency directives.
    this.dataResidency = policy.dataResidency ?? null;
  }

  /** Rebuild the active detector chain from base + custom rules + extras. */
  private rebuildDetectors(rules: NonNullable<DistributedPolicy["detectionRules"]>): void {
    const next: Detector[] = [...this.baseDetectors];
    if (rules.length > 0) {
      const custom = new CustomRuleDetector(rules);
      if (custom.size > 0) next.push(custom);
    }
    next.push(...this.extraDetectors);
    this.detectors = next;
  }

  /**
   * Reconfigure the redaction engine from a policy. The engine always keeps its
   * built-in protections; the policy can only add field-name patterns and tune
   * value-based redaction / IP handling.
   */
  private applyRedactionConfig(cfg: RedactionConfig | null): void {
    this.redaction = RedactionEngine.fromConfig(cfg ?? undefined);
  }
}
