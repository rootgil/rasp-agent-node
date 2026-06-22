/**
 * Heartbeat scheduler.
 *
 * Periodically sends an {@link HeartbeatPayload} to the collector. The
 * heartbeat is the bidirectional control channel: the agent reports its
 * health and mode, and the collector replies with the kill-switch flag and
 * the current policy version.
 *
 * Behaviour:
 *  - {@link start} immediately fires one heartbeat, then arms an interval
 *    of `cfg.heartbeatIntervalMs`. The timer is `unref`'d so it doesn't
 *    keep the process alive.
 *  - On a `killSwitch: true` response, the scheduler stops itself and
 *    invokes `onKillSwitch` so the agent can drain its buffer and disable
 *    inspection.
 *  - On a `policyVersion` change, `onPolicyChange` is invoked once
 *    (reserved for future dynamic rule refresh).
 *  - All heartbeat failures are swallowed by {@link TransportClient.sendHeartbeat}
 *    so the loop never crashes.
 */
import type { HeartbeatPayload, AgentStatus, AgentMode } from "../types.js";
import type { TransportClient } from "./client.js";
import type { ValidatedRaspConfig } from "../config.js";

export type KillSwitchHandler = () => void;
export type RecoverHandler = () => void;
export type PolicyChangeHandler = (version: string) => void;
export type ModeChangeHandler = (mode: AgentMode) => void;
export interface TargetVersionInfo {
  targetVersion: string | null;
  upgradeAvailable: boolean;
  changelog: string | null;
  impact: string | null;
}
export type TargetVersionHandler = (info: TargetVersionInfo) => void;

export class HeartbeatScheduler {
  private timer: ReturnType<typeof setInterval> | null = null;
  private status: AgentStatus = "healthy";
  private readonly onKillSwitch: KillSwitchHandler;
  private readonly onRecover?: RecoverHandler;
  private readonly onPolicyChange: PolicyChangeHandler;
  private readonly onModeChange: ModeChangeHandler;
  private readonly onTargetVersion?: TargetVersionHandler;
  private readonly getMode: () => AgentMode;
  private lastPolicyVersion = "";
  private lastMode: AgentMode | "" = "";
  private lastTargetVersion: string | null | undefined = undefined;
  /** Tracks whether the kill switch was active on the last heartbeat response. */
  private killSwitchActive = false;
  /** One-shot upgrade lifecycle event sent on the next beat, then cleared. */
  private pendingUpgradeStatus?: "upgrade_failed" | "upgrade_succeeded" | "rollback_loaded";
  private pendingUpgradeStatusReason?: string;

  /**
   * @param client - Transport used to deliver heartbeats.
   * @param cfg - Validated config. Provides identity, mode and interval.
   * @param handlers - Callbacks fired when the backend signals a kill
   *   switch, a policy change, or a mode change.
   */
  constructor(
    private readonly client: TransportClient,
    private readonly cfg: ValidatedRaspConfig,
    handlers: {
      onKillSwitch: KillSwitchHandler;
      /** Called once when the kill switch transitions from active back to inactive. */
      onRecover?: RecoverHandler;
      onPolicyChange: PolicyChangeHandler;
      onModeChange: ModeChangeHandler;
      onTargetVersion?: TargetVersionHandler;
      /** Returns the agent's current enforcement mode so the heartbeat payload stays accurate. */
      getMode: () => AgentMode;
    }
  ) {
    this.onKillSwitch = handlers.onKillSwitch;
    this.onRecover = handlers.onRecover;
    this.onPolicyChange = handlers.onPolicyChange;
    this.onModeChange = handlers.onModeChange;
    this.onTargetVersion = handlers.onTargetVersion;
    this.getMode = handlers.getMode;
  }

  /**
   * Send an immediate heartbeat and arm the periodic loop. Idempotent -
   * calling `start` twice has no extra effect.
   */
  start(): void {
    if (this.timer) return;

    this.beat().catch(() => {});

    this.timer = setInterval(() => {
      this.beat().catch(() => {});
    }, this.cfg.heartbeatIntervalMs);

    if (this.timer.unref) {
      this.timer.unref();
    }
  }

  /** Cancel the periodic loop. Safe to call multiple times. */
  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  /**
   * Override the self-reported status sent on the next beat. Used by the
   * agent when subsystems degrade.
   */
  setStatus(status: AgentStatus): void {
    this.status = status;
  }

  /**
   * Record an upgrade lifecycle event to be reported on the next heartbeat
   * (Addendum D.4). After it is sent once, the field is cleared so subsequent
   * heartbeats do not repeatedly report the same event.
   */
  setUpgradeStatus(
    upgradeStatus: "upgrade_failed" | "upgrade_succeeded" | "rollback_loaded",
    reason?: string
  ): void {
    this.pendingUpgradeStatus = upgradeStatus;
    this.pendingUpgradeStatusReason = reason;
  }

  /**
   * Send one heartbeat, then react to the response:
   *  - `killSwitch` → stop the loop and fire {@link onKillSwitch}.
   *  - `policyVersion` change → cache it and fire {@link onPolicyChange}.
   */
  private async beat(): Promise<void> {
    const upgradeStatus = this.pendingUpgradeStatus;
    const upgradeStatusReason = this.pendingUpgradeStatusReason;
    // Clear before sending so a transport error doesn't cause duplicate reports.
    this.pendingUpgradeStatus = undefined;
    this.pendingUpgradeStatusReason = undefined;

    const payload: HeartbeatPayload = {
      projectId: this.cfg.projectId,
      agentId: this.cfg.agentId,
      agentVersion: this.cfg.agentVersion,
      runtime: this.cfg.runtime,
      framework: this.cfg.framework,
      status: this.status,
      mode: this.getMode(),
      timestamp: new Date().toISOString(),
      ...(upgradeStatus ? { upgradeStatus, upgradeStatusReason } : {}),
    };

    const res = await this.client.sendHeartbeat(payload);
    if (!res) return;

    if (res.killSwitch && !this.killSwitchActive) {
      this.killSwitchActive = true;
      this.onKillSwitch();
    } else if (!res.killSwitch && this.killSwitchActive) {
      this.killSwitchActive = false;
      this.onRecover?.();
    }

    if (res.policyVersion && res.policyVersion !== this.lastPolicyVersion) {
      this.lastPolicyVersion = res.policyVersion;
      if (this.lastPolicyVersion) {
        this.onPolicyChange(res.policyVersion);
      }
    }

    if (res.mode && res.mode !== this.lastMode) {
      this.lastMode = res.mode;
      this.onModeChange(res.mode);
    }

    if (this.onTargetVersion && res.targetVersion !== this.lastTargetVersion) {
      this.lastTargetVersion = res.targetVersion ?? null;
      this.onTargetVersion({
        targetVersion: res.targetVersion ?? null,
        upgradeAvailable: res.upgradeAvailable ?? false,
        changelog: res.changelog ?? null,
        impact: res.impact ?? null,
      });
    }
  }
}
