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
import type { HeartbeatPayload, AgentStatus } from "../types.js";
import type { TransportClient } from "./client.js";
import type { ValidatedRaspConfig } from "../config.js";

export type KillSwitchHandler = () => void;
export type PolicyChangeHandler = (version: string) => void;

export class HeartbeatScheduler {
  private timer: ReturnType<typeof setInterval> | null = null;
  private status: AgentStatus = "healthy";
  private readonly onKillSwitch: KillSwitchHandler;
  private readonly onPolicyChange: PolicyChangeHandler;
  private lastPolicyVersion = "";

  /**
   * @param client - Transport used to deliver heartbeats.
   * @param cfg - Validated config. Provides identity, mode and interval.
   * @param handlers - Callbacks fired when the backend signals a kill
   *   switch or a policy change.
   */
  constructor(
    private readonly client: TransportClient,
    private readonly cfg: ValidatedRaspConfig,
    handlers: {
      onKillSwitch: KillSwitchHandler;
      onPolicyChange: PolicyChangeHandler;
    }
  ) {
    this.onKillSwitch = handlers.onKillSwitch;
    this.onPolicyChange = handlers.onPolicyChange;
  }

  /**
   * Send an immediate heartbeat and arm the periodic loop. Idempotent —
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
   * Send one heartbeat, then react to the response:
   *  - `killSwitch` → stop the loop and fire {@link onKillSwitch}.
   *  - `policyVersion` change → cache it and fire {@link onPolicyChange}.
   */
  private async beat(): Promise<void> {
    const payload: HeartbeatPayload = {
      projectId: this.cfg.projectId,
      agentId: this.cfg.agentId,
      agentVersion: this.cfg.agentVersion,
      runtime: this.cfg.runtime,
      framework: this.cfg.framework,
      status: this.status,
      mode: this.cfg.mode,
      timestamp: new Date().toISOString(),
    };

    const res = await this.client.sendHeartbeat(payload);
    if (!res) return;

    if (res.killSwitch) {
      this.stop();
      this.onKillSwitch();
    }

    if (res.policyVersion && res.policyVersion !== this.lastPolicyVersion) {
      this.lastPolicyVersion = res.policyVersion;
      if (this.lastPolicyVersion) {
        this.onPolicyChange(res.policyVersion);
      }
    }
  }
}
