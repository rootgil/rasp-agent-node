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

  start(): void {
    if (this.timer) return;

    // Send immediately on start
    this.beat().catch(() => {});

    this.timer = setInterval(() => {
      this.beat().catch(() => {});
    }, this.cfg.heartbeatIntervalMs);

    if (this.timer.unref) {
      this.timer.unref();
    }
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  setStatus(status: AgentStatus): void {
    this.status = status;
  }

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
