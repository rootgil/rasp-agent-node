import type { EventPayload, HeartbeatPayload, HeartbeatResponse } from "../types.js";

export interface TransportConfig {
  collectorUrl: string;
  apiKey: string;
  timeoutMs: number;
}

export class TransportClient {
  private readonly baseUrl: string;
  private readonly headers: Record<string, string>;
  private readonly timeoutMs: number;

  constructor(cfg: TransportConfig) {
    this.baseUrl = cfg.collectorUrl.replace(/\/$/, "");
    this.headers = {
      "Content-Type": "application/json",
      Authorization: `Bearer ${cfg.apiKey}`,
    };
    this.timeoutMs = cfg.timeoutMs;
  }

  async sendEvent(payload: EventPayload): Promise<void> {
    await this.post("/v1/events", payload);
  }

  async sendHeartbeat(payload: HeartbeatPayload): Promise<HeartbeatResponse | null> {
    try {
      const res = await this.post("/v1/heartbeat", payload);
      return res as HeartbeatResponse;
    } catch {
      return null;
    }
  }

  private async post(path: string, body: unknown): Promise<unknown> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const res = await fetch(`${this.baseUrl}${path}`, {
        method: "POST",
        headers: this.headers,
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(`[rasp-transport] ${path} → HTTP ${res.status}: ${text}`);
      }

      return res.json();
    } finally {
      clearTimeout(timer);
    }
  }
}
