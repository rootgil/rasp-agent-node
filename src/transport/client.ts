/**
 * Thin HTTP client used to talk to the collector.
 *
 * The agent only ever calls two endpoints — `POST /v1/events` and
 * `POST /v1/heartbeat`. Both use `Authorization: Bearer <apiKey>` and a JSON
 * body. A per-call `AbortController` enforces the `timeoutMs` budget.
 *
 * Failure semantics differ between the two methods:
 *  - {@link sendEvent} **throws** on transport / non-2xx errors so the
 *    buffer layer can decide whether to retry or drop.
 *  - {@link sendHeartbeat} **swallows** errors and returns `null` so the
 *    heartbeat loop never crashes the host application.
 */
import type { EventPayload, HeartbeatPayload, HeartbeatResponse, DiscoveryPayload } from "../types.js";

export interface TransportConfig {
  /** Base URL of the collector (no trailing slash required). */
  collectorUrl: string;
  /** Bearer API key sent with every request. */
  apiKey: string;
  /** Per-request timeout in ms (also enforced via `AbortController`). */
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

  /**
   * POST a sanitised event to `/v1/events`.
   *
   * @throws On non-2xx responses or network errors. The buffer treats this
   *   as a per-event failure and drops the event (fail-open).
   */
  async sendEvent(payload: EventPayload): Promise<void> {
    await this.post("/v1/events", payload);
  }

  async sendDiscovery(payload: DiscoveryPayload): Promise<void> {
    await this.post("/v1/discovery", payload);
  }

  /**
   * POST a heartbeat to `/v1/heartbeat`.
   *
   * @returns The parsed {@link HeartbeatResponse}, or `null` if the request
   *   failed for any reason. Errors are intentionally suppressed — the
   *   heartbeat must never crash the host.
   */
  async sendHeartbeat(payload: HeartbeatPayload): Promise<HeartbeatResponse | null> {
    try {
      const res = await this.post("/v1/heartbeat", payload);
      return res as HeartbeatResponse;
    } catch {
      return null;
    }
  }

  /**
   * Shared POST helper.
   *
   * Sets up an `AbortController` that fires after `timeoutMs`, sends the
   * JSON body and rejects on a non-2xx status.
   */
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
