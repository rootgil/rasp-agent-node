/**
 * Thin HTTP client used to talk to the collector.
 *
 * The agent only ever calls two endpoints - `POST /v1/events` and
 * `POST /v1/heartbeat`. Both use `Authorization: Bearer <apiKey>` and a JSON
 * body. A per-call `AbortController` enforces the `timeoutMs` budget.
 *
 * Failure semantics differ between the two methods:
 *  - {@link sendEvent} **throws** on transport / non-2xx errors so the
 *    buffer layer can decide whether to retry or drop.
 *  - {@link sendHeartbeat} **swallows** errors and returns `null` so the
 *    heartbeat loop never crashes the host application.
 */
import { createHmac } from "node:crypto";
import type { EventPayload, HeartbeatPayload, HeartbeatResponse, DiscoveryPayload } from "../types.js";
import type { DistributedPolicy } from "../policy/types.js";
import { secureRequest, type TlsOptions } from "./secure-request.js";
import { SecureStore } from "../self-protect.js";

export interface TransportConfig {
  /** Base URL of the collector (no trailing slash required). */
  collectorUrl: string;
  /** Bearer API key sent with every request. */
  apiKey: string;
  /** Per-request timeout in ms (also enforced via `AbortController`). */
  timeoutMs: number;
  /**
   * Optional per-agent HMAC secret. When set, every request body is signed and
   * the digest is sent as `X-RASP-Signature: sha256=<hex>` (Addendum E.5).
   */
  hmacSecret?: string;
  /**
   * Optional TLS options enabling certificate pinning + mutual TLS. When set,
   * requests use a pinned HTTPS transport instead of `fetch` (Addendum E.4.2).
   */
  tls?: TlsOptions;
}

export class TransportClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly tls?: TlsOptions;
  /**
   * Secrets (API key, HMAC secret) are held encrypted in memory rather than as
   * plaintext fields, so a heap dump or accidental log of the client does not
   * leak them (Addendum E.7).
   */
  private readonly secrets = new SecureStore();
  private readonly hasHmac: boolean;

  constructor(cfg: TransportConfig) {
    this.baseUrl = cfg.collectorUrl.replace(/\/$/, "");
    this.timeoutMs = cfg.timeoutMs;
    this.tls = cfg.tls;
    this.secrets.set("apiKey", cfg.apiKey);
    this.hasHmac = Boolean(cfg.hmacSecret);
    if (cfg.hmacSecret) this.secrets.set("hmacSecret", cfg.hmacSecret);
  }

  /** Build request headers, decrypting the API key on demand. */
  private buildHeaders(extra?: Record<string, string>): Record<string, string> {
    return {
      "Content-Type": "application/json",
      Authorization: `Bearer ${this.secrets.get("apiKey") ?? ""}`,
      ...extra,
    };
  }

  /** Compute the `X-RASP-Signature` value for a serialised body, if signing. */
  private signBody(body: string): string | null {
    if (!this.hasHmac) return null;
    const secret = this.secrets.get("hmacSecret");
    if (!secret) return null;
    const digest = createHmac("sha256", secret).update(body).digest("hex");
    return `sha256=${digest}`;
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
   * Fetch the latest signed policy from `GET /v1/policy`.
   *
   * Returns the parsed {@link DistributedPolicy} or `null` on any failure
   * (network, 404 when no policy is published, etc.). Errors are swallowed so a
   * policy fetch can never crash the host application.
   *
   * @param agentId - Used by the collector to resolve the agent's channel.
   * @param channel - Optional explicit channel override.
   */
  async fetchPolicy(agentId: string, channel?: string): Promise<DistributedPolicy | null> {
    try {
      const qs = new URLSearchParams({ agentId });
      if (channel) qs.set("channel", channel);
      const res = await this.get(`/v1/policy?${qs.toString()}`);
      return res as DistributedPolicy;
    } catch {
      return null;
    }
  }

  /**
   * POST a heartbeat to `/v1/heartbeat`.
   *
   * @returns The parsed {@link HeartbeatResponse}, or `null` if the request
   *   failed for any reason. Errors are intentionally suppressed - the
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
      const serialized = JSON.stringify(body);
      const signature = this.signBody(serialized);
      const headers = this.buildHeaders(
        signature ? { "X-RASP-Signature": signature } : undefined
      );

      // Pinned HTTPS / mutual-TLS path.
      if (this.tls) {
        return await secureRequest({
          method: "POST",
          url: `${this.baseUrl}${path}`,
          headers,
          body: serialized,
          timeoutMs: this.timeoutMs,
          tls: this.tls,
        });
      }

      const res = await fetch(`${this.baseUrl}${path}`, {
        method: "POST",
        headers,
        body: serialized,
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

  /**
   * Shared GET helper. Same timeout budget and non-2xx handling as POST.
   */
  private async get(path: string): Promise<unknown> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const headers = this.buildHeaders();
      if (this.tls) {
        return await secureRequest({
          method: "GET",
          url: `${this.baseUrl}${path}`,
          headers,
          timeoutMs: this.timeoutMs,
          tls: this.tls,
        });
      }

      const res = await fetch(`${this.baseUrl}${path}`, {
        method: "GET",
        headers,
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
