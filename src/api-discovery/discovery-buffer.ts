/**
 * Periodic buffer that drains {@link EndpointObserver} and ships batches to
 * the collector via {@link TransportClient.sendDiscovery}.
 *
 * - Flushes every `flushIntervalMs` milliseconds (default 60 s).
 * - Sends at most 500 endpoints per HTTP call; splits into multiple calls if needed.
 * - Fail-open: transport errors are swallowed so the host application is not affected.
 */
import type { TransportClient } from "../transport/client.js";
import type { EndpointObserver } from "./endpoint-observer.js";

export interface DiscoveryBufferOptions {
  projectId: string;
  agentId: string;
  flushIntervalMs: number;
  /** Optional redaction/sanitizer; return null to drop the batch. */
  sanitize?: (payload: unknown) => unknown | null;
}

const MAX_BATCH_SIZE = 500;

export class DiscoveryBuffer {
  private readonly client: TransportClient;
  private readonly observer: EndpointObserver;
  private readonly projectId: string;
  private readonly agentId: string;
  private readonly sanitize?: (payload: unknown) => unknown | null;
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(
    client: TransportClient,
    observer: EndpointObserver,
    opts: DiscoveryBufferOptions
  ) {
    this.client = client;
    this.observer = observer;
    this.projectId = opts.projectId;
    this.agentId = opts.agentId;
    this.sanitize = opts.sanitize;

    this.timer = setInterval(() => {
      this.flush().catch(() => {});
    }, opts.flushIntervalMs);

    // Allow Node.js to exit even if the timer is still running
    if (this.timer.unref) this.timer.unref();
  }

  /** Stop the flush timer and send a final batch. */
  async stop(): Promise<void> {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    await this.flush();
  }

  private async flush(): Promise<void> {
    const entries = this.observer.drain();
    if (entries.length === 0) return;

    const timestamp = new Date().toISOString();

    // Split into chunks of MAX_BATCH_SIZE
    for (let i = 0; i < entries.length; i += MAX_BATCH_SIZE) {
      const chunk = entries.slice(i, i + MAX_BATCH_SIZE);
      try {
        const payload = {
          projectId: this.projectId,
          agentId: this.agentId,
          timestamp,
          endpoints: chunk,
        };
        const toSend = this.sanitize ? this.sanitize(payload) : payload;
        if (!toSend) continue;
        await this.client.sendDiscovery(
          toSend as {
            projectId: string;
            agentId: string;
            timestamp: string;
            endpoints: typeof chunk;
          }
        );
      } catch {
        // Fail open
      }
    }
  }
}
