import type { EventPayload } from "../types.js";
import type { TransportClient } from "./client.js";

export interface BufferConfig {
  flushIntervalMs: number;
  maxSize: number;
}

export class EventBuffer {
  private readonly queue: EventPayload[] = [];
  private readonly client: TransportClient;
  private readonly maxSize: number;
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(client: TransportClient, cfg: BufferConfig) {
    this.client = client;
    this.maxSize = cfg.maxSize;

    this.timer = setInterval(() => {
      this.flush().catch(() => {
        // Fail open — transport errors must not propagate.
      });
    }, cfg.flushIntervalMs);

    // Allow the Node.js process to exit even if the timer is running.
    if (this.timer.unref) {
      this.timer.unref();
    }
  }

  enqueue(event: EventPayload): void {
    this.queue.push(event);

    if (this.queue.length >= this.maxSize) {
      this.flush().catch(() => {});
    }
  }

  async flush(): Promise<void> {
    if (this.queue.length === 0) return;

    const batch = this.queue.splice(0, this.queue.length);

    await Promise.allSettled(
      batch.map((event) =>
        this.client.sendEvent(event).catch(() => {
          // Individual send failure — fail open, event is dropped.
        })
      )
    );
  }

  async stop(): Promise<void> {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    await this.flush();
  }
}
