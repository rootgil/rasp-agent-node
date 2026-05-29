/**
 * In-memory event buffer with periodic and size-triggered flushing.
 *
 * Acts as a small queue between {@link RaspAgent.inspect} (synchronous, in
 * the request hot path) and the network-bound {@link TransportClient}.
 *
 * Flush triggers:
 *  - **Periodic**: `setInterval(flush, flushIntervalMs)`.
 *  - **Size-based**: as soon as the queue reaches `maxSize`, `enqueue`
 *    triggers an opportunistic flush.
 *  - **Final**: {@link stop} cancels the timer and drains the queue once.
 *
 * Fail-open guarantees:
 *  - Individual `sendEvent` failures are swallowed (the event is dropped).
 *  - The flush timer is `unref`'d so it never keeps the Node process alive.
 */
import type { EventPayload } from "../types.js";
import type { TransportClient } from "./client.js";

export interface BufferConfig {
  /** Periodic flush interval in ms. */
  flushIntervalMs: number;
  /** Queue length above which `enqueue` triggers an opportunistic flush. */
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
        // Fail-open - transport errors must not propagate.
      });
    }, cfg.flushIntervalMs);

    if (this.timer.unref) {
      this.timer.unref();
    }
  }

  /**
   * Append an event. Triggers an immediate flush once the queue reaches
   * `maxSize`.
   *
   * The event is expected to have already passed through the redaction
   * engine - the buffer does not sanitise.
   */
  enqueue(event: EventPayload): void {
    this.queue.push(event);

    if (this.queue.length >= this.maxSize) {
      this.flush().catch(() => {});
    }
  }

  /**
   * Atomically drain the queue and fire all sends in parallel.
   *
   * Uses `Promise.allSettled` so a single failed send cannot block the
   * others. Per-event errors are caught and ignored (the event is lost).
   */
  async flush(): Promise<void> {
    if (this.queue.length === 0) return;

    const batch = this.queue.splice(0, this.queue.length);

    await Promise.allSettled(
      batch.map((event) =>
        this.client.sendEvent(event).catch(() => {
          // Per-event failure - the event is dropped.
        })
      )
    );
  }

  /**
   * Cancel the timer and perform a final drain. Awaited during agent
   * shutdown.
   */
  async stop(): Promise<void> {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    await this.flush();
  }
}
