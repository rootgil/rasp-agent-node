/**
 * Minimal HTTP mock for the RASP collector.
 *
 * Captures event/heartbeat/discovery payloads in memory so integration and
 * E2E tests can assert on what the agent sent without needing a real collector.
 *
 * Usage:
 *   const col = new MockCollector();
 *   await col.start();          // binds to an OS-assigned port
 *   process.env.RASP_COLLECTOR_URL = col.url;
 *   // ... run agent ...
 *   col.events                  // SecurityEvent bodies received
 *   col.heartbeats              // HeartbeatPayload bodies received
 *   await col.stop();
 */
import http from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";

export interface CapturedRequest {
  path: string;
  body: unknown;
}

export class MockCollector {
  private server: http.Server;
  private _port = 0;

  readonly events: unknown[] = [];
  readonly heartbeats: unknown[] = [];
  readonly discoveries: unknown[] = [];
  readonly all: CapturedRequest[] = [];

  constructor() {
    this.server = http.createServer(
      (req: IncomingMessage, res: ServerResponse) => this.handleRequest(req, res)
    );
  }

  get url(): string {
    return `http://127.0.0.1:${this._port}`;
  }

  get port(): number {
    return this._port;
  }

  private handleRequest(req: IncomingMessage, res: ServerResponse): void {
    let raw = "";
    req.on("data", (chunk: Buffer) => { raw += chunk.toString(); });
    req.on("end", () => {
      let body: unknown = null;
      try { body = JSON.parse(raw); } catch { body = raw; }

      const path = req.url ?? "/";
      this.all.push({ path, body });

      if (path === "/v1/events") {
        this.events.push(body);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      if (path === "/v1/heartbeat") {
        this.heartbeats.push(body);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          killSwitch: false,
          mode: "monitor",
          policyVersion: null,
          upgradeAvailable: false,
        }));
        return;
      }
      if (path === "/v1/discovery") {
        this.discoveries.push(body);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      // /v1/policy - no policy by default
      if (path.startsWith("/v1/policy")) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "no policy" }));
        return;
      }
      res.writeHead(404);
      res.end();
    });
  }

  start(): Promise<void> {
    return new Promise((resolve) => {
      this.server.listen(0, "127.0.0.1", () => {
        const addr = this.server.address();
        if (addr && typeof addr === "object") {
          this._port = addr.port;
        }
        resolve();
      });
    });
  }

  stop(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server.close((err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  /** Reset captured payloads between tests. */
  reset(): void {
    this.events.length = 0;
    this.heartbeats.length = 0;
    this.discoveries.length = 0;
    this.all.length = 0;
  }
}
