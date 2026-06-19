/**
 * Integration tests for the Express middleware.
 *
 * Verifies that:
 *  - In monitor mode, attacks pass through (HTTP 200) but events are enqueued.
 *  - In block mode, attacks are short-circuited with HTTP 403 + eventType.
 *  - Clean requests pass in both modes.
 *  - Middleware never throws (fail-open).
 */
import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import express from "express";
import supertest from "supertest";
import { RaspAgent, createExpressMiddleware } from "../../src/index.js";

function buildApp(mode: "monitor" | "block") {
  const agent = new RaspAgent({
    apiKey: "test_key",
    projectId: "proj_test",
    agentId: "agent_test",
    auditLog: false,
    mode,
  });

  const app = express();
  app.use(express.json());
  app.use(createExpressMiddleware(agent));
  app.get("/echo", (req, res) => res.json({ q: req.query }));
  app.post("/echo", (req, res) => res.json({ body: req.body }));
  app.get("/health", (_req, res) => res.json({ ok: true }));

  return { app, agent };
}

describe("Express middleware - monitor mode", () => {
  let app: ReturnType<typeof buildApp>["app"];
  let agent: RaspAgent;

  beforeAll(() => {
    ({ app, agent } = buildApp("monitor"));
  });
  afterAll(async () => { await agent.stop(); });

  it("passes clean request - HTTP 200", async () => {
    const res = await supertest(app).get("/health");
    expect(res.status).toBe(200);
  });

  it("passes SQLi request in monitor mode - HTTP 200", async () => {
    const res = await supertest(app).get("/echo?id=1' OR '1'='1");
    expect(res.status).toBe(200);
  });

  it("passes path traversal in monitor mode - HTTP 200", async () => {
    const res = await supertest(app).get("/echo?file=../../../secret.txt");
    expect(res.status).toBe(200);
  });
});

describe("Express middleware - block mode", () => {
  let app: ReturnType<typeof buildApp>["app"];
  let agent: RaspAgent;

  beforeAll(() => {
    ({ app, agent } = buildApp("block"));
  });
  afterAll(async () => { await agent.stop(); });

  it("blocks SQLi - HTTP 403 with eventType", async () => {
    const res = await supertest(app).get("/echo?id=1' OR '1'='1");
    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/blocked/i);
    expect(res.body.eventType).toBe("sql_injection");
  });

  it("blocks path traversal - HTTP 403", async () => {
    const res = await supertest(app).get("/echo?file=../../../secret.txt");
    expect(res.status).toBe(403);
    expect(res.body.eventType).toBe("path_traversal");
  });

  it("blocks XSS - HTTP 403", async () => {
    const res = await supertest(app)
      .get("/echo?search=%3Cscript%3Ealert(1)%3C%2Fscript%3E");
    expect(res.status).toBe(403);
    expect(res.body.eventType).toBe("xss");
  });

  it("blocks command injection - HTTP 403", async () => {
    const res = await supertest(app).get("/echo?cmd=ping+127.0.0.1%3Bcat+/etc/passwd");
    expect(res.status).toBe(403);
    expect(res.body.eventType).toBe("command_injection");
  });

  it("passes clean request - HTTP 200", async () => {
    const res = await supertest(app).get("/health");
    expect(res.status).toBe(200);
  });

  it("blocks SQLi in POST body - HTTP 403", async () => {
    const res = await supertest(app)
      .post("/echo")
      .send({ email: "admin", password: "' OR '1'='1" })
      .set("Content-Type", "application/json");
    expect(res.status).toBe(403);
    expect(res.body.eventType).toBe("sql_injection");
  });
});

describe("Express middleware - event enqueue in monitor mode", () => {
  it("enqueues event on detection without blocking", async () => {
    const agent = new RaspAgent({
      apiKey: "test_key",
      projectId: "proj_test",
      agentId: "agent_test",
      auditLog: false,
      mode: "monitor",
    });
    const enqueueSpy = vi.spyOn(
      (agent as unknown as Record<string, unknown>).buffer as { enqueue: (e: unknown) => void },
      "enqueue"
    );

    const app = express();
    app.use(express.json());
    app.use(createExpressMiddleware(agent));
    app.get("/echo", (_req, res) => res.json({ ok: true }));

    const res = await supertest(app).get("/echo?id=1' OR '1'='1");
    expect(res.status).toBe(200);

    // Allow handleDetection async to run
    await new Promise((r) => setImmediate(r));
    expect(enqueueSpy).toHaveBeenCalledOnce();
    const event = enqueueSpy.mock.calls[0][0] as Record<string, unknown>;
    expect(event.eventType).toBe("sql_injection");

    await agent.stop();
  });
});
