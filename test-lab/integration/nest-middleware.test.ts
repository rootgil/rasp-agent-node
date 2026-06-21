/**
 * Integration tests for the NestJS middleware.
 *
 * NestJS middleware is Express-compatible, so we can test it via a minimal
 * Express app wired with the NestJS middleware class instance - no DI
 * container needed for these unit-level integration tests.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import express from "express";
import supertest from "supertest";
import { RaspAgent, createNestMiddleware } from "../../src/index.js";
import { createOfflineDetectors } from "../../src/detectors/index.js";

function buildNestApp(mode: "monitor" | "block") {
  const agent = new RaspAgent(
    {
      apiKey: "test_key",
      projectId: "proj_test",
      agentId: "agent_test",
      auditLog: false,
      mode,
    },
    createOfflineDetectors(),
  );

  const MiddlewareClass = createNestMiddleware(agent);
  const middleware = new MiddlewareClass();

  const app = express();
  app.use(express.json());
  app.use((req, res, next) => middleware.use(req, res, next));
  app.get("/echo", (req, res) => res.json({ q: req.query }));
  app.post("/echo", (req, res) => res.json({ body: req.body }));
  app.get("/health", (_req, res) => res.json({ ok: true }));

  return { app, agent };
}

describe("NestJS middleware - monitor mode", () => {
  let app: ReturnType<typeof buildNestApp>["app"];
  let agent: RaspAgent;

  beforeAll(() => {
    ({ app, agent } = buildNestApp("monitor"));
  });
  afterAll(async () => { await agent.stop(); });

  it("passes clean request - HTTP 200", async () => {
    const res = await supertest(app).get("/health");
    expect(res.status).toBe(200);
  });

  it("passes SQLi in monitor mode - HTTP 200", async () => {
    const res = await supertest(app).get("/echo?id=1' OR '1'='1");
    expect(res.status).toBe(200);
  });
});

describe("NestJS middleware - block mode", () => {
  let app: ReturnType<typeof buildNestApp>["app"];
  let agent: RaspAgent;

  beforeAll(() => {
    ({ app, agent } = buildNestApp("block"));
  });
  afterAll(async () => { await agent.stop(); });

  it("blocks SQLi - HTTP 403 with eventType", async () => {
    const res = await supertest(app).get("/echo?id=1' OR '1'='1");
    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/blocked/i);
    expect(res.body.eventType).toBe("sql_injection");
  });

  it("blocks command injection - HTTP 403", async () => {
    const res = await supertest(app).get("/echo?cmd=ping+127.0.0.1%3Bcat+/etc/passwd");
    expect(res.status).toBe(403);
    expect(res.body.eventType).toBe("command_injection");
  });

  it("blocks XSS in POST body - HTTP 403", async () => {
    const res = await supertest(app)
      .post("/echo")
      .send({ comment: "<script>alert(1)</script>" })
      .set("Content-Type", "application/json");
    expect(res.status).toBe(403);
    expect(res.body.eventType).toBe("xss");
  });

  it("passes clean POST - HTTP 200", async () => {
    const res = await supertest(app)
      .post("/echo")
      .send({ name: "Alice", age: 30 })
      .set("Content-Type", "application/json");
    expect(res.status).toBe(200);
  });
});
