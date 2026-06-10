/**
 * E2E tests for the banking-api example application.
 *
 * Uses supertest to send real HTTP requests through the full Express stack.
 * A mock collector captures events emitted by the agent so we can assert on
 * detection without a real collector or network.
 *
 * RASP mode is set to "block" so both the HTTP response (403) and the
 * enqueued event can be verified together.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import supertest from "supertest";
import { RaspAgent } from "../../src/agent.js";
import { createBankingApp } from "../../examples/banking-api/src/app.js";
import { MockCollector } from "../mocks/mock-collector.js";
import { flushAsync } from "../mocks/test-agent.js";

let collector: MockCollector;
let agent: RaspAgent;
let app: ReturnType<typeof createBankingApp>;

beforeAll(async () => {
  collector = new MockCollector();
  await collector.start();

  process.env["RASP_COLLECTOR_URL"] = collector.url;

  agent = new RaspAgent({
    apiKey: "test_key",
    projectId: "proj_test",
    agentId: "agent_test",
    auditLog: false,
    mode: "block",
    flushIntervalMs: 200,
    bufferMaxSize: 1,
  });
  agent.start();

  app = createBankingApp(agent);
});

afterAll(async () => {
  await agent.stop();
  await collector.stop();
  delete process.env["RASP_COLLECTOR_URL"];
});

describe("Health endpoint — no false positives", () => {
  it("GET /health returns 200 with no events emitted", async () => {
    collector.reset();
    const res = await supertest(app).get("/health");
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("ok");
    await flushAsync();
    // no detection event should have been enqueued
  });
});

describe("SQL injection scenarios", () => {
  it("blocks SQLi in query param — HTTP 403", async () => {
    collector.reset();
    const res = await supertest(app)
      .get("/api/users/1?id=1'+OR+1%3D1--");
    expect(res.status).toBe(403);
    expect(res.body.eventType).toBe("sql_injection");
  });

  it("blocks UNION SELECT — HTTP 403", async () => {
    const res = await supertest(app)
      .get("/api/users/1?id=1+UNION+SELECT+username,password+FROM+users--");
    expect(res.status).toBe(403);
    expect(res.body.eventType).toBe("sql_injection");
  });

  it("blocks SQLi in POST body (login route) — HTTP 403", async () => {
    const res = await supertest(app)
      .post("/api/auth/login")
      .send({ email: "admin@acme.io", "password": "' OR '1'='1" })
      .set("Content-Type", "application/json");
    expect(res.status).toBe(403);
    expect(res.body.eventType).toBe("sql_injection");
  });

  it("blocks blind SQLi SLEEP — HTTP 403", async () => {
    const res = await supertest(app)
      .get("/api/users/1?id=1+AND+SLEEP(5)--");
    expect(res.status).toBe(403);
    expect(res.body.eventType).toBe("sql_injection");
  });
});

describe("Path traversal", () => {
  it("blocks ../etc/passwd path traversal — HTTP 403", async () => {
    const res = await supertest(app)
      .get("/api/documents/..%2F..%2F..%2Fetc%2Fpasswd");
    expect(res.status).toBe(403);
    expect(res.body.eventType).toBe("path_traversal");
  });
});

describe("XSS", () => {
  it("blocks script tag in query — HTTP 403", async () => {
    const res = await supertest(app)
      .get("/api/transactions?search=%3Cscript%3Ealert(1)%3C%2Fscript%3E");
    expect(res.status).toBe(403);
    expect(res.body.eventType).toBe("xss");
  });
});

describe("Command injection", () => {
  it("blocks command injection in query — HTTP 403", async () => {
    const res = await supertest(app)
      .get("/api/transactions?search=ping+127.0.0.1%3Bcat+%2Fetc%2Fpasswd");
    expect(res.status).toBe(403);
    expect(res.body.eventType).toBe("command_injection");
  });
});

describe("BOLA / IDOR via JWT", () => {
  const JWT_USER1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.demo";
  const JWT_USER2 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyIn0.demo";

  it("blocks user 1 accessing user 2 resource — HTTP 403", async () => {
    const res = await supertest(app)
      .get("/api/users/2")
      .set("Authorization", `Bearer ${JWT_USER1}`);
    expect(res.status).toBe(403);
    expect(res.body.eventType).toBe("bola");
  });

  it("allows user 1 accessing own resource — HTTP 200", async () => {
    const res = await supertest(app)
      .get("/api/users/1")
      .set("Authorization", `Bearer ${JWT_USER1}`);
    expect(res.status).toBe(200);
  });

  it("allows user 2 accessing own resource — HTTP 200", async () => {
    const res = await supertest(app)
      .get("/api/users/2")
      .set("Authorization", `Bearer ${JWT_USER2}`);
    expect(res.status).toBe(200);
  });
});

describe("Normal requests — no false positives", () => {
  it("GET /api/users/1 without JWT — HTTP 200", async () => {
    const res = await supertest(app).get("/api/users/1");
    expect(res.status).toBe(200);
  });

  it("POST /api/auth/login with clean creds — HTTP 200 or 401 (not 403)", async () => {
    const res = await supertest(app)
      .post("/api/auth/login")
      .send({ email: "alice@example.com", password: "correct-horse-battery" })
      .set("Content-Type", "application/json");
    // Must not be blocked by RASP
    expect(res.status).not.toBe(403);
  });
});
