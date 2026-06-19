/**
 * Integration tests for the Fastify plugin.
 *
 * Uses supertest against a real bound HTTP server (port 0) to avoid
 * any inject() quirks with query parsing in onRequest hooks.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import Fastify, { type FastifyInstance } from "fastify";
import supertest from "supertest";
import type { AddressInfo } from "node:net";
import { RaspAgent, createFastifyPlugin } from "../../src/index.js";

async function buildFastifyApp(mode: "monitor" | "block") {
  const agent = new RaspAgent({
    apiKey: "test_key",
    projectId: "proj_test",
    agentId: "agent_test",
    auditLog: false,
    mode,
  });

  const fastify: FastifyInstance = Fastify({ logger: false });
  await fastify.register(createFastifyPlugin(agent));

  fastify.get("/echo", async (request) => ({ q: request.query }));
  fastify.post("/echo", async (request) => ({ body: request.body }));
  fastify.get("/health", async () => ({ ok: true }));

  await fastify.listen({ port: 0, host: "127.0.0.1" });
  const port = (fastify.server.address() as AddressInfo).port;
  const base = `http://127.0.0.1:${port}`;

  return { fastify, agent, base };
}

describe("Fastify plugin - monitor mode", () => {
  let fastify: FastifyInstance;
  let agent: RaspAgent;
  let base: string;

  beforeAll(async () => {
    ({ fastify, agent, base } = await buildFastifyApp("monitor"));
  });
  afterAll(async () => {
    await fastify.close();
    await agent.stop();
  });

  it("passes clean request - HTTP 200", async () => {
    const res = await supertest(base).get("/health");
    expect(res.status).toBe(200);
  });

  it("passes SQLi in monitor mode - HTTP 200", async () => {
    const res = await supertest(base).get("/echo?id=1' OR '1'='1");
    expect(res.status).toBe(200);
  });
});

describe("Fastify plugin - block mode", () => {
  let fastify: FastifyInstance;
  let agent: RaspAgent;
  let base: string;

  beforeAll(async () => {
    ({ fastify, agent, base } = await buildFastifyApp("block"));
  });
  afterAll(async () => {
    await fastify.close();
    await agent.stop();
  });

  it("blocks SQLi - HTTP 403 with eventType", async () => {
    const res = await supertest(base)
      .get("/echo")
      .query({ id: "1 UNION SELECT username,password FROM users--" });
    expect(res.status).toBe(403);
    expect(res.body.eventType).toBe("sql_injection");
  });

  it("blocks path traversal - HTTP 403", async () => {
    const res = await supertest(base)
      .get("/echo")
      .query({ file: "../../../secret.txt" });
    expect(res.status).toBe(403);
    expect(res.body.eventType).toBe("path_traversal");
  });

  it("blocks XSS - HTTP 403", async () => {
    const res = await supertest(base)
      .get("/echo")
      .query({ search: "<script>alert(1)</script>" });
    expect(res.status).toBe(403);
  });

  it("passes clean request - HTTP 200", async () => {
    const res = await supertest(base).get("/health");
    expect(res.status).toBe(200);
  });
});
