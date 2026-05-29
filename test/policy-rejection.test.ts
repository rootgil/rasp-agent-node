/**
 * Tests for policy-rejection observability (logging + telemetry).
 *
 * Covers three layers:
 *  1. PolicyManager pure-unit: accept() returns the correct rejection reasons.
 *  2. Agent console.warn: operators see a message on every distinct rejection.
 *  3. Agent telemetry: a `policy_rejected` event is enqueued exactly once per
 *     unique version+reason pair (deduplication).
 */
import crypto from "node:crypto";
import { describe, it, expect, vi, afterEach } from "vitest";
import { PolicyManager } from "../src/policy/policy-manager.js";
import { RaspAgent } from "../src/agent.js";
import { canonicalPolicyBytes } from "../src/policy/canonical.js";
import type { DistributedPolicy } from "../src/policy/types.js";
import type { SignablePolicy } from "../src/policy/canonical.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    pubPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

function signPolicy(signable: SignablePolicy, privPem: string): string {
  const key = crypto.createPrivateKey(privPem);
  const bytes = canonicalPolicyBytes(signable);
  return crypto.sign(null, bytes, key).toString("base64");
}

function makePolicy(
  overrides: Partial<DistributedPolicy> & { privPem?: string } = {}
): DistributedPolicy {
  const { privPem, ...rest } = overrides;
  const base: SignablePolicy = {
    projectId: rest.projectId ?? "proj1",
    version: rest.version ?? 1,
    channel: rest.channel ?? "stable",
    mode: rest.mode ?? "monitor",
    detectionRules: rest.detectionRules ?? null,
    redactionConfig: rest.redactionConfig ?? null,
    dataResidency: rest.dataResidency ?? null,
    targetAgentVersion: rest.targetAgentVersion ?? null,
  };
  return {
    ...base,
    signature: privPem ? signPolicy(base, privPem) : "INVALIDSIG==",
    signingKeyId: null,
    ...rest,
  };
}

/** Drain the microtask + I/O queue so promise `.then()` handlers run. */
function flushAsync(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

// ---------------------------------------------------------------------------
// 1. PolicyManager – pure unit tests
// ---------------------------------------------------------------------------

describe("PolicyManager rejection reasons", () => {
  it("returns no_trust_anchor when no public keys are configured", () => {
    const pm = new PolicyManager("proj1", []);
    expect(pm.hasTrustAnchor).toBe(false);

    const result = pm.accept(makePolicy());
    expect(result).toEqual({ applied: false, reason: "no_trust_anchor" });
  });

  it("returns no_trust_anchor when all provided keys are blank strings", () => {
    const pm = new PolicyManager("proj1", ["", "  "]);
    expect(pm.hasTrustAnchor).toBe(false);
  });

  it("returns invalid_signature when signature does not match the trust anchor", () => {
    const { pubPem } = makeKeyPair();
    const { privPem: wrongPriv } = makeKeyPair();

    const pm = new PolicyManager("proj1", [pubPem]);
    const policy = makePolicy({ privPem: wrongPriv, projectId: "proj1" });

    const result = pm.accept(policy);
    expect(result).toEqual({ applied: false, reason: "invalid_signature" });
    expect(pm.currentPolicy).toBeNull();
  });

  it("returns invalid_signature for a corrupted trust anchor (non-PEM garbage)", () => {
    const pm = new PolicyManager("proj1", ["NOT_A_VALID_KEY"]);
    expect(pm.hasTrustAnchor).toBe(true); // non-empty, so counts as configured

    const { privPem } = makeKeyPair();
    const result = pm.accept(makePolicy({ privPem, projectId: "proj1" }));
    expect(result).toEqual({ applied: false, reason: "invalid_signature" });
  });

  it("applies a policy when signature is valid", () => {
    const { pubPem, privPem } = makeKeyPair();
    const pm = new PolicyManager("proj1", [pubPem]);

    const policy = makePolicy({ privPem, projectId: "proj1", version: 1 });
    const result = pm.accept(policy);
    expect(result).toEqual({ applied: true });
    expect(pm.currentPolicy).toBe(policy);
    expect(pm.currentVersion).toBe(1);
  });

  it("returns stale_version when an older version arrives after a newer one", () => {
    const { pubPem, privPem } = makeKeyPair();
    const pm = new PolicyManager("proj1", [pubPem]);

    pm.accept(makePolicy({ privPem, projectId: "proj1", version: 5 }));
    const stale = pm.accept(makePolicy({ privPem, projectId: "proj1", version: 3 }));
    expect(stale).toEqual({ applied: false, reason: "stale_version" });
  });
});

// ---------------------------------------------------------------------------
// 2. RaspAgent – console.warn on rejection
// ---------------------------------------------------------------------------

describe("RaspAgent policy rejection logging", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("warns immediately when no trust anchor is configured", async () => {
    const agent = new RaspAgent({
      apiKey: "k",
      projectId: "proj1",
      agentId: "agent1",
      auditLog: false,
      policyPublicKey: "", // empty string → no trust anchor after filter
    });
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    (agent as unknown as Record<string, (v: string) => void>).handlePolicyChange("1");

    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(warnSpy.mock.calls[0][0]).toContain("no trust anchor");

    await agent.stop();
  });

  it("warns with version and reason on invalid_signature", async () => {
    const { pubPem } = makeKeyPair();
    const { privPem: wrongPriv } = makeKeyPair();

    const agent = new RaspAgent({
      apiKey: "k",
      projectId: "proj1",
      agentId: "agent1",
      auditLog: false,
      policyPublicKey: pubPem,
    });

    const badPolicy = makePolicy({ privPem: wrongPriv, projectId: "proj1", version: 1 });
    const agentAny = agent as unknown as Record<string, unknown>;
    vi.spyOn(agentAny.client as { fetchPolicy: () => Promise<DistributedPolicy> }, "fetchPolicy")
      .mockResolvedValue(badPolicy);
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    agentAny.handlePolicyChange("1");
    await flushAsync();

    expect(warnSpy).toHaveBeenCalledTimes(1);
    const msg: string = warnSpy.mock.calls[0][0] as string;
    expect(msg).toContain("v1");
    expect(msg).toContain("invalid_signature");

    await agent.stop();
  });

  it("warns with version and reason on stale_version", async () => {
    const { pubPem, privPem } = makeKeyPair();

    const agent = new RaspAgent({
      apiKey: "k",
      projectId: "proj1",
      agentId: "agent1",
      auditLog: false,
      policyPublicKey: pubPem,
    });

    const agentAny = agent as unknown as Record<string, unknown>;
    const pm = agentAny.policyManager as PolicyManager;
    // Manually advance the PolicyManager to version 5 so next accept of v3 is stale.
    pm.accept(makePolicy({ privPem, projectId: "proj1", version: 5 }));

    const stalePolicy = makePolicy({ privPem, projectId: "proj1", version: 3 });
    vi.spyOn(agentAny.client as { fetchPolicy: () => Promise<DistributedPolicy> }, "fetchPolicy")
      .mockResolvedValue(stalePolicy);
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    agentAny.handlePolicyChange("3");
    await flushAsync();

    expect(warnSpy).toHaveBeenCalledTimes(1);
    const msg: string = warnSpy.mock.calls[0][0] as string;
    expect(msg).toContain("v3");
    expect(msg).toContain("stale_version");

    await agent.stop();
  });

  it("does not warn when the policy is successfully applied", async () => {
    const { pubPem, privPem } = makeKeyPair();

    const agent = new RaspAgent({
      apiKey: "k",
      projectId: "proj1",
      agentId: "agent1",
      auditLog: false,
      policyPublicKey: pubPem,
    });

    const goodPolicy = makePolicy({ privPem, projectId: "proj1", version: 1 });
    const agentAny = agent as unknown as Record<string, unknown>;
    vi.spyOn(agentAny.client as { fetchPolicy: () => Promise<DistributedPolicy> }, "fetchPolicy")
      .mockResolvedValue(goodPolicy);
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    agentAny.handlePolicyChange("1");
    await flushAsync();

    expect(warnSpy).not.toHaveBeenCalled();

    await agent.stop();
  });
});

// ---------------------------------------------------------------------------
// 3. RaspAgent – policy_rejected telemetry event
// ---------------------------------------------------------------------------

describe("RaspAgent policy_rejected telemetry", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("enqueues a policy_rejected event on invalid_signature", async () => {
    const { pubPem } = makeKeyPair();
    const { privPem: wrongPriv } = makeKeyPair();

    const agent = new RaspAgent({
      apiKey: "k",
      projectId: "proj1",
      agentId: "agent1",
      auditLog: false,
      policyPublicKey: pubPem,
    });

    const badPolicy = makePolicy({ privPem: wrongPriv, projectId: "proj1", version: 2 });
    const agentAny = agent as unknown as Record<string, unknown>;
    vi.spyOn(agentAny.client as { fetchPolicy: () => Promise<DistributedPolicy> }, "fetchPolicy")
      .mockResolvedValue(badPolicy);
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const enqueueSpy = vi.spyOn(agentAny.buffer as { enqueue: (e: unknown) => void }, "enqueue");

    agentAny.handlePolicyChange("2");
    await flushAsync();

    expect(enqueueSpy).toHaveBeenCalledTimes(1);
    const event = enqueueSpy.mock.calls[0][0] as Record<string, unknown>;
    expect(event.eventType).toBe("policy_rejected");
    expect(event.projectId).toBe("proj1");
    expect(event.agentId).toBe("agent1");
    expect((event.metadata as Record<string, unknown>).reason).toBe("invalid_signature");
    expect((event.metadata as Record<string, unknown>).version).toBe(2);
    expect((event.metadata as Record<string, unknown>).redacted).toBe(true);

    await agent.stop();
  });

  it("deduplicates: only one enqueue for repeated rejections of the same version+reason", async () => {
    const { pubPem } = makeKeyPair();
    const { privPem: wrongPriv } = makeKeyPair();

    const agent = new RaspAgent({
      apiKey: "k",
      projectId: "proj1",
      agentId: "agent1",
      auditLog: false,
      policyPublicKey: pubPem,
    });

    const badPolicy = makePolicy({ privPem: wrongPriv, projectId: "proj1", version: 1 });
    const agentAny = agent as unknown as Record<string, unknown>;
    vi.spyOn(agentAny.client as { fetchPolicy: () => Promise<DistributedPolicy> }, "fetchPolicy")
      .mockResolvedValue(badPolicy);
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const enqueueSpy = vi.spyOn(agentAny.buffer as { enqueue: (e: unknown) => void }, "enqueue");

    // Simulate two consecutive heartbeats advertising the same rejected policy.
    agentAny.handlePolicyChange("1");
    await flushAsync();
    agentAny.handlePolicyChange("1");
    await flushAsync();

    expect(enqueueSpy).toHaveBeenCalledTimes(1);

    await agent.stop();
  });

  it("enqueues again when a different policy version is rejected", async () => {
    const { pubPem } = makeKeyPair();
    const { privPem: wrongPriv } = makeKeyPair();

    const agent = new RaspAgent({
      apiKey: "k",
      projectId: "proj1",
      agentId: "agent1",
      auditLog: false,
      policyPublicKey: pubPem,
    });

    const agentAny = agent as unknown as Record<string, unknown>;
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const enqueueSpy = vi.spyOn(agentAny.buffer as { enqueue: (e: unknown) => void }, "enqueue");

    // First rejection: version 1
    const policy1 = makePolicy({ privPem: wrongPriv, projectId: "proj1", version: 1 });
    vi.spyOn(agentAny.client as { fetchPolicy: () => Promise<DistributedPolicy> }, "fetchPolicy")
      .mockResolvedValue(policy1);
    agentAny.handlePolicyChange("1");
    await flushAsync();

    // Second rejection: different version → new event
    const policy2 = makePolicy({ privPem: wrongPriv, projectId: "proj1", version: 2 });
    vi.spyOn(agentAny.client as { fetchPolicy: () => Promise<DistributedPolicy> }, "fetchPolicy")
      .mockResolvedValue(policy2);
    agentAny.handlePolicyChange("2");
    await flushAsync();

    expect(enqueueSpy).toHaveBeenCalledTimes(2);
    const event2 = enqueueSpy.mock.calls[1][0] as Record<string, unknown>;
    expect((event2.metadata as Record<string, unknown>).version).toBe(2);

    await agent.stop();
  });

  it("does not enqueue when no trust anchor is configured", async () => {
    const agent = new RaspAgent({
      apiKey: "k",
      projectId: "proj1",
      agentId: "agent1",
      auditLog: false,
      policyPublicKey: "",
    });

    const agentAny = agent as unknown as Record<string, unknown>;
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const enqueueSpy = vi.spyOn(agentAny.buffer as { enqueue: (e: unknown) => void }, "enqueue");

    // no_trust_anchor returns before fetchPolicy, so no event payload to enqueue
    agentAny.handlePolicyChange("1");
    await flushAsync();

    expect(enqueueSpy).not.toHaveBeenCalled();

    await agent.stop();
  });
});

// ---------------------------------------------------------------------------
// 4. RaspAgent – heartbeat mode-change bypass prevention (Addendum E.4.1)
// ---------------------------------------------------------------------------

describe("RaspAgent heartbeat mode-change bypass prevention", () => {
  it("does NOT apply a heartbeat mode hint when a trust anchor is configured", () => {
    const { pubPem } = makeKeyPair();

    // Agent starts in block mode with a trust anchor → mode changes must
    // only arrive via a verified signed policy.
    const agent = new RaspAgent({
      apiKey: "k",
      projectId: "proj1",
      agentId: "agent1",
      auditLog: false,
      mode: "block",
      policyPublicKey: pubPem,
    });

    const agentAny = agent as unknown as Record<string, unknown>;
    expect(agentAny.currentMode).toBe("block");

    // The policyManager must report hasTrustAnchor = true.
    const pm = agentAny.policyManager as { hasTrustAnchor: boolean };
    expect(pm.hasTrustAnchor).toBe(true);

    // Directly invoke the onModeChange closure the agent passed to the
    // HeartbeatScheduler (accessible through the scheduler's private field
    // via the same any-cast pattern used elsewhere in this suite).
    const scheduler = agentAny.heartbeat as Record<string, unknown>;
    const onModeChange = scheduler.onModeChange as ((m: string) => void) | undefined;
    expect(onModeChange).toBeDefined();
    onModeChange?.("monitor");

    // currentMode must remain block - the unsigned heartbeat hint is ignored.
    expect(agentAny.currentMode).toBe("block");

    agent.stop().catch(() => {});
  });

  it("DOES apply a heartbeat mode hint when no trust anchor is configured (legacy path)", () => {
    const agent = new RaspAgent({
      apiKey: "k",
      projectId: "proj1",
      agentId: "agent1",
      auditLog: false,
      mode: "block",
      policyPublicKey: "", // empty → hasTrustAnchor = false
    });

    const agentAny = agent as unknown as Record<string, unknown>;
    expect(agentAny.currentMode).toBe("block");

    const scheduler = agentAny.heartbeat as Record<string, unknown>;
    const onModeChange = scheduler.onModeChange as ((m: string) => void) | undefined;
    expect(onModeChange).toBeDefined();
    onModeChange?.("monitor");

    // With no trust anchor the heartbeat mode is the only control channel.
    expect(agentAny.currentMode).toBe("monitor");

    agent.stop().catch(() => {});
  });
});
