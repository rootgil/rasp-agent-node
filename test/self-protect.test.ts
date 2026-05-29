import { describe, it, expect } from "vitest";
import { SecureStore, detectDebugger, startSelfProtection } from "../src/self-protect.js";

describe("SecureStore", () => {
  it("round-trips a secret without storing plaintext", () => {
    const store = new SecureStore();
    store.set("apiKey", "super-secret-value");
    expect(store.has("apiKey")).toBe(true);
    expect(store.get("apiKey")).toBe("super-secret-value");
  });

  it("returns null for unknown keys", () => {
    const store = new SecureStore();
    expect(store.get("nope")).toBeNull();
    expect(store.has("nope")).toBe(false);
  });

  it("clears entries", () => {
    const store = new SecureStore();
    store.set("a", "1");
    store.clear();
    expect(store.get("a")).toBeNull();
  });

  it("does not expose the plaintext on the instance", () => {
    const store = new SecureStore();
    store.set("hmac", "plaintext-marker");
    expect(JSON.stringify(store)).not.toContain("plaintext-marker");
  });
});

describe("detectDebugger", () => {
  it("returns null when no inspector is attached", () => {
    // The test runner is not launched with --inspect.
    expect(detectDebugger()).toBeNull();
  });
});

describe("startSelfProtection", () => {
  it("returns a stop function and never throws", () => {
    const stop = startSelfProtection({ antiDebug: true, checkHooks: false, intervalMs: 10_000 });
    expect(typeof stop).toBe("function");
    stop();
  });
});
