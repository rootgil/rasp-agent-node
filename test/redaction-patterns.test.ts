import { describe, it, expect } from "vitest";
import { redactValueString } from "../src/redaction/patterns.js";

describe("redactValueString", () => {
  it("masks a Luhn-valid credit card keeping the last 4 digits", () => {
    const { value, redacted } = redactValueString("card 4111 1111 1111 1111 end");
    expect(redacted).toBe(true);
    expect(value).toContain("****-****-****-1111");
    expect(value).not.toContain("4111 1111 1111 1111");
  });

  it("leaves plain non-sensitive text untouched", () => {
    const { value, redacted } = redactValueString("the quick brown fox jumps over");
    expect(redacted).toBe(false);
    expect(value).toBe("the quick brown fox jumps over");
  });

  it("hashes emails instead of leaking them", () => {
    const { value, redacted } = redactValueString("contact alice@example.com please");
    expect(redacted).toBe(true);
    expect(value).toMatch(/\[EMAIL:[0-9a-f]{16}\]/);
    expect(value).not.toContain("alice@example.com");
  });

  it("hashes the same email deterministically", () => {
    const a = redactValueString("alice@example.com").value;
    const b = redactValueString("ALICE@example.com").value;
    expect(a).toBe(b);
  });

  it("masks IPv4 addresses by default (hash mode)", () => {
    const { value } = redactValueString("from 192.168.1.42");
    expect(value).not.toContain("192.168.1.42");
  });

  it("passes through IPs when ipMode is passthrough", () => {
    const { value } = redactValueString("from 8.8.8.8", "passthrough");
    expect(value).toContain("8.8.8.8");
  });

  it("scrubs SQL string and numeric literals", () => {
    const { value, redacted } = redactValueString("SELECT * FROM users WHERE id = 42 AND name = 'bob'");
    expect(redacted).toBe(true);
    expect(value).toContain("[INT]");
    expect(value).toContain("[STRING]");
  });

  it("scrubs Bearer and JWT shapes", () => {
    const { value, redacted } = redactValueString(
      "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaa.bbb"
    );
    expect(redacted).toBe(true);
    expect(value).toContain("Bearer [REDACTED]");
  });
});
