import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, readFileSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { AuditLog } from "../src/redaction/audit-log.js";
import type { RedactionAuditEntry } from "../src/types.js";

describe("AuditLog", () => {
  let dir: string;
  let filePath: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "rasp-audit-"));
    filePath = join(dir, "audit.jsonl");
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("writes metadata-only entries without raw secrets", () => {
    const log = new AuditLog(filePath, 1024 * 1024);
    const entry: RedactionAuditEntry = {
      ts: new Date().toISOString(),
      agentId: "agent-1",
      projectId: "proj-1",
      eventType: "sql_injection",
      redactedFields: ["body.password"],
      dropped: false,
    };
    log.write(entry);
    log.close();

    expect(existsSync(filePath)).toBe(true);
    const content = readFileSync(filePath, "utf8");
    expect(content).toContain("body.password");
    expect(content).not.toContain("supersecret");
  });
});
