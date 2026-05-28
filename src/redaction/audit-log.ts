import fs from "node:fs";
import path from "node:path";
import type { RedactionAuditEntry } from "../types.js";

export class AuditLog {
  private readonly filePath: string;
  private readonly maxBytes: number;
  private fd: number | null = null;
  private currentBytes = 0;
  private rotationIndex = 0;

  constructor(filePath: string, maxBytes: number) {
    this.filePath = path.resolve(filePath);
    this.maxBytes = maxBytes;
  }

  write(entry: RedactionAuditEntry): void {
    try {
      const line = JSON.stringify(entry) + "\n";
      const lineBytes = Buffer.byteLength(line, "utf8");

      this.ensureOpen();

      if (this.currentBytes + lineBytes > this.maxBytes) {
        this.rotate();
      }

      if (this.fd !== null) {
        fs.writeSync(this.fd, line);
        this.currentBytes += lineBytes;
      }
    } catch {
      // Audit log failure must never crash the host application.
    }
  }

  close(): void {
    if (this.fd !== null) {
      try {
        fs.closeSync(this.fd);
      } catch {
        // ignore
      }
      this.fd = null;
    }
  }

  private ensureOpen(): void {
    if (this.fd !== null) return;

    const dir = path.dirname(this.filePath);
    fs.mkdirSync(dir, { recursive: true });

    this.fd = fs.openSync(this.filePath, "a");

    try {
      const stat = fs.fstatSync(this.fd);
      this.currentBytes = stat.size;
    } catch {
      this.currentBytes = 0;
    }
  }

  private rotate(): void {
    this.close();
    this.rotationIndex += 1;
    const rotated = `${this.filePath}.${this.rotationIndex}`;
    try {
      fs.renameSync(this.filePath, rotated);
    } catch {
      // If rename fails, continue writing to the same file.
    }
    this.currentBytes = 0;
    this.ensureOpen();
  }
}
