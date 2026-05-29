/**
 * Local redaction audit log.
 *
 * Per `AGENTS.md` "Local Redaction Audit Log" rules:
 *  - every redaction action is recorded locally inside the customer
 *    environment;
 *  - lines never contain raw sensitive values - only metadata;
 *  - log rotation by file size is supported to avoid filling the disk;
 *  - audit-log failures must NEVER crash the host application - every
 *    failure path here returns silently.
 *
 * On-disk format: JSON-Lines (one {@link RedactionAuditEntry} per line),
 * UTF-8, append-mode. When the file exceeds `maxBytes`, it is renamed to
 * `<path>.<n>` and a fresh file is opened.
 */
import fs from "node:fs";
import path from "node:path";
import type { RedactionAuditEntry } from "../types.js";

export class AuditLog {
  private readonly filePath: string;
  private readonly maxBytes: number;
  private fd: number | null = null;
  private currentBytes = 0;
  private rotationIndex = 0;

  /**
   * @param filePath - Destination file. Relative paths are resolved against
   *   the process CWD.
   * @param maxBytes - Maximum file size before rotation.
   */
  constructor(filePath: string, maxBytes: number) {
    this.filePath = path.resolve(filePath);
    this.maxBytes = maxBytes;
  }

  /**
   * Append one entry as JSON + `\n`. Rotates the file first if appending
   * the line would cross the size threshold.
   *
   * All failures (disk full, EBADF, permissions…) are swallowed: an audit
   * log issue must never propagate into the request hot path.
   */
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
      // Intentional - see class-level note.
    }
  }

  /**
   * Close the underlying file descriptor. Idempotent; safe to call from
   * shutdown handlers and from the kill-switch path.
   */
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

  /**
   * Lazily open the file (creating the parent directory if needed) and
   * seed `currentBytes` from the existing file size so we don't blow past
   * `maxBytes` after a restart.
   */
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

  /**
   * Close the active file, rename it to `<path>.<rotationIndex>` and reopen
   * a fresh one. If the rename fails (e.g. EACCES), keep writing to the
   * same file - losing rotation is preferred to losing audit data.
   */
  private rotate(): void {
    this.close();
    this.rotationIndex += 1;
    const rotated = `${this.filePath}.${this.rotationIndex}`;
    try {
      fs.renameSync(this.filePath, rotated);
    } catch {
      // See rationale above.
    }
    this.currentBytes = 0;
    this.ensureOpen();
  }
}
