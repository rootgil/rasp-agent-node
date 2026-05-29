/**
 * Agent self-protection (Addendum E.7).
 *
 * Three best-effort, fail-open defences that raise the bar for tampering with
 * the agent at runtime:
 *
 *  1. {@link SecureStore} - keeps secrets (API key, HMAC secret) encrypted in
 *     memory with a per-process random key, so a heap dump or accidental log of
 *     the config object does not leak them in plaintext.
 *  2. Hook-integrity monitoring - periodically verifies the DB instrumentation
 *     hooks are still installed and unmodified (detects an attacker un-hooking
 *     the agent to evade BOLA-via-DB detection).
 *  3. Basic anti-debug - detects an attached V8 inspector / `--inspect` flag,
 *     which is a common foothold for tampering with a running process.
 *
 * None of these are a substitute for OS-level hardening; they are defence in
 * depth and never crash the host application.
 */
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { verifyHookIntegrity } from "./db-hooks/instrument.js";

const nodeRequire = createRequire(import.meta.url);

/**
 * Encrypts string secrets in memory under a per-process key. The key lives only
 * in this closure and is never persisted, so the stored ciphertext is useless
 * outside the running process.
 */
export class SecureStore {
  private readonly key = randomBytes(32);
  private readonly entries = new Map<string, { iv: Buffer; tag: Buffer; data: Buffer }>();

  set(name: string, value: string): void {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    const data = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    this.entries.set(name, { iv, tag, data });
  }

  get(name: string): string | null {
    const e = this.entries.get(name);
    if (!e) return null;
    try {
      const decipher = createDecipheriv("aes-256-gcm", this.key, e.iv);
      decipher.setAuthTag(e.tag);
      return Buffer.concat([decipher.update(e.data), decipher.final()]).toString("utf8");
    } catch {
      return null;
    }
  }

  has(name: string): boolean {
    return this.entries.has(name);
  }

  clear(): void {
    this.entries.clear();
  }
}

/**
 * Detect whether a V8 inspector/debugger is attached or was requested via exec
 * args (`--inspect`, `--inspect-brk`, `--debug`). Returns the reason, or null.
 */
export function detectDebugger(): string | null {
  try {
    const inspectArg = process.execArgv.find((a) => /^--(inspect|debug)/.test(a));
    if (inspectArg) return `exec-arg:${inspectArg}`;
  } catch {
    /* ignore */
  }
  try {
    // Lazy require so environments without the module are unaffected.
    const inspector = nodeRequire("node:inspector") as { url?: () => string | undefined };
    if (typeof inspector.url === "function" && inspector.url()) {
      return "inspector-attached";
    }
  } catch {
    /* ignore */
  }
  return null;
}

export interface SelfProtectionOptions {
  /** Verify DB hook integrity (only meaningful when DB instrumentation is on). */
  checkHooks?: boolean;
  /** Watch for an attached debugger. */
  antiDebug?: boolean;
  /** Poll interval in ms. Default 30s. */
  intervalMs?: number;
  /** Sink for warnings. Defaults to `console.warn`. */
  onWarning?: (message: string, detail: unknown) => void;
}

/**
 * Start periodic self-protection checks. Returns a stop function. The timer is
 * `unref`'d so it never keeps the host process alive.
 */
export function startSelfProtection(options: SelfProtectionOptions = {}): () => void {
  const interval = options.intervalMs ?? 30_000;
  const warn =
    options.onWarning ??
    ((message: string, detail: unknown) => {
      try {
        console.warn(`[rasp:self-protect] ${message}`, detail);
      } catch {
        /* ignore */
      }
    });

  let debuggerReported = false;

  const tick = () => {
    if (options.checkHooks) {
      try {
        const tampered = verifyHookIntegrity();
        if (tampered.length > 0) {
          warn("DB hook integrity violation detected", tampered);
        }
      } catch {
        /* fail open */
      }
    }
    if (options.antiDebug) {
      try {
        const reason = detectDebugger();
        if (reason && !debuggerReported) {
          debuggerReported = true;
          warn("debugger/inspector detected", { reason });
        } else if (!reason) {
          debuggerReported = false;
        }
      } catch {
        /* fail open */
      }
    }
  };

  const timer = setInterval(tick, interval);
  if (typeof timer.unref === "function") timer.unref();
  // Run one immediate check so violations present at boot are surfaced fast.
  tick();

  return () => clearInterval(timer);
}
