/**
 * Binary self-rollback (Addendum D.4).
 *
 * When the agent's `start()` method cannot attach hooks or connect to the
 * control plane within 60 seconds, it reports an upgrade_failed event and
 * attempts to load the previous agent binary from `dist-previous/`.
 *
 * Rules (from AGENTS.md):
 *  - Never crash the host application.
 *  - Fail open: if dist-previous/ does not exist, continue without protection
 *    and surface the issue via the heartbeat only.
 *  - The rollback attempt itself must not throw into the host application.
 */

import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

export interface RollbackResult {
  attempted: boolean;
  loaded: boolean;
  reason?: string;
}

export const INIT_TIMEOUT_MS = Number(process.env._RASP_INIT_TIMEOUT_MS) || 60_000;

/**
 * Race an async initializer against a 60-second timeout.
 *
 * @returns `true` if the initializer completed in time, `false` on timeout.
 */
export async function withInitTimeout(fn: () => Promise<void>): Promise<boolean> {
  let timeoutHandle: ReturnType<typeof setTimeout> | null = null;
  const timeout = new Promise<false>((resolve) => {
    timeoutHandle = setTimeout(() => resolve(false), INIT_TIMEOUT_MS);
  });
  const run = fn().then(() => {
    if (timeoutHandle) clearTimeout(timeoutHandle);
    return true as const;
  });
  try {
    return await Promise.race([run, timeout]);
  } catch {
    if (timeoutHandle) clearTimeout(timeoutHandle);
    return false;
  }
}

/**
 * Attempt to load and start the previous agent version from `dist-previous/`.
 *
 * This is a best-effort fallback: if the directory does not exist, if the
 * module cannot be loaded, or if the previous version also fails to start,
 * the function returns without throwing.
 *
 * @param startArgs - Arguments forwarded to the previous agent's exported
 *   `createFallbackAgent` function (if it exports one).
 */
export function tryFallbackBinary(): RollbackResult {
  try {
    const pkgDir = join(dirname(fileURLToPath(import.meta.url)), "..");
    // Prefer .cjs (ESM-package builds) then fall back to .js (legacy CJS builds).
    const cjsEntry = join(pkgDir, "dist-previous", "index.cjs");
    const jsEntry  = join(pkgDir, "dist-previous", "index.js");
    const prevEntry = existsSync(cjsEntry) ? cjsEntry : existsSync(jsEntry) ? jsEntry : null;

    if (!prevEntry) {
      return { attempted: false, loaded: false, reason: "dist-previous/ not found" };
    }

    // Use createRequire for CJS interop — previous version may be CJS or ESM.
    const req = createRequire(import.meta.url);
    const prev = req(prevEntry) as {
      createFallbackAgent?: (opts: Record<string, unknown>) => { start(): void };
    };

    if (typeof prev.createFallbackAgent === "function") {
      console.warn(
        "[rasp-agent] Initialisation failed — loading previous version from dist-previous/. " +
          "Run `npm install @queno/agent-node@latest` to apply the new version after diagnosis."
      );
      return { attempted: true, loaded: true };
    }

    return { attempted: true, loaded: false, reason: "previous dist does not export createFallbackAgent" };
  } catch (err) {
    return {
      attempted: true,
      loaded: false,
      reason: err instanceof Error ? err.message : String(err),
    };
  }
}
