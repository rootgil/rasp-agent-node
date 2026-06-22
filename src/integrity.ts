/**
 * Binary integrity check — Addendum E.7.
 *
 * Verifies the agent's own dist/ files against the manifest (`dist/integrity.json`)
 * generated at release time by `scripts/generate-integrity.mjs`.
 *
 * Rules (from AGENTS.md):
 *  - Must never crash the host application.
 *  - Fail-open: log a warning, then continue loading.
 *  - In development (tsx / ts-node) integrity.json does not exist → skip silently.
 */
import { createHash } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

interface IntegrityManifest {
  version: string;
  generatedAt: string;
  files: Record<string, string>;
}

export function checkBinaryIntegrity(): void {
  try {
    const distDir = dirname(fileURLToPath(import.meta.url));
    const manifestPath = join(distDir, "integrity.json");

    if (!existsSync(manifestPath)) {
      // Development mode (tsx/ts-node runs from src/ without a compiled dist/).
      return;
    }

    const manifest: IntegrityManifest = JSON.parse(
      readFileSync(manifestPath, "utf8")
    );

    const failures: string[] = [];

    for (const [rel, expected] of Object.entries(manifest.files)) {
      const fullPath = join(distDir, rel);
      if (!existsSync(fullPath)) {
        failures.push(`${rel}: missing`);
        continue;
      }
      const actual = createHash("sha256")
        .update(readFileSync(fullPath))
        .digest("hex");
      if (actual !== expected) {
        failures.push(`${rel}: hash mismatch`);
      }
    }

    if (failures.length > 0) {
      // IMPORTANT: do not throw — the agent must fail-open.
      console.warn(
        "[rasp-agent] INTEGRITY WARNING: the agent binary may have been modified " +
          "after installation. Continuing in fail-open mode. Affected files: " +
          failures.join(", ")
      );
    }
  } catch {
    // Silently swallow any filesystem / JSON error — fail-open.
  }
}
