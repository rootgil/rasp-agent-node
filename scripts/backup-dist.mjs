#!/usr/bin/env node
/**
 * Backup current dist/ to dist-previous/ BEFORE upgrading the agent package.
 *
 * Run this script from your project root BEFORE running `npm install @queno/agent-node@<new>`:
 *
 *   node node_modules/@queno/agent-node/scripts/backup-dist.mjs
 *
 * This enables binary self-rollback (Addendum D.4): if the new version fails to
 * initialize within 60 seconds, the agent automatically loads dist-previous/ and
 * reports an upgrade_failed event to the control plane.
 *
 * The backup is also created automatically at the end of each release build by the
 * GitLab CI pipeline (the PREVIOUS release's dist/ is embedded as dist-previous/ in
 * every new release tarball).
 */

import { cpSync, existsSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const pkgDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const distDir = join(pkgDir, "dist");
const prevDir = join(pkgDir, "dist-previous");

if (!existsSync(distDir)) {
  console.log("[rasp-agent] No dist/ found — nothing to back up.");
  process.exit(0);
}

if (existsSync(prevDir)) {
  rmSync(prevDir, { recursive: true, force: true });
}

cpSync(distDir, prevDir, { recursive: true });

console.log(`[rasp-agent] dist/ backed up to dist-previous/ (${pkgDir})`);
console.log("[rasp-agent] You can now safely upgrade to the new agent version.");
