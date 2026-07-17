/**
 * Post-build script: hash every .js file in dist/ and write dist/integrity.json.
 *
 * integrity.json is intentionally excluded from its own manifest (it cannot
 * hash itself). The agent reads this file at startup and compares hashes to
 * detect post-install tampering (Addendum E.7).
 *
 * Usage: node scripts/generate-integrity.mjs (called by npm postbuild)
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const rootDir = join(__dirname, "..");
const distDir = join(rootDir, "dist");

const pkg = JSON.parse(readFileSync(join(rootDir, "package.json"), "utf8"));

function sha256(filePath) {
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}

function collectJsFiles(dir, result = {}) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      collectJsFiles(full, result);
    } else if (entry.name.endsWith(".js") && entry.name !== "integrity.json") {
      result[relative(distDir, full)] = sha256(full);
    }
  }
  return result;
}

const files = collectJsFiles(distDir);

// Stable key order so JSON output does not depend on readdir() order.
const sortedFiles = Object.fromEntries(
  Object.entries(files).sort(([a], [b]) => a.localeCompare(b))
);

// Prefer SOURCE_DATE_EPOCH so dual CI builds produce identical integrity.json.
const epoch = process.env.SOURCE_DATE_EPOCH;
const generatedAt =
  epoch != null && epoch !== ""
    ? new Date(Number(epoch) * 1000).toISOString()
    : new Date().toISOString();

const manifest = {
  version: pkg.version,
  generatedAt,
  files: sortedFiles,
};

writeFileSync(join(distDir, "integrity.json"), JSON.stringify(manifest, null, 2) + "\n");
console.log(
  `[integrity] Hashed ${Object.keys(sortedFiles).length} files → dist/integrity.json (v${pkg.version})`
);
