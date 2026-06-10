#!/usr/bin/env node
/**
 * Compare P99 latency between baseline and with-agent k6 runs.
 *
 * Reads two compact JSON files produced by handleSummary() in the k6 scripts
 * and checks that the agent overhead stays within the allowed thresholds:
 *   - > 1%  → warning (exit 0, printed to stdout)
 *   - > 5%  → error (exit 1, CI fails)
 *
 * Usage:
 *   node benchmarks/compare-p99.js \
 *     benchmarks/output/baseline.json \
 *     benchmarks/output/with-agent.json
 *
 * Expected file format (written by k6 handleSummary):
 *   { "p99": <number in ms> }
 */
import { readFileSync } from "node:fs";

const WARN_THRESHOLD = 0.01;  // 1%
const FAIL_THRESHOLD = 0.05;  // 5%

function readP99(filePath) {
  const { p99 } = JSON.parse(readFileSync(filePath, "utf8"));
  if (typeof p99 !== "number") {
    throw new Error(`No p99 value in ${filePath}`);
  }
  return p99;
}

function main() {
  const [, , baselineFile, withAgentFile] = process.argv;

  if (!baselineFile || !withAgentFile) {
    console.error("Usage: node compare-p99.js <baseline.json> <with-agent.json>");
    process.exit(2);
  }

  let baselineP99, withAgentP99;

  try {
    baselineP99  = readP99(baselineFile);
    withAgentP99 = readP99(withAgentFile);
  } catch (err) {
    console.error(`Error reading k6 output: ${err.message}`);
    process.exit(2);
  }

  const delta        = (withAgentP99 - baselineP99) / baselineP99;
  const deltaPercent = (delta * 100).toFixed(2);

  console.log(`Baseline P99  : ${baselineP99.toFixed(2)} ms`);
  console.log(`With-agent P99: ${withAgentP99.toFixed(2)} ms`);
  console.log(`Delta         : ${deltaPercent}%`);

  if (delta > FAIL_THRESHOLD) {
    console.error(
      `FAIL: agent P99 overhead is ${deltaPercent}% (> ${FAIL_THRESHOLD * 100}% allowed). ` +
      "This commit must be reviewed before merging."
    );
    process.exit(1);
  }

  if (delta > WARN_THRESHOLD) {
    console.warn(
      `WARN: agent P99 overhead is ${deltaPercent}% (> ${WARN_THRESHOLD * 100}% threshold). ` +
      "Manual review recommended."
    );
    // exit 0 — warning only
  } else {
    console.log(`OK: overhead within ${WARN_THRESHOLD * 100}% threshold.`);
  }
}

main();
