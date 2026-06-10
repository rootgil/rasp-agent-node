#!/usr/bin/env node
/**
 * Reads benchmarks/output/with-agent.json (produced by the nightly k6 run)
 * and overwrites benchmarks/baselines/p99-baseline.json with the new P99 value.
 *
 * Called by the nightly workflow after a successful benchmark run so that the
 * committed baseline always reflects the current state of main.
 *
 * Usage:
 *   node benchmarks/update-baseline.js
 */
import { readFileSync, writeFileSync } from "node:fs";

const WITH_AGENT_PATH = "benchmarks/output/with-agent.json";
const BASELINE_PATH   = "benchmarks/baselines/p99-baseline.json";

const { p99 } = JSON.parse(readFileSync(WITH_AGENT_PATH, "utf8"));

if (typeof p99 !== "number") {
  console.error(`update-baseline: no numeric p99 in ${WITH_AGENT_PATH}`);
  process.exit(1);
}

const majorNodeVersion = process.version.slice(1).split(".")[0];
const date = new Date().toISOString().slice(0, 10);

const baseline = {
  _comment:
    "Reference P99 (with-agent, monitor mode) on main. Updated automatically by the nightly workflow after each successful benchmark run.",
  date,
  environment: process.env.BENCHMARK_ENV ?? "github-actions-ubuntu-latest",
  nodeVersion: majorNodeVersion,
  vus: 50,
  duration: "30s",
  p99,
};

writeFileSync(BASELINE_PATH, JSON.stringify(baseline, null, 2) + "\n");
console.log(`Baseline updated: p99 = ${p99.toFixed(2)} ms  (${date}, Node ${majorNodeVersion})`);
