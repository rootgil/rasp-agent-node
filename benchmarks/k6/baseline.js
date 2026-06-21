/**
 * k6 baseline benchmark - banking-api WITHOUT RASP agent.
 *
 * Used to capture the reference P99 latency of the application alone.
 * Run against banking-api started with RASP_ENABLED=false.
 *
 * Usage:
 *   k6 run benchmarks/k6/baseline.js --env BASE_URL=http://127.0.0.1:3001
 *
 * Output: benchmarks/output/baseline.json (written by handleSummary)
 */
import http from "k6/http";
import { check, sleep } from "k6";
import { textSummary } from "https://jslib.k6.io/k6-summary/0.0.2/index.js";

export const options = {
  vus: 50,
  duration: "30s",
  summaryTrendStats: ["p(99)"],
  thresholds: {
    // Baseline passes unconditionally - only used as reference
    http_req_duration: ["p(99)<2000"],
  },
};

const BASE_URL = __ENV.BASE_URL || "http://127.0.0.1:3001";

export default function () {
  const healthRes = http.get(`${BASE_URL}/health`);
  check(healthRes, { "health 200": (r) => r.status === 200 });

  const usersRes = http.get(`${BASE_URL}/api/users/1`);
  check(usersRes, { "users 200": (r) => r.status === 200 });

  sleep(0.01);
}

export function handleSummary(data) {
  const p99 = data.metrics["http_req_duration"].values["p(99)"];
  if (typeof p99 !== "number") {
    throw new Error("handleSummary: p(99) not found in http_req_duration metrics");
  }
  const quiet = __ENV.CI_QUIET === "1";
  return {
    "benchmarks/output/baseline.json": JSON.stringify({ p99 }, null, 2),
    stdout: quiet
      ? `baseline p99=${p99.toFixed(2)}ms\n`
      : textSummary(data, { indent: " ", enableColors: true }),
  };
}
