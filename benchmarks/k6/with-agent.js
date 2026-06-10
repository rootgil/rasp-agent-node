/**
 * k6 benchmark — banking-api WITH RASP agent (monitor mode).
 *
 * Used to measure the overhead introduced by the agent on the same endpoint
 * mix as the baseline. The compare-p99 script then computes the delta.
 *
 * Usage:
 *   k6 run benchmarks/k6/with-agent.js --env BASE_URL=http://127.0.0.1:3000
 *
 * Output: benchmarks/output/with-agent.json (written by handleSummary)
 *
 * Thresholds here catch catastrophic regressions (>10x baseline). The
 * precise 5% gate is enforced by compare-p99.js using the baseline output.
 */
import http from "k6/http";
import { check, sleep } from "k6";
import { textSummary } from "https://jslib.k6.io/k6-summary/0.0.2/index.js";

export const options = {
  vus: 50,
  duration: "30s",
  summaryTrendStats: ["p(99)"],
  thresholds: {
    // Hard stop if P99 exceeds 2 s (catastrophic — agent should not add that much)
    http_req_duration: ["p(99)<2000"],
  },
};

const BASE_URL = __ENV.BASE_URL || "http://127.0.0.1:3000";

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
  return {
    "benchmarks/output/with-agent.json": JSON.stringify({ p99 }, null, 2),
    stdout: textSummary(data, { indent: " ", enableColors: true }),
  };
}
