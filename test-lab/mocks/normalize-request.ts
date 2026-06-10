/**
 * Helper to construct a NormalizedRequest from partial data for use in tests.
 * Fills in safe defaults so tests only need to specify what they care about.
 */
import type { NormalizedRequest } from "../../src/types.js";

export function normalizeRequest(
  partial: Partial<NormalizedRequest> & { path: string }
): NormalizedRequest {
  return {
    method: partial.method ?? "GET",
    path: partial.path,
    query: partial.query ?? {},
    headers: partial.headers ?? {},
    body: partial.body ?? null,
    sourceIp: partial.sourceIp ?? "127.0.0.1",
  };
}

/** Build a NormalizedRequest from a fixture payload entry. */
export function requestFromFixture(fixture: {
  method: string;
  path: string;
  query: Record<string, unknown>;
  headers: Record<string, string>;
  body: unknown;
}): NormalizedRequest {
  return {
    method: fixture.method,
    path: fixture.path,
    query: fixture.query,
    headers: fixture.headers,
    body: fixture.body,
    sourceIp: "1.2.3.4",
  };
}
