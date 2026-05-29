/**
 * Observes HTTP requests passively and aggregates per-endpoint statistics for
 * runtime API discovery (Addendum A.2): endpoint inventory, auth state, data
 * sensitivity, schema inference and traffic profile (volume, error rate,
 * latency).
 *
 * All operations are synchronous and in-memory - no I/O, no throws. Designed to
 * be called from {@link RaspAgent.inspect} (request phase) and from the
 * integration's response hook via {@link EndpointObserver.observeOutcome}.
 */
import type { NormalizedRequest, AuthStatus, DiscoveryEntry, RequestOutcome } from "../types.js";
import { normalizePath } from "./route-normalizer.js";
import { DEFAULT_REDACTION_PATTERNS } from "../redaction/patterns.js";

interface EndpointStats {
  authStatus: AuthStatus;
  hasSensitiveData: boolean;
  count: number;
  authObserved: boolean;
  errorCount: number;
  sumDurationMs: number;
  timedCount: number;
  schemaFields: Record<string, string>;
}

function hasSensitiveKeys(obj: unknown): boolean {
  if (!obj || typeof obj !== "object") return false;
  return Object.keys(obj as Record<string, unknown>).some((key) =>
    DEFAULT_REDACTION_PATTERNS.some((p) => p.matchKey.test(key))
  );
}

function inferAuthStatus(req: NormalizedRequest): AuthStatus {
  const auth = req.headers["authorization"];
  if (auth && typeof auth === "string" && auth.length > 0) {
    return "authenticated";
  }
  return "unauthenticated";
}

function inferHasSensitiveData(req: NormalizedRequest): boolean {
  return hasSensitiveKeys(req.body) || hasSensitiveKeys(req.query);
}

function jsonType(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  return typeof v;
}

/** Merge the top-level keys of query + body into a field -> type map. */
function inferSchema(req: NormalizedRequest, into: Record<string, string>): void {
  const sources: unknown[] = [req.query, req.body];
  for (const src of sources) {
    if (src && typeof src === "object" && !Array.isArray(src)) {
      for (const [k, v] of Object.entries(src as Record<string, unknown>)) {
        if (!(k in into)) into[k] = jsonType(v);
      }
    }
  }
}

function keyFor(req: NormalizedRequest): string {
  return `${req.method.toUpperCase()}:${normalizePath(req.path)}`;
}

export class EndpointObserver {
  private readonly stats = new Map<string, EndpointStats>();

  /** Record one request observation. Synchronous, never throws. */
  observe(req: NormalizedRequest): void {
    try {
      const key = keyFor(req);
      const existing = this.stats.get(key);
      if (existing) {
        existing.count++;
        if (existing.authStatus !== "authenticated") {
          existing.authStatus = inferAuthStatus(req);
        }
        if (!existing.hasSensitiveData) {
          existing.hasSensitiveData = inferHasSensitiveData(req);
        }
        inferSchema(req, existing.schemaFields);
      } else {
        const schemaFields: Record<string, string> = {};
        inferSchema(req, schemaFields);
        this.stats.set(key, {
          authStatus: inferAuthStatus(req),
          hasSensitiveData: inferHasSensitiveData(req),
          count: 1,
          authObserved: false,
          errorCount: 0,
          sumDurationMs: 0,
          timedCount: 0,
          schemaFields,
        });
      }
    } catch {
      // Fail open - never propagate to host application.
    }
  }

  /**
   * Record the response-phase outcome for a request. Updates the traffic
   * profile (error rate, latency) and confirms auth middleware execution.
   */
  observeOutcome(req: NormalizedRequest, outcome: RequestOutcome): void {
    try {
      const key = keyFor(req);
      const s = this.stats.get(key);
      if (!s) return;
      if (typeof outcome.statusCode === "number" && outcome.statusCode >= 400) {
        s.errorCount++;
      }
      if (typeof outcome.durationMs === "number" && outcome.durationMs >= 0) {
        s.sumDurationMs += outcome.durationMs;
        s.timedCount++;
      }
      if (outcome.authenticated) {
        s.authObserved = true;
        s.authStatus = "authenticated";
      }
    } catch {
      // Fail open.
    }
  }

  /** Drain accumulated stats and reset. */
  drain(): DiscoveryEntry[] {
    const entries: DiscoveryEntry[] = [];
    for (const [key, s] of this.stats) {
      const colonIdx = key.indexOf(":");
      entries.push({
        method: key.slice(0, colonIdx),
        pathPattern: key.slice(colonIdx + 1),
        authStatus: s.authStatus,
        hasSensitiveData: s.hasSensitiveData,
        observationCount: s.count,
        authObserved: s.authObserved,
        errorCount: s.errorCount,
        sumDurationMs: s.sumDurationMs,
        timedCount: s.timedCount,
        schemaFields: s.schemaFields,
      });
    }
    this.stats.clear();
    return entries;
  }

  get size(): number {
    return this.stats.size;
  }
}
