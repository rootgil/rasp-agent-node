/**
 * Observes HTTP requests passively and aggregates per-endpoint statistics.
 *
 * All operations are synchronous and in-memory — no I/O, no throws.
 * The observer is designed to be called from {@link RaspAgent.inspect} on
 * every request before the detector pipeline runs.
 */
import type { NormalizedRequest } from "../types.js";
import type { AuthStatus, DiscoveryEntry } from "../types.js";
import { normalizePath } from "./route-normalizer.js";
import { DEFAULT_REDACTION_PATTERNS } from "../redaction/patterns.js";

interface EndpointStats {
  authStatus: AuthStatus;
  hasSensitiveData: boolean;
  count: number;
}

/**
 * Keys that signal sensitive data in the request body or query params.
 * Reuses the same patterns as the redaction engine for consistency.
 */
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

export class EndpointObserver {
  private readonly stats = new Map<string, EndpointStats>();

  /**
   * Record one observation for the given request.
   *
   * Synchronous, never throws. Safe to call from the hot request path.
   */
  observe(req: NormalizedRequest): void {
    try {
      const pathPattern = normalizePath(req.path);
      const method = req.method.toUpperCase();
      const key = `${method}:${pathPattern}`;

      const existing = this.stats.get(key);
      if (existing) {
        existing.count++;
        // Promote from unauthenticated/unknown to authenticated if we see auth
        if (existing.authStatus !== "authenticated") {
          existing.authStatus = inferAuthStatus(req);
        }
        // Sticky: once sensitive data seen, stays true
        if (!existing.hasSensitiveData) {
          existing.hasSensitiveData = inferHasSensitiveData(req);
        }
      } else {
        this.stats.set(key, {
          authStatus: inferAuthStatus(req),
          hasSensitiveData: inferHasSensitiveData(req),
          count: 1,
        });
      }
    } catch {
      // Fail open — never propagate to host application
    }
  }

  /**
   * Drain the accumulated stats and reset the map.
   *
   * Returns the current batch as an array of {@link DiscoveryEntry} objects,
   * ready to be included in a {@link DiscoveryPayload}.
   */
  drain(): DiscoveryEntry[] {
    const entries: DiscoveryEntry[] = [];

    for (const [key, s] of this.stats) {
      const colonIdx = key.indexOf(":");
      const method = key.slice(0, colonIdx);
      const pathPattern = key.slice(colonIdx + 1);

      entries.push({
        method,
        pathPattern,
        authStatus: s.authStatus,
        hasSensitiveData: s.hasSensitiveData,
        observationCount: s.count,
      });
    }

    this.stats.clear();
    return entries;
  }

  /** Current number of distinct endpoints accumulated since last drain. */
  get size(): number {
    return this.stats.size;
  }
}
