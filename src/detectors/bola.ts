/**
 * Broken Object Level Authorization (BOLA / IDOR) detector.
 *
 * OWASP API Security Top-10 #1. Two complementary heuristics:
 *
 * 1. **JWT-sub mismatch** - if the `Authorization: Bearer …` header carries
 *    a JWT whose `sub` claim does not match the resource ID present in the
 *    URL path, the request is flagged. This catches user A trying to read
 *    user B's resource by directly tampering with the URL.
 *
 * 2. **High-velocity ID enumeration** - per source IP, the detector tracks
 *    distinct resource IDs seen in the path over a rolling
 *    {@link WINDOW_MS} window. More than {@link DISTINCT_ID_THRESHOLD}
 *    distinct IDs in that window triggers an alert: behaviour consistent
 *    with a scripted scrape.
 *
 * Both heuristics rely on the path containing a recognisable object ID -
 * the detector looks for short numeric segments or RFC 4122 UUIDs.
 *
 * Severity: `high`.
 *
 * State note: per-IP windows are stored in memory; {@link prune} drops
 * entries older than `2 * WINDOW_MS` and should be called periodically by
 * the host process to bound memory.
 */
import type { Detector } from "./base.js";
import type { DetectionResult, NormalizedRequest } from "../types.js";

interface IpState {
  ids: Set<string>;
  windowStart: number;
}

/** Rolling window length used by the enumeration heuristic, in ms. */
const WINDOW_MS = 60_000;
/** Distinct-ID count above which an IP is treated as enumerating. */
const DISTINCT_ID_THRESHOLD = 20;

/** Short numeric IDs (typical `GET /users/42` style). */
const NUMERIC_ID_RE = /^\d{1,12}$/;
/** Canonical RFC 4122 UUID, case-insensitive. */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class BolaDetector implements Detector {
  readonly name = "bola";

  private readonly ipState = new Map<string, IpState>();

  detect(req: NormalizedRequest): DetectionResult | null {
    const pathId = extractPathId(req.path);

    const jwtSub = extractJwtSub(req.headers["authorization"]);
    if (jwtSub && pathId && pathId !== jwtSub) {
      return {
        detectorName: this.name,
        eventType: "bola",
        severity: "high",
        description: "Path resource ID does not match authenticated user (JWT sub)",
        matchedValue: pathId,
        location: "path",
      };
    }

    if (pathId && req.sourceIp) {
      const result = this.trackIpId(req.sourceIp, pathId);
      if (result) return result;
    }

    return null;
  }

  /**
   * Record an `(ip, id)` observation and flag the IP when too many distinct
   * IDs have been seen within {@link WINDOW_MS}.
   */
  private trackIpId(sourceIp: string, id: string): DetectionResult | null {
    const now = Date.now();
    let state = this.ipState.get(sourceIp);

    if (!state || now - state.windowStart > WINDOW_MS) {
      state = { ids: new Set(), windowStart: now };
      this.ipState.set(sourceIp, state);
    }

    state.ids.add(id);

    if (state.ids.size > DISTINCT_ID_THRESHOLD) {
      return {
        detectorName: this.name,
        eventType: "bola",
        severity: "high",
        description: `BOLA enumeration: ${state.ids.size} distinct resource IDs accessed from ${sourceIp} within 60s`,
        location: "path",
      };
    }

    return null;
  }

  /**
   * Drop per-IP state older than `2 * WINDOW_MS`.
   *
   * Safe to call at any time; the host process should invoke this on a
   * timer (e.g. once a minute) to prevent unbounded memory growth on
   * long-lived processes.
   */
  prune(): void {
    const cutoff = Date.now() - WINDOW_MS * 2;
    for (const [ip, state] of this.ipState) {
      if (state.windowStart < cutoff) {
        this.ipState.delete(ip);
      }
    }
  }
}

/**
 * Return the first path segment that looks like a resource ID, or `null` if
 * no segment matches.
 */
export function extractPathId(path: string): string | null {
  const segments = path.split("/").filter(Boolean);
  for (const seg of segments) {
    if (NUMERIC_ID_RE.test(seg) || UUID_RE.test(seg)) {
      return seg;
    }
  }
  return null;
}

/**
 * Decode the `sub` claim of a `Bearer <jwt>` header **without verifying the
 * signature**.
 *
 * This is acceptable here because the value is only used as a heuristic
 * cross-check (BOLA), never for authentication decisions. Returns `null`
 * for any malformed input.
 */
export function extractJwtSub(authHeader: string | string[] | undefined): string | null {
  const header = Array.isArray(authHeader) ? authHeader[0] : authHeader;
  if (!header?.startsWith("Bearer ")) return null;
  const token = header.slice(7);
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8")) as Record<string, unknown>;
    return typeof payload["sub"] === "string" ? payload["sub"] : null;
  } catch {
    return null;
  }
}
