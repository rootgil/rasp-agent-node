import type { Detector } from "./base.js";
import type { DetectionResult, NormalizedRequest } from "../types.js";

/**
 * BOLA / IDOR detector — OWASP API Security Top 1.
 *
 * Heuristics (stateless + lightweight stateful):
 * 1. ID enumeration probe: sequential integer IDs in the URL path.
 * 2. JWT sub vs path ID mismatch: if a JWT is present and the user ID in
 *    the path differs from the `sub` claim, flag as suspicious.
 * 3. High-velocity ID variation: tracks distinct resource IDs accessed per
 *    source IP within a rolling window and flags rapid enumeration.
 */

interface IpState {
  ids: Set<string>;
  windowStart: number;
}

const WINDOW_MS = 60_000;
const DISTINCT_ID_THRESHOLD = 20;

// Path segments that look like numeric or UUID object IDs
const NUMERIC_ID_RE = /^\d{1,12}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class BolaDetector implements Detector {
  readonly name = "bola";

  private readonly ipState = new Map<string, IpState>();

  detect(req: NormalizedRequest): DetectionResult | null {
    const pathId = extractPathId(req.path);

    // 1. JWT sub vs path ID mismatch
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

    // 2. High-velocity ID enumeration per source IP
    if (pathId && req.sourceIp) {
      const result = this.trackIpId(req.sourceIp, pathId);
      if (result) return result;
    }

    return null;
  }

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

  /** Prune stale IP entries to prevent unbounded memory growth. */
  prune(): void {
    const cutoff = Date.now() - WINDOW_MS * 2;
    for (const [ip, state] of this.ipState) {
      if (state.windowStart < cutoff) {
        this.ipState.delete(ip);
      }
    }
  }
}

function extractPathId(path: string): string | null {
  const segments = path.split("/").filter(Boolean);
  for (const seg of segments) {
    if (NUMERIC_ID_RE.test(seg) || UUID_RE.test(seg)) {
      return seg;
    }
  }
  return null;
}

function extractJwtSub(authHeader: string | string[] | undefined): string | null {
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
