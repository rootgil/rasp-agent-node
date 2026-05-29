/**
 * BOLA-via-DB correlation (Addendum A.4 / OWASP API #1).
 *
 * Runs at response time. Correlates the request (authenticated user, resource
 * id in the URL) with the DB queries that actually executed while handling it.
 *
 * Heuristics (each is monitor-grade - flagged, not blocked):
 *  1. **Cross-object access**: an authenticated request whose DB queries
 *     reference id literals that match neither the URL resource id nor the
 *     user id, on an endpoint that did NOT have authorization enforced. This is
 *     the classic IDOR shape: the handler fetched an object the request was not
 *     scoped to and no authz gate ran.
 *  2. **Fan-out enumeration**: a single request issuing queries that touch an
 *     unusually large number of distinct object ids (possible mass-extraction).
 */
import type { DetectionResult } from "../types.js";
import type { RequestContext } from "../runtime-context.js";

/** Distinct DB object ids in one request above which we flag fan-out. */
const FANOUT_ID_THRESHOLD = 25;

export function correlateBola(ctx: RequestContext): DetectionResult | null {
  if (ctx.dbQueries.length === 0) return null;

  const distinctIds = new Set<string>();
  for (const q of ctx.dbQueries) {
    for (const id of q.ids) distinctIds.add(id);
  }

  // Heuristic 2: fan-out enumeration in a single request.
  if (distinctIds.size > FANOUT_ID_THRESHOLD) {
    return {
      detectorName: "bola-db",
      eventType: "bola",
      severity: "high",
      description: `Single request touched ${distinctIds.size} distinct object ids in the database (possible mass extraction)`,
      location: "db",
    };
  }

  // Heuristic 1: cross-object access without authorization.
  if (ctx.userId && !ctx.authEnforced) {
    const allowed = new Set<string>();
    if (ctx.userId) allowed.add(ctx.userId);
    if (ctx.pathId) allowed.add(ctx.pathId);

    for (const q of ctx.dbQueries) {
      for (const id of q.ids) {
        if (!allowed.has(id)) {
          return {
            detectorName: "bola-db",
            eventType: "bola",
            severity: "medium",
            description:
              "Authenticated request accessed a database object id not scoped to the URL/user, with no authorization enforced",
            matchedValue: id,
            location: "db",
          };
        }
      }
    }
  }

  return null;
}
