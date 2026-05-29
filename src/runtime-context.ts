/**
 * Per-request runtime context, propagated via {@link AsyncLocalStorage}.
 *
 * The framework integration enters a context at the start of each request; the
 * database hooks ({@link instrumentDatabaseDrivers}) then record every query
 * issued while handling that request into the same context. At response time
 * the agent correlates the request (path/user) with the observed DB queries to
 * detect Broken Object Level Authorization (BOLA / IDOR).
 *
 * All accessors are fail-safe: if no context is active they no-op, so DB hooks
 * never throw in code paths unrelated to an HTTP request.
 */
import { AsyncLocalStorage } from "node:async_hooks";

export interface DbQueryRecord {
  /** Driver that issued the query (e.g. `pg`, `mysql2`, `mongoose`). */
  driver: string;
  /** Truncated, non-parameterised query text or operation descriptor. */
  op: string;
  /** Id-like literals (numeric / UUID) extracted from the query text. */
  ids: string[];
}

export interface RequestContext {
  method: string;
  path: string;
  /** Resource id taken from the URL path, if any. */
  pathId: string | null;
  /** Authenticated user id (JWT sub or req.user.id), if known. */
  userId: string | null;
  sourceIp?: string;
  /** Whether an authorization middleware was confirmed for this request. */
  authEnforced: boolean;
  /** DB queries observed during this request. */
  dbQueries: DbQueryRecord[];
}

const storage = new AsyncLocalStorage<RequestContext>();

/**
 * Bind a context to the current async execution for the remainder of the
 * request. Uses `enterWith` so it survives across framework hooks and awaits
 * without needing to wrap the downstream handler.
 */
export function enterContext(ctx: RequestContext): void {
  storage.enterWith(ctx);
}

export function getContext(): RequestContext | undefined {
  return storage.getStore();
}

/** Record a DB query against the active request context (no-op if none). */
export function recordDbQuery(record: DbQueryRecord): void {
  const ctx = storage.getStore();
  if (!ctx) return;
  // Bound memory: keep at most 200 queries per request.
  if (ctx.dbQueries.length < 200) ctx.dbQueries.push(record);
}

const ID_LITERAL_RE =
  /\b(\d{1,12}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b/gi;

/** Extract id-like literals from a query string (bounded). */
export function extractIdLiterals(sql: string): string[] {
  const out: string[] = [];
  let m: RegExpExecArray | null;
  ID_LITERAL_RE.lastIndex = 0;
  while ((m = ID_LITERAL_RE.exec(sql)) !== null && out.length < 20) {
    out.push(m[1]!);
  }
  return out;
}
