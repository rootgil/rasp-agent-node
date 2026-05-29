/**
 * Database driver instrumentation.
 *
 * Monkey-patches the query entry point of common Node.js database drivers so
 * that every query issued while handling an HTTP request is recorded into the
 * active {@link RequestContext}. This is the data source for BOLA-via-DB
 * correlation (Addendum A.4 / OWASP API #1).
 *
 * Design constraints:
 *  - **Never break the host app.** Every patch is wrapped in try/catch; if a
 *    driver is absent or its shape is unexpected, instrumentation is skipped.
 *  - **Never change query behaviour.** Patches record metadata then delegate to
 *    the original method with the original arguments and `this`.
 *  - **Idempotent.** Re-patching is guarded by a marker symbol.
 *
 * Supported drivers (best-effort): pg, mysql2, mongoose, sequelize, knex.
 * Prisma is instrumented separately via {@link instrumentPrismaClient} because
 * it requires the client instance.
 */
import { createRequire } from "node:module";
import { recordDbQuery, extractIdLiterals } from "../runtime-context.js";

const PATCHED = Symbol.for("rasp.dbHook.patched");

const nodeRequire = createRequire(import.meta.url);

function isPatched(fn: unknown): boolean {
  return Boolean((fn as Record<symbol, unknown>)[PATCHED]);
}

function markPatched(fn: unknown): void {
  (fn as Record<symbol, unknown>)[PATCHED] = true;
}

/**
 * Registry of installed hooks for integrity verification (self-protection,
 * Addendum E.7). Each entry remembers the prototype, method name and the exact
 * wrapper reference we installed, so we can later detect if a hook was removed
 * or overwritten by another actor.
 */
interface HookRecord {
  driver: string;
  method: string;
  proto: Record<string, unknown>;
  wrapped: unknown;
}
const hookRegistry: HookRecord[] = [];

/**
 * Verify every installed DB hook is still in place (same wrapper reference and
 * carrying the PATCHED marker). Returns the list of tampered hooks; empty when
 * integrity is intact.
 */
export function verifyHookIntegrity(): { driver: string; method: string }[] {
  const tampered: { driver: string; method: string }[] = [];
  for (const h of hookRegistry) {
    const current = h.proto[h.method];
    if (current !== h.wrapped || !isPatched(current)) {
      tampered.push({ driver: h.driver, method: h.method });
    }
  }
  return tampered;
}

/** Number of hooks currently registered (diagnostics / tests). */
export function installedHookCount(): number {
  return hookRegistry.length;
}

function record(driver: string, op: unknown): void {
  try {
    const text = typeof op === "string" ? op : safeStringify(op);
    if (!text) return;
    recordDbQuery({ driver, op: text.slice(0, 500), ids: extractIdLiterals(text) });
  } catch {
    // Never throw from the hot path.
  }
}

function safeStringify(op: unknown): string {
  if (op && typeof op === "object") {
    const o = op as Record<string, unknown>;
    if (typeof o.text === "string") return o.text;
    if (typeof o.sql === "string") return o.sql;
    try {
      return JSON.stringify(op);
    } catch {
      return "";
    }
  }
  return String(op ?? "");
}

function tryRequire(name: string): unknown {
  try {
    return nodeRequire(name);
  } catch {
    return null;
  }
}

function patchMethod(
  proto: Record<string, unknown> | undefined | null,
  method: string,
  driver: string
): void {
  if (!proto || typeof proto[method] !== "function") return;
  const fn = proto[method] as (...args: unknown[]) => unknown;
  if (isPatched(fn)) return;
  const wrapped = function (this: unknown, ...args: unknown[]): unknown {
    record(driver, args[0]);
    return fn.apply(this, args);
  };
  markPatched(wrapped);
  proto[method] = wrapped;
  hookRegistry.push({ driver, method, proto, wrapped });
}

let done = false;

/**
 * Instrument all detectable database drivers. Safe to call multiple times.
 *
 * @param requireFn - Optional resolver (used in tests). Defaults to the
 *   ambient CommonJS `require` when available.
 */
export function instrumentDatabaseDrivers(requireFn: (name: string) => unknown = tryRequire): void {
  if (done) return;
  done = true;

  // pg - Client.prototype.query and Pool.prototype.query.
  try {
    const pg = requireFn("pg") as { Client?: { prototype: Record<string, unknown> }; Pool?: { prototype: Record<string, unknown> } } | null;
    if (pg) {
      patchMethod(pg.Client?.prototype, "query", "pg");
      patchMethod(pg.Pool?.prototype, "query", "pg");
    }
  } catch {
    /* skip */
  }

  // mysql2 - Connection.prototype.query / execute.
  try {
    const conn = requireFn("mysql2/lib/connection.js") as { prototype: Record<string, unknown> } | null;
    if (conn) {
      patchMethod(conn.prototype, "query", "mysql2");
      patchMethod(conn.prototype, "execute", "mysql2");
    }
  } catch {
    /* skip */
  }

  // sequelize - Sequelize.prototype.query.
  try {
    const seq = requireFn("sequelize") as { Sequelize?: { prototype: Record<string, unknown> } } | null;
    if (seq?.Sequelize) {
      patchMethod(seq.Sequelize.prototype, "query", "sequelize");
    }
  } catch {
    /* skip */
  }

  // mongoose - Query.prototype.exec (covers find/findOne/update/etc).
  try {
    const mongoose = requireFn("mongoose") as { Query?: { prototype: Record<string, unknown> } } | null;
    if (mongoose?.Query) {
      const proto = mongoose.Query.prototype;
      if (typeof proto.exec === "function" && !isPatched(proto.exec)) {
        const orig = proto.exec as (...a: unknown[]) => unknown;
        const wrapped = function (this: Record<string, unknown>, ...args: unknown[]): unknown {
          record("mongoose", { op: this.op, model: (this.model as { modelName?: string } | undefined)?.modelName, filter: this._conditions });
          return orig.apply(this, args);
        };
        markPatched(wrapped);
        proto.exec = wrapped;
        hookRegistry.push({ driver: "mongoose", method: "exec", proto, wrapped });
      }
    }
  } catch {
    /* skip */
  }

  // knex - client.prototype.query (knex/lib/client).
  try {
    const Client = requireFn("knex/lib/client.js") as { prototype: Record<string, unknown> } | null;
    if (Client) {
      patchMethod(Client.prototype, "query", "knex");
    }
  } catch {
    /* skip */
  }
}

/**
 * Instrument a Prisma Client instance. Prisma cannot be patched at the module
 * level, so the integrator passes the client (created with
 * `new PrismaClient({ log: [{ emit: 'event', level: 'query' }] })`).
 */
export function instrumentPrismaClient(client: unknown): void {
  try {
    const c = client as { $on?: (event: string, cb: (e: { query?: string }) => void) => void };
    if (typeof c.$on === "function") {
      c.$on("query", (e) => record("prisma", e.query ?? ""));
    }
  } catch {
    /* skip */
  }
}

/** Reset the one-shot guard (tests only). */
export function __resetInstrumentationForTests(): void {
  done = false;
  hookRegistry.length = 0;
}
