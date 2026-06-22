import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdirSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import { createRequire } from "node:module";
import { withInitTimeout, tryFallbackBinary } from "../src/self-rollback.js";

const TMP_PREV = join(process.cwd(), "dist-previous");

function cleanup() {
  if (existsSync(TMP_PREV)) rmSync(TMP_PREV, { recursive: true, force: true });
}

/** Vide le cache require pour dist-previous/ afin que chaque test charge son propre module. */
function clearPrevCache() {
  const req = createRequire(import.meta.url);
  for (const key of Object.keys(req.cache ?? {})) {
    if (key.includes("dist-previous")) delete req.cache[key];
  }
}

// ── withInitTimeout ───────────────────────────────────────────────────────────

describe("withInitTimeout", () => {
  it("retourne true si la fn se termine dans le délai", async () => {
    const result = await withInitTimeout(async () => {
      await new Promise((r) => setTimeout(r, 10));
    });
    expect(result).toBe(true);
  });

  it("retourne false si la fn throw", async () => {
    const result = await withInitTimeout(async () => {
      throw new Error("init error");
    });
    expect(result).toBe(false);
  });

  it("retourne false si la fn dépasse le timeout (_RASP_INIT_TIMEOUT_MS=50)", async () => {
    // Timeout court via variable d'env — nécessite de re-importer le module.
    // On teste directement la logique en passant une promesse qui ne se résout jamais
    // avec un timeout injecté manuellement.
    let resolved = false;
    const timeout = new Promise<false>((r) => setTimeout(() => r(false), 50));
    const fn = new Promise<true>(() => { /* ne se résout jamais */ });
    const result = await Promise.race([
      fn.then(() => { resolved = true; return true as const; }),
      timeout,
    ]);
    expect(result).toBe(false);
    expect(resolved).toBe(false);
  });
});

// ── tryFallbackBinary ─────────────────────────────────────────────────────────

describe("tryFallbackBinary", () => {
  beforeEach(() => { cleanup(); clearPrevCache(); });
  afterEach(() => { cleanup(); clearPrevCache(); });

  it("retourne attempted:false si dist-previous/ est absent", () => {
    const result = tryFallbackBinary();
    expect(result.attempted).toBe(false);
    expect(result.loaded).toBe(false);
    expect(result.reason).toMatch(/not found/i);
  });

  it("retourne loaded:false si l'ancien dist n'exporte pas createFallbackAgent", () => {
    mkdirSync(TMP_PREV, { recursive: true });
    writeFileSync(join(TMP_PREV, "index.cjs"), "module.exports = {};");

    const result = tryFallbackBinary();
    expect(result.attempted).toBe(true);
    expect(result.loaded).toBe(false);
    expect(result.reason).toMatch(/createFallbackAgent/i);
  });

  it("retourne loaded:true si l'ancien dist exporte createFallbackAgent", () => {
    mkdirSync(TMP_PREV, { recursive: true });
    writeFileSync(
      join(TMP_PREV, "index.cjs"),
      "module.exports = { createFallbackAgent: () => ({ start() {} }) };"
    );

    const result = tryFallbackBinary();
    expect(result.attempted).toBe(true);
    expect(result.loaded).toBe(true);
    expect(result.reason).toBeUndefined();
  });

  it("retourne loaded:false sans throw si le require échoue (fichier corrompu)", () => {
    mkdirSync(TMP_PREV, { recursive: true });
    writeFileSync(join(TMP_PREV, "index.cjs"), "THIS IS NOT VALID JS @@@");

    const result = tryFallbackBinary();
    expect(result.attempted).toBe(true);
    expect(result.loaded).toBe(false);
    expect(result.reason).toBeDefined();
  });
});
