#!/usr/bin/env node
/**
 * Simulation du binary self-rollback (Addendum D.4).
 *
 * Ce script reproduit le scénario complet :
 *   1. Une version "précédente" saine est placée dans dist-previous/
 *   2. La "nouvelle" version échoue à s'initialiser (timeout ou throw)
 *   3. L'agent charge automatiquement dist-previous/ et continue
 *
 * Usage :
 *   node scripts/simulate-rollback.mjs            → échec par timeout (2s)
 *   node scripts/simulate-rollback.mjs throw      → échec par exception
 *   node scripts/simulate-rollback.mjs ok         → init réussie (pas de rollback)
 */

import { mkdirSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const PREV_DIR = join(ROOT, "dist-previous");
const PREV_ENTRY = join(PREV_DIR, "index.cjs");

// ── Couleurs terminal ──────────────────────────────────────────────────────────
const R = "\x1b[0m";
const G = "\x1b[32m";
const Y = "\x1b[33m";
const RED = "\x1b[31m";
const B = "\x1b[34m";
const BOLD = "\x1b[1m";

function log(color, prefix, msg) {
  console.log(`${color}${BOLD}[${prefix}]${R} ${msg}`);
}

// ── Scénario ───────────────────────────────────────────────────────────────────
const scenario = process.argv[2] ?? "timeout";

console.log(`\n${BOLD}╔══════════════════════════════════════════════════════╗`);
console.log(`║     Simulation : Binary Self-Rollback (Addendum D.4) ║`);
console.log(`╚══════════════════════════════════════════════════════╝${R}\n`);
log(B, "SETUP", `Scénario : ${scenario}`);

// ── 1. Créer un faux dist-previous/ (ancienne version saine) ─────────────────
log(Y, "SETUP", "Création de dist-previous/ (ancienne version v0.2.9)…");
mkdirSync(PREV_DIR, { recursive: true });
writeFileSync(PREV_ENTRY, `
"use strict";
module.exports = {
  createFallbackAgent: function(opts) {
    return {
      start() {
        console.log("\\x1b[32m\\x1b[1m[FALLBACK v0.2.9]\\x1b[0m Agent précédent démarré — protection active (mode monitor).");
      }
    };
  }
};
`);
log(G, "SETUP", "dist-previous/index.cjs créé (v0.2.9 simulée).\n");

// ── 2. Simuler withInitTimeout ────────────────────────────────────────────────
const TIMEOUT_MS = 2000; // 2s pour la démo (au lieu de 60s)

log(B, "NEW v0.3.6", `Tentative d'initialisation (timeout : ${TIMEOUT_MS / 1000}s)…`);

async function simulateInit() {
  if (scenario === "ok") {
    // Init réussie → pas de rollback
    await new Promise((r) => setTimeout(r, 200));
    return;
  }
  if (scenario === "throw") {
    throw new Error("Hook attachment failed: cannot patch http.IncomingMessage");
  }
  // "timeout" : bloque indéfiniment
  await new Promise(() => {});
}

async function withTimeout(fn, ms) {
  let handle;
  const timer = new Promise((resolve) => {
    handle = setTimeout(() => resolve(false), ms);
  });
  const run = fn()
    .then(() => { clearTimeout(handle); return true; })
    .catch(() => { clearTimeout(handle); return false; });
  return Promise.race([run, timer]);
}

const initialized = await withTimeout(simulateInit, TIMEOUT_MS);

// ── 3. Résultat ───────────────────────────────────────────────────────────────
if (initialized) {
  log(G, "NEW v0.3.6", "Initialisation réussie. Aucun rollback nécessaire.\n");
  log(G, "RESULT", "✓ Agent v0.3.6 actif — pas de rollback.");
} else {
  log(RED, "NEW v0.3.6", "Initialisation échouée (timeout / erreur). Déclenchement du rollback…\n");

  // Charger dist-previous/
  const req = createRequire(import.meta.url);
  let rollbackLoaded = false;
  let rollbackReason;

  try {
    if (!existsSync(PREV_ENTRY)) {
      rollbackReason = "dist-previous/ introuvable — fail open (agent désactivé).";
    } else {
      const prev = req(PREV_ENTRY);
      if (typeof prev.createFallbackAgent === "function") {
        const fallback = prev.createFallbackAgent({});
        fallback.start();
        rollbackLoaded = true;
      } else {
        rollbackReason = "dist-previous/ ne contient pas createFallbackAgent.";
      }
    }
  } catch (err) {
    rollbackReason = err.message;
  }

  console.log();
  if (rollbackLoaded) {
    log(G, "RESULT", "✓ Rollback réussi — ancienne version active.");
    log(Y, "RESULT", "⚠ Signalement upgrade_failed envoyé au control plane via prochain heartbeat.");
    log(Y, "RESULT", "→ Relancez: npm install @queno/agent-node@latest pour réappliquer la mise à jour.");
  } else {
    log(RED, "RESULT", `✗ Rollback impossible — ${rollbackReason}`);
    log(RED, "RESULT", "  Fail open : l'app continue sans protection RASP.");
  }
}

// ── 4. Nettoyage ──────────────────────────────────────────────────────────────
console.log();
log(B, "CLEANUP", "Suppression de dist-previous/ (simulation terminée).");
rmSync(PREV_DIR, { recursive: true, force: true });
console.log();
