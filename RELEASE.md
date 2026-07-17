# Release

Tag `vX.Y.Z` → build, verify, SBOM, publish npm.

## Variables CI

| Variable | Description |
|----------|-------------|
| `NPM_TOKEN` | Token npm (Protected + Masked, environnement `npm-production`) |

Pas de GPG ni Sigstore — compatible runner shell sans accès admin.

## Bump de version

Le projet utilise **npm** (`package-lock.json`). Préférer `npm version` plutôt que d’éditer `package.json` à la main : ça met à jour la version, crée le commit et le tag annoté.

```bash
# Patch  0.3.6 → 0.3.7
npm version patch -m "Bump version to %s"

# Minor  0.3.6 → 0.4.0
npm version minor -m "Bump version to %s"

# Major  0.3.6 → 1.0.0
npm version major -m "Bump version to %s"

# Version exacte
npm version 0.3.9 -m "Bump version to %s"
```

Équivalent pnpm (si tu l’utilises localement) :

```bash
pnpm version patch
# ou
pnpm version 0.3.9
```

Vérifier ensuite :

```bash
grep '"version"' package.json
git log -1 --oneline
git tag -l 'v*' | tail -5
```

## Release

Après le bump (commit + tag déjà créés par `npm version`) :

```bash
git push origin main
git push origin vX.Y.Z   # même version que package.json, ex. v0.3.7
```

Si tu as bumpé à la main sans `npm version` :

```bash
grep '"version"' package.json
git add package.json package-lock.json
git commit -m "Bump version to X.Y.Z"
git tag -a vX.Y.Z -m "Release X.Y.Z"
git push origin main
git push origin vX.Y.Z
```

Pipeline tag : `build` → `verify` → `sbom` (CycloneDX + SPDX + npm pack) → **`publish` (manuel)**.

Les SBOM sont inclus dans le tarball npm et conservés en artifacts GitLab (365 j).

## Pourquoi `publish` est manuel ?

Le job `publish` est `when: manual` et lié à l’environnement protégé `npm-production` (Addendum E.3.2) :

1. **Gate humaine** — un tag poussé ne publie pas tout seul sur npm ; quelqu’un doit cliquer Play après que build/verify/sbom soient verts.
2. **Approbations** — l’environnement GitLab peut exiger des approbateurs (objectif : minimum 2) avant d’exécuter le job.
3. **Isolation du secret** — `NPM_TOKEN` est scoped à `npm-production` uniquement, pas aux jobs de test/build.

Dans GitLab : pipeline du tag → attendre les stages verts → **Play** sur `publish`.
