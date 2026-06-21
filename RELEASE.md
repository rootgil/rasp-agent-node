# Release — création de tag et déclenchement du pipeline

Ce dépôt publie sur npm uniquement lorsqu’un tag semver `vX.Y.Z` est poussé sur GitLab.  
Un push sur `main` exécute test, benchmark et security ; le tag déclenche en plus build, verify, sign et publish.

## Prérequis

1. Mettre à jour `"version"` dans `package.json` (ex. `0.3.3`).
2. S’assurer que `main` est à jour et que les changements de version sont prêts à être commités.
3. Variable CI **`NPM_TOKEN`** (Settings → CI/CD → Variables, Protected + Masked).
4. Protected tag **`v*`** activé (pour injecter `NPM_TOKEN`).

## Flow complet

```bash
cd /home/rootgil/C.O.D.E/N.E.W/agent-node

grep '"version"' package.json

git add package.json
git commit -m "Bump version to X.Y.Z for release pipeline"
git tag -a vX.Y.Z -m "Release X.Y.Z"

git push origin main
git push origin vX.Y.Z
```

Remplace `X.Y.Z` par la version réelle (ex. `0.3.3` → tag `v0.3.3`).

## Sigstore / cosign (gitlab.oriso.dev)

Le Fulcio public (`fulcio.sigstore.dev`) n’accepte les tokens OIDC GitLab **que depuis `gitlab.com`**.  
Sur une instance self-hosted (`gitlab.oriso.dev`), le pipeline :

- **sign** : `npm pack` + SBOM CycloneDX (pas de cosign)
- **publish** : `npm publish` **sans** `--provenance`

Pour activer Sigstore sur une instance privée, déployer Fulcio/Rekor et définir la variable CI `SIGSTORE_SIGNING=true`.

## En cas d’échec sur le tag

Les tags `v*` protégés ne se suppriment **pas** en CLI :

```bash
git push origin :refs/tags/vX.Y.Z   # refusé si tag protégé
```

→ Supprimer le tag dans **Repository → Tags** (UI GitLab), **ou** incrémenter la version et créer un **nouveau tag** (`v0.3.4`, etc.).

Ne pas retagger un tag existant sur remote sans le supprimer via l’UI.

## Vérifications après push

- Pipeline GitLab sur le tag : `build` → `verify` → `sign` → `publish`
- Package visible : `@queno/agent-node@X.Y.Z` sur npm
