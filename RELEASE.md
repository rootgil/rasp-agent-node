# Release — création de tag et déclenchement du pipeline

Ce dépôt publie sur npm uniquement lorsqu’un tag semver `vX.Y.Z` est poussé sur GitLab.  
Un push sur `main` exécute test, benchmark et security ; le tag déclenche en plus build, verify, sign et publish.

## Prérequis

1. Mettre à jour `"version"` dans `package.json` (ex. `0.3.1`).
2. S’assurer que `main` est à jour et que les changements de version sont prêts à être commités.

## Flow complet

```bash
cd /home/rootgil/C.O.D.E/N.E.W/agent-node

# 1. Vérifier que package.json correspond à la version visée
grep '"version"' package.json

# 2. Commit + tag annoté
git add package.json
git commit -m "Bump version to X.Y.Z for release pipeline"
git tag -a vX.Y.Z -m "Release X.Y.Z"

# 3. Pousser branche + tag (déclenche le pipeline complet)
git push origin main
git push origin vX.Y.Z
```

Remplace `X.Y.Z` par la version réelle (ex. `0.3.1` → tag `v0.3.1`, message `Release 0.3.1`).

## Exemple concret — release 0.3.1

```bash
cd /home/rootgil/C.O.D.E/N.E.W/agent-node

grep '"version"' package.json
# attendu : "version": "0.3.1",

git add package.json
git commit -m "Bump version to 0.3.1 for release pipeline"
git tag -a v0.3.1 -m "Release 0.3.1"

git push origin main
git push origin v0.3.1
```

## Vérifications après push

- Pipeline GitLab : tag `vX.Y.Z` → stages `build`, `verify`, `sign`, `publish`.
- Variable CI `NPM_TOKEN` requise (Settings → CI/CD → Variables, Protected + Masked).
- Package publié : `@queno/agent-node@X.Y.Z` sur npm.

## En cas d’erreur sur le tag

Ne pas réutiliser le même tag après échec sans le supprimer côté remote :

```bash
# local uniquement
git tag -d vX.Y.Z

# remote (avec prudence)
git push origin :refs/tags/vX.Y.Z
```

Puis corriger le problème, recréer le tag et le repousser.
