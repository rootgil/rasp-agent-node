# Release

Tag `vX.Y.Z` → build, verify, SBOM, publish npm.

## Variables CI

| Variable | Description |
|----------|-------------|
| `NPM_TOKEN` | Token npm (Protected + Masked, tags `v*`) |

Pas de GPG ni Sigstore — compatible runner shell sans accès admin.

## Release

```bash
grep '"version"' package.json
git add package.json
git commit -m "Bump version to X.Y.Z"
git tag -a vX.Y.Z -m "Release X.Y.Z"
git push origin main
git push origin vX.Y.Z
```

Pipeline tag : `build` → `verify` → `sbom` (CycloneDX + SPDX + npm pack) → `publish`.

Les SBOM sont inclus dans le tarball npm et conservés en artifacts GitLab (365 j).
