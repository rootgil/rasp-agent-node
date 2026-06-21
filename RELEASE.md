# Release — E.1.3 SBOM + GPG (sans Sigstore)

Tag `vX.Y.Z` → build, verify, SBOM, signature GPG, publish npm.

## Variables CI (Protected + Masked, tags `v*`)

| Variable | Description |
|----------|-------------|
| `NPM_TOKEN` | Token npm publish |
| `GPG_PRIVATE_KEY` | `gpg --armor --export-secret-keys KEY_ID` |
| `GPG_PASSPHRASE` | Optionnel |

Runner **oriso-runner-01** : `gpg` doit être installé (`apt install gnupg`).

## Release

```bash
grep '"version"' package.json
git add package.json
git commit -m "Bump version to X.Y.Z"
git tag -a vX.Y.Z -m "Release X.Y.Z"
git push origin main
git push origin vX.Y.Z
```

**Ne pas retry `v0.3.3`** — ce tag utilise encore l’ancienne CI cosign. Utiliser **`v0.3.4`** ou plus.

## Vérification client

```bash
gpg --verify sbom.cdx.json.asc sbom.cdx.json
```
