# Érable CI Runner (`DeVinci-Leonard/erable-ci-runner`)

Banc d'exécution et de validation multiplateforme natif sur GitHub Actions pour l'écosystème **Érable** (`cortexa/native-application-ai/erable`).

---

## Architecture & Workflows GitHub Actions

Ce dépôt expose deux workflows déclenchés via `repository_dispatch` (depuis les pipelines GitLab CI d'`erable/core`) ou manuellement via `workflow_dispatch` :

### 1. Validation de paquets — `.github/workflows/validate-package.yml`
- **Événement** : `repository_dispatch` (`validate-package`) ou `workflow_dispatch`.
- **Matrice 2026 jusqu'à 6 cibles natives** :
  - `x86_64-linux` → `ubuntu-latest`
  - `aarch64-linux` → `ubuntu-26.04-arm`
  - `x86_64-windows` → `windows-latest`
  - `aarch64-windows` → `windows-11-vs2026-arm`
  - `aarch64-macos` → `macos-latest`
  - `x86_64-macos` → `macos-26-intel` (failover possible vers `macos-15-intel` en cas de saturation de file)
- **Payloads / Entrées** : `package_name`, `version`, `category` (`cli`, `gui`, `fonts`), `targets_toml`, `matrix`, `correlation_id`, `check_cmd`, `hooks_json` (compressé `gzb64:`).
- **Exécution (`runner/validate.py`)** :
  - Détection `Python 3.12`, résolution dynamique des dernières versions `nu` et `ouch` avec **vérification SHA-256 officielle** + mise en cache (`actions/cache`).
  - Contrôle strict HTTPS + FQDN + DNS anti-SSRF + gestionnaire de redirections `StrictRedirectHandler` avant et pendant le téléchargement.
  - Contrôle cryptographique SHA-256 en flux O(1) RAM.
  - Extraction sécurisée (`ouch`-first, `hdiutil` macOS / `msiexec /a` / extraction ZIP membre-par-membre résistante aux entrées GoReleaser `.`, contrôle `is_relative_to()` anti-ZipSlip/TarSlip + `filter="data"` et audit post-extraction des liens symboliques).
  - Audit bas niveau des signatures binaires (`PE`, `ELF`, `Mach-O`), détection des bundles GUI / WPF / Next.js et polices (`.ttf`/`.otf`/`.ttc`/`.woff`/`.woff2`).
  - Exécution des hooks `.nu` (`pre_install`, `post_install`, `pre_uninstall`, `post_uninstall`) en confinement **Zero-Egress** (`unshare --user --map-root-user --net` / `sandbox-exec`, variables d'environnement filtrées par allowlist stricte, shadowing `http *` + proxy blackhole).
  - Sondes CLI directes hors `PATH` (`--version`, `check_cmd` validé) avec promotion automatique du JDK ≥ 21.

### 2. Compilation des Trampolines Rust — `.github/workflows/build-trampoline.yml`
- **Événement** : `repository_dispatch` (`build-trampoline`) ou `workflow_dispatch` (`ref`, `correlation_id`).
- **Portée** : Compile et exécute `cargo test --release` + `cargo build --release` pour les **6 cibles** (`x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`, `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `aarch64-apple-darwin`, `x86_64-apple-darwin`).
- **Validation croisée** : Chaque binaire produit est validé en conditions réelles via un shim enveloppant la dernière version vérifiée d'`ouch`.
- **Sorties** : Artefacts individuels + `trampoline-universal-macos` (`lipo -create`) + `trampoline-checksums` (`SHA256SUMS`), rapatriés par `scripts/ci/fetch_trampoline_artifacts.py` dans `erable/core`.

---

## Tests locaux du runner

```bash
python -m unittest discover -s tests -v
```

---

## Sécurité

- `permissions: {}` minimaliste au niveau workflow (`contents: read` uniquement sur les jobs effectuant un checkout).
- Toutes les Actions tierces et officielles sont épinglées par commit SHA 40 caractères.
- Les entrées `ref` transmises lors du build sont validées strictement côté environnement avant passage à `git clone --branch ... --`.

---

## Licence

MIT License.
