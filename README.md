# Install IntentGate

This folder is an IntentGate **release bundle**. It installs exactly one signed release manifest (`release-manifest.json`). The manifest names every component by source commit and **image digest**, the database schema level, the configuration contract and the provenance evidence. Compose (this installer) and the Helm chart (`helm/intentgate/`) install the same manifest. There is no separate "Compose product" and "Helm product".

## What the installer guarantees

1. **Signature.** The manifest's detached signature (`release-manifest.json.sig`) verifies against the pinned IntentGate release key (`release/trust/`). An unsigned, tampered or wrongly signed manifest is refused.
2. **Releasability.** The manifest must be customer-releasable. `releasable` is computed from the evidence and cannot be set by hand.
3. **Exact bundle.** Every file is the one the manifest hashes. `docker-compose.yml` must be the manifest's render. A file that is not part of the bundle (a stray copy, an archive, a nested clone) stops the install.
4. **Configuration contract.** `release/config-contract.json` lists every key: whether it is required, whether it is secret, how it is generated and how it is validated. Generated secrets are created once with a cryptographic RNG. A missing or invalid required key stops the install. Only key names are ever printed.
5. **Digest-only images.** Images are pulled by digest and checked. There are no tags and no `latest`, and there is no fallback.
6. **Provenance chain.** After start, the installer reads the running product and checks each link: images by digest, the revision each service reports, schema fingerprint, configuration keys and installed files. The chain must be GREEN.

## Prerequisites

- Docker Engine or Docker Desktop, with the `docker compose` plugin.
- Python 3.8 or newer, with either the `cryptography` package or `cosign` on the PATH (for the signature check).
- Registry access. The images are private, so run `docker login ghcr.io` with a token that has `read:packages`.

## Install

Linux / macOS:

```sh
./install.sh
```

Windows (PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

The first run creates `.env` with generated secrets, then stops and lists any operator keys still missing: OIDC (`AUTH_OIDC_*`), role mapping, public URLs and tenant. Fill them in `.env` (`.env.example` documents every key) and run the installer again. For an unattended install, set `INTENTGATE_ENV_SEED=/path/to/env`.

The console and gateway bind to `127.0.0.1` by default. Put a TLS reverse proxy in front of them.

## Kubernetes (Helm)

```sh
python3 release/release-manifest.py config-generate --contract release/config-contract.json --env .env
python3 release/release-manifest.py config-validate --contract release/config-contract.json --env .env --scope helm
kubectl create namespace intentgate
kubectl -n intentgate create secret generic intentgate-config --from-env-file=.env
helm install intentgate helm/intentgate -n intentgate -f helm/intentgate/values.release.yaml
```

The chart refuses to render without `values.release.yaml`. It refuses any image that is not pinned by digest, and it refuses a manifest that is not customer-releasable.

## Release engineering

`release/` holds the canonical tooling: the manifest schema, `release-manifest.py` (build / verify / render / verify-install), the configuration contract, the bundle definition and the evidence the manifest binds. CI and the clean-room acceptance workflow are described in `.github/workflows/`.
