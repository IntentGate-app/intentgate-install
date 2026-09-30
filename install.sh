#!/usr/bin/env bash
#
# IntentGate installer (Linux / macOS): installs ONE signed canonical release manifest.
#
#   ./install.sh                  interactive-free; stops with guidance if configuration is missing
#   INTENTGATE_ENV_SEED=/path/env ./install.sh
#                                 unattended: operator-provided keys are copied into .env first
#
# Order of operations. Nothing starts until every step before it passed:
#   1. prerequisites (docker, compose, python3)
#   2. the release manifest's detached signature against the pinned IntentGate release key
#      (python 'cryptography' or cosign), and that the manifest is customer-releasable
#   3. the bundle: every file is the signed manifest's (hash), docker-compose.yml IS the render of
#      the manifest (every image by digest), and there is no file that is not part of the bundle
#   4. configuration: generated secrets filled once, then the whole .env validated against
#      release/config-contract.json; a missing required key stops the install
#   5. images pulled BY DIGEST and each pulled image checked to carry exactly that digest
#   6. start, wait for health, then verify the provenance chain of the RUNNING product
#
# There is no tag fallback anywhere: the compose file has no tags, and IMAGE_TAG-style keys are
# refused by the configuration contract.
#
# INTENTGATE_ACCEPT_UNRELEASABLE_CANDIDATE=1 is for the clean-room acceptance run ONLY. It lets a
# signed but not-yet-releasable candidate be measured; it never skips signature, bundle, config or
# digest verification.

set -euo pipefail
cd "$(dirname "$0")"
HERE=$(pwd)
TOOL="release/release-manifest.py"
MAN="release-manifest.json"
SIG="release-manifest.json.sig"
CONTRACT="release/config-contract.json"
TRUST=(--key-set release/trust/release-key-set.json --trust-anchor release/trust/release-trust-anchor.json)

if [ -t 1 ]; then B=$'\033[1m'; G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; Z=$'\033[0m'; else B=""; G=""; R=""; Y=""; Z=""; fi
say()  { printf '%s%s%s\n' "$B" "$*" "$Z"; }
ok()   { printf '%s  OK%s %s\n' "$G" "$Z" "$*"; }
info() { printf '     %s\n' "$*"; }
die()  { printf '%s  X%s %s\n' "$R" "$Z" "$*" >&2; exit 1; }

say "IntentGate installer"

say "Step 1 of 6  Prerequisites"
command -v docker >/dev/null 2>&1 || die "Docker is not installed."
docker compose version >/dev/null 2>&1 || die "The Docker Compose plugin (docker compose) is required."
docker info >/dev/null 2>&1 || die "Docker is installed but not running."
command -v python3 >/dev/null 2>&1 || die "python3 is required (the release verifier is a Python script)."
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' || die "python3 >= 3.8 is required."
ok "docker, docker compose and python3 are available."

say "Step 2 of 6  Verifying the signed release manifest"
[ -f "$MAN" ] || die "$MAN is missing: this folder is not a release bundle."
[ -s "$SIG" ] || die "$SIG is missing: an unsigned manifest is never installed."
REQ=(--require-releasable)
if [ "${INTENTGATE_ACCEPT_UNRELEASABLE_CANDIDATE:-}" = "1" ]; then
  printf '%s  !! CLEAN-ROOM CANDIDATE MODE: a signed but NOT customer-releasable manifest may be installed for measurement. Never use this for a customer.%s\n' "$Y" "$Z"
  REQ=()
fi
python3 "$TOOL" verify --manifest "$MAN" --sig "$SIG" "${TRUST[@]}" "${REQ[@]}" \
  || die "The release manifest did not verify (signature, integrity or releasability). Nothing was started."
ok "Manifest signature verified against the pinned IntentGate release key."

say "Step 3 of 6  Verifying the release bundle"
python3 "$TOOL" verify-bundle --manifest "$MAN" --bundle-dir "$HERE" \
  || die "This folder is not exactly the signed bundle (modified, missing or extra files). Nothing was started."
ok "Every file is the signed bundle's; docker-compose.yml is the manifest's digest-pinned render."

say "Step 4 of 6  Configuration"
if [ -n "${INTENTGATE_ENV_SEED:-}" ] && [ ! -f .env ]; then
  [ -f "$INTENTGATE_ENV_SEED" ] || die "INTENTGATE_ENV_SEED points at a missing file."
  install -m 600 "$INTENTGATE_ENV_SEED" .env
  ok "Seeded .env from INTENTGATE_ENV_SEED (values not printed)."
fi
python3 "$TOOL" config-generate --contract "$CONTRACT" --env .env
if ! python3 "$TOOL" config-validate --contract "$CONTRACT" --env .env --scope compose; then
  echo
  die "Configuration is incomplete or invalid (key names above; values are never printed).
     Edit .env (see .env.example for every key and what it is for) and run ./install.sh again."
fi
ok "Configuration satisfies the contract."

say "Step 5 of 6  Pulling images by digest"
if ! docker compose pull; then
  die "Could not pull the IntentGate images. They are private: log in once with
       docker login ghcr.io -u <user>   (token with read:packages)
     and run ./install.sh again. Images are pulled only by digest; there is no tag fallback."
fi
while IFS= read -r line; do
  ref=${line#*=}
  case "$ref" in *@sha256:*) ;; *) die "Image $ref is not pinned by digest (refusing).";; esac
  dig=${ref##*@}
  docker image inspect --format '{{join .RepoDigests "\n"}}' "$ref" 2>/dev/null | grep -q "@$dig\$" \
    || die "Pulled image for $ref does not carry digest $dig."
done < <(python3 "$TOOL" image-refs --kind compose --file docker-compose.yml)
ok "Every image is present locally with exactly the manifest's digest."

say "Step 6 of 6  Starting and verifying the running product"
docker compose up -d
deadline=$(( $(date +%s) + ${INTENTGATE_HEALTH_TIMEOUT_S:-300} ))
while :; do
  unhealthy=$(docker compose ps --format '{{.Service}} {{.Health}} {{.State}}' | awk '$2=="starting"||$2=="unhealthy"||$3!="running"{print $1}')
  [ -z "$unhealthy" ] && break
  [ "$(date +%s)" -lt "$deadline" ] || die "Services not healthy in time: $unhealthy (docker compose logs <service>)"
  sleep 3
done
ok "All services are running and healthy."
FACTS=$(mktemp)
trap 'rm -f "$FACTS"' EXIT
python3 "$TOOL" collect-facts --manifest "$MAN" --form compose --project intentgate --install-dir "$HERE" \
  --contract "$CONTRACT" --out "$FACTS" >/dev/null
if python3 "$TOOL" verify-install --manifest "$MAN" --sig "$SIG" "${TRUST[@]}" --contract "$CONTRACT" --facts "$FACTS"; then
  ok "Provenance chain GREEN: the running product is the signed release."
else
  die "Provenance chain RED: the running product is NOT the signed release (links above)."
fi
echo
say "Done. Console: ${CONSOLE_PRO_PUBLIC_URL:-see CONSOLE_PRO_PUBLIC_URL in .env} (bound to 127.0.0.1:3000 by default; put a TLS reverse proxy in front)."
