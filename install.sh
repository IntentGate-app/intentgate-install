#!/usr/bin/env bash
#
# IntentGate one-click installer for Linux and macOS.
# Run it once. It checks Docker, generates your secrets, starts the three
# services, waits until the gateway is healthy, and prints the console URL.
#
#   chmod +x install.sh
#   ./install.sh
#
# Re-running it is safe: it keeps your existing secrets and just brings the
# stack back up.

set -euo pipefail
cd "$(dirname "$0")"

# --- pretty output ------------------------------------------------------
if [ -t 1 ]; then B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; C=$'\033[36m'; Z=$'\033[0m'; else B=""; G=""; Y=""; R=""; C=""; Z=""; fi
say()  { printf '%s%s%s\n' "$B" "$*" "$Z"; }
ok()   { printf '%s  OK%s %s\n' "$G" "$Z" "$*"; }
info() { printf '     %s\n' "$*"; }
die()  { printf '%s  X%s %s\n' "$R" "$Z" "$*" >&2; exit 1; }

say "IntentGate installer"
echo

# --- step 1: prerequisites ---------------------------------------------
say "Step 1 of 5  Checking prerequisites"
command -v docker >/dev/null 2>&1 || die "Docker is not installed. Install Docker Desktop (Mac) or Docker Engine (Linux), then re-run."
if docker compose version >/dev/null 2>&1; then COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then COMPOSE="docker-compose"
else die "Docker Compose is not available. Install Docker Compose, then re-run."; fi
docker info >/dev/null 2>&1 || die "Docker is installed but not running. Start Docker, then re-run."
ok "Docker and Docker Compose are ready."

# --- step 2: secrets / .env --------------------------------------------
say "Step 2 of 5  Preparing configuration"
gen() { openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
if [ ! -f .env ]; then
  cp .env.example .env
  # fill the blank secrets
  for kv in "POSTGRES_PASSWORD=$(gen)" "INTENTGATE_MASTER_KEY=$(gen)" "INTENTGATE_ADMIN_TOKEN=$(gen)" "AUTH_SECRET=$(gen)"; do
    key="${kv%%=*}"; val="${kv#*=}"
    # replace the empty "key=" line with the generated value
    if grep -qE "^${key}=$" .env; then
      tmp="$(mktemp)"; sed "s|^${key}=$|${key}=${val}|" .env > "$tmp" && mv "$tmp" .env
    fi
  done
  ok "Created .env with fresh secrets (kept private on this host)."
else
  ok "Using the existing .env (secrets preserved)."
fi

# --- step 3: pull images -----------------------------------------------
say "Step 3 of 5  Downloading IntentGate (published images)"
info "This is a one-time download of the gateway, console, and database."
if ! $COMPOSE pull; then
  echo
  die "Could not download the IntentGate images.

     The IntentGate images are PRIVATE, so this machine has to log in to
     the image registry (ghcr.io) once before it can download them.

     1. Get an access token from IntentGate (a GitHub token with the one
        permission: read:packages).
     2. Log in on this machine (paste the token when asked for a password):

          docker login ghcr.io -u <your-github-username>

     3. Run this installer again:

          ./install.sh

     If you saw 'unauthorized' just above, this is the reason."
fi
ok "Images downloaded."

# --- step 4: start ------------------------------------------------------
say "Step 4 of 5  Starting the services"
$COMPOSE up -d
ok "Postgres, gateway, and console are starting."

# --- step 5: wait for health ------------------------------------------
say "Step 5 of 5  Waiting for the gateway to become healthy"
deadline=$(( $(date +%s) + 180 ))
until curl -fsS -o /dev/null "http://127.0.0.1:8080/healthz" 2>/dev/null; do
  [ "$(date +%s)" -lt "$deadline" ] || die "Gateway did not become healthy in time. Check logs: $COMPOSE logs gateway"
  sleep 2
done
ok "Gateway is healthy."

echo
say "Done. IntentGate is running."
echo
info "Open the console in your browser:"
printf '     %shttp://localhost:3000%s   (on this machine)\n' "$C" "$Z"
printf '     %shttp://THIS-HOST-IP:3000%s (from another machine on the network)\n' "$C" "$Z"
echo
info "Sign-in is in demo (mock) mode so you can log in right away."
info "For production, set AUTH_PROVIDER, AUTH_URL and OIDC (Entra) in .env,"
info "put a reverse proxy with HTTPS in front, then run ./install.sh again."
echo
info "Your admin token and keys are in the .env file next to this script."
