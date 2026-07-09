# Install IntentGate

One command brings up the three services (database, gateway, console) on a single host. You only need Docker installed first.

## Before you start (all systems)

You need **Docker** running:
- **Windows / Mac:** install **Docker Desktop** and start it.
- **Linux:** install **Docker Engine** and the **Docker Compose** plugin.

That is the only prerequisite. The installer downloads everything else.

## Log in to the image registry (one time)

The IntentGate images are **private**, so each install machine has to log in
to the registry (`ghcr.io`) once before it can download them.

1. Ask IntentGate for an access token (a GitHub token with the single
   permission `read:packages`).
2. On the install machine, log in and paste the token when it asks for a
   password:
   ```bash
   docker login ghcr.io -u <your-github-username>
   ```

You only do this once per machine. If you skip it, the installer stops at the
download step with an `unauthorized` message and reminds you to log in.

## Install

Put this `install` folder on the machine that will run IntentGate, open a terminal in it, and run the one command for your system.

### Linux or macOS
```bash
chmod +x install.sh
./install.sh
```

### Windows (PowerShell)
```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

The script will:
1. Check Docker is installed and running.
2. Generate your secrets (database password, master key, admin token, session secret) into a private `.env` file.
3. Download the published IntentGate images.
4. Start Postgres, the gateway, and the console.
5. Wait until the gateway reports healthy.

When it finishes it prints the console address.

## Open the console

- On the machine itself: **http://localhost:3000**
- From another computer on the same network: **http://THE-HOST-IP:3000**

Sign-in starts in demo (mock) mode so you can log in immediately and look around.

## Make it production (when you are ready)

Edit `.env` and set:
- `AUTH_PROVIDER=oidc` and your Entra (OIDC) details, and `AUTH_URL` to your real HTTPS hostname.
- `INTENTGATE_LICENSE_KEY` to enable Pro features.
- `INTENTGATE_UPSTREAM_URL` to your real tool server (where the gateway forwards allowed calls).

Put a reverse proxy with HTTPS in front of port 3000 (and a DNS name), then run the installer again to apply. See the Operations Runbook, section "Accessing the console", for the exact reverse-proxy and DNS steps.

## Everyday commands

```bash
docker compose ps          # see what is running
docker compose logs -f     # follow logs
docker compose down        # stop everything (data is kept)
docker compose up -d        # start again
```

Your secrets and settings live in `.env` next to these scripts. Keep that file safe.
