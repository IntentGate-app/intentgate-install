# IntentGate one-click installer for Windows (PowerShell).
# Run it once from PowerShell in this folder:
#
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
#
# It checks Docker Desktop, generates your secrets, starts the three
# services, waits until the gateway is healthy, and prints the console URL.
# Re-running it is safe: it keeps your existing secrets.

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

function Say($m)  { Write-Host $m -ForegroundColor White }
function OK($m)   { Write-Host "  OK " -ForegroundColor Green -NoNewline; Write-Host $m }
function Info($m) { Write-Host "     $m" }
function Die($m)  { Write-Host "  X  " -ForegroundColor Red -NoNewline; Write-Host $m; exit 1 }

Say "IntentGate installer"
Write-Host ""

# --- step 1: prerequisites ---
Say "Step 1 of 5  Checking prerequisites"
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Die "Docker is not installed. Install Docker Desktop for Windows, then re-run." }
try { docker compose version | Out-Null; $compose = "docker compose" }
catch { if (Get-Command docker-compose -ErrorAction SilentlyContinue) { $compose = "docker-compose" } else { Die "Docker Compose is not available." } }
try { docker info | Out-Null } catch { Die "Docker is installed but not running. Start Docker Desktop, then re-run." }
OK "Docker and Docker Compose are ready."

# --- step 2: secrets / .env ---
Say "Step 2 of 5  Preparing configuration"
function New-Secret { -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Minimum 0 -Maximum 256) }) }
if (-not (Test-Path ".env")) {
  Copy-Item ".env.example" ".env"
  $content = Get-Content ".env"
  foreach ($key in @("POSTGRES_PASSWORD","INTENTGATE_MASTER_KEY","INTENTGATE_ADMIN_TOKEN","AUTH_SECRET")) {
    $val = New-Secret
    $content = $content -replace "^$key=$", "$key=$val"
  }
  Set-Content ".env" $content
  OK "Created .env with fresh secrets (kept private on this host)."
} else {
  OK "Using the existing .env (secrets preserved)."
}

# --- step 3: pull images ---
Say "Step 3 of 5  Downloading IntentGate (published images)"
Info "This is a one-time download of the gateway, console, and database."
Invoke-Expression "$compose pull"
OK "Images downloaded."

# --- step 4: start ---
Say "Step 4 of 5  Starting the services"
Invoke-Expression "$compose up -d"
OK "Postgres, gateway, and console are starting."

# --- step 5: wait for health ---
Say "Step 5 of 5  Waiting for the gateway to become healthy"
$deadline = (Get-Date).AddSeconds(180)
do {
  try { Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:8080/healthz" -TimeoutSec 3 | Out-Null; $healthy = $true }
  catch { $healthy = $false; Start-Sleep -Seconds 2 }
} until ($healthy -or (Get-Date) -gt $deadline)
if (-not $healthy) { Die "Gateway did not become healthy in time. Check logs: $compose logs gateway" }
OK "Gateway is healthy."

Write-Host ""
Say "Done. IntentGate is running."
Write-Host ""
Info "Open the console in your browser:"
Write-Host "     http://localhost:3000" -ForegroundColor Cyan -NoNewline; Write-Host "   (on this machine)"
Write-Host "     http://THIS-HOST-IP:3000" -ForegroundColor Cyan -NoNewline; Write-Host " (from another machine on the network)"
Write-Host ""
Info "Sign-in is in demo (mock) mode so you can log in right away."
Info "For production, set AUTH_PROVIDER, AUTH_URL and OIDC (Entra) in .env,"
Info "put a reverse proxy with HTTPS in front, then run install.ps1 again."
Write-Host ""
Info "Your admin token and keys are in the .env file next to this script."
