# Local start (PowerShell). Prefer this if .bat still looks wrong.
# Usage:  .\start-local.ps1
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location "$Root\backend"

if (-not (Test-Path "node_modules")) {
  Write-Host "[1/2] Installing npm packages..." -ForegroundColor Cyan
  npm install
} else {
  Write-Host "[1/2] node_modules exists, skip install" -ForegroundColor DarkGray
}

# Stop process listening on 3000 (old demo instance)
$owned = Get-NetTCPConnection -LocalPort 3000 -State Listen -ErrorAction SilentlyContinue |
  Select-Object -ExpandProperty OwningProcess -Unique
foreach ($procId in $owned) {
  if ($procId -and $procId -ne 0) {
    Write-Host "Stopping PID $procId on port 3000..." -ForegroundColor Yellow
    Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
  }
}

$env:PORT = "3000"
$env:ATTCK_PATH = Join-Path $Root "data\ATTCK.json"
Write-Host "[2/2] Starting -> http://127.0.0.1:3000/  (auto fallback to 3001+)" -ForegroundColor Green
node app.js
