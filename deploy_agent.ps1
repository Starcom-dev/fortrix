# Fortrix Agent Deploy v0.4.0 (with Remote Commands)
Write-Host "=== FORTRIX AGENT DEPLOY v0.4.0 ===" -ForegroundColor Cyan
Write-Host ""

$agentSrc = "C:\Users\strco\Projects\fortrix\agent-windows\fortrix-agent.exe"
$agentDest = "C:\Program Files\Fortrix\fortrix-agent.exe"

if (-not (Test-Path $agentSrc)) {
    Write-Host "ERROR: Source binary not found at $agentSrc" -ForegroundColor Red
    exit 1
}

Write-Host "[1/4] Stopping FortrixAgent service..." -ForegroundColor Yellow
Stop-Service FortrixAgent -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

Write-Host "[2/4] Backing up old binary..." -ForegroundColor Yellow
$backup = "$agentDest.bak_v0.3.0"
Copy-Item $agentDest $backup -Force -ErrorAction SilentlyContinue

Write-Host "[3/4] Copying new binary v0.4.0 (with Remote Commands)..." -ForegroundColor Yellow
Copy-Item $agentSrc $agentDest -Force
$size = (Get-Item $agentDest).Length / 1MB
$sizeStr = [math]::Round($size,2)
Write-Host "       Binary: $sizeStr MB" -ForegroundColor Green

Write-Host "[4/4] Starting FortrixAgent service..." -ForegroundColor Yellow
Start-Service FortrixAgent
Start-Sleep -Seconds 3

$svc = Get-Service FortrixAgent
Write-Host ""
Write-Host "=== DEPLOY COMPLETE ===" -ForegroundColor Green
Write-Host "Service: $($svc.Status)"
Write-Host "Binary:  $agentDest"
Write-Host "Backup:  $backup"
Write-Host ""
Write-Host "Next: run fortrix_preflight.ps1 to verify" -ForegroundColor Cyan
