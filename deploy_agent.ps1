# Fortrix Agent Deploy v0.4.0 Final
Write-Host "=== FORTRIX AGENT DEPLOY v0.4.0 FINAL ===" -ForegroundColor Cyan

$agentSrc = "C:\Users\strco\Projects\fortrix\agent-windows\fortrix-agent.exe"
$agentDest = "C:\Program Files\Fortrix\fortrix-agent.exe"

Write-Host "[1/3] Stopping service..." -ForegroundColor Yellow
Stop-Service FortrixAgent -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

Write-Host "[2/3] Copying binary..." -ForegroundColor Yellow
Copy-Item $agentSrc $agentDest -Force
$size = [math]::Round((Get-Item $agentDest).Length / 1MB, 2)
Write-Host "       v0.4.0 Final - $size MB" -ForegroundColor Green

Write-Host "[3/3] Starting service..." -ForegroundColor Yellow
Start-Service FortrixAgent
Start-Sleep -Seconds 3

Write-Host ""
Write-Host "Status: $((Get-Service FortrixAgent).Status)" -ForegroundColor Green
Write-Host "=== DEPLOY COMPLETE ===" -ForegroundColor Green
