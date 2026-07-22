# =============================================================================
# Fortrix Pre-Flight Check
# Run this FIRST to verify agent is ready for testing
# =============================================================================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  FORTRIX PRE-FLIGHT CHECK" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# 1. Check if Fortrix agent service is running
$service = Get-Service -Name "FortrixAgent" -ErrorAction SilentlyContinue
if ($service) {
    Write-Host "[SERVICE] FortrixAgent: $($service.Status)" -ForegroundColor $(if($service.Status -eq 'Running'){'Green'}else{'Red'})
} else {
    Write-Host "[SERVICE] FortrixAgent: NOT INSTALLED" -ForegroundColor Red
}

# 2. Check agent binary version
$agentPath = "C:\Program Files\Fortrix\fortrix-agent.exe"
if (Test-Path $agentPath) {
    $versionInfo = (Get-Item $agentPath).VersionInfo
    $size = (Get-Item $agentPath).Length / 1MB
    Write-Host "[AGENT]  Path: $agentPath" -ForegroundColor Gray
    Write-Host "[AGENT]  Size: $([math]::Round($size, 1))MB" -ForegroundColor Gray
    
    # Check file date — new agent was deployed Jul 22
    $fileDate = (Get-Item $agentPath).LastWriteTime
    Write-Host "[AGENT]  Date: $($fileDate.ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor $(if($fileDate -gt (Get-Date '2026-07-22')){'Green'}else{'Yellow'})
    
    if ($fileDate -lt (Get-Date '2026-07-22')) {
        Write-Host "`n  ⚠ WARNING: Agent is OLD version (pre-Respond/Protect)." -ForegroundColor Yellow
        Write-Host "  ⚠ Auto-Protect, Isolate, Kill Process WILL NOT WORK." -ForegroundColor Yellow
        Write-Host "  ⚠ Detection tests (file/clipboard/network) will still work." -ForegroundColor Yellow
        Write-Host "`n  To update:" -ForegroundColor Yellow
        Write-Host "    1. Stop-Service FortrixAgent" -ForegroundColor White
        Write-Host "    2. Download https://fortrix.xyz/agent/fortrix-agent.exe" -ForegroundColor White
        Write-Host "    3. Copy to C:\Program Files\Fortrix\fortrix-agent.exe" -ForegroundColor White
        Write-Host "    4. Start-Service FortrixAgent" -ForegroundColor White
    } else {
        Write-Host "[AGENT]  Status: UP TO DATE (v0.3.0+)" -ForegroundColor Green
        Write-Host "[AGENT]  Respond + Protect features: ENABLED" -ForegroundColor Green
    }
} else {
    Write-Host "[AGENT]  NOT FOUND at $agentPath" -ForegroundColor Red
}

# 3. Check agent log for recent activity
$logPath = "C:\Program Files\Fortrix\fortrix-agent.log"
if (Test-Path $logPath) {
    $lastLines = Get-Content $logPath -Tail 3
    Write-Host "`n[LOG]    Last 3 entries:" -ForegroundColor Gray
    foreach ($line in $lastLines) {
        Write-Host "         $line" -ForegroundColor Gray
    }
}

# 4. Connectivity check
Write-Host "`n[NET]    Testing connection to fortrix.xyz..."
try {
    $result = Invoke-WebRequest -Uri "https://fortrix.xyz" -TimeoutSec 5 -UseBasicParsing
    Write-Host "[NET]    fortrix.xyz: REACHABLE ($($result.StatusCode))" -ForegroundColor Green
} catch {
    Write-Host "[NET]    fortrix.xyz: UNREACHABLE" -ForegroundColor Red
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  READY FOR TESTS" -ForegroundColor $(if($fileDate -ge (Get-Date '2026-07-22')){'Green'}else{'Yellow'})
Write-Host "  Next: Run .\fortrix_detection_test.ps1" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan
