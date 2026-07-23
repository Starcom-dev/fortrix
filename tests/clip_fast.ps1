Add-Type -AssemblyName System.Windows.Forms
Write-Host "Clipboard burst: 40 changes in 30 seconds" -ForegroundColor Yellow
for ($i=1; $i -le 40; $i++) {
    [System.Windows.Forms.Clipboard]::SetText("Fx-T$i-$(Get-Random)")
    Start-Sleep -Milliseconds 700
}
Write-Host "Done. Waiting 90s for agent to detect and send..." -ForegroundColor Yellow
Start-Sleep 90
Write-Host "Check: https://fortrix.xyz/app/alerts" -ForegroundColor Green
