# Quick E2E: trigger IO burst, verify auto-isolate command
Write-Host "=== FINAL AUTO-PROTECT TEST ===" -ForegroundColor Cyan

$tempFile = "$env:TEMP\ftx_auto_test.dat"
$bytes = New-Object byte[] (100 * 1024 * 1024)
$random = New-Object System.Random
$fs = [System.IO.File]::OpenWrite($tempFile)
for ($i=0; $i -lt 6; $i++) { $random.NextBytes($bytes); $fs.Write($bytes,0,$bytes.Length) }
$fs.Close()

# Sustained read - keep process alive > 60s for IO collector
$job = Start-Job -ScriptBlock {
    param($f)
    $r = [System.IO.File]::OpenRead($f)
    $b = New-Object byte[] (10 * 1024 * 1024)
    $t=0; $s=Get-Date
    while(((Get-Date)-$s).TotalSeconds -lt 95) {
        $n=$r.Read($b,0,$b.Length)
        if($n -le 0){$r.Position=0;continue}
        $t+=$n
    }
    $r.Close()
} -ArgumentList $tempFile

Write-Host "IO job started. Waiting 100s..." -ForegroundColor Yellow
Start-Sleep 100
Receive-Job $job -Wait | Out-Null
Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

Write-Host "Waiting 70s for detection + auto-protect..." -ForegroundColor Yellow
Start-Sleep 70

Write-Host "DONE. Check: https://fortrix.xyz/app/alerts" -ForegroundColor Green
Write-Host "Expected: fs.read_burst HIGH + auto-isolate device_command" -ForegroundColor Green
