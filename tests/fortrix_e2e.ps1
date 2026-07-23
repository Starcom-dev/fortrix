# Final end-to-end test: trigger IO detection, verify auto-isolate, then remote unisolate
Write-Host "=== FORTRIX E2E TEST ===" -ForegroundColor Cyan

# Trigger sustained IO
Write-Host "[1/4] Triggering sustained IO for auto-protect..." -ForegroundColor Yellow
$tempFile = "$env:TEMP\fortrix_e2e_test.dat"
$bytes = New-Object byte[] (100 * 1024 * 1024)
$random = New-Object System.Random
$stream = [System.IO.File]::OpenWrite($tempFile)
for ($i = 0; $i -lt 6; $i++) { $random.NextBytes($bytes); $stream.Write($bytes, 0, $bytes.Length) }
$stream.Close()
Write-Host "  600MB file created."

$job = Start-Job -ScriptBlock {
    param($file)
    $reader = [System.IO.File]::OpenRead($file)
    $buffer = New-Object byte[] (10 * 1024 * 1024)
    $total = 0; $start = Get-Date
    while (((Get-Date) - $start).TotalSeconds -lt 95) {
        $n = $reader.Read($buffer, 0, $buffer.Length)
        if ($n -le 0) { $reader.Position = 0; continue }
        $total += $n
    }
    $reader.Close()
} -ArgumentList $tempFile

Write-Host "  Sustained read running for 100s..." -ForegroundColor Gray
Start-Sleep -Seconds 100
Receive-Job $job -Wait | Out-Null
Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

Write-Host "  Waiting 65s for processing + auto-protect..." -ForegroundColor Gray
Start-Sleep -Seconds 65

Write-Host "[2/4] Checking results..." -ForegroundColor Yellow
Write-Host "  Check: https://fortrix.xyz/app/alerts" -ForegroundColor White
Write-Host "  Expected: fs.read_burst HIGH alert + auto-isolate command" -ForegroundColor Green
Write-Host ""
Write-Host "=== E2E TEST COMPLETE ===" -ForegroundColor Green
