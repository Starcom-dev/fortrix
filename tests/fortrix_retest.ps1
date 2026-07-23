# Targeted retest - sustained IO + single-window clipboard
Write-Host "=== FORTRIX TARGETED RETEST ===" -ForegroundColor Cyan

# TEST A: SUSTAINED IO (keep process alive for 90+ seconds)
Write-Host "[TEST A] Sustained File IO (90+ sec runtime)" -ForegroundColor Yellow
$tempFile = "$env:TEMP\fortrix_sustained_test.dat"

# Create 600MB file
$bytes = New-Object byte[] (100 * 1024 * 1024)
$random = New-Object System.Random
$stream = [System.IO.File]::OpenWrite($tempFile)
for ($i = 0; $i -lt 6; $i++) {
    $random.NextBytes($bytes)
    $stream.Write($bytes, 0, $bytes.Length)
}
$stream.Close()
Write-Host "  600MB file created. Starting sustained read for 90 seconds..."

# Read continuously for 90+ seconds to ensure IO collector catches it
$job = Start-Job -ScriptBlock {
    param($file)
    $reader = [System.IO.File]::OpenRead($file)
    $buffer = New-Object byte[] (10 * 1024 * 1024)
    $total = 0
    $start = Get-Date
    while (((Get-Date) - $start).TotalSeconds -lt 95) {
        $n = $reader.Read($buffer, 0, $buffer.Length)
        if ($n -le 0) { 
            $reader.Position = 0  # re-read from start
            continue
        }
        $total += $n
    }
    $reader.Close()
    Write-Output "Total read: $([math]::Round($total/1MB))MB"
} -ArgumentList $tempFile

Write-Host "  IO job running (PID: $($job.Id))... waiting 100s for 2 IO poll cycles"
Start-Sleep -Seconds 100

$result = Receive-Job $job -Wait
Write-Host "  $result" -ForegroundColor Green
Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

# Wait for agent to process
Write-Host "  Waiting 35s for events to send..." -ForegroundColor Gray
Start-Sleep -Seconds 35

# TEST B: Clipboard in single window (compress 40 changes into 50 seconds)
Write-Host "`n[TEST B] Clipboard Burst (40 changes in 50 seconds - single window)" -ForegroundColor Yellow
Add-Type -AssemblyName System.Windows.Forms

$start = Get-Date
for ($i = 1; $i -le 40; $i++) {
    [System.Windows.Forms.Clipboard]::SetText("Fx-Test-$i-$(Get-Random)")
    Write-Host "  Change $i/40 ($([math]::Round(((Get-Date)-$start).TotalSeconds,1))s)" -ForegroundColor Gray
    Start-Sleep -Milliseconds 1200
}

Write-Host "  Done. Waiting 70s for aggregation..." -ForegroundColor Gray
Start-Sleep -Seconds 70

Write-Host "`n=== RETEST COMPLETE ===" -ForegroundColor Cyan
Write-Host "Check: https://fortrix.xyz/app/alerts" -ForegroundColor White
