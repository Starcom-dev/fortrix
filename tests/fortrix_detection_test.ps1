# Fortrix Detection Test Suite v1.1
# Run as Administrator for full accuracy
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  FORTRIX DETECTION TEST SUITE" -ForegroundColor Cyan
Write-Host "  Target: $(hostname)" -ForegroundColor Cyan
Write-Host "  Time:   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# TEST 1 - FILE EXFILTRATION (fs.read_burst)
# Simulates: Attacker reads large volume of files to exfiltrate data
# Expected:  Alert "Burst file read" severity HIGH
# ---------------------------------------------------------------------------
Write-Host "[TEST 1/3] File Exfiltration Simulation" -ForegroundColor Yellow
Write-Host "  Reading 600MB of random data to simulate data exfiltration..."

$tempFile = "$env:TEMP\fortrix_test_exfil.dat"
try {
    $bytes = New-Object byte[] (100 * 1024 * 1024)
    $random = New-Object System.Random
    $stream = [System.IO.File]::OpenWrite($tempFile)
    
    for ($i = 0; $i -lt 6; $i++) {
        $random.NextBytes($bytes)
        $stream.Write($bytes, 0, $bytes.Length)
        Write-Host "  Written $((($i+1)*100))MB / 600MB..."
    }
    $stream.Close()
    
    Write-Host "  File created. Now reading it back rapidly..."
    
    $reader = [System.IO.File]::OpenRead($tempFile)
    $buffer = New-Object byte[] (10 * 1024 * 1024)
    $totalRead = 0
    while ($reader.Read($buffer, 0, $buffer.Length) -gt 0) {
        $totalRead += $buffer.Length
    }
    $reader.Close()
    
    Write-Host "  Total read: $([math]::Round($totalRead / 1MB))MB" -ForegroundColor Green
    Write-Host "  >> CHECK: https://fortrix.xyz/app/alerts" -ForegroundColor Green
    Write-Host "  >> Expected: 'Burst file read' alert, severity HIGH`n" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: $_" -ForegroundColor Red
} finally {
    if (Test-Path $tempFile) { Remove-Item $tempFile -Force }
}

Write-Host "  Waiting 35s for agent to send events..." -ForegroundColor Gray
Start-Sleep -Seconds 35

# ---------------------------------------------------------------------------
# TEST 2 - CLIPBOARD SCRAPING (clipboard.rapid_changes)
# Simulates: Malware rapidly reads clipboard to steal copied passwords/keys
# Expected:  Alert "Rapid clipboard changes" severity MEDIUM
# ---------------------------------------------------------------------------
Write-Host "`n[TEST 2/3] Clipboard Scraping Simulation" -ForegroundColor Yellow
Write-Host "  Simulating rapid clipboard access (40 changes in 60 seconds)..."

Add-Type -AssemblyName System.Windows.Forms

for ($i = 1; $i -le 40; $i++) {
    [System.Windows.Forms.Clipboard]::SetText("Fortrix-Test-$i-$(Get-Random)")
    Write-Host "  Clipboard change $i/40" -ForegroundColor Gray
    Start-Sleep -Milliseconds 1500
}

Write-Host "  Clipboard scraping simulation complete." -ForegroundColor Green
Write-Host "  >> CHECK: https://fortrix.xyz/app/alerts" -ForegroundColor Green
Write-Host "  >> Expected: 'Rapid clipboard changes' alert, severity MEDIUM`n" -ForegroundColor Green

Write-Host "  Waiting 65s for agent to aggregate clipboard events..." -ForegroundColor Gray
Start-Sleep -Seconds 65

# ---------------------------------------------------------------------------
# TEST 3 - SUSPICIOUS OUTBOUND CONNECTION (net.outbound_new_remote)
# Simulates: Malware connects to external C2 server on unusual port
# Expected:  Alert "Uncommon outbound connection" severity MEDIUM
# ---------------------------------------------------------------------------
Write-Host "`n[TEST 3/3] Suspicious Outbound Connection Simulation" -ForegroundColor Yellow
Write-Host "  Connecting to external IP on non-standard port (port 8443)..."

$testIP = "8.8.8.8"
$testPort = 8443

try {
    $client = New-Object System.Net.Sockets.TcpClient
    $timeout = 3000
    $result = $client.BeginConnect($testIP, $testPort, $null, $null)
    
    if ($result.AsyncWaitHandle.WaitOne($timeout, $false)) {
        Write-Host "  Connection to ${testIP}:${testPort} succeeded." -ForegroundColor Gray
        $client.Close()
    } else {
        Write-Host "  Connection attempt to ${testIP}:${testPort} (timeout OK - port is closed)" -ForegroundColor Gray
    }
    
    Write-Host "  Outbound connection test complete." -ForegroundColor Green
    Write-Host "  >> CHECK: https://fortrix.xyz/app/alerts" -ForegroundColor Green
    Write-Host "  >> Expected: 'Uncommon outbound connection' alert, severity MEDIUM`n" -ForegroundColor Green
} catch {
    Write-Host "  Connection attempted: $_ (this is expected - port closed)" -ForegroundColor Gray
}

# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  TEST SUITE COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Open https://fortrix.xyz/app/alerts" -ForegroundColor White
Write-Host ""
Write-Host "  Expected alerts:" -ForegroundColor Yellow
Write-Host "    TEST 1: 'Burst file read' - severity HIGH" -ForegroundColor Green
Write-Host "    TEST 2: 'Rapid clipboard changes' - severity MEDIUM" -ForegroundColor Green
Write-Host "    TEST 3: 'Uncommon outbound connection' - severity MEDIUM" -ForegroundColor Green
Write-Host ""
Write-Host "  NOTE: Allow 1-2 minutes for all alerts to appear." -ForegroundColor Gray
