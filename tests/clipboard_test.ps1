# Targeted clipboard test - verify GetClipboardSequenceNumber works
Add-Type -AssemblyName System.Windows.Forms
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class ClipTest {
    [DllImport("user32.dll")]
    public static extern uint GetClipboardSequenceNumber();
}
"@

# Check baseline
$before = [ClipTest]::GetClipboardSequenceNumber()
Write-Host "Baseline sequence: $before"

# Do 40 rapid clipboard changes
for ($i = 1; $i -le 40; $i++) {
    [System.Windows.Forms.Clipboard]::SetText("Fx-Cmd-$i-$(Get-Random)")
    Start-Sleep -Milliseconds 100
}

$after = [ClipTest]::GetClipboardSequenceNumber()
Write-Host "After 40 changes: $after"
Write-Host "Delta: $($after - $before)"
Write-Host "Expected: delta >= 40 (each SetText increments counter)"
