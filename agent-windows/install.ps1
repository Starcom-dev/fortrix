# Fortrix Agent — Windows service installer
# Run as Administrator:
#   powershell -ExecutionPolicy Bypass -File install.ps1 [-EnrollKey <KEY>]
#Requires -RunAsAdministrator
param(
    [string]$Source = (Join-Path $PSScriptRoot 'fortrix-agent.exe'),
    [string]$InstallDir = 'C:\Program Files\Fortrix',
    [string]$Server = 'https://fortrix.xyz',
    [string]$EnrollKey = ''
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Source)) { throw "Agent exe not found: $Source" }

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

$exeDst = Join-Path $InstallDir 'fortrix-agent.exe'
$cfgDst = Join-Path $InstallDir 'fortrix-agent.json'

# Stop existing service before replacing the binary.
$svc = Get-Service FortrixAgent -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') { Stop-Service FortrixAgent -Force }

Copy-Item $Source $exeDst -Force

# Carry over existing enrollment (device identity) from alongside the source exe.
$cfgSrc = Join-Path (Split-Path $Source -Parent) 'fortrix-agent.json'
if ((Test-Path $cfgSrc) -and -not (Test-Path $cfgDst)) { Copy-Item $cfgSrc $cfgDst }

# Enroll if this machine has no device identity yet.
if (-not (Test-Path $cfgDst)) {
    if (-not $EnrollKey) { throw 'Not enrolled: re-run with -EnrollKey <KEY>' }
    & $exeDst -server $Server -enroll $EnrollKey -once
    if ($LASTEXITCODE -ne 0 -and -not (Test-Path $cfgDst)) { throw 'Enrollment failed' }
}

if (-not $svc) { & $exeDst -install }
Start-Service FortrixAgent
Start-Sleep -Seconds 2
Get-Service FortrixAgent | Format-Table Name, Status, StartType -AutoSize
Write-Host "Log: $InstallDir\fortrix-agent.log"
