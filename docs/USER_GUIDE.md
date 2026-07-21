# Fortrix — User Guide

**Fortrix Endpoint Protection Platform** — data exfiltration detection & behavioral monitoring for Windows endpoints.

- Dashboard: https://fortrix.my/app
- Version: MVP Phase 2 (agent 0.3.0)

---

## 1. Concepts

| Term | Meaning |
|---|---|
| **Agent** | Lightweight Windows service (`fortrix-agent.exe`, ~6MB, no dependencies) installed on each endpoint. Collects behavioral signals and sends them to the server. |
| **Enroll key** | Shared secret used **once** per device to register it. Created/deactivated by admins in Settings. |
| **Device token** | Per-device credential issued at enrollment, stored in `fortrix-agent.json` next to the agent exe. All API calls after enrollment use this token. |
| **Event** | Raw behavioral signal (new process, new outbound connection, file-read burst, clipboard activity). |
| **Alert** | Event that matched a detection rule. Has severity + status (`open → ack → resolved`). |

## 2. Quick Start (Admin)

1. Open https://fortrix.my/app and log in.
2. Go to **Settings** → copy an active **enroll key** (or generate a new one per customer/department).
3. Install the agent on each endpoint (next section).
4. Watch **Overview** and **Alerts**.

## 3. Installing the Agent (per endpoint)

Requirements: Windows 10/11 or Server 2016+, outbound HTTPS to `fortrix.my`, admin rights.

1. Copy `fortrix-agent.exe` and `install.ps1` to the target machine (any folder).
2. Open **PowerShell as Administrator** in that folder:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\install.ps1 -EnrollKey <ENROLL_KEY>
   ```

   The script:
   - copies the agent to `C:\Program Files\Fortrix`
   - enrolls the device (once) and stores its identity in `fortrix-agent.json`
   - registers Windows service **FortrixAgent** (auto-start, auto-restart on failure)
   - starts the service

3. Verify: the device appears in **Dashboard → Devices** as `online` within ~1 minute.

Manual alternative (without the script):

```powershell
.\fortrix-agent.exe -server https://fortrix.my -enroll <ENROLL_KEY> -once   # enroll + one test cycle
.\fortrix-agent.exe -install                                                 # register service
Start-Service FortrixAgent
```

### Updating the agent

Re-run `install.ps1` with the new exe — it stops the service, replaces the binary, keeps the device identity, and restarts.

### Uninstalling

```powershell
& 'C:\Program Files\Fortrix\fortrix-agent.exe' -uninstall
Remove-Item -Recurse 'C:\Program Files\Fortrix'
```

### Troubleshooting (endpoint)

- Log file: `C:\Program Files\Fortrix\fortrix-agent.log`
- Service status: `Get-Service FortrixAgent`
- Test one collection cycle interactively: `& 'C:\Program Files\Fortrix\fortrix-agent.exe' -once`
- Device shows `offline` in dashboard → agent stopped >3 min (service killed, machine off, or no network). SCM restarts crashed agents automatically after 60–120s.

## 4. Using the Dashboard

### Overview
Fleet at a glance: devices online/total, open alerts by severity, events in the last 24h, alert timeline chart, recent alerts.

### Devices
All enrolled endpoints: hostname, OS, agent version, online/offline, last seen. Click a device for CPU/RAM heartbeat metrics and its recent events. A device is marked **offline** after 3 minutes without heartbeat — treat unexpected offline as a signal (agent tampering, machine compromise).

### Alerts — main working page
Detection rules (server-side, deterministic):

| Rule | Trigger | Severity | Typical meaning |
|---|---|---|---|
| Burst file read | Process reads ≥ 500 MB in 60s window | **High** | Data staging before exfiltration |
| Uncommon outbound connection | New connection to public IP on port ≠ 80/443 | Medium | Covert exfil channel (FTP, raw TCP, custom C2) |
| Rapid clipboard changes | ≥ 30 clipboard changes/min | Medium | Clipboard scraping / credential harvesting |
| Suspicious new process | New process launched from `%TEMP%` or Downloads | Medium | Dropper / unpacked malware |

Workflow: alert comes in → investigate (open device detail + Events) → **Ack** (being handled) → **Resolve** (closed). Filter by status and severity.

### Events
Raw explorer of everything agents reported, paginated, filterable by device and type. Use for forensics/timeline reconstruction after an alert.

### Settings
- **Enroll keys** — generate one key per customer/department; deactivate a key to stop new enrollments with it (already-enrolled devices are unaffected).
- **Thresholds** — tune `read_burst_mb` (default 500) and `clipboard_per_min` (default 30). Agents refresh config hourly.

## 5. What the Agent Collects (privacy scope)

- New process starts: name, exe path, command line, parent PID (every 15s snapshot)
- New outbound connections: process, remote address, port, public/private flag (every 20s)
- Per-process disk read volume deltas (every 60s) — **volume only, never file contents**
- Clipboard **change frequency** only — never clipboard contents
- Heartbeat: CPU %, RAM %, uptime (every 60s)

No file contents, no keystrokes, no screenshots, no clipboard data leave the endpoint.

## 6. Current Limitations (MVP)

- **Detect & alert only** — no blocking yet (block mode ships with the Phase 3 kernel driver).
- No outbound notifications (email/webhook) yet — alerts live in the dashboard.
- Windows & macOS agents available.
- Agent binary is unsigned (code signing planned in Phase 2).

---

*Fortrix — see the exfiltration before the data is gone.*
