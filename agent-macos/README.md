# Fortrix macOS Agent

macOS endpoint agent for the Fortrix Endpoint Protection Platform.

## Architecture

Same architecture as the Windows agent:
- Enroll → get device token
- Heartbeat every 60s (CPU, memory, uptime)
- Poll collectors at configurable intervals
- Batch POST events every 30s
- Auto-update via server check every 4h

## Collectors

| Collector | Interval | Event Type | Method |
|-----------|----------|------------|--------|
| Process | 1s | `proc.new` | gopsutil process.Processes() |
| Network | 20s | `net.outbound_new_remote` | gopsutil net.Connections() |
| I/O Burst | 60s | `fs.read_burst` | gopsutil process.IOCounters() |
| Clipboard | 2s | `clipboard.rapid_changes` | NSPasteboard (CGo) or osascript |

## Build

### On macOS (Recommended)

```bash
# Requires Xcode Command Line Tools (for CGo + code signing checks)
cd agent-macos

# Intel Mac
GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 go build -o fortrix-agent-darwin-amd64 .

# Apple Silicon
GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build -o fortrix-agent-darwin-arm64 .

# Universal binary
lipo -create fortrix-agent-darwin-amd64 fortrix-agent-darwin-arm64 -output fortrix-agent
```

### Cross-compile from Linux/Windows (no CGo — clipboard fallback to osascript)

```bash
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -o fortrix-agent-darwin-amd64 .
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o fortrix-agent-darwin-arm64 .
```

⚠️ Without CGo, the clipboard collector uses `osascript` as fallback, and code-signing checks via `spctl`/`codesign` are still available as external binaries.

## Install

```bash
# Copy binary + install script to target Mac
scp fortrix-agent-darwin-arm64 user@mac:/tmp/
scp install.sh user@mac:/tmp/
scp com.fortrix.agent.plist user@mac:/tmp/

# On the Mac:
ssh user@mac
cd /tmp
chmod +x fortrix-agent-darwin-arm64
sudo bash install.sh
# Enter server URL and enroll key when prompted
```

## Manual Test

```bash
# Grant Full Disk Access to Terminal first (System Preferences > Security & Privacy)

# Single collection cycle
./fortrix-agent -server https://fortrix.xyz -enroll <KEY> -once

# Run as foreground daemon
./fortrix-agent -server https://fortrix.xyz -enroll <KEY>
```

## LaunchDaemon

```bash
# Start
sudo launchctl load /Library/LaunchDaemons/com.fortrix.agent.plist

# Stop
sudo launchctl unload /Library/LaunchDaemons/com.fortrix.agent.plist

# Status
sudo launchctl list com.fortrix.agent

# Logs
tail -f /var/log/fortrix-agent.log
```

## Permissions

The agent needs these permissions on macOS:
- **Full Disk Access** — for process inspection (IOCounters)
- **Accessibility** — for system event monitoring (future ETW-equivalent)

Prompt appears on first launch. Guide users to:
System Preferences → Security & Privacy → Privacy → Full Disk Access → Add `/usr/local/fortrix/fortrix-agent`

## macOS-Specific Notes

- **Process monitoring** uses gopsutil which reads via sysctl/libproc. No kext required.
- **Code sign check** uses `spctl` and `codesign` CLI tools (built-in on macOS).
- **Suspicious paths:** ~/Downloads, ~/Desktop, /tmp, /var/tmp, /var/folders
- **LaunchDaemon** provides automatic restart (KeepAlive), runs as root.
- **No kernel extension needed** for MVP — user-mode polling only.
