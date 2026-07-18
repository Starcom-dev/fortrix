# FORTRIX — Technical Spec (MVP Phase 1)

**Product:** Endpoint Protection Platform — data exfiltration detection, behavioral monitoring.
**Landing:** https://fortrix.xyz (static, FROZEN — do not touch index.html)
**Repo:** C:\Users\strco\Projects\fortrix (local) — VPS deploy: 72.61.210.56

## Architecture

```
[Agent Go .exe (Windows)] --HTTPS--> [fortrix.xyz/api/v1/*] --OLS proxy--> [Node server :3010]
                                     [fortrix.xyz/app/*]    --OLS proxy--> [dashboard EJS]
```

## Server (server/)
- Node 20 + Express + better-sqlite3 + EJS + Tailwind CDN + Chart.js CDN + Lucide
- Base paths: `/api/v1` (agent API), `/app` (dashboard). Listen 127.0.0.1:3010 (env PORT).
- DB: SQLite file `data/fortrix.db` (WAL mode)

### DB Schema
- `admins` (id, username UNIQUE, password_hash bcrypt, created_at)
- `enroll_keys` (id, key UNIQUE, label, active 1/0, created_at)
- `devices` (id, token UNIQUE, hostname, os, arch, agent_version, ip, status online/offline, enrolled_at, last_seen)
- `events` (id, device_id FK, type, severity info/low/medium/high/critical, data JSON, created_at) — INDEX (device_id, created_at), (type)
- `alerts` (id, device_id FK, event_id FK, rule, title, severity, status open/ack/resolved, created_at, updated_at)
- `settings` (key PRIMARY, value JSON) — thresholds

### Agent API (Bearer device token, except enroll)
- `POST /api/v1/enroll` {enroll_key, hostname, os, arch, agent_version} → 201 {device_id, device_token} (key must be active; token = 48 hex random)
- `POST /api/v1/heartbeat` {cpu_pct, mem_pct, uptime_s, agent_version} → 200; updates last_seen, status online
- `POST /api/v1/events` {events:[{type, ts, severity, data}]} max 200/batch → 200 {accepted, alerts_created}
- `GET /api/v1/config` → thresholds JSON (from settings)

### Rules engine (on ingest, simple deterministic)
- `net.outbound_new_remote` + data.public=true + data.port NOT IN (80,443) → alert medium "Uncommon outbound connection"
- `fs.read_burst` data.read_mb >= threshold(default 500) → alert high "Burst file read"
- `clipboard.rapid_changes` data.count >= threshold(default 30) → alert medium
- `proc.new` data.suspicious=true (agent flags temp-dir/unsigned) → alert medium
- severity critical if event.severity=critical passthrough

### Dashboard `/app` (session auth, bcrypt)
- `/app/login` — dark theme login
- `/app` — overview: fleet cards (devices online/total, open alerts by severity, events 24h), alerts timeline chart (Chart.js), recent alerts table
- `/app/devices` — table (hostname, os, agent ver, status, last seen); `/app/devices/:id` — detail + recent events + heartbeat metrics
- `/app/alerts` — filterable (status/severity), ack/resolve buttons (POST)
- `/app/events` — paginated explorer, filter by device/type
- `/app/settings` — enroll keys CRUD (generate/deactivate), thresholds edit
- Style: dark cyber theme (#0a0e1a bg, #4f6ef7 primary accent OK), rounded-2xl cards, Tailwind CDN. Match landing page vibe (dark, security product).
- Offline marking: cron-ish setInterval — device offline if last_seen > 3 min.
- Seed: admin / (generated pwd printed once to console + written to server/SEED_CREDENTIALS.txt), 1 enroll key.

## Agent (agent-windows/) — Go
- Single exe `fortrix-agent.exe`. Config JSON alongside exe.
- Flags: `-server URL -enroll KEY` (first run), `-once` (single collection cycle, for tests)
- Enroll → save device_token to config. Heartbeat 60s (gopsutil cpu/mem).
- Collectors (poll):
  1. **proc**: snapshot 15s; new PIDs → `proc.new` {name, exe, cmdline, ppid}; suspicious=true if exe under %TEMP%/Downloads
  2. **net**: connections snapshot 20s; new (pid,raddr) pairs → `net.outbound_new_remote` {proc, raddr, port, public}
  3. **io**: per-proc ReadBytes delta 60s window; if >500MB → `fs.read_burst` {proc, read_mb}
  4. **clipboard**: GetClipboardSequenceNumber poll 2s; count changes/min; >30 → `clipboard.rapid_changes` {count}
- Queue events, batch POST 30s. Retry w/ backoff, drop if >5000 queued.

## Deploy (VPS 72.61.210.56)
- `/home/fortrix.xyz/server` — PM2 `fortrix-server`, PORT=3010
- OLS vhost fortrix.xyz: extprocessor proxy 127.0.0.1:3010 + context /app + /api
- Landing `/` stays static.

## Roadmap (post-MVP)
- Phase 2: Windows service install, code signing, ETW-based collectors, macOS agent
- Phase 3: KMDF minifilter driver (block mode), behavioral baseline ML, on-prem option
