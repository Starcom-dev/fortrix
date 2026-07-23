'use strict';

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const SERVER_DIR = path.join(__dirname, '..');
const DATA_DIR = path.join(SERVER_DIR, 'data');
const DB_PATH = path.join(DATA_DIR, 'fortrix.db');
const SEED_FILE = path.join(SERVER_DIR, 'SEED_CREDENTIALS.txt');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ---------------------------------------------------------------------------
// Schema v2 — multi-tenant (idempotent migrations)
// ---------------------------------------------------------------------------
db.exec(`
CREATE TABLE IF NOT EXISTS orgs (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id        INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
  username      TEXT NOT NULL UNIQUE,
  email         TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'analyst' CHECK (role IN ('super_admin','owner','admin','analyst')),
  active        INTEGER NOT NULL DEFAULT 1,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  last_login    TEXT
);

CREATE TABLE IF NOT EXISTS enroll_keys (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  key        TEXT NOT NULL UNIQUE,
  label      TEXT NOT NULL DEFAULT '',
  active     INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS devices (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  token         TEXT NOT NULL UNIQUE,
  hostname      TEXT NOT NULL DEFAULT 'unknown',
  os            TEXT NOT NULL DEFAULT '',
  arch          TEXT NOT NULL DEFAULT '',
  agent_version TEXT NOT NULL DEFAULT '',
  ip            TEXT NOT NULL DEFAULT '',
  status        TEXT NOT NULL DEFAULT 'online' CHECK (status IN ('online','offline')),
  enrolled_at   TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  type       TEXT NOT NULL,
  severity   TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info','low','medium','high','critical')),
  data       TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_events_device_created ON events(device_id, created_at);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);

CREATE TABLE IF NOT EXISTS alerts (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  event_id   INTEGER REFERENCES events(id) ON DELETE SET NULL,
  rule       TEXT NOT NULL,
  title      TEXT NOT NULL,
  severity   TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('info','low','medium','high','critical')),
  status     TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','ack','resolved')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_device ON alerts(device_id, created_at);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS org_settings (
  org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  key    TEXT NOT NULL,
  value  TEXT NOT NULL,
  PRIMARY KEY (org_id, key)
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id     INTEGER,
  user_id    INTEGER,
  username   TEXT NOT NULL DEFAULT '',
  action     TEXT NOT NULL,
  details    TEXT NOT NULL DEFAULT '',
  ip         TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_logs(org_id, created_at);

CREATE TABLE IF NOT EXISTS leads (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  email      TEXT NOT NULL,
  name       TEXT NOT NULL DEFAULT '',
  company    TEXT NOT NULL DEFAULT '',
  message    TEXT NOT NULL DEFAULT '',
  source     TEXT NOT NULL DEFAULT 'landing',
  ip         TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- agent versions for auto-update
CREATE TABLE IF NOT EXISTS agent_versions (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  version      TEXT NOT NULL,
  platform     TEXT NOT NULL DEFAULT 'windows',
  arch         TEXT NOT NULL DEFAULT 'amd64',
  url          TEXT NOT NULL,
  sha256       TEXT NOT NULL DEFAULT '',
  release_notes TEXT NOT NULL DEFAULT '',
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

-- heartbeat metric history (small helper table for device detail charts)
CREATE TABLE IF NOT EXISTS heartbeats (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  cpu_pct    REAL,
  mem_pct    REAL,
  uptime_s   INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_heartbeats_device ON heartbeats(device_id, created_at);

-- Auto-protect rules: when a detection fires, auto-execute actions
CREATE TABLE IF NOT EXISTS protect_rules (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id          INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  event_type      TEXT NOT NULL,
  condition_json  TEXT NOT NULL DEFAULT '{}',
  action_type     TEXT NOT NULL DEFAULT 'alert_only',
  action_payload  TEXT NOT NULL DEFAULT '{}',
  enabled         INTEGER NOT NULL DEFAULT 1,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Application control policies: whitelist/blacklist apps
CREATE TABLE IF NOT EXISTS app_policies (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id      INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  policy_type TEXT NOT NULL DEFAULT 'blacklist',
  match_type  TEXT NOT NULL DEFAULT 'path',
  match_value TEXT NOT NULL,
  action      TEXT NOT NULL DEFAULT 'alert',
  enabled     INTEGER NOT NULL DEFAULT 1,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Remote command queue: agent polls this table for pending instructions
CREATE TABLE IF NOT EXISTS device_commands (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id    INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  org_id       INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
  command_type TEXT NOT NULL,
  payload      TEXT NOT NULL DEFAULT '{}',
  status       TEXT NOT NULL DEFAULT 'pending',
  result       TEXT NOT NULL DEFAULT '',
  issued_by    INTEGER REFERENCES users(id),
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  executed_at  TEXT
) ;
CREATE INDEX IF NOT EXISTS idx_device_cmds_device ON device_commands(device_id, status);

-- License schema: per-org license tracking
CREATE TABLE IF NOT EXISTS licenses (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id         INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  license_key    TEXT NOT NULL UNIQUE,
  plan           TEXT NOT NULL DEFAULT 'individu',
  max_endpoints  INTEGER NOT NULL DEFAULT 5,
  issued_at      TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at     TEXT,
  active         INTEGER NOT NULL DEFAULT 1
);
`);

// Column migration for pre-existing tables (production DB)
function addColumnIfMissing(table, col, def) {
  const exists = db.prepare('PRAGMA table_info(' + table + ')').all().some(function(c) { return c.name === col; });
  if (!exists) {
    db.exec('ALTER TABLE ' + table + ' ADD COLUMN ' + col + ' ' + def);
    console.log('[fortrix] added column ' + col + ' to ' + table);
  }
}
// Existing production licenses table uses different column names; add compatibility
if (db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='licenses'").get()) {
  addColumnIfMissing('licenses', 'max_endpoints', 'INTEGER NOT NULL DEFAULT 5');
  addColumnIfMissing('licenses', 'active', 'INTEGER NOT NULL DEFAULT 1');
  addColumnIfMissing('licenses', 'issued_at', "TEXT NOT NULL DEFAULT (datetime('now'))");
}

// Re-issue the schema block for clean installs

// Column adds for pre-multi-tenant databases (idempotent).
function hasColumn(table, col) {
  return db.prepare(`PRAGMA table_info(${table})`).all().some((c) => c.name === col);
}
if (!hasColumn('devices', 'org_id')) db.exec('ALTER TABLE devices ADD COLUMN org_id INTEGER REFERENCES orgs(id)');
if (!hasColumn('enroll_keys', 'org_id')) db.exec('ALTER TABLE enroll_keys ADD COLUMN org_id INTEGER REFERENCES orgs(id)');

// ---------------------------------------------------------------------------
// v1 → v2 data migration (runs once)
// ---------------------------------------------------------------------------
const migrateV2 = db.transaction(() => {
  if (db.prepare('SELECT COUNT(*) AS c FROM orgs').get().c === 0) {
    db.prepare("INSERT INTO orgs (id, name) VALUES (1, 'Default Organization')").run();
  }

  const legacyTable = db
    .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='admins'")
    .get();
  if (legacyTable) {
    for (const a of db.prepare('SELECT * FROM admins').all()) {
      const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(a.username);
      if (!exists) {
        db.prepare(
          'INSERT INTO users (org_id, username, password_hash, role, created_at) VALUES (1, ?, ?, ?, ?)'
        ).run(a.username, a.password_hash, 'super_admin', a.created_at);
      }
    }
    db.exec('ALTER TABLE admins RENAME TO admins_legacy_v1');
    console.log('[fortrix] migrated legacy admins → users (super_admin), table kept as admins_legacy_v1');
  }

  db.prepare('UPDATE devices SET org_id = 1 WHERE org_id IS NULL').run();
  db.prepare('UPDATE enroll_keys SET org_id = 1 WHERE org_id IS NULL').run();
});
migrateV2();

// ---------------------------------------------------------------------------
// Settings helpers (global defaults + per-org overrides)
// ---------------------------------------------------------------------------
const getSettingStmt = db.prepare('SELECT value FROM settings WHERE key = ?');
const setSettingStmt = db.prepare(
  'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
);
const getOrgSettingStmt = db.prepare('SELECT value FROM org_settings WHERE org_id = ? AND key = ?');
const setOrgSettingStmt = db.prepare(
  'INSERT INTO org_settings (org_id, key, value) VALUES (?, ?, ?) ON CONFLICT(org_id, key) DO UPDATE SET value = excluded.value'
);

function getSetting(key, fallback = null) {
  const row = getSettingStmt.get(key);
  if (!row) return fallback;
  try { return JSON.parse(row.value); } catch { return fallback; }
}

function setSetting(key, value) {
  setSettingStmt.run(key, JSON.stringify(value));
}

function getOrgSetting(orgId, key, fallback = null) {
  const row = getOrgSettingStmt.get(orgId, key);
  if (!row) return fallback;
  try { return JSON.parse(row.value); } catch { return fallback; }
}

function setOrgSetting(orgId, key, value) {
  setOrgSettingStmt.run(orgId, key, JSON.stringify(value));
}

const DEFAULT_SETTINGS = {
  fs_read_burst_mb: 500,
  clipboard_rapid_changes: 30,
  heartbeat_interval_s: 60,
  event_batch_interval_s: 30,
};

for (const [k, v] of Object.entries(DEFAULT_SETTINGS)) {
  if (getSettingStmt.get(k) === undefined) {
    db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)').run(k, JSON.stringify(v));
  }
}

if (getSettingStmt.get('session_secret') === undefined) {
  db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)')
    .run('session_secret', JSON.stringify(crypto.randomBytes(32).toString('hex')));
}

// Thresholds: global default, overridable per org.
function getThresholds(orgId = null) {
  const global = {
    fs_read_burst_mb: Number(getSetting('fs_read_burst_mb', DEFAULT_SETTINGS.fs_read_burst_mb)),
    clipboard_rapid_changes: Number(getSetting('clipboard_rapid_changes', DEFAULT_SETTINGS.clipboard_rapid_changes)),
  };
  if (!orgId) return global;
  return {
    fs_read_burst_mb: Number(getOrgSetting(orgId, 'fs_read_burst_mb', global.fs_read_burst_mb)),
    clipboard_rapid_changes: Number(getOrgSetting(orgId, 'clipboard_rapid_changes', global.clipboard_rapid_changes)),
  };
}

function getIntervals() {
  return {
    heartbeat_interval_s: Number(getSetting('heartbeat_interval_s', DEFAULT_SETTINGS.heartbeat_interval_s)),
    event_batch_interval_s: Number(getSetting('event_batch_interval_s', DEFAULT_SETTINGS.event_batch_interval_s)),
  };
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------
const auditStmt = db.prepare(
  'INSERT INTO audit_logs (org_id, user_id, username, action, details, ip) VALUES (?, ?, ?, ?, ?, ?)'
);

function audit(orgId, user, action, details = '', ip = '') {
  try {
    auditStmt.run(
      orgId ?? null,
      user ? user.id : null,
      user ? user.username : '',
      String(action),
      typeof details === 'string' ? details : JSON.stringify(details),
      String(ip || '')
    );
  } catch (err) {
    console.error('[fortrix] audit write failed:', err.message);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function randomPassword(len) {
  const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%';
  let out = '';
  while (out.length < len) {
    const b = crypto.randomBytes(1)[0];
    if (b < charset.length * Math.floor(256 / charset.length)) {
      out += charset[b % charset.length];
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Seed (first run only): org + super admin + 1 enroll key
// ---------------------------------------------------------------------------
function seedIfNeeded() {
  const userCount = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  if (userCount > 0) return null;

  if (db.prepare('SELECT COUNT(*) AS c FROM orgs').get().c === 0) {
    db.prepare("INSERT INTO orgs (id, name) VALUES (1, 'Default Organization')").run();
  }

  const password = randomPassword(16);
  const hash = bcrypt.hashSync(password, 10);
  db.prepare("INSERT INTO users (org_id, username, password_hash, role) VALUES (1, 'admin', ?, 'super_admin')").run(hash);

  const enrollKey = 'ftx_' + crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO enroll_keys (key, label, active, org_id) VALUES (?, ?, 1, 1)').run(enrollKey, 'default');

  const banner = [
    '=== FORTRIX SEED CREDENTIALS (generated on first run) ===',
    `Dashboard : /app/login`,
    `Username  : admin`,
    `Password  : ${password}`,
    `EnrollKey : ${enrollKey}`,
    `Generated : ${new Date().toISOString()}`,
    '=========================================================',
  ].join('\n');

  try {
    fs.writeFileSync(SEED_FILE, banner + '\n', 'utf8');
  } catch (err) {
    console.error('[fortrix] failed to write SEED_CREDENTIALS.txt:', err.message);
  }

  console.log('\n' + banner + '\n');
  console.log(`[fortrix] credentials also written to ${SEED_FILE}`);
  return { username: 'admin', password, enrollKey };
}

module.exports = {
  db,
  getSetting, setSetting,
  getOrgSetting, setOrgSetting,
  getThresholds, getIntervals,
  audit, randomPassword,
  seedIfNeeded, DB_PATH,
};
