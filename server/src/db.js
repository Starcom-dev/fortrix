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
// Schema (idempotent migrations)
// ---------------------------------------------------------------------------
db.exec(`
CREATE TABLE IF NOT EXISTS admins (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
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
`);

// ---------------------------------------------------------------------------
// Settings helpers
// ---------------------------------------------------------------------------
const getSettingStmt = db.prepare('SELECT value FROM settings WHERE key = ?');
const setSettingStmt = db.prepare(
  'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
);

function getSetting(key, fallback = null) {
  const row = getSettingStmt.get(key);
  if (!row) return fallback;
  try { return JSON.parse(row.value); } catch { return fallback; }
}

function setSetting(key, value) {
  setSettingStmt.run(key, JSON.stringify(value));
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

function getThresholds() {
  return {
    fs_read_burst_mb: Number(getSetting('fs_read_burst_mb', DEFAULT_SETTINGS.fs_read_burst_mb)),
    clipboard_rapid_changes: Number(getSetting('clipboard_rapid_changes', DEFAULT_SETTINGS.clipboard_rapid_changes)),
  };
}

function getIntervals() {
  return {
    heartbeat_interval_s: Number(getSetting('heartbeat_interval_s', DEFAULT_SETTINGS.heartbeat_interval_s)),
    event_batch_interval_s: Number(getSetting('event_batch_interval_s', DEFAULT_SETTINGS.event_batch_interval_s)),
  };
}

// ---------------------------------------------------------------------------
// Seed (first run only): admin + 1 enroll key
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

function seedIfNeeded() {
  const adminCount = db.prepare('SELECT COUNT(*) AS c FROM admins').get().c;
  if (adminCount > 0) return null;

  const password = randomPassword(16);
  const hash = bcrypt.hashSync(password, 10);
  db.prepare('INSERT INTO admins (username, password_hash) VALUES (?, ?)').run('admin', hash);

  const enrollKey = 'ftx_' + crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO enroll_keys (key, label, active) VALUES (?, ?, 1)').run(enrollKey, 'default');

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

module.exports = { db, getSetting, setSetting, getThresholds, getIntervals, seedIfNeeded, DB_PATH };
