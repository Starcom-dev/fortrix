'use strict';

const express = require('express');
const session = require('express-session');
const MemoryStore = require('memorystore')(session);
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { db, getSetting, setSetting, getThresholds } = require('../db');
const { rateLimit } = require('../rate-limit');

const router = express.Router();

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const ALERT_STATUSES = ['open', 'ack', 'resolved'];
const EVENTS_PAGE_SIZE = 50;

// ---------------------------------------------------------------------------
// Sessions (dashboard only)
// ---------------------------------------------------------------------------
router.use(session({
  name: 'fortrix.sid',
  secret: getSetting('session_secret', 'fortrix-dev-secret'),
  store: new MemoryStore({ checkPeriod: 60 * 60 * 1000 }),
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: 'auto',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  },
}));

function requireAuth(req, res, next) {
  if (req.session && req.session.adminId) return next();
  return res.redirect('/app/login');
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------
router.get('/login', (req, res) => {
  if (req.session && req.session.adminId) return res.redirect('/app');
  res.render('login', { layout: 'layout', bare: true, title: 'Sign in', error: null, active: '' });
});

router.post('/login', rateLimit({ windowMs: 10 * 60 * 1000, max: 10, prefix: 'login' }), (req, res) => {
  const { username, password } = req.body || {};
  const admin = username
    ? db.prepare('SELECT * FROM admins WHERE username = ?').get(String(username).trim())
    : null;
  if (!admin || !bcrypt.compareSync(String(password || ''), admin.password_hash)) {
    // Small fixed delay to blunt brute-force / timing probes.
    return setTimeout(() => {
      res.status(401).render('login', {
        layout: 'layout', bare: true, title: 'Sign in',
        error: 'Invalid username or password.', active: '',
      });
    }, 200);
  }
  req.session.adminId = admin.id;
  req.session.adminName = admin.username;
  return res.redirect('/app');
});

router.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/app/login'));
});

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------
router.get('/', requireAuth, (req, res) => {
  const fleet = db.prepare(`
    SELECT COUNT(*) AS total,
           COALESCE(SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END), 0) AS online
    FROM devices
  `).get();

  const openBySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const row of db.prepare("SELECT severity, COUNT(*) AS c FROM alerts WHERE status = 'open' GROUP BY severity").all()) {
    openBySeverity[row.severity] = row.c;
  }
  const openTotal = Object.values(openBySeverity).reduce((a, b) => a + b, 0);

  const events24h = db.prepare("SELECT COUNT(*) AS c FROM events WHERE created_at >= datetime('now', '-1 day')").get().c;

  // Alerts timeline: last 24h bucketed per hour, stacked by severity.
  const rows = db.prepare(`
    SELECT strftime('%Y-%m-%d %H:00', created_at) AS bucket, severity, COUNT(*) AS c
    FROM alerts
    WHERE created_at >= datetime('now', '-1 day')
    GROUP BY bucket, severity
  `).all();

  const buckets = [];
  const now = new Date();
  for (let i = 23; i >= 0; i--) {
    const d = new Date(now.getTime() - i * 3600 * 1000);
    const pad = (n) => String(n).padStart(2, '0');
    buckets.push(`${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:00`);
  }
  const datasets = {};
  for (const sev of SEVERITIES) datasets[sev] = buckets.map(() => 0);
  for (const row of rows) {
    const idx = buckets.indexOf(row.bucket);
    if (idx >= 0 && datasets[row.severity]) datasets[row.severity][idx] = row.c;
  }

  const recentAlerts = db.prepare(`
    SELECT a.*, d.hostname
    FROM alerts a JOIN devices d ON d.id = a.device_id
    ORDER BY a.created_at DESC, a.id DESC
    LIMIT 10
  `).all();

  res.render('overview', {
    title: 'Overview',
    active: 'overview',
    fleet,
    openBySeverity,
    openTotal,
    events24h,
    chart: {
      labels: buckets.map((b) => b.slice(11, 16)),
      datasets,
    },
    recentAlerts,
  });
});

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------
router.get('/devices', requireAuth, (req, res) => {
  const devices = db.prepare('SELECT * FROM devices ORDER BY last_seen DESC').all();
  res.render('devices', { title: 'Devices', active: 'devices', devices });
});

router.get('/devices/:id', requireAuth, (req, res) => {
  const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(req.params.id);
  if (!device) return res.status(404).render('notfound', { title: 'Not found', active: 'devices' });

  const recentEvents = db.prepare(`
    SELECT * FROM events WHERE device_id = ? ORDER BY created_at DESC, id DESC LIMIT 50
  `).all(device.id);

  const heartbeats = db.prepare(`
    SELECT * FROM (
      SELECT cpu_pct, mem_pct, uptime_s, created_at
      FROM heartbeats WHERE device_id = ?
      ORDER BY created_at DESC, id DESC LIMIT 60
    ) ORDER BY created_at ASC
  `).all(device.id);

  const openAlertCount = db.prepare("SELECT COUNT(*) AS c FROM alerts WHERE device_id = ? AND status = 'open'").get(device.id).c;
  const lastHb = heartbeats.length ? heartbeats[heartbeats.length - 1] : null;

  res.render('device_detail', {
    title: device.hostname,
    active: 'devices',
    device,
    recentEvents,
    openAlertCount,
    lastHb,
    hbChart: {
      labels: heartbeats.map((h) => h.created_at.slice(11, 16)),
      cpu: heartbeats.map((h) => h.cpu_pct),
      mem: heartbeats.map((h) => h.mem_pct),
    },
  });
});

// ---------------------------------------------------------------------------
// Leads
// ---------------------------------------------------------------------------
router.get('/leads', requireAuth, (req, res) => {
  const leads = db.prepare('SELECT * FROM leads ORDER BY created_at DESC, id DESC LIMIT 500').all();
  res.render('leads', { title: 'Leads', active: 'leads', leads });
});

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------
router.get('/alerts', requireAuth, (req, res) => {
  const status = ALERT_STATUSES.includes(req.query.status) ? req.query.status : '';
  const severity = SEVERITIES.includes(req.query.severity) ? req.query.severity : '';

  let sql = 'SELECT a.*, d.hostname FROM alerts a JOIN devices d ON d.id = a.device_id WHERE 1=1';
  const params = [];
  if (status) { sql += ' AND a.status = ?'; params.push(status); }
  if (severity) { sql += ' AND a.severity = ?'; params.push(severity); }
  sql += ' ORDER BY a.created_at DESC, a.id DESC LIMIT 200';

  const alerts = db.prepare(sql).all(...params);
  res.render('alerts', {
    title: 'Alerts', active: 'alerts', alerts,
    filters: { status, severity },
    severities: SEVERITIES, statuses: ALERT_STATUSES,
  });
});

router.post('/alerts/:id/status', requireAuth, (req, res) => {
  const next = String((req.body || {}).status || '');
  if (ALERT_STATUSES.includes(next)) {
    db.prepare("UPDATE alerts SET status = ?, updated_at = datetime('now') WHERE id = ?")
      .run(next, req.params.id);
  }
  const back = req.get('referer');
  res.redirect(back && back.includes('/app') ? back : '/app/alerts');
});

// ---------------------------------------------------------------------------
// Events explorer
// ---------------------------------------------------------------------------
router.get('/events', requireAuth, (req, res) => {
  const deviceId = /^\d+$/.test(String(req.query.device_id || '')) ? Number(req.query.device_id) : '';
  const type = typeof req.query.type === 'string' ? req.query.type.trim().slice(0, 128) : '';
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);

  let where = 'WHERE 1=1';
  const params = [];
  if (deviceId) { where += ' AND e.device_id = ?'; params.push(deviceId); }
  if (type) { where += ' AND e.type = ?'; params.push(type); }

  const total = db.prepare(`SELECT COUNT(*) AS c FROM events e ${where}`).get(...params).c;
  const pages = Math.max(1, Math.ceil(total / EVENTS_PAGE_SIZE));
  const current = Math.min(page, pages);

  const events = db.prepare(`
    SELECT e.*, d.hostname
    FROM events e JOIN devices d ON d.id = e.device_id
    ${where}
    ORDER BY e.created_at DESC, e.id DESC
    LIMIT ? OFFSET ?
  `).all(...params, EVENTS_PAGE_SIZE, (current - 1) * EVENTS_PAGE_SIZE);

  const devices = db.prepare('SELECT id, hostname FROM devices ORDER BY hostname').all();
  const types = db.prepare('SELECT DISTINCT type FROM events ORDER BY type').all().map((r) => r.type);

  res.render('events', {
    title: 'Events', active: 'events',
    events, devices, types, total, pages, current,
    filters: { device_id: deviceId, type },
  });
});

// ---------------------------------------------------------------------------
// Settings — enroll keys CRUD + thresholds
// ---------------------------------------------------------------------------
router.get('/settings', requireAuth, (req, res) => {
  const keys = db.prepare('SELECT * FROM enroll_keys ORDER BY created_at DESC, id DESC').all();
  res.render('settings', {
    title: 'Settings', active: 'settings',
    keys,
    thresholds: getThresholds(),
    saved: req.query.saved === '1',
  });
});

router.post('/settings/keys', requireAuth, (req, res) => {
  const label = String((req.body || {}).label || '').trim().slice(0, 64) || 'unnamed';
  const key = 'ftx_' + crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO enroll_keys (key, label, active) VALUES (?, ?, 1)').run(key, label);
  res.redirect('/app/settings');
});

router.post('/settings/keys/:id/deactivate', requireAuth, (req, res) => {
  db.prepare('UPDATE enroll_keys SET active = 0 WHERE id = ?').run(req.params.id);
  res.redirect('/app/settings');
});

router.post('/settings/keys/:id/activate', requireAuth, (req, res) => {
  db.prepare('UPDATE enroll_keys SET active = 1 WHERE id = ?').run(req.params.id);
  res.redirect('/app/settings');
});

router.post('/settings/thresholds', requireAuth, (req, res) => {
  const body = req.body || {};
  const burst = Number(body.fs_read_burst_mb);
  const clip = Number(body.clipboard_rapid_changes);
  if (Number.isFinite(burst) && burst > 0) setSetting('fs_read_burst_mb', Math.floor(burst));
  if (Number.isFinite(clip) && clip > 0) setSetting('clipboard_rapid_changes', Math.floor(clip));
  res.redirect('/app/settings?saved=1');
});

module.exports = router;
