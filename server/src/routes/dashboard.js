'use strict';

const express = require('express');
const session = require('express-session');
const MemoryStore = require('memorystore')(session);
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const {
  db, getSetting, setSetting, setOrgSetting, getOrgSetting, getThresholds,
  audit, randomPassword,
} = require('../db');
const { rateLimit } = require('../rate-limit');

const router = express.Router();

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const ALERT_STATUSES = ['open', 'ack', 'resolved'];
const EVENTS_PAGE_SIZE = 50;

// Role hierarchy. Higher rank = more privileges.
const ROLE_RANK = { analyst: 1, admin: 2, owner: 3, super_admin: 4 };
const ORG_ROLES = ['owner', 'admin', 'analyst']; // assignable within an org

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

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------
function loadUser(req) {
  if (!req.session || !req.session.userId) return null;
  const user = db.prepare('SELECT * FROM users WHERE id = ? AND active = 1').get(req.session.userId);
  return user || null;
}

function requireAuth(req, res, next) {
  const user = loadUser(req);
  if (!user) return res.redirect('/app/login');
  req.user = user;
  req.isSuper = user.role === 'super_admin';

  // Resolve the org context. Super admins can switch orgs; others are pinned.
  let orgId = user.org_id;
  if (req.isSuper && req.session.viewOrgId) {
    const exists = db.prepare('SELECT id FROM orgs WHERE id = ?').get(req.session.viewOrgId);
    if (exists) orgId = exists.id;
  }
  if (!orgId) {
    const first = db.prepare('SELECT id FROM orgs ORDER BY id LIMIT 1').get();
    orgId = first ? first.id : 1;
  }
  req.orgId = orgId;
  req.org = db.prepare('SELECT * FROM orgs WHERE id = ?').get(orgId) || { id: orgId, name: 'Unknown' };

  // View locals (layout sidebar/header).
  res.locals.currentUser = { id: user.id, username: user.username, role: user.role };
  res.locals.currentOrg = req.org;
  res.locals.roleRank = ROLE_RANK[user.role] || 0;
  res.locals.isSuper = req.isSuper;
  res.locals.orgs = req.isSuper ? db.prepare('SELECT id, name FROM orgs ORDER BY name').all() : [];

  // One-shot flash message (e.g. generated credentials).
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;

  next();
}

function requireRole(minRole) {
  const min = ROLE_RANK[minRole] || 99;
  return (req, res, next) => {
    if ((ROLE_RANK[req.user.role] || 0) >= min) return next();
    return res.status(403).render('notfound', { title: 'Forbidden', active: '' });
  };
}

function clientIp(req) {
  return req.get('cf-connecting-ip') || req.get('x-real-ip') || req.ip || '';
}

// ---------------------------------------------------------------------------
// Auth routes
// ---------------------------------------------------------------------------
router.get('/login', (req, res) => {
  if (loadUser(req)) return res.redirect('/app');
  res.render('login', { layout: 'layout', bare: true, title: 'Sign in', error: null, active: '' });
});

router.post('/login', rateLimit({ windowMs: 10 * 60 * 1000, max: 10, prefix: 'login' }), (req, res) => {
  const { username, password } = req.body || {};
  const user = username
    ? db.prepare('SELECT * FROM users WHERE username = ? AND active = 1').get(String(username).trim())
    : null;
  if (!user || !bcrypt.compareSync(String(password || ''), user.password_hash)) {
    audit(user ? user.org_id : null, null, 'login_failed', `username=${String(username || '').slice(0, 64)}`, clientIp(req));
    // Small fixed delay to blunt brute-force / timing probes.
    return setTimeout(() => {
      res.status(401).render('login', {
        layout: 'layout', bare: true, title: 'Sign in',
        error: 'Invalid username or password.', active: '',
      });
    }, 200);
  }
  req.session.userId = user.id;
  delete req.session.viewOrgId;
  db.prepare("UPDATE users SET last_login = datetime('now') WHERE id = ?").run(user.id);
  audit(user.org_id, user, 'login_success', '', clientIp(req));
  return res.redirect('/app');
});

router.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/app/login'));
});

// Org switcher (super admin only).
router.post('/org/switch', requireAuth, requireRole('super_admin'), (req, res) => {
  const orgId = Number((req.body || {}).org_id);
  if (Number.isInteger(orgId) && db.prepare('SELECT id FROM orgs WHERE id = ?').get(orgId)) {
    req.session.viewOrgId = orgId;
  }
  const back = req.get('referer');
  res.redirect(back && back.includes('/app') ? back : '/app');
});

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------
router.get('/', requireAuth, (req, res) => {
  const fleet = db.prepare(`
    SELECT COUNT(*) AS total,
           COALESCE(SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END), 0) AS online
    FROM devices WHERE org_id = ?
  `).get(req.orgId);

  const openBySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const sevRows = db.prepare(`
    SELECT a.severity, COUNT(*) AS c
    FROM alerts a JOIN devices d ON d.id = a.device_id
    WHERE a.status = 'open' AND d.org_id = ?
    GROUP BY a.severity
  `).all(req.orgId);
  for (const row of sevRows) openBySeverity[row.severity] = row.c;
  const openTotal = Object.values(openBySeverity).reduce((a, b) => a + b, 0);

  const events24h = db.prepare(`
    SELECT COUNT(*) AS c FROM events e JOIN devices d ON d.id = e.device_id
    WHERE e.created_at >= datetime('now', '-1 day') AND d.org_id = ?
  `).get(req.orgId).c;

  // Alerts timeline: last 24h bucketed per hour, stacked by severity.
  const rows = db.prepare(`
    SELECT strftime('%Y-%m-%d %H:00', a.created_at) AS bucket, a.severity, COUNT(*) AS c
    FROM alerts a JOIN devices d ON d.id = a.device_id
    WHERE a.created_at >= datetime('now', '-1 day') AND d.org_id = ?
    GROUP BY bucket, a.severity
  `).all(req.orgId);

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
    WHERE d.org_id = ?
    ORDER BY a.created_at DESC, a.id DESC
    LIMIT 10
  `).all(req.orgId);

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
  const devices = db.prepare('SELECT * FROM devices WHERE org_id = ? ORDER BY last_seen DESC').all(req.orgId);
  res.render('devices', { title: 'Devices', active: 'devices', devices });
});

router.get('/devices/:id', requireAuth, (req, res) => {
  const device = db.prepare('SELECT * FROM devices WHERE id = ? AND org_id = ?').get(req.params.id, req.orgId);
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
// Leads (platform-level; super admin only)
// ---------------------------------------------------------------------------
router.get('/leads', requireAuth, requireRole('super_admin'), (req, res) => {
  const leads = db.prepare('SELECT * FROM leads ORDER BY created_at DESC, id DESC LIMIT 500').all();
  res.render('leads', { title: 'Leads', active: 'leads', leads });
});

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------
router.get('/alerts', requireAuth, (req, res) => {
  const status = ALERT_STATUSES.includes(req.query.status) ? req.query.status : '';
  const severity = SEVERITIES.includes(req.query.severity) ? req.query.severity : '';

  let sql = 'SELECT a.*, d.hostname FROM alerts a JOIN devices d ON d.id = a.device_id WHERE d.org_id = ?';
  const params = [req.orgId];
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
    const info = db.prepare(`
      UPDATE alerts SET status = ?, updated_at = datetime('now')
      WHERE id = ? AND device_id IN (SELECT id FROM devices WHERE org_id = ?)
    `).run(next, req.params.id, req.orgId);
    if (info.changes > 0) {
      audit(req.orgId, req.user, 'alert_status', `alert=${req.params.id} status=${next}`, clientIp(req));
    }
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

  let where = 'WHERE d.org_id = ?';
  const params = [req.orgId];
  if (deviceId) { where += ' AND e.device_id = ?'; params.push(deviceId); }
  if (type) { where += ' AND e.type = ?'; params.push(type); }

  const total = db.prepare(`SELECT COUNT(*) AS c FROM events e JOIN devices d ON d.id = e.device_id ${where}`).get(...params).c;
  const pages = Math.max(1, Math.ceil(total / EVENTS_PAGE_SIZE));
  const current = Math.min(page, pages);

  const events = db.prepare(`
    SELECT e.*, d.hostname
    FROM events e JOIN devices d ON d.id = e.device_id
    ${where}
    ORDER BY e.created_at DESC, e.id DESC
    LIMIT ? OFFSET ?
  `).all(...params, EVENTS_PAGE_SIZE, (current - 1) * EVENTS_PAGE_SIZE);

  const devices = db.prepare('SELECT id, hostname FROM devices WHERE org_id = ? ORDER BY hostname').all(req.orgId);
  const types = db.prepare(`
    SELECT DISTINCT e.type FROM events e JOIN devices d ON d.id = e.device_id
    WHERE d.org_id = ? ORDER BY e.type
  `).all(req.orgId).map((r) => r.type);

  res.render('events', {
    title: 'Events', active: 'events',
    events, devices, types, total, pages, current,
    filters: { device_id: deviceId, type },
  });
});

// ---------------------------------------------------------------------------
// Settings — enroll keys CRUD + thresholds (org-scoped; admin+)
// ---------------------------------------------------------------------------
router.get('/settings', requireAuth, requireRole('admin'), (req, res) => {
  const keys = db.prepare('SELECT * FROM enroll_keys WHERE org_id = ? ORDER BY created_at DESC, id DESC').all(req.orgId);
  res.render('settings', {
    title: 'Settings', active: 'settings',
    keys,
    thresholds: getThresholds(req.orgId),
    saved: req.query.saved === '1',
    email: {
      enabled: getOrgSetting(req.orgId, 'notify_enabled', '0') === '1',
      notify_email: getOrgSetting(req.orgId, 'notify_email', ''),
      notify_min_severity: getOrgSetting(req.orgId, 'notify_min_severity', 'high'),
    },
  });
});

router.post('/settings/keys', requireAuth, requireRole('admin'), (req, res) => {
  const label = String((req.body || {}).label || '').trim().slice(0, 64) || 'unnamed';
  const key = 'ftx_' + crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO enroll_keys (key, label, active, org_id) VALUES (?, ?, 1, ?)').run(key, label, req.orgId);
  audit(req.orgId, req.user, 'enroll_key_generate', `label=${label}`, clientIp(req));
  res.redirect('/app/settings');
});

router.post('/settings/keys/:id/deactivate', requireAuth, requireRole('admin'), (req, res) => {
  const info = db.prepare('UPDATE enroll_keys SET active = 0 WHERE id = ? AND org_id = ?').run(req.params.id, req.orgId);
  if (info.changes > 0) audit(req.orgId, req.user, 'enroll_key_deactivate', `key_id=${req.params.id}`, clientIp(req));
  res.redirect('/app/settings');
});

router.post('/settings/keys/:id/activate', requireAuth, requireRole('admin'), (req, res) => {
  const info = db.prepare('UPDATE enroll_keys SET active = 1 WHERE id = ? AND org_id = ?').run(req.params.id, req.orgId);
  if (info.changes > 0) audit(req.orgId, req.user, 'enroll_key_activate', `key_id=${req.params.id}`, clientIp(req));
  res.redirect('/app/settings');
});

router.post('/settings/thresholds', requireAuth, requireRole('admin'), (req, res) => {
  const body = req.body || {};
  const burst = Number(body.fs_read_burst_mb);
  const clip = Number(body.clipboard_rapid_changes);
  if (Number.isFinite(burst) && burst > 0) setOrgSetting(req.orgId, 'fs_read_burst_mb', Math.floor(burst));
  if (Number.isFinite(clip) && clip > 0) setOrgSetting(req.orgId, 'clipboard_rapid_changes', Math.floor(clip));
  audit(req.orgId, req.user, 'thresholds_update', `burst_mb=${burst} clip_per_min=${clip}`, clientIp(req));
  res.redirect('/app/settings?saved=1');
});

router.post('/settings/email', requireAuth, requireRole('admin'), (req, res) => {
  const body = req.body || {};
  const email = String(body.notify_email || '').trim().slice(0, 255);
  const minSev = String(body.notify_min_severity || 'high').trim();
  const enabled = body.notify_enabled === '1' ? '1' : '0';

  if (email && !email.includes('@')) {
    req.session.flash = { type: 'error', message: 'Invalid email address.' };
    return res.redirect('/app/settings');
  }
  if (!['info', 'low', 'medium', 'high', 'critical'].includes(minSev)) {
    req.session.flash = { type: 'error', message: 'Invalid severity.' };
    return res.redirect('/app/settings');
  }

  setOrgSetting(req.orgId, 'notify_enabled', enabled);
  setOrgSetting(req.orgId, 'notify_email', email);
  setOrgSetting(req.orgId, 'notify_min_severity', minSev);
  audit(req.orgId, req.user, 'email_settings_update', `enabled=${enabled} email=${email.slice(0, 32)} severity=${minSev}`, clientIp(req));
  req.session.flash = { type: 'success', message: 'Email notification settings saved.' };
  res.redirect('/app/settings');
});

// ---------------------------------------------------------------------------
// Users (org user management; owner+)
// ---------------------------------------------------------------------------
function canManageTarget(actor, target) {
  if (!target) return false;
  if (actor.id === target.id) return false; // never manage self via these routes
  if (actor.role === 'super_admin') return true;
  // Org owners manage only users in their own org, below owner rank.
  return target.org_id === actor.org_id && (ROLE_RANK[target.role] || 0) < ROLE_RANK.owner;
}

router.get('/users', requireAuth, requireRole('owner'), (req, res) => {
  const users = db.prepare(`
    SELECT id, org_id, username, email, role, active, created_at, last_login
    FROM users WHERE org_id = ? ORDER BY created_at ASC
  `).all(req.orgId);
  res.render('users', {
    title: 'Users', active: 'users',
    users,
    assignableRoles: req.isSuper ? ORG_ROLES : ORG_ROLES.filter((r) => r !== 'owner'),
  });
});

router.post('/users', requireAuth, requireRole('owner'), (req, res) => {
  const body = req.body || {};
  const username = String(body.username || '').trim().toLowerCase().slice(0, 64);
  const email = String(body.email || '').trim().slice(0, 255);
  const role = String(body.role || 'analyst');

  const allowedRoles = req.isSuper ? ORG_ROLES : ORG_ROLES.filter((r) => r !== 'owner');
  if (!/^[a-z0-9_.-]{3,64}$/.test(username) || !allowedRoles.includes(role)) {
    req.session.flash = { type: 'error', message: 'Invalid username (3-64 chars: a-z 0-9 _ . -) or role.' };
    return res.redirect('/app/users');
  }
  if (db.prepare('SELECT id FROM users WHERE username = ?').get(username)) {
    req.session.flash = { type: 'error', message: `Username "${username}" is already taken.` };
    return res.redirect('/app/users');
  }

  const password = randomPassword(16);
  db.prepare('INSERT INTO users (org_id, username, email, password_hash, role) VALUES (?, ?, ?, ?, ?)')
    .run(req.orgId, username, email, bcrypt.hashSync(password, 10), role);
  audit(req.orgId, req.user, 'user_create', `username=${username} role=${role}`, clientIp(req));

  req.session.flash = {
    type: 'success',
    message: `User "${username}" (${role}) created.`,
    creds: { username, password },
  };
  res.redirect('/app/users');
});

router.post('/users/:id/toggle-active', requireAuth, requireRole('owner'), (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (canManageTarget(req.user, target)) {
    const next = target.active ? 0 : 1;
    db.prepare('UPDATE users SET active = ? WHERE id = ?').run(next, target.id);
    audit(req.orgId, req.user, next ? 'user_activate' : 'user_deactivate', `username=${target.username}`, clientIp(req));
  } else {
    req.session.flash = { type: 'error', message: 'Not allowed.' };
  }
  res.redirect('/app/users');
});

router.post('/users/:id/reset-password', requireAuth, requireRole('owner'), (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (canManageTarget(req.user, target)) {
    const password = randomPassword(16);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(password, 10), target.id);
    audit(req.orgId, req.user, 'user_reset_password', `username=${target.username}`, clientIp(req));
    req.session.flash = {
      type: 'success',
      message: `Password reset for "${target.username}".`,
      creds: { username: target.username, password },
    };
  } else {
    req.session.flash = { type: 'error', message: 'Not allowed.' };
  }
  res.redirect('/app/users');
});

router.post('/users/:id/delete', requireAuth, requireRole('owner'), (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (canManageTarget(req.user, target)) {
    db.prepare('DELETE FROM users WHERE id = ?').run(target.id);
    audit(req.orgId, req.user, 'user_delete', `username=${target.username}`, clientIp(req));
  } else {
    req.session.flash = { type: 'error', message: 'Not allowed.' };
  }
  res.redirect('/app/users');
});

// Change own password (any role).
router.post('/profile/password', requireAuth, (req, res) => {
  const body = req.body || {};
  const current = String(body.current_password || '');
  const next = String(body.new_password || '');
  if (!bcrypt.compareSync(current, req.user.password_hash)) {
    req.session.flash = { type: 'error', message: 'Current password is incorrect.' };
  } else if (next.length < 10) {
    req.session.flash = { type: 'error', message: 'New password must be at least 10 characters.' };
  } else {
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(next, 10), req.user.id);
    audit(req.orgId, req.user, 'password_change', '', clientIp(req));
    req.session.flash = { type: 'success', message: 'Password updated.' };
  }
  const back = req.get('referer');
  res.redirect(back && back.includes('/app') ? back : '/app');
});

// ---------------------------------------------------------------------------
// Organizations (super admin only)
// ---------------------------------------------------------------------------
router.get('/orgs', requireAuth, requireRole('super_admin'), (req, res) => {
  const orgs = db.prepare(`
    SELECT o.*,
      (SELECT COUNT(*) FROM devices d WHERE d.org_id = o.id) AS device_count,
      (SELECT COUNT(*) FROM users u WHERE u.org_id = o.id) AS user_count,
      (SELECT COUNT(*) FROM alerts a JOIN devices d ON d.id = a.device_id WHERE d.org_id = o.id AND a.status = 'open') AS open_alerts
    FROM orgs o ORDER BY o.created_at ASC
  `).all();
  res.render('orgs', { title: 'Organizations', active: 'orgs', orgs });
});

router.post('/orgs', requireAuth, requireRole('super_admin'), (req, res) => {
  const body = req.body || {};
  const name = String(body.name || '').trim().slice(0, 128);
  const ownerUsername = String(body.owner_username || '').trim().toLowerCase().slice(0, 64);

  if (!name) {
    req.session.flash = { type: 'error', message: 'Organization name is required.' };
    return res.redirect('/app/orgs');
  }
  if (ownerUsername && !/^[a-z0-9_.-]{3,64}$/.test(ownerUsername)) {
    req.session.flash = { type: 'error', message: 'Invalid owner username.' };
    return res.redirect('/app/orgs');
  }
  if (ownerUsername && db.prepare('SELECT id FROM users WHERE username = ?').get(ownerUsername)) {
    req.session.flash = { type: 'error', message: `Username "${ownerUsername}" is already taken.` };
    return res.redirect('/app/orgs');
  }

  const orgInfo = db.prepare('INSERT INTO orgs (name) VALUES (?)').run(name);
  const orgId = orgInfo.lastInsertRowid;

  const enrollKey = 'ftx_' + crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO enroll_keys (key, label, active, org_id) VALUES (?, ?, 1, ?)').run(enrollKey, 'default', orgId);

  let creds = null;
  if (ownerUsername) {
    const password = randomPassword(16);
    db.prepare('INSERT INTO users (org_id, username, password_hash, role) VALUES (?, ?, ?, ?)')
      .run(orgId, ownerUsername, bcrypt.hashSync(password, 10), 'owner');
    creds = { username: ownerUsername, password };
  }

  audit(orgId, req.user, 'org_create', `name=${name} owner=${ownerUsername || '-'}`, clientIp(req));
  req.session.flash = {
    type: 'success',
    message: `Organization "${name}" created. Enroll key: ${enrollKey}`,
    creds,
  };
  res.redirect('/app/orgs');
});

router.post('/orgs/:id/rename', requireAuth, requireRole('super_admin'), (req, res) => {
  const name = String((req.body || {}).name || '').trim().slice(0, 128);
  if (name) {
    db.prepare('UPDATE orgs SET name = ? WHERE id = ?').run(name, req.params.id);
    audit(Number(req.params.id), req.user, 'org_rename', `name=${name}`, clientIp(req));
  }
  res.redirect('/app/orgs');
});

// ---------------------------------------------------------------------------
// Audit log (owner+)
// ---------------------------------------------------------------------------
router.get('/audit', requireAuth, requireRole('owner'), (req, res) => {
  const entries = db.prepare(`
    SELECT * FROM audit_logs WHERE org_id = ? ORDER BY created_at DESC, id DESC LIMIT 200
  `).all(req.orgId);
  res.render('audit', { title: 'Audit Log', active: 'audit', entries });
});

module.exports = router;

// ---------------------------------------------------------------------------
// Agent versions CRUD (admin+, dashboard; scoped for admins to see across orgs)
// ---------------------------------------------------------------------------
router.get('/agent/versions', requireAuth, requireRole('admin'), (req, res) => {
  const platform = typeof req.query.platform === 'string' ? req.query.platform.trim() : '';
  const arch = typeof req.query.arch === 'string' ? req.query.arch.trim() : '';

  let sql = 'SELECT * FROM agent_versions WHERE 1=1';
  const params = [];
  if (platform) { sql += ' AND platform = ?'; params.push(platform); }
  if (arch) { sql += ' AND arch = ?'; params.push(arch); }
  sql += ' ORDER BY created_at DESC LIMIT 50';

  const versions = db.prepare(sql).all(...params);
  res.render('agent_versions', {
    title: 'Agent Versions', active: 'settings',
    versions,
    filters: { platform, arch },
  });
});

router.post('/agent/versions', requireAuth, requireRole('admin'), (req, res) => {
  const body = req.body || {};
  const version = String(body.version || '').trim().slice(0, 32);
  const platform = String(body.platform || 'windows').trim().slice(0, 16);
  const arch = String(body.arch || 'amd64').trim().slice(0, 16);
  const url = String(body.url || '').trim().slice(0, 2000);
  const sha256 = String(body.sha256 || '').trim().slice(0, 64);
  const releaseNotes = String(body.release_notes || '').trim().slice(0, 2000);

  if (!version || !/^\d+\.\d+\.\d+$/.test(version)) {
    req.session.flash = { type: 'error', message: 'Version must be semver format (e.g. 0.2.0).' };
    return res.redirect('/app/agent/versions');
  }
  if (!url || !url.startsWith('http')) {
    req.session.flash = { type: 'error', message: 'Download URL is required and must start with http(s).' };
    return res.redirect('/app/agent/versions');
  }
  if (!sha256 || sha256.length !== 64 || !/^[0-9a-f]{64}$/.test(sha256)) {
    req.session.flash = { type: 'error', message: 'SHA256 must be 64 lowercase hex chars.' };
    return res.redirect('/app/agent/versions');
  }

  // Upsert: if (version, platform, arch) exists, update; else insert.
  const exists = db.prepare('SELECT id FROM agent_versions WHERE version = ? AND platform = ? AND arch = ?').get(version, platform, arch);
  if (exists) {
    db.prepare('UPDATE agent_versions SET url = ?, sha256 = ?, release_notes = ?, created_at = datetime(\'now\') WHERE id = ?').run(url, sha256, releaseNotes, exists.id);
    audit(req.orgId, req.user, 'agent_version_update', `version=${version} platform=${platform} arch=${arch}`, clientIp(req));
    req.session.flash = { type: 'success', message: `Agent ${version} (${platform}/${arch}) updated.` };
  } else {
    db.prepare('INSERT INTO agent_versions (version, platform, arch, url, sha256, release_notes) VALUES (?, ?, ?, ?, ?, ?)').run(version, platform, arch, url, sha256, releaseNotes);
    audit(req.orgId, req.user, 'agent_version_create', `version=${version} platform=${platform} arch=${arch}`, clientIp(req));
    req.session.flash = { type: 'success', message: `Agent ${version} (${platform}/${arch}) published.` };
  }
  res.redirect('/app/agent/versions');
});

router.post('/agent/versions/:id/delete', requireAuth, requireRole('admin'), (req, res) => {
  const v = db.prepare('SELECT * FROM agent_versions WHERE id = ?').get(req.params.id);
  if (v) {
    db.prepare('DELETE FROM agent_versions WHERE id = ?').run(req.params.id);
    audit(req.orgId, req.user, 'agent_version_delete', `version=${v.version} platform=${v.platform} arch=${v.arch}`, clientIp(req));
    req.session.flash = { type: 'success', message: `Agent ${v.version} deleted.` };
  }
  res.redirect('/app/agent/versions');
});
