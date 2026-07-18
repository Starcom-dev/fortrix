'use strict';

const express = require('express');
const crypto = require('crypto');
const { db, getThresholds, getIntervals } = require('../db');
const { evaluateEvent } = require('../rules');
const { rateLimit } = require('../rate-limit');

const router = express.Router();

const SEVERITIES = new Set(['info', 'low', 'medium', 'high', 'critical']);
const MAX_BATCH = 200;

// ---------------------------------------------------------------------------
// POST /api/v1/enroll  (no bearer auth; enroll key gate)
// ---------------------------------------------------------------------------
router.post('/enroll', rateLimit({ windowMs: 10 * 60 * 1000, max: 10, prefix: 'enroll' }), (req, res) => {
  const body = req.body || {};
  const enrollKey = typeof body.enroll_key === 'string' ? body.enroll_key.trim() : '';
  if (!enrollKey) return res.status(403).json({ error: 'invalid_enroll_key' });

  const key = db.prepare('SELECT id FROM enroll_keys WHERE key = ? AND active = 1').get(enrollKey);
  if (!key) return res.status(403).json({ error: 'invalid_enroll_key' });

  const token = crypto.randomBytes(24).toString('hex'); // 48 hex chars
  const info = db.prepare(`
    INSERT INTO devices (token, hostname, os, arch, agent_version, ip, status, enrolled_at, last_seen)
    VALUES (?, ?, ?, ?, ?, ?, 'online', datetime('now'), datetime('now'))
  `).run(
    token,
    String(body.hostname || 'unknown').slice(0, 255),
    String(body.os || '').slice(0, 64),
    String(body.arch || '').slice(0, 32),
    String(body.agent_version || '').slice(0, 32),
    req.ip || ''
  );

  return res.status(201).json({ device_id: info.lastInsertRowid, device_token: token });
});

// ---------------------------------------------------------------------------
// POST /api/v1/lead  (public; landing page early-access form)
// ---------------------------------------------------------------------------
const LEAD_RATE_LIMIT = 5;
const LEAD_RATE_WINDOW_MS = 60 * 60 * 1000; // 1 hour
const leadRate = new Map(); // ip -> [timestamps]

function leadRateLimited(ip) {
  const now = Date.now();
  const hits = (leadRate.get(ip) || []).filter((t) => now - t < LEAD_RATE_WINDOW_MS);
  if (hits.length >= LEAD_RATE_LIMIT) {
    leadRate.set(ip, hits);
    return true;
  }
  hits.push(now);
  leadRate.set(ip, hits);
  // Cheap cleanup: prune stale IPs occasionally.
  if (Math.random() < 0.01) {
    for (const [k, v] of leadRate) {
      const fresh = v.filter((t) => now - t < LEAD_RATE_WINDOW_MS);
      if (fresh.length === 0) leadRate.delete(k);
      else leadRate.set(k, fresh);
    }
  }
  return false;
}

function leadClientIp(req) {
  // Behind Cloudflare the socket/XFF hop is a rotating CF edge IP;
  // CF-Connecting-IP carries the real client address.
  return req.get('cf-connecting-ip') || req.get('x-real-ip') || req.ip || '';
}

router.post('/lead', (req, res) => {
  const ip = leadClientIp(req);
  if (leadRateLimited(ip)) {
    return res.status(429).json({ error: 'rate_limited' });
  }

  const body = req.body || {};
  const email = typeof body.email === 'string' ? body.email.trim().slice(0, 255) : '';
  if (!email || !email.includes('@') || !email.includes('.')) {
    return res.status(400).json({ error: 'invalid_email' });
  }

  const clean = (v) => (typeof v === 'string' ? v.trim().slice(0, 255) : '');
  const name = clean(body.name);
  const company = clean(body.company);
  const message = clean(body.message);

  db.prepare(`
    INSERT INTO leads (email, name, company, message, source, ip)
    VALUES (?, ?, ?, ?, 'landing', ?)
  `).run(email, name, company, message, ip);

  return res.status(201).json({ success: true });
});

// ---------------------------------------------------------------------------
// Bearer device-token auth for everything below
// ---------------------------------------------------------------------------
function deviceAuth(req, res, next) {
  const header = req.get('authorization') || '';
  const m = header.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ error: 'unauthorized' });
  const device = db.prepare('SELECT * FROM devices WHERE token = ?').get(m[1].trim());
  if (!device) return res.status(401).json({ error: 'unauthorized' });
  req.device = device;
  next();
}

router.use(deviceAuth);

// ---------------------------------------------------------------------------
// POST /api/v1/heartbeat
// ---------------------------------------------------------------------------
router.post('/heartbeat', (req, res) => {
  const body = req.body || {};
  const cpu = Number.isFinite(Number(body.cpu_pct)) ? Number(body.cpu_pct) : null;
  const mem = Number.isFinite(Number(body.mem_pct)) ? Number(body.mem_pct) : null;
  const uptime = Number.isFinite(Number(body.uptime_s)) ? Math.floor(Number(body.uptime_s)) : null;
  const agentVersion = typeof body.agent_version === 'string' ? body.agent_version.slice(0, 32) : null;

  db.prepare(`
    UPDATE devices
    SET last_seen = datetime('now'),
        status = 'online',
        ip = ?,
        agent_version = COALESCE(?, agent_version)
    WHERE id = ?
  `).run(req.ip || req.device.ip, agentVersion, req.device.id);

  db.prepare('INSERT INTO heartbeats (device_id, cpu_pct, mem_pct, uptime_s) VALUES (?, ?, ?, ?)')
    .run(req.device.id, cpu, mem, uptime);

  // Cheap retention: keep ~48h of heartbeat history.
  if (Math.random() < 0.02) {
    db.prepare("DELETE FROM heartbeats WHERE created_at < datetime('now', '-2 days')").run();
  }

  return res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// POST /api/v1/events  {events:[{type, ts, severity, data}]}  max 200/batch
// ---------------------------------------------------------------------------
const insertEventStmt = db.prepare(
  'INSERT INTO events (device_id, type, severity, data) VALUES (?, ?, ?, ?)'
);
const insertAlertStmt = db.prepare(
  'INSERT INTO alerts (device_id, event_id, rule, title, severity, status) VALUES (?, ?, ?, ?, ?, ?)'
);

router.post('/events', (req, res) => {
  const body = req.body || {};
  const events = body.events;
  if (!Array.isArray(events)) {
    return res.status(400).json({ error: 'invalid_payload', detail: 'events must be an array' });
  }
  if (events.length > MAX_BATCH) {
    return res.status(400).json({ error: 'batch_too_large', max: MAX_BATCH });
  }

  const thresholds = getThresholds();
  let accepted = 0;
  let alertsCreated = 0;

  const ingest = db.transaction((batch) => {
    for (const raw of batch) {
      if (!raw || typeof raw !== 'object') continue;
      const type = typeof raw.type === 'string' ? raw.type.trim().slice(0, 128) : '';
      if (!type) continue;

      const severity = SEVERITIES.has(raw.severity) ? raw.severity : 'info';
      const data = (raw.data && typeof raw.data === 'object' && !Array.isArray(raw.data)) ? raw.data : {};
      if (raw.ts !== undefined && data.agent_ts === undefined) data.agent_ts = raw.ts;

      const evt = { type, severity, data };
      const info = insertEventStmt.run(req.device.id, type, severity, JSON.stringify(data));
      accepted++;

      const alert = evaluateEvent(evt, thresholds);
      if (alert) {
        insertAlertStmt.run(req.device.id, info.lastInsertRowid, alert.rule, alert.title, alert.severity, 'open');
        alertsCreated++;
      }
    }
  });

  ingest(events);

  // Event traffic also proves liveness.
  db.prepare("UPDATE devices SET last_seen = datetime('now'), status = 'online' WHERE id = ?")
    .run(req.device.id);

  return res.json({ accepted, alerts_created: alertsCreated });
});

// ---------------------------------------------------------------------------
// GET /api/v1/config
// ---------------------------------------------------------------------------
router.get('/config', (req, res) => {
  return res.json({
    thresholds: getThresholds(),
    intervals: getIntervals(),
  });
});

module.exports = router;
