'use strict';

const path = require('path');
const fs = require('fs');
const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const { db, seedIfNeeded, DB_PATH } = require('./db');
const apiRouter = require('./routes/api');
const dashboardRouter = require('./routes/dashboard');

const app = express();

app.set('trust proxy', 1);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));
app.use(expressLayouts);
app.set('layout', 'layout');

// ---------------------------------------------------------------------------
// Security headers (HSTS handled by Cloudflare)
// ---------------------------------------------------------------------------
app.use((req, res, next) => {
  res.set('X-Frame-Options', 'DENY');
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false }));

// ---------------------------------------------------------------------------
// View helpers
// ---------------------------------------------------------------------------
app.locals.sevBadge = (sev) => ({
  critical: 'bg-red-500/15 text-red-400 border border-red-500/30',
  high: 'bg-orange-500/15 text-orange-400 border border-orange-500/30',
  medium: 'bg-amber-500/15 text-amber-300 border border-amber-500/30',
  low: 'bg-sky-500/15 text-sky-300 border border-sky-500/30',
  info: 'bg-slate-500/15 text-slate-300 border border-slate-500/30',
}[sev] || 'bg-slate-500/15 text-slate-300 border border-slate-500/30');

app.locals.statusBadge = (status) => ({
  open: 'bg-red-500/15 text-red-400 border border-red-500/30',
  ack: 'bg-amber-500/15 text-amber-300 border border-amber-500/30',
  resolved: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30',
  online: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30',
  offline: 'bg-slate-500/15 text-slate-400 border border-slate-500/30',
}[status] || 'bg-slate-500/15 text-slate-300 border border-slate-500/30');

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------
app.get('/', (req, res) => res.redirect('/app'));
app.use('/api/v1', apiRouter);
app.use('/app', dashboardRouter);

app.use('/api', (req, res) => res.status(404).json({ error: 'not_found' }));
app.use((req, res) => res.status(404).send('Not found'));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[fortrix] error:', err.message);
  if (req.path.startsWith('/api')) {
    return res.status(err.status || 500).json({ error: 'server_error' });
  }
  return res.status(err.status || 500).send('Server error');
});

// ---------------------------------------------------------------------------
// Seed + offline marker + listen
// ---------------------------------------------------------------------------
seedIfNeeded();

const offlineStmt = db.prepare(`
  UPDATE devices SET status = 'offline'
  WHERE status = 'online' AND last_seen < datetime('now', '-3 minutes')
`);
setInterval(() => {
  try { offlineStmt.run(); } catch (err) { console.error('[fortrix] offline sweep failed:', err.message); }
}, 30 * 1000).unref();

// ---------------------------------------------------------------------------
// Daily DB backup (03:00 UTC = 10:00 WIB), keep last 7 days
// ---------------------------------------------------------------------------
const BACKUP_DIR = path.join(path.dirname(DB_PATH), 'backups');
const BACKUP_HOUR_UTC = 3;
const BACKUP_KEEP = 7;

function runBackup() {
  try {
    if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const stamp = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
    const dest = path.join(BACKUP_DIR, `fortrix-${stamp}.db`);
    if (fs.existsSync(dest)) return; // already done today

    try { db.pragma('wal_checkpoint(TRUNCATE)'); } catch { /* best effort */ }
    fs.copyFileSync(DB_PATH, dest);

    const files = fs.readdirSync(BACKUP_DIR)
      .filter((f) => /^fortrix-\d{4}-\d{2}-\d{2}\.db$/.test(f))
      .sort();
    while (files.length > BACKUP_KEEP) {
      fs.unlinkSync(path.join(BACKUP_DIR, files.shift()));
    }
    console.log(`[fortrix] db backup written: ${dest}`);
  } catch (err) {
    console.error('[fortrix] db backup failed:', err.message);
  }
}

setInterval(() => {
  if (new Date().getUTCHours() === BACKUP_HOUR_UTC) runBackup();
}, 60 * 60 * 1000).unref();

const PORT = parseInt(process.env.PORT || '3010', 10);
const HOST = process.env.HOST || '127.0.0.1';

app.listen(PORT, HOST, () => {
  console.log(`[fortrix] server listening on http://${HOST}:${PORT} (api: /api/v1, dashboard: /app)`);
});
