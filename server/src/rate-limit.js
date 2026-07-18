'use strict';

// ---------------------------------------------------------------------------
// In-memory sliding-window rate limiter. No external dependencies.
//
// Usage:
//   const { rateLimit } = require('./rate-limit');
//   router.post('/login', rateLimit({ windowMs: 600000, max: 10, prefix: 'login' }), handler);
//
// Keys on the Cloudflare client IP (cf-connecting-ip) when present, otherwise
// req.ip. Each key holds an array of hit timestamps inside the window.
// ---------------------------------------------------------------------------

const buckets = new Map(); // key -> number[] (ascending timestamps)

let maxWindowMs = 60 * 1000;

// Periodic sweep so idle keys don't leak memory.
setInterval(() => {
  const cutoff = Date.now() - maxWindowMs;
  for (const [key, hits] of buckets) {
    while (hits.length && hits[0] <= cutoff) hits.shift();
    if (hits.length === 0) buckets.delete(key);
  }
}, 10 * 60 * 1000).unref();

function clientIp(req) {
  const cf = req.get ? req.get('cf-connecting-ip') : null;
  if (cf) return cf.trim();
  return req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';
}

function isApiRequest(req) {
  const url = req.originalUrl || req.url || '';
  return url.startsWith('/api');
}

/**
 * @param {object} opts
 * @param {number} opts.windowMs sliding window size in milliseconds
 * @param {number} opts.max     max requests per key per window
 * @param {string} opts.prefix  bucket namespace (e.g. 'login', 'enroll')
 */
function rateLimit({ windowMs, max, prefix }) {
  if (!Number.isFinite(windowMs) || windowMs <= 0) throw new Error('rateLimit: windowMs required');
  if (!Number.isFinite(max) || max <= 0) throw new Error('rateLimit: max required');
  if (windowMs > maxWindowMs) maxWindowMs = windowMs;

  return function rateLimitMiddleware(req, res, next) {
    const key = `${prefix || 'rl'}:${clientIp(req)}`;
    const now = Date.now();
    const cutoff = now - windowMs;

    let hits = buckets.get(key);
    if (!hits) {
      hits = [];
      buckets.set(key, hits);
    }
    while (hits.length && hits[0] <= cutoff) hits.shift();

    if (hits.length >= max) {
      const retrySeconds = Math.max(1, Math.ceil((hits[0] + windowMs - now) / 1000));
      res.set('Retry-After', String(retrySeconds));
      if (isApiRequest(req)) {
        return res.status(429).json({ error: 'rate_limited', retry_seconds: retrySeconds });
      }
      return res
        .status(429)
        .type('text/plain')
        .send(`Too many requests. Retry after ${retrySeconds} seconds`);
    }

    hits.push(now);
    return next();
  };
}

module.exports = { rateLimit };
