'use strict';

/**
 * Fortrix rules engine — simple, deterministic, evaluated on ingest.
 *
 * Rules (per spec):
 *  - net.outbound_new_remote  + data.public=true + data.port NOT IN (80,443) -> medium "Uncommon outbound connection"
 *  - fs.read_burst            data.read_mb >= threshold (default 500)        -> high   "Burst file read"
 *  - clipboard.rapid_changes  data.count   >= threshold (default 30)         -> medium
 *  - proc.new                 data.suspicious=true                           -> medium
 *  - event.severity=critical passthrough                                     -> critical
 */

const COMMON_PORTS = new Set([80, 443]);

/**
 * @param {{type:string, severity:string, data:object}} evt normalized event
 * @param {{fs_read_burst_mb:number, clipboard_rapid_changes:number}} thresholds
 * @returns {{rule:string, title:string, severity:string}|null}
 */
function evaluateEvent(evt, thresholds) {
  const data = evt.data || {};
  let match = null;

  switch (evt.type) {
    case 'net.outbound_new_remote': {
      const port = Number(data.port);
      if (data.public === true && Number.isFinite(port) && !COMMON_PORTS.has(port)) {
        match = {
          rule: 'net.outbound_new_remote',
          title: 'Uncommon outbound connection',
          severity: 'medium',
        };
      }
      break;
    }
    case 'fs.read_burst': {
      const readMb = Number(data.read_mb);
      if (Number.isFinite(readMb) && readMb >= thresholds.fs_read_burst_mb) {
        match = {
          rule: 'fs.read_burst',
          title: 'Burst file read',
          severity: 'high',
        };
      }
      break;
    }
    case 'clipboard.rapid_changes': {
      const count = Number(data.count);
      if (Number.isFinite(count) && count >= thresholds.clipboard_rapid_changes) {
        match = {
          rule: 'clipboard.rapid_changes',
          title: 'Rapid clipboard changes',
          severity: 'medium',
        };
      }
      break;
    }
    case 'proc.new': {
      if (data.suspicious === true) {
        match = {
          rule: 'proc.new',
          title: 'Suspicious process started',
          severity: 'medium',
        };
      }
      break;
    }
    default:
      break;
  }

  // Critical severity passthrough: always alert, always critical.
  if (evt.severity === 'critical') {
    if (match) {
      match.severity = 'critical';
    } else {
      match = {
        rule: 'severity.passthrough',
        title: `Critical event: ${evt.type}`,
        severity: 'critical',
      };
    }
  }

  return match;
}

module.exports = { evaluateEvent };
