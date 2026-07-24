'use strict';

/**
 * Fortrix rules engine — simple, deterministic, evaluated on ingest.
 *
 * Rules cover the 4-pillar security model:
 *   DETECT  → Real-time event analysis
 *   PROTECT → Auto-isolation triggers
 *   RESPOND → Commandable alerts
 *   RECOVER → Remediation-guide-mapped alerts
 */

const COMMON_PORTS = new Set([80, 443, 53, 8080, 8443]);
const KNOWN_BROWSERS = /(chrome|firefox|edge|safari|opera|brave)/i;
const SUSPICIOUS_TLDS = /(\.tk|\.ml|\.ga|\.cf|\.gq|\.xyz|\.top|\.wang|\.bid|\.trade|\.date|\.loan|\.win|\.download|\.racing|\.accountant|\.science|\.party|\.review|\.country)$/i;

/**
 * @param {{type:string, severity:string, data:object}} evt normalized event
 * @param {{fs_read_burst_mb:number, clipboard_rapid_changes:number, fs_write_burst_mb:number}} thresholds
 * @returns {{rule:string, title:string, severity:string}|null}
 */
function evaluateEvent(evt, thresholds) {
  const data = evt.data || {};
  let match = null;

  switch (evt.type) {
    // ── Network Detection ──────────────────────────────────────────
    case 'net.outbound_new_remote': {
      const port = Number(data.port);
      const ip = String(data.remote_ip || '');
      const proc = String(data.process || '').toLowerCase();

      // Known browser connecting on standard ports — ignore.
      if (COMMON_PORTS.has(port) && KNOWN_BROWSERS.test(proc)) break;

      // Non-standard port to public IP → medium.
      if (data.public === true && Number.isFinite(port) && !COMMON_PORTS.has(port)) {
        match = { rule: 'net.outbound_new_remote', title: 'Uncommon outbound connection', severity: 'medium' };
        // Ports commonly associated with RAT/backdoor → high.
        if ([4444, 1337, 31337, 6666, 6667, 6668, 6669, 9999, 12345, 54321, 65534].includes(port)) {
          match.title = 'Suspicious port connection (known C2 port)';
          match.severity = 'high';
        }
      }

      // Connection to suspicious TLD or known-bad IP pattern.
      if (match && SUSPICIOUS_TLDS.test(ip)) {
        match.title = 'Connection to high-risk domain';
        match.severity = 'high';
      }
      break;
    }

    case 'net.connection_burst': {
      const count = Number(data.count);
      const withinSec = Number(data.within_sec);
      if (Number.isFinite(count) && count >= 50) {
        match = { rule: 'net.connection_burst', title: `Burst of ${count} connections in ${withinSec || '?'}s`, severity: 'medium' };
        if (count >= 200) match.severity = 'high';
      }
      break;
    }

    case 'net.dns_suspicious': {
      const domain = String(data.domain || '');
      if (SUSPICIOUS_TLDS.test(domain)) {
        match = { rule: 'net.dns_suspicious', title: `Suspicious DNS query: ${domain.slice(0, 40)}`, severity: 'high' };
      }
      break;
    }

    // ── File System Detection ──────────────────────────────────────
    case 'fs.read_burst': {
      const readMb = Number(data.read_mb);
      if (Number.isFinite(readMb) && readMb >= (thresholds.fs_read_burst_mb || 500)) {
        match = { rule: 'fs.read_burst', title: 'Burst file read', severity: 'high' };
        if (readMb >= 2000) match.severity = 'critical';
      }
      break;
    }

    case 'fs.write_burst': {
      const writeMb = Number(data.write_mb);
      if (Number.isFinite(writeMb) && writeMb >= (thresholds.fs_write_burst_mb || 200)) {
        match = { rule: 'fs.write_burst', title: 'Burst file write', severity: 'medium' };
        if (writeMb >= 500) match.severity = 'high';
        if (writeMb >= 1000) match.severity = 'critical';
      }
      break;
    }

    case 'fs.delete_burst': {
      const count = Number(data.count);
      if (Number.isFinite(count) && count >= 20) {
        match = { rule: 'fs.delete_burst', title: `${count} files deleted rapidly`, severity: 'high' };
        if (count >= 100) match.severity = 'critical';
      }
      break;
    }

    case 'fs.ransomware_pattern': {
      // Extension changes + file renames in quick succession.
      const extChanged = Number(data.extensions_changed || data.count);
      if (Number.isFinite(extChanged) && extChanged >= 10) {
        match = { rule: 'fs.ransomware_pattern', title: `Possible ransomware: ${extChanged} file extensions changed`, severity: 'critical' };
      }
      break;
    }

    // ── Process Detection ──────────────────────────────────────────
    case 'proc.new': {
      if (data.suspicious === true) {
        match = { rule: 'proc.new', title: 'Suspicious process started', severity: 'medium' };
      }
      const exe = String(data.exe || '').toLowerCase();
      // Known-offensive tool names.
      if (/\b(mimikatz|procdump|psexec|powersploit|cobalt.?strike|meterpreter|nc\.exe|netcat|wget|curl)\b/i.test(exe)) {
        match = { rule: 'proc.known_tool', title: `Potentially malicious tool: ${data.name || exe}`, severity: 'critical' };
      }
      break;
    }

    case 'proc.unsigned': {
      if (data.exe && data.signed === false) {
        const path = String(data.exe).toLowerCase();
        if (path.includes('\\windows\\') || path.includes('\\system32\\')) {
          match = { rule: 'proc.unsigned', title: 'Unsigned process in system directory', severity: 'high' };
        }
      }
      break;
    }

    case 'proc.parent_suspicious': {
      const parent = String(data.parent || '').toLowerCase();
      if (/(mshta|wscript|cscript|powershell|cmd|rundll32|regsvr32)/i.test(parent)) {
        match = { rule: 'proc.parent_suspicious', title: `Process spawned by script host: ${parent}`, severity: 'high' };
      }
      break;
    }

    // ── Persistence Detection ──────────────────────────────────────
    case 'reg.run_key': {
      match = { rule: 'reg.run_key', title: 'Registry Run key modified', severity: 'high' };
      break;
    }

    case 'reg.startup_folder': {
      match = { rule: 'reg.startup_folder', title: 'Startup folder modified', severity: 'medium' };
      break;
    }

    case 'service.new': {
      const name = String(data.service_name || '');
      match = { rule: 'service.new', title: `New service installed: ${name.slice(0, 40)}`, severity: 'high' };
      break;
    }

    case 'wmi.process_create': {
      match = { rule: 'wmi.process_create', title: 'WMI process creation detected', severity: 'medium' };
      break;
    }

    case 'task.scheduled': {
      match = { rule: 'task.scheduled', title: 'New scheduled task created', severity: 'medium' };
      break;
    }

    // ── Credential / Privilege Detection ───────────────────────────
    case 'credential.access': {
      const target = String(data.target || '');
      match = { rule: 'credential.access', title: `Credential store access: ${target.slice(0, 40)}`, severity: 'high' };
      break;
    }

    case 'privilege.escalation': {
      match = { rule: 'privilege.escalation', title: 'Privilege escalation attempt detected', severity: 'critical' };
      break;
    }

    case 'injection.remote_thread': {
      match = { rule: 'injection.remote_thread', title: 'Remote thread injection detected', severity: 'critical' };
      break;
    }

    // ── User Activity Detection ────────────────────────────────────
    case 'clipboard.rapid_changes': {
      const count = Number(data.count);
      if (Number.isFinite(count) && count >= (thresholds.clipboard_rapid_changes || 30)) {
        match = { rule: 'clipboard.rapid_changes', title: 'Rapid clipboard changes', severity: 'medium' };
        if (count >= 100) match.severity = 'high';
      }
      break;
    }

    case 'screenshot.capture': {
      match = { rule: 'screenshot.capture', title: 'Screenshot capture detected', severity: 'medium' };
      break;
    }

    case 'keyboard.hook': {
      match = { rule: 'keyboard.hook', title: 'Keyboard hook detected', severity: 'high' };
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
