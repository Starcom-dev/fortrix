'use strict';

const { execFile } = require('child_process');
const { getOrgSetting } = require('./db');

/**
 * Send notification email for an alert.
 * Uses sendmail (Postfix) on localhost.
 *
 * @param {object} options
 * @param {number} options.orgId
 * @param {object} options.alert - { id, rule, title, severity }
 * @param {object} options.device - { id, hostname }
 * @param {object} options.event - { type, data }
 * @param {string} options.baseUrl - public URL for links
 */
function sendAlertEmail(options) {
  const { orgId, alert, device, event } = options;

  // Check if org has email notifications enabled.
  const to = getOrgSetting(orgId, 'notify_email', '').trim();
  if (!to) return;

  // Minimum severity filter.
  const minSev = getOrgSetting(orgId, 'notify_min_severity', 'high').trim();
  const severityRank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  if ((severityRank[alert.severity] || 0) < (severityRank[minSev] || 0)) return;

  const subject = `[Fortrix] ${alert.severity.toUpperCase()} Alert: ${alert.title} on ${device.hostname}`;

  const body = [
    `Fortrix Alert Notification`,
    `===========================`,
    ``,
    `Severity:  ${alert.severity.toUpperCase()}`,
    `Alert:     ${alert.title}`,
    `Rule:      ${alert.rule}`,
    `Device:    ${device.hostname} (ID: ${device.id})`,
    `Event:     ${event.type}`,
    ``,
    `Details:   ${formatEventData(event)}`,
    ``,
    `View:      https://fortrix.xyz/app/alerts`,
    ``,
    `---`,
    `Fortrix Endpoint Protection`,
    `This is an automated alert. Replies to this email are not monitored.`,
  ].join('\n');

  // Deliver via Postfix sendmail.
  const child = execFile('/usr/sbin/sendmail', ['-f', 'noreply@fortrix.site', to], {
    timeout: 15_000,
    windowsHide: true,
  }, (err) => {
    if (err) {
      console.error(`[fortrix] alert email failed (alert #${alert.id}):`, err.message);
    }
  });

  child.stdin.write(
    `From: Fortrix <noreply@fortrix.site>\r\n` +
    `To: ${to}\r\n` +
    `Subject: ${subject}\r\n` +
    `Content-Type: text/plain; charset=UTF-8\r\n` +
    `\r\n` +
    body
  );
  child.stdin.end();
}

/**
 * Send a generic notification email (no alert context).
 * Used for welcome emails, password resets, etc.
 */
function sendNotificationEmail(options) {
  const { to, subject, body } = options;
  if (!to) return;

  const child = execFile('/usr/sbin/sendmail', ['-f', 'noreply@fortrix.site', to], {
    timeout: 15_000,
    windowsHide: true,
  }, (err) => {
    if (err) {
      console.error(`[fortrix] notification email failed:`, err.message);
    }
  });

  child.stdin.write(
    `From: Fortrix <noreply@fortrix.site>\r\n` +
    `To: ${to}\r\n` +
    `Subject: ${subject}\r\n` +
    `Content-Type: text/plain; charset=UTF-8\r\n` +
    `\r\n` +
    body
  );
  child.stdin.end();
}

function formatEventData(event) {
  if (!event || !event.data) return '(no details)';
  try {
    const data = typeof event.data === 'string' ? JSON.parse(event.data) : event.data;
    const lines = [];
    for (const [k, v] of Object.entries(data)) {
      if (k === 'agent_ts') continue;
      lines.push(`  ${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`);
    }
    return lines.length ? lines.join('\n') : '(empty)';
  } catch {
    return String(event.data);
  }
}

module.exports = { sendAlertEmail, sendNotificationEmail };
