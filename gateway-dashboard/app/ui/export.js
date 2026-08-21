"use client";

/**
 * Download whatever is on screen.
 *
 * Exports the *filtered* rows rather than everything held, because the useful
 * artefact is the view an operator built while investigating -- the filter is
 * the finding.
 */

/** RFC 4180: quote anything containing a comma, quote or newline; double the quotes. */
function cell(value) {
  if (value === null || value === undefined) return "";
  const text = Array.isArray(value) ? value.join(" ") : String(value);
  return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export function toCsv(rows, columns) {
  const head = columns.map((c) => cell(c.label)).join(",");
  const body = rows.map((row) => columns.map((c) => cell(c.value(row))).join(","));
  return [head, ...body].join("\r\n");
}

function download(filename, text, mime) {
  const url = URL.createObjectURL(new Blob([text], { type: `${mime};charset=utf-8` }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  // Revoking immediately can cancel the download in some browsers.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** A name that says what it holds and when it was taken. */
export function stamp(prefix, ext) {
  const now = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  const date = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}`;
  const time = `${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
  return `iasg-${prefix}-${date}-${time}.${ext}`;
}

export function exportCsv(prefix, rows, columns) {
  download(stamp(prefix, "csv"), toCsv(rows, columns), "text/csv");
}

export function exportJson(prefix, rows) {
  download(stamp(prefix, "json"), JSON.stringify(rows, null, 2), "application/json");
}

/** The columns each exportable view uses. */
export const EVENT_COLUMNS = [
  { label: "time", value: (e) => e.ts },
  { label: "ip", value: (e) => e.ip },
  { label: "method", value: (e) => e.method },
  { label: "path", value: (e) => e.path },
  { label: "query", value: (e) => e.query },
  { label: "status", value: (e) => e.status },
  { label: "decision", value: (e) => e.decision },
  { label: "risk", value: (e) => e.riskScore },
  { label: "signals", value: (e) => (e.fired || []).join(" ") },
  { label: "userAgent", value: (e) => e.userAgent },
  { label: "backendMs", value: (e) => e.backendMs },
  { label: "requestId", value: (e) => e.requestId },
];

export const CAMPAIGN_COLUMNS = [
  { label: "id", value: (c) => c.id },
  { label: "type", value: (c) => c.type },
  { label: "severity", value: (c) => c.severity },
  { label: "status", value: (c) => c.status },
  { label: "confidence", value: (c) => c.confidence },
  { label: "events", value: (c) => c.events },
  { label: "ips", value: (c) => (c.ips || []).join(" ") },
  { label: "stages", value: (c) => (c.stages || []).join(" > ") },
  { label: "lastAction", value: (c) => c.lastAction },
  { label: "outcome", value: (c) => c.outcome },
  { label: "reason", value: (c) => c.reason },
  { label: "firstSeen", value: (c) => c.firstSeen },
  { label: "lastSeen", value: (c) => c.lastSeen },
];

export const POLICY_COLUMNS = [
  { label: "ip", value: (p) => p.ip },
  { label: "action", value: (p) => p.action },
  { label: "expiresIn", value: (p) => p.expiresIn },
  { label: "campaignId", value: (p) => p.campaignId },
  { label: "confidence", value: (p) => p.confidence },
  { label: "source", value: (p) => p.source },
  { label: "issuedAt", value: (p) => p.issuedAt },
  { label: "reason", value: (p) => p.reason },
];
