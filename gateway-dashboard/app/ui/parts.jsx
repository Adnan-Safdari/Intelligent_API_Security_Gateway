"use client";

import Link from "next/link";
import { exportCsv, exportJson } from "./export";
import {
  ACTION_TONE,
  LADDER,
  actionLabel,
  formatTime,
  formatTtl,
  riskTone,
  signalMeta,
} from "./format";

export function Metric({ label, value, detail, bars, max, href }) {
  const body = (
    <>
      <p>{label}</p>
      <strong>{Number(value || 0).toLocaleString()}</strong>
      {bars ? (
        <div className="spark" aria-hidden="true">
          {bars.map((n, i) => (
            <span key={i} style={{ height: `${Math.max(8, (n / max) * 100)}%` }} />
          ))}
        </div>
      ) : null}
      <small>{detail}</small>
    </>
  );

  // A metric that has a page behind it should take you there.
  return href ? (
    <Link href={href} className="metric linked">
      {body}
    </Link>
  ) : (
    <article className="metric">{body}</article>
  );
}

export function ActionRow({ ips, current, busyKey, busy, onInstruct, label = "Overrule the agent" }) {
  return (
    <div className="campaign-actions">
      <span>{label}</span>
      {LADDER.map((action) => (
        <button
          key={action}
          type="button"
          disabled={Boolean(busy) || action === current}
          className={action === current ? "act current" : "act"}
          onClick={() => onInstruct(ips, action, busyKey)}
          title={
            action === current
              ? `The agent already chose ${actionLabel(action)}`
              : `Instruct ${actionLabel(action)} for ${ips.length} ${
                  ips.length === 1 ? "address" : "addresses"
                }`
          }
        >
          {busy === `${busyKey}:${action}` ? "…" : actionLabel(action)}
        </button>
      ))}
    </div>
  );
}

export function CampaignCard({ campaign: c, onInstruct, busy, compact }) {
  return (
    <li className={c.status === "contained" ? "campaign contained" : "campaign"}>
      <div className="campaign-head">
        <strong>
          #{c.id} {c.type}
        </strong>
        <span className={`risk ${ACTION_TONE[c.lastAction] || "low"}`}>
          {actionLabel(c.lastAction)}
        </span>
      </div>

      <div className="campaign-facts">
        <span>
          {c.ips.length} {c.ips.length === 1 ? "IP" : "IPs"}
        </span>
        <span>confidence {c.confidence.toFixed(2)}</span>
        <span>{c.severity}</span>
        <span>{c.events} events</span>
        <span className={c.status === "contained" ? "tag good" : "tag"}>{c.status}</span>
        {/* In the reader's own zone. The narration below carries UTC because
            it is stored and travels to places with no browser to localise it;
            without this line the only time on the card was that one, and an
            operator reads a bare clock as their own. */}
        {c.lastSeen ? (
          <span title={`First seen ${formatTime(c.firstSeen)}, last seen ${formatTime(c.lastSeen)} local time`}>
            {c.firstSeen && formatTime(c.firstSeen) !== formatTime(c.lastSeen)
              ? `${formatTime(c.firstSeen)}–${formatTime(c.lastSeen)}`
              : formatTime(c.lastSeen)}
          </span>
        ) : null}
      </div>

      <p className="campaign-reason">{c.reason}</p>

      {!compact ? (
        <>
          {c.stages.length > 1 ? (
            <p className="campaign-note">
              <b>Stages</b> {c.stages.join(" → ")} — {c.stages.length} phases of one
              intrusion, not {c.stages.length} separate attacks
            </p>
          ) : null}

          {c.rotations > 0 ? (
            <p className="campaign-note">
              <b>Continuity</b> re-identified by behaviour through {c.rotations} address{" "}
              {c.rotations === 1 ? "change" : "changes"}
            </p>
          ) : null}

          {c.persistence > 0 ? (
            <p className="campaign-note">
              <b>Adapted</b> survived {c.persistence} enforcement{" "}
              {c.persistence === 1 ? "round" : "rounds"} — answered with{" "}
              {actionLabel(c.lastAction)}
            </p>
          ) : null}

          {c.outcome ? (
            <p className="campaign-note">
              <b>Outcome</b> {c.outcome}
            </p>
          ) : null}

          {c.explanation ? <p className="campaign-explain">{c.explanation}</p> : null}

          {c.assessment ? (
            <p className="campaign-note assess">
              <b>Assessment</b> {c.assessment}
            </p>
          ) : null}
        </>
      ) : null}

      <div className="campaign-ips">
        {c.ips.slice(0, 8).map((ip) => (
          // Every address is a way into everything known about it.
          <Link key={ip} href={`/ip/${encodeURIComponent(ip)}`} className="ip-chip">
            {ip}
          </Link>
        ))}
        {c.ips.length > 8 ? <small>+{c.ips.length - 8} more</small> : null}
      </div>

      {onInstruct ? (
        <ActionRow
          ips={c.ips}
          current={c.lastAction}
          busyKey={`campaign-${c.id}`}
          busy={busy}
          onInstruct={onInstruct}
        />
      ) : null}
    </li>
  );
}

export function PolicyList({ policies }) {
  if (!policies.length) return <p className="empty">No policy keys written.</p>;

  return (
    <ul className="policy-list">
      {policies.map((p) => (
        <li key={p.ip}>
          <div className="policy-top">
            <IpLink ip={p.ip} />
            <span className={`risk ${ACTION_TONE[p.action] || "low"}`}>
              {actionLabel(p.action)}
            </span>
          </div>
          <small>
            {formatTtl(p.expiresIn)}
            {p.campaignId && p.campaignId !== "manual"
              ? ` · campaign #${p.campaignId}`
              : ""}
            {p.source === "human" ? " · set by a human" : ""}
          </small>
        </li>
      ))}
    </ul>
  );
}

export function EventTable({ events, empty, showSerialNumber = false }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {showSerialNumber ? <th>S. No.</th> : null}
            <th>Time</th>
            <th>Source</th>
            <th>Endpoint</th>
            <th>Status</th>
            <th>Risk</th>
            <th>Signals</th>
          </tr>
        </thead>
        <tbody>
          {events.length === 0 ? (
            <tr>
              <td colSpan={showSerialNumber ? 7 : 6} className="empty">
                {empty}
              </td>
            </tr>
          ) : (
            events.map((event, index) => (
              <tr
                key={event.id || event.requestId}
                className={event.fired?.length ? "alert-row" : ""}
              >
                {showSerialNumber ? <td className="mono">{index + 1}</td> : null}
                <td className="mono">{formatTime(event.ts)}</td>
                <td>
                  <IpLink ip={event.ip} />
                </td>
                <td>
                  <span className="method">{event.method}</span> {event.path}
                </td>
                <td className="mono">{event.status}</td>
                <td>
                  <span className={`risk ${riskTone(event.riskScore || 0)}`}>
                    {event.riskScore || 0}
                  </span>
                </td>
                <td>
                  {(event.fired || []).length === 0
                    ? "—"
                    : event.fired.map((name) => signalMeta(name).label).join(", ")}
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

/**
 * An address, linked to everything known about it.
 *
 * Used everywhere an IP appears, so the route into the investigation view is
 * the same wherever you notice the address.
 */
export function IpLink({ ip, className = "mono" }) {
  if (!ip) return <span className={className}>—</span>;
  return (
    <Link href={`/ip/${encodeURIComponent(ip)}`} className={className} title={`Everything known about ${ip}`}>
      {ip}
    </Link>
  );
}

/** Download the current view. Disabled when there is nothing in it. */
export function ExportMenu({ rows, columns, prefix, label = "export" }) {
  const count = rows?.length || 0;
  return (
    <span className="export-menu">
      <button
        type="button"
        className="act"
        disabled={!count}
        onClick={() => exportCsv(prefix, rows, columns)}
        title={count ? `Download these ${count} rows as CSV` : "Nothing to export"}
      >
        {label} csv
      </button>
      <button
        type="button"
        className="act"
        disabled={!count}
        onClick={() => exportJson(prefix, rows)}
        title={count ? `Download these ${count} rows as JSON` : "Nothing to export"}
      >
        json
      </button>
    </span>
  );
}
