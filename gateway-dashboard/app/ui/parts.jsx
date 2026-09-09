"use client";

import Link from "next/link";
import { exportCsv, exportJson } from "./export";
import { EmptyIcon, SpinnerIcon } from "./icons";
import {
  ACTION_TONE,
  LADDER,
  actionLabel,
  clampRiskScore,
  formatTime,
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

export function CampaignCard({
  campaign: c,
  onInstruct,
  busy,
  compact,
  // Selection is optional: the IP page renders these bare in a list and
  // never passes them, so it looks exactly as it did before. Only the
  // Campaigns grid, where each card can be checked for a bulk action, sets
  // these -- which is also what puts the "selected" class in play, since
  // .campaign-grid > .campaign.selected is the only place that class means
  // anything visually.
  selectable,
  selected,
  onToggleSelect,
}) {
  const classes = [c.status === "contained" ? "campaign contained" : "campaign"];
  if (selected) classes.push("selected");

  return (
    <li className={classes.join(" ")}>
      {selectable ? (
        <label className="select-row">
          <input type="checkbox" checked={Boolean(selected)} onChange={onToggleSelect} />
          select for bulk action
        </label>
      ) : null}

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

/**
 * One control, not three. .segmented (Campaigns' status filter) and .seg
 * (Events' window/range) were the same idea built twice with slightly
 * different markup; a third call site toggled plain buttons by hand. Callers
 * normalize their own data into { value, label, count?, title? } rather than
 * this component guessing at shapes -- keeps this simple and keeps each
 * page's own data (a plain array of numbers, an array of {label, ms}
 * objects, whatever) from needing to change shape just to be displayed.
 */
export function SegmentedControl({ options, value, onChange }) {
  return (
    <span className="segmented">
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          className={option.value === value ? "on" : ""}
          onClick={() => onChange(option.value)}
          title={option.title}
        >
          {option.label}
          {option.count != null ? <em>{option.count}</em> : null}
        </button>
      ))}
    </span>
  );
}

/**
 * One labelled-field family, not two. Settings had Num/Text/Toggle/List;
 * Adaptive had its own local Field handling text/number/select/multiline by
 * itself -- same CSS classes (.field, .field-label), built by hand twice.
 * Field.Textarea (a raw string) and Field.List (a newline-separated array)
 * stay distinct rather than merged: they return different value shapes to
 * their caller, and collapsing them would force one side to convert.
 */
export function Field({ label, hint, children }) {
  return (
    <label className="field block">
      <span className="field-label">{label}</span>
      {children}
      {hint ? <small>{hint}</small> : null}
    </label>
  );
}

Field.Text = function FieldText({ label, value, onChange, hint }) {
  return (
    <Field label={label} hint={hint}>
      <input type="text" value={value ?? ""} onChange={(e) => onChange(e.target.value)} />
    </Field>
  );
};

Field.Number = function FieldNumber({ label, value, onChange, min, max, step, hint }) {
  return (
    <Field label={label} hint={hint}>
      <input
        type="number"
        value={value ?? ""}
        min={min}
        max={max}
        step={step}
        onChange={(e) => onChange(e.target.value === "" ? "" : Number(e.target.value))}
      />
    </Field>
  );
};

Field.Select = function FieldSelect({ label, value, onChange, options, optionLabel, hint }) {
  return (
    <Field label={label} hint={hint}>
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map((option) => (
          <option key={option} value={option}>
            {optionLabel ? optionLabel(option) : option}
          </option>
        ))}
      </select>
    </Field>
  );
};

// A raw string in a textarea -- Adaptive's prior "multiline" mode. Parsing it
// into ranges/patterns happens outside this component, same as before.
Field.Textarea = function FieldTextarea({ label, value, onChange, hint, rows = 3 }) {
  return (
    <Field label={label} hint={hint}>
      <textarea rows={rows} value={value ?? ""} onChange={(e) => onChange(e.target.value)} />
    </Field>
  );
};

// An array, one entry per line -- Settings' prior "List" mode: patterns and
// CIDRs pasted in from somewhere else, where a textarea takes the paste whole.
Field.List = function FieldList({ label, value, onChange, hint }) {
  return (
    <Field label={label} hint={hint}>
      <textarea
        rows={Math.min(Math.max(value.length + 1, 3), 10)}
        value={value.join("\n")}
        onChange={(e) =>
          onChange(
            e.target.value
              .split("\n")
              .map((line) => line.trim())
              .filter(Boolean),
          )
        }
      />
    </Field>
  );
};

Field.Toggle = function FieldToggle({ label, checked, onChange }) {
  return (
    <label className="check toggle">
      <input type="checkbox" checked={Boolean(checked)} onChange={(e) => onChange(e.target.checked)} />
      {label}
    </label>
  );
};

/**
 * Standardizes content, not just the container: every empty state before this
 * used the same .empty visual mechanism but wildly different content -- a
 * one-liner here, a runnable shell command there, an env-var explanation
 * somewhere else. A shell command sitting in an empty panel reads as an
 * unfinished dev tool in front of anyone this gets demoed to; that kind of
 * detail belongs in docs, not in the UI.
 */
export function EmptyState({ icon: Icon = EmptyIcon, title, hint }) {
  return (
    <div className="empty-state">
      <Icon size={22} aria-hidden="true" />
      <p>{title}</p>
      {hint ? <small>{hint}</small> : null}
    </div>
  );
}

/** One loading primitive, replacing five-plus inconsistently-capitalized ad
 * hoc strings ("Loading map…", "loading…", "Loading {ip}…", ...). */
export function Loading({ label = "Loading…" }) {
  return (
    <span className="loading">
      <SpinnerIcon size={14} className="spin" aria-hidden="true" />
      {label}
    </span>
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
                  <span className={`risk ${riskTone(clampRiskScore(event.riskScore))}`}>
                    {clampRiskScore(event.riskScore)}
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
