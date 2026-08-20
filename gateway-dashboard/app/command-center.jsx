"use client";

import dynamic from "next/dynamic";
import { useEffect, useMemo, useState } from "react";

const TrafficMap = dynamic(() => import("./traffic-map"), {
  ssr: false,
  loading: () => <div className="map-canvas map-loading">Loading map…</div>,
});

const SIGNAL_META = {
  api_flooding: { label: "Flood", color: "#c9842a" },
  sql_injection: { label: "SQLi", color: "#c43c51" },
  brute_force: { label: "Brute force", color: "#7c5cbf" },
  password_spraying: { label: "Spray", color: "#9a6bb8" },
  enumeration_path_traversal: { label: "Enum/trav", color: "#2a8f7c" },
  path_traversal: { label: "Traversal", color: "#2f7d9a" },
  enumeration: { label: "Enum", color: "#3d8a55" },
};

function signalMeta(name) {
  return SIGNAL_META[name] || { label: name, color: "#6b7785" };
}

function riskTone(score) {
  if (score >= 70) return "high";
  if (score >= 30) return "mid";
  return "low";
}

// The policy ladder, weakest to strongest. Colour tracks the rung so an
// escalation is visible without reading the label.
const ACTION_TONE = {
  monitor: "low",
  throttle: "mid",
  temp_block: "high",
  escalate: "high",
};

function actionLabel(action) {
  return action ? action.replace(/_/g, " ") : "no action";
}

function formatTtl(seconds) {
  if (seconds == null || seconds < 0) return "no expiry";
  if (seconds < 60) return `${seconds}s left`;
  return `${Math.round(seconds / 60)}m left`;
}

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleTimeString([], { hour12: false });
}

function requestHistogram(events) {
  const buckets = Array.from({ length: 16 }, () => 0);
  if (!events.length) return buckets;
  const newest = new Date(events[0].ts).getTime();
  if (Number.isNaN(newest)) return buckets;
  const span = 16 * 60 * 1000;
  for (const event of events) {
    const t = new Date(event.ts).getTime();
    if (Number.isNaN(t)) continue;
    const idx = Math.min(15, Math.max(0, Math.floor(((newest - t) / span) * 16)));
    buckets[15 - idx] += 1;
  }
  return buckets;
}

export default function CommandCenter() {
  const [data, setData] = useState({
    redis: false,
    stats: { requests: 0, alerts: 0, decisions: {}, signals: {} },
    attackers: [],
    events: [],
    sources: [],
    site: null,
  });
  // What the control plane concluded, as opposed to what the gateway saw.
  const [plane, setPlane] = useState({
    redis: false,
    campaigns: [],
    policies: [],
    alerts: [],
    learned: [],
    heartbeat: { alive: false },
    active: 0,
  });
  // The record rather than the working set, so it needs its own slower poll.
  const [history, setHistory] = useState({
    available: false,
    campaigns: [],
    byType: [],
    total: 0,
  });
  const [alertsOnly, setAlertsOnly] = useState(false);
  const [query, setQuery] = useState("");
  const [paused, setPaused] = useState(false);
  const [busy, setBusy] = useState("");
  const [toast, setToast] = useState(null);
  const [updatedAt, setUpdatedAt] = useState(null);
  const [theme, setTheme] = useState("dark");

  useEffect(() => {
    const stored = localStorage.getItem("iasg-theme");
    const next = stored === "light" || stored === "dark" ? stored : "dark";
    setTheme(next);
    document.documentElement.setAttribute("data-theme", next);
  }, []);

  function toggleTheme() {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    localStorage.setItem("iasg-theme", next);
    document.documentElement.setAttribute("data-theme", next);
  }

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        // Two independent reads: the gateway's telemetry and the agent's
        // conclusions. Either can be empty without the other being wrong.
        const [overview, control] = await Promise.all([
          fetch("/api/overview", { cache: "no-store" }).then((r) => r.json()),
          fetch("/api/campaigns", { cache: "no-store" }).then((r) => r.json()),
        ]);
        if (!cancelled) {
          setData(overview);
          setPlane(control);
          setUpdatedAt(new Date());
        }
      } catch {
        if (!cancelled) setData((prev) => ({ ...prev, redis: false }));
      }
    }
    load();
    // Paused still loads once, so un-pausing is not the only way to refresh.
    const id = paused ? null : setInterval(load, 2500);
    return () => {
      cancelled = true;
      if (id) clearInterval(id);
    };
  }, [paused]);

  // History is the durable record, not the live view. Thirty seconds is
  // generous for something that only changes when a campaign does.
  useEffect(() => {
    let cancelled = false;
    async function loadHistory() {
      try {
        const res = await fetch("/api/history", { cache: "no-store" });
        const json = await res.json();
        if (!cancelled) setHistory(json);
      } catch {
        /* the panel says it is unavailable on its own */
      }
    }
    loadHistory();
    const id = setInterval(loadHistory, 30_000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  async function instruct(ips, action, label) {
    const targets = [...new Set(ips)].filter(Boolean);
    if (!targets.length) return;

    setBusy(`${label}:${action}`);
    try {
      const results = await Promise.all(
        targets.map((ip) =>
          fetch("/api/overrides", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              ip,
              action,
              actor: "dashboard",
              reason: `${actionLabel(action)} set from the console`,
            }),
          }).then((r) => r.json()),
        ),
      );

      const failed = results.filter((r) => !r.ok);
      setToast(
        failed.length
          ? {
              tone: "bad",
              text: `${failed.length} of ${targets.length} rejected: ${failed[0].error}`,
            }
          : {
              tone: "good",
              // Deliberately not "blocked": the agent applies this on its next
              // cycle, after the same safety checks its own decisions face.
              text: `${actionLabel(action)} queued for ${targets.length} ${
                targets.length === 1 ? "address" : "addresses"
              } — applies next cycle`,
            },
      );
    } catch (err) {
      setToast({ tone: "bad", text: `could not reach the gateway: ${err.message}` });
    } finally {
      setBusy("");
    }
  }

  useEffect(() => {
    if (!toast) return;
    const id = setTimeout(() => setToast(null), 6000);
    return () => clearTimeout(id);
  }, [toast]);

  const stats = data.stats || { requests: 0, alerts: 0, decisions: {}, signals: {} };
  const events = data.events || [];
  const sources = data.sources || [];
  const campaigns = plane.campaigns || [];
  const policies = plane.policies || [];
  const escalations = plane.alerts || [];
  const learned = plane.learned || [];
  const beat = plane.heartbeat || { alive: false };
  const alertRate = stats.requests ? ((stats.alerts / stats.requests) * 100).toFixed(1) : "0.0";
  const uniqueIps = sources.length;

  const needle = query.trim().toLowerCase();
  const visibleEvents = events.filter((event) => {
    if (alertsOnly && !event.fired?.length) return false;
    if (!needle) return true;
    return (
      event.ip?.toLowerCase().includes(needle) ||
      event.path?.toLowerCase().includes(needle) ||
      event.userAgent?.toLowerCase().includes(needle) ||
      (event.fired || []).some((f) => signalMeta(f).label.toLowerCase().includes(needle))
    );
  });
  const histogram = useMemo(() => requestHistogram(events), [events]);
  const histMax = Math.max(1, ...histogram);

  const signalRows = useMemo(() => {
    const entries = Object.entries(stats.signals || {});
    const total = entries.reduce((sum, [, count]) => sum + count, 0) || 1;
    return entries
      .sort((a, b) => b[1] - a[1])
      .map(([name, count]) => ({
        name,
        count,
        pct: Math.round((count / total) * 100),
        ...signalMeta(name),
      }));
  }, [stats.signals]);

  return (
    <div className="app">
      <header className="top">
        <div className="brand">
          <span className="logo">IASG</span>
          <div>
            <strong>Operations</strong>
            <small>Intelligent API Security Gateway</small>
          </div>
        </div>
        <div className="top-meta">
          <span className={`dot ${data.redis ? "on" : "off"}`} />
          {data.redis ? "Redis connected" : "Redis unavailable"}
          <span className="sep" />
          {/* Liveness, not activity. A quiet network and a dead agent look
              identical without this, and they mean opposite things. */}
          <span className={`dot ${beat.alive ? (beat.late ? "late" : "on") : "off"}`} />
          {beat.alive
            ? beat.late
              ? `Agent late — ${beat.secondsAgo}s since last cycle`
              : `Agent live — cycled ${beat.secondsAgo}s ago`
            : "Agent not running"}
          {beat.alive && beat.dryRun ? " (dry run)" : ""}
          <span className="sep" />
          {policies.length > 0
            ? `${policies.length} policy ${policies.length === 1 ? "key" : "keys"} in force`
            : "Detect-only"}
          <span className="sep" />
          {updatedAt ? `Refreshed ${updatedAt.toLocaleTimeString([], { hour12: false })}` : "Connecting"}
        </div>
        <button
          type="button"
          className={paused ? "theme-btn on" : "theme-btn"}
          onClick={() => setPaused((p) => !p)}
          title="Stop the 2.5s refresh while you read"
        >
          {paused ? "Resume" : "Pause"}
        </button>
        <button type="button" className="theme-btn" onClick={toggleTheme}>
          {theme === "dark" ? "Light theme" : "Dark theme"}
        </button>
      </header>

      {toast ? (
        <div className={`toast ${toast.tone}`} role="status">
          {toast.text}
          <button type="button" onClick={() => setToast(null)} aria-label="Dismiss">
            ×
          </button>
        </div>
      ) : null}

      <section className="metrics">
        <Metric
          label="Requests"
          value={stats.requests}
          detail={stats.derived ? "visible window" : "since gateway start"}
          bars={histogram}
          max={histMax}
        />
        <Metric label="Alerts" value={stats.alerts} detail={`${alertRate}% of requests`} />
        <Metric
          label="Under policy"
          value={policies.length}
          detail={`${campaigns.filter((c) => c.status === "active").length} active ${
            campaigns.filter((c) => c.status === "active").length === 1
              ? "campaign"
              : "campaigns"
          }`}
        />
        <Metric label="Unique IPs" value={uniqueIps} detail={`${sources.filter((s) => s.private).length} private`} />
      </section>

      <section className="workbench">
        <article className="card map-card">
          <div className="card-head">
            <h2>Request origin map</h2>
            <span>Public IPs plot at true geo. Docker traffic is pinned to this gateway’s site.</span>
          </div>
          <TrafficMap sources={sources} site={data.site} theme={theme} />
        </article>

        <div className="side">
          <article className="card">
            <div className="card-head">
              <h2>Signals</h2>
            </div>
            {signalRows.length === 0 ? (
              <p className="empty">No hits in the current window.</p>
            ) : (
              <ul className="signal-list">
                {signalRows.map((row) => (
                  <li key={row.name}>
                    <span className="swatch" style={{ background: row.color }} />
                    <span className="grow">{row.label}</span>
                    <b>{row.count}</b>
                    <span className="pct">{row.pct}%</span>
                  </li>
                ))}
              </ul>
            )}
          </article>

          <article className="card">
            <div className="card-head">
              <h2>Top IPs</h2>
            </div>
            {(data.attackers || []).length === 0 ? (
              <p className="empty">No alerting IPs yet.</p>
            ) : (
              <ol className="ip-list">
                {data.attackers.map((row) => (
                  <li key={row.ip}>
                    <code className="grow">{row.ip}</code>
                    <span>{row.alerts}</span>
                    {/* An address the agent never grouped into a campaign is
                        the plainest reason to reach for an override. */}
                    <button
                      type="button"
                      className="act small"
                      disabled={Boolean(busy)}
                      onClick={() => instruct([row.ip], "temp_block", `ip-${row.ip}`)}
                      title={`Instruct temp block for ${row.ip}`}
                    >
                      {busy === `ip-${row.ip}:temp_block` ? "…" : "block"}
                    </button>
                  </li>
                ))}
              </ol>
            )}
          </article>
        </div>
      </section>

      <section className="workbench plane">
        <article className="card">
          <div className="card-head">
            <h2>Campaigns</h2>
            <span>
              What the control plane correlated out of the events above. Rebuilt every 30s.
            </span>
          </div>
          {campaigns.length === 0 ? (
            <p className="empty">
              No campaigns yet. Run the control plane, or seed evidence with{" "}
              <code>python -m tools.seed_evidence --scenario credential-stuffing</code>.
            </p>
          ) : (
            <ul className="campaign-list">
              {campaigns.map((c) => (
                <CampaignCard
                  key={c.id}
                  campaign={c}
                  onInstruct={instruct}
                  busy={busy}
                />
              ))}
            </ul>
          )}
        </article>

        <div className="side">
          <article className="card">
            <div className="card-head">
              <h2>Policy in force</h2>
              <span>Live TTL from Redis</span>
            </div>
            {policies.length === 0 ? (
              <p className="empty">No policy keys written.</p>
            ) : (
              <ul className="policy-list">
                {policies.map((p) => (
                  <li key={p.ip}>
                    <div className="policy-top">
                      <code>{p.ip}</code>
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
            )}
          </article>

          {escalations.length > 0 ? (
            <article className="card">
              <div className="card-head">
                <h2>Escalated</h2>
                <span>Raised once per campaign</span>
              </div>
              <ul className="policy-list">
                {escalations.map((a) => (
                  <li key={a.id}>
                    <div className="policy-top">
                      <code>#{a.campaignId}</code>
                      <span className="risk high">{a.ipCount} IPs</span>
                    </div>
                    <small>
                      {a.type} · confidence {a.confidence.toFixed(2)}
                    </small>
                  </li>
                ))}
              </ul>
            </article>
          ) : null}

          {learned.length > 0 ? (
            <article className="card">
              <div className="card-head">
                <h2>Learned from humans</h2>
                <span>Shifts the recommendation one rung, never more</span>
              </div>
              <ul className="policy-list">
                {learned.map((row) => (
                  <li key={row.type}>
                    <div className="policy-top">
                      <span className="grow">{row.type}</span>
                      <span className={`risk ${row.net > 0 ? "high" : "low"}`}>
                        {row.net > 0 ? "stronger" : "weaker"}
                      </span>
                    </div>
                    <small>
                      +{row.up} / -{row.down} corrections
                    </small>
                  </li>
                ))}
              </ul>
            </article>
          ) : null}
        </div>
      </section>

      <article className="card table-card">
        <div className="card-head">
          <h2>Campaign history</h2>
          <span>
            {history.available
              ? `${history.total} recorded in Postgres — survives a restart`
              : "Durable store not configured"}
          </span>
        </div>
        <HistoryPanel history={history} />
      </article>

      <article className="card table-card">
        <div className="card-head">
          <h2>Event stream</h2>
          <div className="head-controls">
            <input
              type="search"
              className="search"
              placeholder="Filter by IP, path, agent…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <label>
              <input
                type="checkbox"
                checked={alertsOnly}
                onChange={(e) => setAlertsOnly(e.target.checked)}
              />
              Alerts only
            </label>
            <span className="count">
              {visibleEvents.length}/{events.length}
            </span>
          </div>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Source</th>
                <th>Endpoint</th>
                <th>Status</th>
                <th>Risk</th>
                <th>Signals</th>
              </tr>
            </thead>
            <tbody>
              {visibleEvents.length === 0 ? (
                <tr>
                  <td colSpan={6} className="empty">
                    {events.length
                      ? "No events match this filter."
                      : "No events. Send traffic through the gateway on port 8082."}
                  </td>
                </tr>
              ) : (
                visibleEvents.map((event) => (
                  <tr key={event.id || event.requestId} className={event.fired?.length ? "alert-row" : ""}>
                    <td className="mono">{formatTime(event.ts)}</td>
                    <td className="mono">{event.ip}</td>
                    <td>
                      <span className="method">{event.method}</span> {event.path}
                    </td>
                    <td className="mono">{event.status}</td>
                    <td>
                      <span className={`risk ${riskTone(event.riskScore || 0)}`}>{event.riskScore || 0}</span>
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
      </article>
    </div>
  );
}

const LADDER = ["monitor", "throttle", "temp_block", "escalate"];

function CampaignCard({ campaign, onInstruct, busy }) {
  const c = campaign;
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
      </div>

      <p className="campaign-reason">{c.reason}</p>

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

      <div className="campaign-ips">
        {c.ips.slice(0, 8).map((ip) => (
          <code key={ip}>{ip}</code>
        ))}
        {c.ips.length > 8 ? <small>+{c.ips.length - 8} more</small> : null}
      </div>

      {onInstruct ? (
        <div className="campaign-actions">
          <span>Overrule the agent</span>
          {LADDER.map((action) => (
            <button
              key={action}
              type="button"
              disabled={Boolean(busy) || action === c.lastAction}
              className={action === c.lastAction ? "act current" : "act"}
              onClick={() => onInstruct(c.ips, action, `campaign-${c.id}`)}
              title={
                action === c.lastAction
                  ? `The agent already chose ${actionLabel(action)}`
                  : `Instruct ${actionLabel(action)} for all ${c.ips.length} addresses`
              }
            >
              {busy === `campaign-${c.id}:${action}` ? "…" : actionLabel(action)}
            </button>
          ))}
        </div>
      ) : null}
    </li>
  );
}

function HistoryPanel({ history }) {
  if (!history.available) {
    return (
      <p className="empty">
        No durable store configured. Set <code>IASG_POSTGRES_URL</code> to keep campaigns
        past a restart.
      </p>
    );
  }

  if (!history.campaigns.length) {
    return <p className="empty">Nothing recorded yet.</p>;
  }

  return (
    <>
      <ul className="bytype-list">
        {history.byType.map((row) => (
          <li key={row.type}>
            <span className="grow">{row.type}</span>
            <b>{row.campaigns}</b>
            <span className="pct">
              {row.events} events · avg {row.avgConfidence.toFixed(2)}
              {row.contained ? ` · ${row.contained} contained` : ""}
            </span>
          </li>
        ))}
      </ul>
      <div className="table-wrap history-wrap">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Type</th>
              <th>IPs</th>
              <th>Events</th>
              <th>Ended as</th>
              <th>Status</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {history.campaigns.map((c) => (
              <tr key={c.id}>
                <td className="mono">{c.id}</td>
                <td>{c.type}</td>
                <td className="mono">{c.ipCount}</td>
                <td className="mono">{c.events}</td>
                <td>
                  <span className={`risk ${ACTION_TONE[c.lastAction] || "low"}`}>
                    {actionLabel(c.lastAction)}
                  </span>
                </td>
                <td>
                  <span className={c.status === "contained" ? "tag good" : "tag"}>
                    {c.status}
                  </span>
                </td>
                <td className="mono">{formatTime(c.lastSeen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

function Metric({ label, value, detail, bars, max }) {
  return (
    <article className="metric">
      <p>{label}</p>
      <strong>{Number(value || 0).toLocaleString()}</strong>
      {bars ? (
        <div className="spark" aria-hidden="true">
          {bars.map((n, i) => (
            <span key={i} style={{ height: `${Math.max(8, (n / max) * 100)}%` }} />
          ))}
        </div>
      ) : (
        <small>{detail}</small>
      )}
      {bars ? <small>{detail}</small> : null}
    </article>
  );
}
