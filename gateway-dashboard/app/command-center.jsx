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
  const [alertsOnly, setAlertsOnly] = useState(false);
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
        const res = await fetch("/api/overview", { cache: "no-store" });
        const json = await res.json();
        if (!cancelled) {
          setData(json);
          setUpdatedAt(new Date());
        }
      } catch {
        if (!cancelled) setData((prev) => ({ ...prev, redis: false }));
      }
    }
    load();
    const id = setInterval(load, 2500);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  const stats = data.stats || { requests: 0, alerts: 0, decisions: {}, signals: {} };
  const events = data.events || [];
  const sources = data.sources || [];
  const visibleEvents = alertsOnly ? events.filter((event) => event.fired?.length) : events;
  const allow = stats.decisions.allow || 0;
  const alertRate = stats.requests ? ((stats.alerts / stats.requests) * 100).toFixed(1) : "0.0";
  const uniqueIps = sources.length;
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
          Detect-only
          <span className="sep" />
          {updatedAt ? `Refreshed ${updatedAt.toLocaleTimeString([], { hour12: false })}` : "Connecting"}
        </div>
        <button type="button" className="theme-btn" onClick={toggleTheme}>
          {theme === "dark" ? "Light theme" : "Dark theme"}
        </button>
      </header>

      <section className="metrics">
        <Metric label="Requests" value={stats.requests} detail="Redis hot window" bars={histogram} max={histMax} />
        <Metric label="Alerts" value={stats.alerts} detail={`${alertRate}% of requests`} />
        <Metric label="Allowed" value={allow} detail="No enforce yet" />
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
                    <code>{row.ip}</code>
                    <span>{row.alerts}</span>
                  </li>
                ))}
              </ol>
            )}
          </article>
        </div>
      </section>

      <article className="card table-card">
        <div className="card-head">
          <h2>Event stream</h2>
          <label>
            <input
              type="checkbox"
              checked={alertsOnly}
              onChange={(e) => setAlertsOnly(e.target.checked)}
            />
            Alerts only
          </label>
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
                    No events. Send traffic through the gateway on port 8082.
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
