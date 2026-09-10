"use client";

import dynamic from "next/dynamic";
import Link from "next/link";
import { useMemo } from "react";
import { requestHistogram, signalMeta } from "@/app/ui/format";
import { Loading, Metric } from "@/app/ui/parts";
import { useLive } from "@/app/ui/store";

const TrafficMap = dynamic(() => import("@/app/traffic-map"), {
  ssr: false,
  loading: () => (
    <div className="map-canvas map-loading">
      <Loading label="Loading map…" />
    </div>
  ),
});

export default function OverviewPage() {
  const { overview, stats, events, sources, attackers, policies, campaigns, busy, instruct } =
    useLive();

  const histogram = useMemo(() => requestHistogram(events), [events]);
  const histMax = Math.max(1, ...histogram);
  const alertRate = stats.requests
    ? ((stats.alerts / stats.requests) * 100).toFixed(1)
    : "0.0";
  const active = campaigns.filter((c) => c.status === "active").length;

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

  // The theme the map needs, read from the document the shell already set.
  const theme =
    typeof document !== "undefined"
      ? document.documentElement.getAttribute("data-theme") || "dark"
      : "dark";

  return (
    <>
      <section className="metrics">
        <Metric
          label="Requests"
          value={stats.requests}
          detail={stats.derived ? "visible window" : "since gateway start"}
          bars={histogram}
          max={histMax}
          href="/events"
        />
        <Metric
          label="Alerts"
          value={stats.alerts}
          detail={`${alertRate}% of requests`}
          href="/events?alerts=1"
        />
        <Metric
          label="Under policy"
          value={policies.length}
          detail={`${active} active ${active === 1 ? "campaign" : "campaigns"}`}
          href="/policy"
        />
        <Metric
          label="Unique IPs"
          value={sources.length}
          detail={`${sources.filter((s) => s.private).length} private`}
          href="/events"
        />
      </section>

      {/* The map is the one hero on this page now -- full width, on its own
          row, rather than sharing a row with a side column. Signals and Top
          IPs move below it as an equal-weight secondary row instead. */}
      <article className="card map-card panel-primary">
        <div className="card-head">
          <h2>Request origin map</h2>
          <span>
            Public IPs plot at true geo. Docker traffic is pinned to this gateway’s site.
          </span>
        </div>
        <TrafficMap sources={sources} site={overview.site} theme={theme} />
      </article>

      <section className="overview-secondary">
        <article className="card">
          <div className="card-head">
            <h2>Signals</h2>
            <Link href="/events?alerts=1">see events</Link>
          </div>
          {signalRows.length === 0 ? (
            <p className="empty">No hits in the current window.</p>
          ) : (
            <ul className="signal-list">
              {signalRows.map((row) => (
                <li key={row.name}>
                  <span className="swatch" style={{ background: row.color }} />
                  <Link href={`/events?q=${encodeURIComponent(row.label)}`} className="grow">
                    {row.label}
                  </Link>
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
            <Link href="/policy">manage</Link>
          </div>
          {attackers.length === 0 ? (
            <p className="empty">No alerting IPs yet.</p>
          ) : (
            <ol className="ip-list">
              {attackers.map((row) => (
                <li key={row.ip}>
                  <Link href={`/events?q=${encodeURIComponent(row.ip)}`} className="mono grow">
                    {row.ip}
                  </Link>
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
      </section>
    </>
  );
}
