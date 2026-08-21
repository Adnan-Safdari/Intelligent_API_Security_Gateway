"use client";

import Link from "next/link";
import { use, useCallback, useEffect, useState } from "react";
import { PageHead } from "@/app/ui/chrome";
import { ACTION_TONE, actionLabel, formatTime, formatTtl, signalMeta } from "@/app/ui/format";
import { ActionRow, CampaignCard, EventTable, ExportMenu } from "@/app/ui/parts";
import { EVENT_COLUMNS } from "@/app/ui/export";
import { useLive } from "@/app/ui/store";

/**
 * Everything known about one address, in one place.
 *
 * Filtering the events table answers "what did it send". Deciding what to do
 * about it needs the rest: whether it is already under policy and for how much
 * longer, whether the agent grouped it with anything, and which signals it
 * keeps tripping.
 */
export default function IpPage({ params }) {
  const { address } = use(params);
  const ip = decodeURIComponent(address);
  const { busy, instruct, paused } = useLive();

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const res = await fetch(`/api/ip/${encodeURIComponent(ip)}`, { cache: "no-store" });
      setData(await res.json());
    } catch {
      /* the page reports its own emptiness */
    } finally {
      setLoading(false);
    }
  }, [ip]);

  useEffect(() => {
    load();
    const id = paused ? null : setInterval(load, 5000);
    return () => id && clearInterval(id);
  }, [load, paused]);

  if (loading && !data) {
    return (
      <article className="card">
        <p className="empty">Loading {ip}…</p>
      </article>
    );
  }

  const summary = data?.summary || {};
  const policy = data?.policy;
  const campaigns = data?.campaigns || [];
  const events = data?.events || [];

  return (
    <>
      <PageHead title={ip}>
        {data?.private
          ? "A private or container address — the control plane will never write policy for it."
          : `${data?.location?.city || "Unknown location"}${
              data?.location?.country ? `, ${data.location.country}` : ""
            }`}
      </PageHead>

      <section className="metrics">
        <article className="metric">
          <p>Requests</p>
          <strong>{(summary.requests || 0).toLocaleString()}</strong>
          <small>in the last {(summary.scanned || 0).toLocaleString()} events</small>
        </article>
        <article className="metric">
          <p>Alerts</p>
          <strong>{(summary.alerts || 0).toLocaleString()}</strong>
          <small>
            {summary.requests
              ? `${Math.round((summary.alerts / summary.requests) * 100)}% of its traffic`
              : "none"}
          </small>
        </article>
        <article className="metric">
          <p>Enforcement</p>
          <strong className={policy ? `risk ${ACTION_TONE[policy.action] || "low"}` : ""}>
            {policy ? actionLabel(policy.action) : "None"}
          </strong>
          <small>{policy ? formatTtl(policy.expiresIn) : "not under policy"}</small>
        </article>
        <article className="metric">
          <p>Campaigns</p>
          <strong>{campaigns.length}</strong>
          <small>{campaigns.length ? "grouped by the agent" : "never grouped"}</small>
        </article>
      </section>

      <section className="workbench">
        <div className="stack">
          {policy ? (
            <article className="card">
              <div className="card-head">
                <h2>Under policy</h2>
                <Link href="/policy">all policy</Link>
              </div>
              <p className="campaign-reason">{policy.reason || "No reason recorded."}</p>
              <div className="campaign-facts">
                <span className={`risk ${ACTION_TONE[policy.action] || "low"}`}>
                  {actionLabel(policy.action)}
                </span>
                <span>{formatTtl(policy.expiresIn)}</span>
                {policy.campaignId && policy.campaignId !== "manual" ? (
                  <span>campaign #{policy.campaignId}</span>
                ) : null}
                <span>{policy.source === "human" ? "set by a human" : "set by the agent"}</span>
                <span>confidence {policy.confidence.toFixed(2)}</span>
              </div>
            </article>
          ) : null}

          <article className="card">
            <div className="card-head">
              <h2>Activity</h2>
              <ExportMenu
                rows={events}
                columns={EVENT_COLUMNS}
                prefix={`ip-${ip.replace(/[^\w.-]/g, "_")}`}
              />
            </div>
            <EventTable
              events={events}
              empty={`Nothing from ${ip} in the events the gateway still holds.`}
            />
          </article>

          {campaigns.length ? (
            <article className="card">
              <div className="card-head">
                <h2>Part of {campaigns.length === 1 ? "a campaign" : "campaigns"}</h2>
                <Link href="/campaigns">all campaigns</Link>
              </div>
              <ul className="campaign-list">
                {campaigns.map((c) => (
                  <CampaignCard
                    key={c.id}
                    campaign={c}
                    onInstruct={instruct}
                    busy={busy}
                    compact
                  />
                ))}
              </ul>
            </article>
          ) : null}
        </div>

        <div className="side">
          <article className="card">
            <div className="card-head">
              <h2>Act on this address</h2>
            </div>
            {data?.private ? (
              <p className="empty">
                Private addresses are never actioned — the control plane refuses them, so an
                instruction here would be discarded.
              </p>
            ) : (
              <ActionRow
                ips={[ip]}
                current={policy?.action || ""}
                busyKey={`ip-page-${ip}`}
                busy={busy}
                onInstruct={instruct}
                label="Instruct the agent"
              />
            )}
          </article>

          <article className="card">
            <div className="card-head">
              <h2>Signals tripped</h2>
            </div>
            {(summary.signals || []).length === 0 ? (
              <p className="empty">Nothing fired for this address.</p>
            ) : (
              <ul className="signal-list">
                {summary.signals.map(([name, count]) => {
                  const meta = signalMeta(name);
                  return (
                    <li key={name}>
                      <span className="swatch" style={{ background: meta.color }} />
                      <span className="grow">{meta.label}</span>
                      <b>{count}</b>
                    </li>
                  );
                })}
              </ul>
            )}
          </article>

          <article className="card">
            <div className="card-head">
              <h2>Endpoints</h2>
            </div>
            {(summary.paths || []).length === 0 ? (
              <p className="empty">No requests in the window.</p>
            ) : (
              <ul className="signal-list">
                {summary.paths.map(([path, count]) => (
                  <li key={path}>
                    <span className="grow mono ellipsis" title={path}>
                      {path}
                    </span>
                    <b>{count}</b>
                  </li>
                ))}
              </ul>
            )}
          </article>

          <article className="card">
            <div className="card-head">
              <h2>Seen</h2>
            </div>
            <ul className="fact-list">
              <li>
                <span>First</span>
                <b>{summary.firstSeen ? formatTime(summary.firstSeen) : "—"}</b>
              </li>
              <li>
                <span>Last</span>
                <b>{summary.lastSeen ? formatTime(summary.lastSeen) : "—"}</b>
              </li>
            </ul>
          </article>

          {/* What the gateway did about it, and what the backend said -- both
              outcomes, and neither of them a thing that was "seen". */}
          <article className="card">
            <div className="card-head">
              <h2>Outcomes</h2>
            </div>
            {(summary.decisions || []).length === 0 &&
            (summary.statuses || []).length === 0 ? (
              <p className="empty">No requests in the window.</p>
            ) : (
              <ul className="fact-list">
                {(summary.decisions || []).map(([action, count]) => (
                  <li key={`d-${action}`}>
                    <span>{actionLabel(action)}</span>
                    <b>{count}</b>
                  </li>
                ))}
                {(summary.statuses || []).slice(0, 6).map(([status, count]) => (
                  <li key={`s-${status}`}>
                    <span>HTTP {status}</span>
                    <b>{count}</b>
                  </li>
                ))}
              </ul>
            )}
          </article>
        </div>
      </section>
    </>
  );
}
