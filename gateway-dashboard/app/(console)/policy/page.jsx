"use client";

import { useState } from "react";
import { PageHead } from "@/app/ui/chrome";
import { ACTION_TONE, LADDER, actionLabel, formatTtl } from "@/app/ui/format";
import { useLive } from "@/app/ui/store";
import { ExportMenu } from "@/app/ui/parts";
import { POLICY_COLUMNS } from "@/app/ui/export";
import Link from "next/link";

export default function PolicyPage() {
  const {
    policies, escalations, learned, busy, pendingPolicyActions, instruct, deletePolicy,
  } = useLive();
  const [ip, setIp] = useState("");
  const [action, setAction] = useState("temp_block");
  const [reason, setReason] = useState("");
  const [sort, setSort] = useState("expiry");

  const rows = [...policies].sort((a, b) =>
    sort === "expiry" ? a.expiresIn - b.expiresIn : b.confidence - a.confidence,
  );

  async function submit(e) {
    e.preventDefault();
    const ok = await instruct([ip.trim()], action, "manual", reason.trim());
    if (ok) {
      setIp("");
      setReason("");
    }
  }

  function removePolicy(policy) {
    if (!window.confirm(
      `Remove the active ${actionLabel(policy.action)} policy for ${policy.ip}? ` +
      "This takes effect immediately. The agent can recreate it if the campaign remains active.",
    )) return;
    deletePolicy(policy.ip);
  }

  return (
    <>
      <PageHead title="Policy">
        What the gateway is currently enforcing, and the one place to tell the agent it
        got something wrong. Nothing here writes policy directly — instructions go to the
        override stream and are applied on the next cycle, after the same allowlist and
        collateral checks the agent’s own decisions face.
      </PageHead>

      <p className="form-note">
        Delete policy removes the current Redis policy key immediately. It does not end the
        underlying campaign, so the agent may create a new policy on a later cycle.
      </p>

      <section className="workbench">
        <article className="card">
          <div className="card-head">
            <h2>In force</h2>
            <ExportMenu rows={rows} columns={POLICY_COLUMNS} prefix="policy" />
            <div className="head-controls">
              <label className="field">
                Sort
                <select value={sort} onChange={(e) => setSort(e.target.value)}>
                  <option value="expiry">expiring first</option>
                  <option value="confidence">confidence</option>
                </select>
              </label>
              <span className="count">{policies.length}</span>
            </div>
          </div>

          {rows.length === 0 ? (
            <p className="empty">
              No policy keys written. The gateway is observing but not enforcing.
            </p>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Address</th>
                    <th>Action</th>
                    <th>Expires</th>
                    <th>Origin</th>
                    <th>Change to</th>
                    <th>Remove</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((p) => (
                    <tr key={p.ip}>
                      <td>
                        <Link href={`/events?q=${encodeURIComponent(p.ip)}`} className="mono">
                          {p.ip}
                        </Link>
                      </td>
                      <td>
                        <span className={`risk ${ACTION_TONE[p.action] || "low"}`}>
                          {actionLabel(p.action)}
                        </span>
                      </td>
                      <td className="mono">{formatTtl(p.expiresIn)}</td>
                      <td>
                        {p.source === "human" ? (
                          <span className="tag">human</span>
                        ) : p.campaignId && p.campaignId !== "manual" ? (
                          <Link href="/campaigns">campaign #{p.campaignId}</Link>
                        ) : (
                          <span className="tag">agent</span>
                        )}
                      </td>
                      <td>
                        <div className="row-actions">
                          {pendingPolicyActions[p.ip] ? (
                            <span className="tag">
                              changing to {actionLabel(pendingPolicyActions[p.ip])}…
                            </span>
                          ) : (
                            LADDER.filter((a) => a !== p.action).map((a) => (
                              <button
                                key={a}
                                type="button"
                                className="act small"
                                disabled={Boolean(busy)}
                                onClick={() => instruct([p.ip], a, `row-${p.ip}`)}
                                title={`Instruct ${actionLabel(a)} for ${p.ip}`}
                              >
                                {busy === `row-${p.ip}:${a}` ? "…" : actionLabel(a)}
                              </button>
                            ))
                          )}
                        </div>
                      </td>
                      <td>
                        <button
                          type="button"
                          className="act danger small"
                          disabled={Boolean(busy)}
                          onClick={() => removePolicy(p)}
                          title={`Remove the active policy for ${p.ip}`}
                        >
                          {busy === `delete-policy:${p.ip}` ? "Removing..." : "Delete policy"}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </article>

        <div className="side">
          <article className="card">
            <div className="card-head">
              <h2>Instruct the agent</h2>
              <span>Any address, campaign or not</span>
            </div>
            <form className="form" onSubmit={submit}>
              <label className="field block">
                Address
                <input
                  type="text"
                  value={ip}
                  onChange={(e) => setIp(e.target.value)}
                  placeholder="203.0.113.5"
                  required
                />
              </label>

              <label className="field block">
                Action
                <select value={action} onChange={(e) => setAction(e.target.value)}>
                  {LADDER.map((a) => (
                    <option key={a} value={a}>
                      {actionLabel(a)}
                    </option>
                  ))}
                </select>
              </label>

              <label className="field block">
                Reason
                <input
                  type="text"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder="confirmed attack"
                />
              </label>

              <button type="submit" className="act primary" disabled={Boolean(busy) || !ip.trim()}>
                {busy?.startsWith("manual") ? "sending…" : `Instruct ${actionLabel(action)}`}
              </button>

              <p className="form-note">
                Applied on the agent’s next cycle. An allowlisted range is protected from a
                mistyped instruction exactly as it is from the agent — and{" "}
                <b>{actionLabel("monitor")}</b> stops future enforcement rather than
                clearing a block that is already standing; that expires on its own TTL.
              </p>
            </form>
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
                      <Link href="/campaigns">#{a.campaignId}</Link>
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

          <article className="card">
            <div className="card-head">
              <h2>Learned from humans</h2>
              <span>One rung, never more</span>
            </div>
            {learned.length === 0 ? (
              <p className="empty">
                Nothing learned yet. Overrule the agent twice in the same direction on one
                campaign type and it starts making that correction itself.
              </p>
            ) : (
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
            )}
          </article>
        </div>
      </section>
    </>
  );
}
