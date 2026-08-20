"use client";

import { useMemo, useState } from "react";
import { PageHead } from "@/app/ui/chrome";
import { CampaignCard } from "@/app/ui/parts";
import { useLive } from "@/app/ui/store";

const SORTS = {
  confidence: (a, b) => b.confidence - a.confidence,
  events: (a, b) => b.events - a.events,
  ips: (a, b) => b.ips.length - a.ips.length,
  newest: (a, b) => new Date(b.lastSeen) - new Date(a.lastSeen),
};

export default function CampaignsPage() {
  const { campaigns, busy, instruct } = useLive();
  const [status, setStatus] = useState("all");
  const [sort, setSort] = useState("confidence");
  const [compact, setCompact] = useState(false);
  const [selected, setSelected] = useState([]);

  const shown = useMemo(() => {
    const filtered =
      status === "all" ? campaigns : campaigns.filter((c) => c.status === status);
    return [...filtered].sort(SORTS[sort]);
  }, [campaigns, status, sort]);

  const counts = {
    all: campaigns.length,
    active: campaigns.filter((c) => c.status === "active").length,
    contained: campaigns.filter((c) => c.status === "contained").length,
  };

  // Acting on several campaigns at once is the difference between a console
  // and a report, and it is one instruction per address either way.
  //
  // Resolved against every campaign rather than the filtered view: selecting a
  // card and then changing tab used to leave the button armed but empty, so it
  // reported success having done nothing.
  const selectedIps = campaigns
    .filter((c) => selected.includes(c.id))
    .flatMap((c) => c.ips);

  function toggle(id) {
    setSelected((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id],
    );
  }

  return (
    <>
      <PageHead title="Campaigns">
        What the control plane correlated out of the raw events — rebuilt every cycle,
        and the only place an address becomes an attacker rather than a row in a log.
      </PageHead>

      <div className="toolbar">
        <div className="segmented">
          {["all", "active", "contained"].map((key) => (
            <button
              key={key}
              type="button"
              className={status === key ? "on" : ""}
              onClick={() => setStatus(key)}
            >
              {key} <em>{counts[key]}</em>
            </button>
          ))}
        </div>

        <label className="field">
          Sort
          <select value={sort} onChange={(e) => setSort(e.target.value)}>
            <option value="confidence">confidence</option>
            <option value="events">events</option>
            <option value="ips">addresses</option>
            <option value="newest">most recent</option>
          </select>
        </label>

        <label className="check">
          <input
            type="checkbox"
            checked={compact}
            onChange={(e) => setCompact(e.target.checked)}
          />
          Compact
        </label>

        <span className="grow" />

        {selected.length ? (
          <div className="bulk">
            <span>
              {selected.length} selected · {selectedIps.length} addresses
            </span>
            <button
              type="button"
              className="act"
              disabled={Boolean(busy)}
              onClick={async () => {
                const ok = await instruct(selectedIps, "temp_block", "bulk");
                if (ok) setSelected([]);
              }}
            >
              {busy === "bulk:temp_block" ? "…" : "temp block all"}
            </button>
            <button type="button" className="act" onClick={() => setSelected([])}>
              clear
            </button>
          </div>
        ) : null}
      </div>

      {shown.length === 0 ? (
        <article className="card">
          <p className="empty">
            {campaigns.length
              ? `No ${status} campaigns.`
              : "No campaigns yet. Run the control plane, or seed evidence with "}
            {campaigns.length ? null : (
              <code>python -m tools.seed_evidence --scenario credential-stuffing</code>
            )}
          </p>
        </article>
      ) : (
        <ul className="campaign-grid">
          {shown.map((c) => (
            <article
              key={c.id}
              className={selected.includes(c.id) ? "card selected" : "card"}
            >
              <label className="select-row">
                <input
                  type="checkbox"
                  checked={selected.includes(c.id)}
                  onChange={() => toggle(c.id)}
                />
                select for bulk action
              </label>
              <ul className="campaign-list">
                <CampaignCard
                  campaign={c}
                  onInstruct={instruct}
                  busy={busy}
                  compact={compact}
                />
              </ul>
            </article>
          ))}
        </ul>
      )}
    </>
  );
}
