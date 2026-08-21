"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { PageHead } from "@/app/ui/chrome";
import { matchesEvent, signalMeta } from "@/app/ui/format";
import { EventTable } from "@/app/ui/parts";
import { useLive } from "@/app/ui/store";

function EventsView() {
  const { events, busy, instruct } = useLive();
  const params = useSearchParams();

  // Arriving from a campaign, a policy row or a signal should land pre-filtered.
  const [query, setQuery] = useState(params.get("q") || "");
  const [alertsOnly, setAlertsOnly] = useState(params.get("alerts") === "1");

  useEffect(() => {
    setQuery(params.get("q") || "");
    setAlertsOnly(params.get("alerts") === "1");
  }, [params]);

  const shown = useMemo(
    () =>
      events.filter((e) => {
        if (alertsOnly && !e.fired?.length) return false;
        return matchesEvent(e, query);
      }),
    [events, query, alertsOnly],
  );

  // Who is in this filtered view, so the filter itself becomes actionable.
  const ips = useMemo(() => [...new Set(shown.map((e) => e.ip).filter(Boolean))], [shown]);

  const signals = useMemo(() => {
    const counts = {};
    for (const e of shown) for (const f of e.fired || []) counts[f] = (counts[f] || 0) + 1;
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [shown]);

  return (
    <>
      <PageHead title="Events">
        The raw stream the gateway publishes, newest first. This is evidence, not
        conclusions — the correlation happens on the Campaigns page.
      </PageHead>

      <div className="toolbar">
        <input
          type="search"
          className="search wide"
          placeholder="Filter by IP, path, method, user agent or signal…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <label className="check">
          <input
            type="checkbox"
            checked={alertsOnly}
            onChange={(e) => setAlertsOnly(e.target.checked)}
          />
          Alerts only
        </label>
        {query || alertsOnly ? (
          <button
            type="button"
            className="act"
            onClick={() => {
              setQuery("");
              setAlertsOnly(false);
            }}
          >
            clear
          </button>
        ) : null}
        <span className="count">
          {shown.length}/{events.length} events · {ips.length}{" "}
          {ips.length === 1 ? "address" : "addresses"}
        </span>
        <span className="grow" />
        {ips.length && ips.length <= 25 ? (
          <button
            type="button"
            className="act"
            disabled={Boolean(busy)}
            onClick={() => instruct(ips, "temp_block", "filtered")}
            title={`Instruct temp block for the ${ips.length} addresses in this view`}
          >
            {busy === "filtered:temp_block"
              ? "…"
              : `block ${ips.length} in view`}
          </button>
        ) : null}
      </div>

      {signals.length ? (
        <div className="chip-row">
          {signals.map(([name, count]) => {
            const meta = signalMeta(name);
            return (
              <button
                key={name}
                type="button"
                className="chip"
                onClick={() => setQuery(meta.label)}
              >
                <span className="swatch" style={{ background: meta.color }} />
                {meta.label} <em>{count}</em>
              </button>
            );
          })}
        </div>
      ) : null}

      <article className="card table-card">
        <EventTable
          events={shown}
          empty={
            events.length
              ? "No events match this filter."
              : "No events. Send traffic through the gateway on port 8082, or seed evidence."
          }
        />
      </article>
    </>
  );
}

export default function EventsPage() {
  // useSearchParams needs a boundary, or the whole route opts out of prerender.
  return (
    <Suspense fallback={<article className="card"><p className="empty">Loading…</p></article>}>
      <EventsView />
    </Suspense>
  );
}
