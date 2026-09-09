"use client";

import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import { PageHead } from "@/app/ui/chrome";
import { matchesEvent, signalMeta } from "@/app/ui/format";
import { EventTable, ExportMenu, SegmentedControl } from "@/app/ui/parts";
import { EVENT_COLUMNS } from "@/app/ui/export";
import { useLive } from "@/app/ui/store";

// The live poll reads a small slice for the metrics and the map. This page has
// its own, deeper read, so investigating does not mean making the 2.5s poll
// expensive for every page.
const WINDOWS = [100, 250, 500, 1000, 2000];

const RANGES = [
  { label: "all", ms: 0 },
  { label: "5m", ms: 5 * 60_000 },
  { label: "15m", ms: 15 * 60_000 },
  { label: "1h", ms: 60 * 60_000 },
  { label: "6h", ms: 6 * 60 * 60_000 },
  { label: "24h", ms: 24 * 60 * 60_000 },
];

function EventsView() {
  const { busy, instruct, paused } = useLive();
  const params = useSearchParams();

  const [query, setQuery] = useState(params.get("q") || "");
  const [alertsOnly, setAlertsOnly] = useState(params.get("alerts") === "1");
  const [limit, setLimit] = useState(250);
  const [rangeMs, setRangeMs] = useState(0);
  const [frozen, setFrozen] = useState(false);

  const [rows, setRows] = useState([]);
  const [cursor, setCursor] = useState(null);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [older, setOlder] = useState(0);

  // Arriving from a campaign, a policy row or a signal should land pre-filtered.
  useEffect(() => {
    setQuery(params.get("q") || "");
    setAlertsOnly(params.get("alerts") === "1");
  }, [params]);

  const load = useCallback(
    async (size) => {
      setLoading(true);
      try {
        const res = await fetch(`/api/events?limit=${size}`, { cache: "no-store" });
        const data = await res.json();
        setRows(data.events || []);
        setCursor(data.cursor || null);
        setTotal(data.total || 0);
        setOlder(0);
      } catch {
        /* the table reports its own emptiness */
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  const loadOlder = useCallback(async () => {
    if (!cursor) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/events?limit=${limit}&before=${encodeURIComponent(cursor)}`, {
        cache: "no-store",
      });
      const data = await res.json();
      setRows((prev) => [...prev, ...(data.events || [])]);
      setCursor(data.cursor || null);
      setOlder((n) => n + 1);
    } catch {
      /* leave what is already loaded in place */
    } finally {
      setLoading(false);
    }
  }, [cursor, limit]);

  useEffect(() => {
    load(limit);
  }, [limit, load]);

  // Refreshing would throw away pages of older evidence and move rows under
  // the cursor mid-read, so it stops once you are paging or have frozen the
  // view -- and the toolbar says which is why.
  const live = !frozen && !paused && older === 0;
  const liveRef = useRef(live);
  liveRef.current = live;

  useEffect(() => {
    if (!live) return undefined;
    const id = setInterval(() => liveRef.current && load(limit), 5000);
    return () => clearInterval(id);
  }, [live, limit, load]);

  const shown = useMemo(() => {
    const floor = rangeMs ? Date.now() - rangeMs : 0;
    return rows.filter((e) => {
      if (alertsOnly && !e.fired?.length) return false;
      if (floor && new Date(e.ts).getTime() < floor) return false;
      return matchesEvent(e, query);
    });
  }, [rows, query, alertsOnly, rangeMs]);

  const ips = useMemo(() => [...new Set(shown.map((e) => e.ip).filter(Boolean))], [shown]);

  const signals = useMemo(() => {
    const counts = {};
    for (const e of shown) for (const f of e.fired || []) counts[f] = (counts[f] || 0) + 1;
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [shown]);

  const filtered = query || alertsOnly || rangeMs;

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
        {filtered ? (
          <button
            type="button"
            className="act"
            onClick={() => {
              setQuery("");
              setAlertsOnly(false);
              setRangeMs(0);
            }}
          >
            clear
          </button>
        ) : null}
        <span className="grow" />
        <ExportMenu rows={shown} columns={EVENT_COLUMNS} prefix="events" />
        {ips.length && ips.length <= 25 ? (
          <button
            type="button"
            className="act"
            disabled={Boolean(busy)}
            onClick={() => instruct(ips, "temp_block", "filtered")}
            title={`Instruct temp block for the ${ips.length} addresses in this view`}
          >
            {busy === "filtered:temp_block" ? "…" : `block ${ips.length} in view`}
          </button>
        ) : null}
      </div>

      <div className="toolbar sub">
        <span className="seg-label">Window</span>
        <SegmentedControl
          value={limit}
          onChange={setLimit}
          options={WINDOWS.map((n) => ({
            value: n,
            label: n,
            title: `Read the newest ${n} events from the stream`,
          }))}
        />

        <span className="seg-label">Since</span>
        <SegmentedControl
          value={rangeMs}
          onChange={setRangeMs}
          options={RANGES.map((r) => ({ value: r.ms, label: r.label }))}
        />

        <button
          type="button"
          className={frozen ? "act on" : "act"}
          onClick={() => setFrozen((f) => !f)}
          title="Stop this table updating while you read it"
        >
          {frozen ? "frozen" : "freeze"}
        </button>

        <span className="grow" />
        <span className="count">
          {shown.length.toLocaleString()}/{rows.length.toLocaleString()} shown
          {total ? ` · ${total.toLocaleString()} retained` : ""}
          {loading ? " · loading…" : ""}
          {!live && !loading
            ? frozen
              ? " · frozen"
              : paused
                ? " · paused"
                : " · paused while paging"
            : ""}
        </span>
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
          showSerialNumber
          empty={
            rows.length
              ? "No events match this filter."
              : "No events. Send traffic through the gateway on port 8082, or seed evidence."
          }
        />
      </article>

      {cursor ? (
        <div className="more-row">
          <button type="button" className="act" onClick={loadOlder} disabled={loading}>
            {loading ? "loading…" : `load ${limit} older`}
          </button>
          <small>
            {rows.length.toLocaleString()} of {total.toLocaleString()} loaded
          </small>
        </div>
      ) : rows.length && total > rows.length ? null : null}
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
