"use client";

import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { PageHead } from "@/app/ui/chrome";
import { isValidIp, matchesEvent, signalMeta, SIGNAL_OPTIONS } from "@/app/ui/format";
import { EventTable, ExportMenu, IpFilterField, Loading, SegmentedControl, SnapshotButton } from "@/app/ui/parts";
import { EVENT_COLUMNS } from "@/app/ui/export";
import { useLive } from "@/app/ui/store";

// The live poll reads a small slice for the metrics and the map. This page has
// its own, deeper read, so investigating does not mean making the 2.5s poll
// expensive for every page.
const WINDOWS = [100, 250, 500, 1000, 2000];

// A snapshot renders the full, uncapped table -- see .snapshotting in
// globals.css -- but an event list can run into the thousands, and a canvas
// that tall risks the browser's area limit even at pixelRatio 1. Capping what
// the table itself renders during capture, rather than relying on pixelRatio
// alone, keeps a snapshot of a large view reliable instead of occasionally
// failing on exactly the busiest page someone wanted to capture.
const SNAPSHOT_ROW_CAP = 500;

const RANGES = [
  { label: "all", ms: 0 },
  { label: "5m", ms: 5 * 60_000 },
  { label: "15m", ms: 15 * 60_000 },
  { label: "1h", ms: 60 * 60_000 },
  { label: "6h", ms: 6 * 60 * 60_000 },
  { label: "24h", ms: 24 * 60 * 60_000 },
];

function EventsView() {
  const { busy, instruct, paused, setPaused, sources } = useLive();
  const params = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();

  // Reuses the same geo lookups the map already paid for -- Overview's poll
  // only geocodes the sources currently visible there, so a row outside that
  // set falls back to "--", same as every other place this console admits
  // it's showing a window rather than everything the gateway has ever seen.
  const geoByIp = useMemo(() => {
    const map = {};
    for (const s of sources) {
      map[s.ip] = s.private ? "Private network" : [s.city, s.country].filter(Boolean).join(", ");
    }
    return map;
  }, [sources]);

  const [query, setQuery] = useState(params.get("q") || "");
  const [alertsOnly, setAlertsOnly] = useState(params.get("alerts") === "1");
  const [ip, setIp] = useState(params.get("ip") || "");
  const [limit, setLimit] = useState(250);
  const [rangeMs, setRangeMs] = useState(0);
  const [frozen, setFrozen] = useState(false);
  const [capturingSnapshot, setCapturingSnapshot] = useState(false);
  const snapRef = useRef(null);

  const [rows, setRows] = useState([]);
  const [cursor, setCursor] = useState(null);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [older, setOlder] = useState(0);

  // Arriving from a campaign, a policy row or a signal should land pre-filtered.
  useEffect(() => {
    setQuery(params.get("q") || "");
    setAlertsOnly(params.get("alerts") === "1");
    setIp(params.get("ip") || "");
  }, [params]);

  // Filters live in the URL, not just component state -- refreshing, sharing
  // a link, or using the browser's back button (after following a row to an
  // IP's own page) all have to land back on the same filtered view. Only a
  // valid ip is written: an in-progress, not-yet-valid keystroke shouldn't
  // spam history or query the server with garbage.
  useEffect(() => {
    const next = new URLSearchParams();
    if (query) next.set("q", query);
    // Raw traffic is the default. Keep the query parameter only when an
    // operator explicitly narrows the view to alerts.
    if (alertsOnly) next.set("alerts", "1");
    if (ip && isValidIp(ip)) next.set("ip", ip);
    const search = next.toString();
    router.replace(search ? `${pathname}?${search}` : pathname, { scroll: false });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, alertsOnly, ip]);

  const effectiveIp = ip && isValidIp(ip) ? ip : "";

  const load = useCallback(
    async (size) => {
      setLoading(true);
      try {
        const qs = new URLSearchParams({ limit: String(size) });
        if (effectiveIp) qs.set("ip", effectiveIp);
        const res = await fetch(`/api/events?${qs}`, { cache: "no-store" });
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
    [effectiveIp],
  );

  const loadOlder = useCallback(async () => {
    if (!cursor) return;
    setLoading(true);
    try {
      const qs = new URLSearchParams({ limit: String(limit), before: cursor });
      if (effectiveIp) qs.set("ip", effectiveIp);
      const res = await fetch(`/api/events?${qs}`, { cache: "no-store" });
      const data = await res.json();
      setRows((prev) => [...prev, ...(data.events || [])]);
      setCursor(data.cursor || null);
      setOlder((n) => n + 1);
    } catch {
      /* leave what is already loaded in place */
    } finally {
      setLoading(false);
    }
  }, [cursor, limit, effectiveIp]);

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
      // Defensive, not the source of truth: /api/events already filtered by
      // ip server-side. This just keeps the table from flashing the previous
      // filter's rows for the moment between changing it and the new fetch
      // landing.
      if (effectiveIp && e.ip !== effectiveIp) return false;
      if (alertsOnly && !e.fired?.length) return false;
      if (floor && new Date(e.ts).getTime() < floor) return false;
      return matchesEvent(e, query);
    });
  }, [rows, query, alertsOnly, rangeMs, effectiveIp]);

  const ips = useMemo(() => [...new Set(shown.map((e) => e.ip).filter(Boolean))], [shown]);

  const signals = useMemo(() => {
    const counts = {};
    for (const e of shown) for (const f of e.fired || []) counts[f] = (counts[f] || 0) + 1;
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [shown]);

  const filtered = query || alertsOnly || rangeMs || ip;

  // Awaited by SnapshotButton before/after it captures snapRef -- see the
  // SNAPSHOT_ROW_CAP comment above. A frame's wait lets the capped table
  // actually re-render (and the browser paint it) before html-to-image reads
  // the DOM; without it the capture could still see the full, uncapped table
  // React had queued but not yet committed.
  const nextFrame = () => new Promise((resolve) => requestAnimationFrame(resolve));
  const beforeSnapshot = useCallback(async () => {
    setCapturingSnapshot(true);
    await nextFrame();
  }, []);
  const afterSnapshot = useCallback(() => setCapturingSnapshot(false), []);

  const tableRows = capturingSnapshot ? shown.slice(0, SNAPSHOT_ROW_CAP) : shown;

  return (
    <div ref={snapRef} className="page-body">
      <PageHead
        eyebrow="Raw traffic"
        title="Events"
        actions={
          <>
            <button
              type="button"
              className="act"
              onClick={() => setPaused((p) => !p)}
              title="Stop the 2.5s refresh while you read"
            >
              {paused ? "Resume stream" : "Pause stream"}
            </button>
            <ExportMenu rows={shown} columns={EVENT_COLUMNS} prefix="events" />
            <SnapshotButton
              targetRef={snapRef}
              prefix="events"
              title="Download a PNG of this events view"
              beforeCapture={beforeSnapshot}
              afterCapture={afterSnapshot}
            />
          </>
        }
      >
        The raw stream the gateway publishes, newest first. This is evidence, not
        conclusions — the correlation happens on the Campaigns page.
      </PageHead>

      <div className="toolbar">
        <input
          type="search"
          className="search wide"
          placeholder="Filter by path, method, user agent or signal…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <IpFilterField value={ip} onChange={setIp} />
        <select
          value={SIGNAL_OPTIONS.includes(query) ? query : ""}
          onChange={(e) => setQuery(e.target.value)}
        >
          <option value="">All signals</option>
          {SIGNAL_OPTIONS.map((label) => (
            <option key={label} value={label}>
              {label}
            </option>
          ))}
        </select>
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
              setIp("");
            }}
          >
            clear filters
          </button>
        ) : null}
        <span className="grow" />
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
        <span className="live-indicator">
          <span className={`live-dot ${!live ? "" : "on"}`} />
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
        </span>
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
      </div>

      <article className="card table-card">
        <EventTable
          events={tableRows}
          showRequestNumber
          showGeo
          geoByIp={geoByIp}
          empty={
            rows.length
              ? "No events match this filter."
              : "No events. Send traffic through the gateway on port 8082, or seed evidence."
          }
        />
        {capturingSnapshot && shown.length > SNAPSHOT_ROW_CAP ? (
          <p className="empty">
            Snapshot shows the newest {SNAPSHOT_ROW_CAP} of {shown.length.toLocaleString()} rows.
          </p>
        ) : null}
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
    </div>
  );
}

export default function EventsPage() {
  // useSearchParams needs a boundary, or the whole route opts out of prerender.
  return (
    <Suspense
      fallback={
        <article className="card">
          <p className="empty">
            <Loading />
          </p>
        </article>
      }
    >
      <EventsView />
    </Suspense>
  );
}
