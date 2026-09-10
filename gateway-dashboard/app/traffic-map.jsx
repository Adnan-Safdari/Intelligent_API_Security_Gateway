"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";

// The design's own recipe (see design_handoff's "Map rendering" section)
// calls for the 110m resolution atlas; that file renders several borders
// -- India's northeast frontier with China worst of all -- as a visibly
// self-crossing line, a real artifact of simplifying that geometry down to
// 110m, not a rendering bug here. The 50m atlas fixes it and every other
// coastline at a real but small cost (roughly 750KB vs 100KB, fetched once
// and cached). Same "countries" object, so it's a one-line swap: d3-geo +
// TopoJSON, geoNaturalEarth1() fitted to the container, a graticule
// underlay, per-country paths -- a flat vector map, not a photographic/
// street basemap.
const WORLD_ATLAS_URL = "https://unpkg.com/world-atlas@2.0.2/countries-50m.json";

// Module-level, not state: every TrafficMap instance (a theme toggle
// remounts nothing, but Overview's own remounts during dev fast-refresh
// would otherwise each re-fetch) shares one in-flight/resolved promise.
let worldPromise = null;
function loadWorld() {
  if (!worldPromise) {
    worldPromise = Promise.all([import("d3-geo"), import("topojson-client"), fetch(WORLD_ATLAS_URL)])
      .then(async ([d3geo, topojson, res]) => {
        if (!res.ok) throw new Error(`world atlas ${res.status}`);
        const topology = await res.json();
        const countries = topojson.feature(topology, topology.objects.countries);
        return { d3geo, countries, graticule: d3geo.geoGraticule10() };
      })
      .catch((err) => {
        worldPromise = null; // let a later mount retry instead of caching the failure forever
        throw err;
      });
  }
  return worldPromise;
}

// A short, stable spread of animation delays so alerting dots don't all
// pulse in unison -- derived from the IP itself, so it's stable across
// re-renders rather than reshuffling on every poll.
function pulseDelay(ip) {
  let hash = 0;
  for (let i = 0; i < ip.length; i++) hash = (hash * 31 + ip.charCodeAt(i)) >>> 0;
  return (hash % 26) / 10; // 0.0 - 2.5s
}

export default function TrafficMap({ sources = [], site = null }) {
  const router = useRouter();
  const containerRef = useRef(null);
  const [size, setSize] = useState({ width: 0, height: 0 });
  const [world, setWorld] = useState(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    loadWorld()
      .then((w) => !cancelled && setWorld(w))
      .catch(() => !cancelled && setError(true));
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return undefined;
    const observer = new ResizeObserver((entries) => {
      const box = entries[0].contentRect;
      setSize({ width: Math.round(box.width), height: Math.round(box.height) });
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  const publicSources = useMemo(
    () => sources.filter((s) => !s.private && s.lat != null && s.lon != null),
    [sources],
  );
  const privateSources = useMemo(() => sources.filter((s) => s.private), [sources]);

  const layout = useMemo(() => {
    if (!world || !size.width || !size.height) return null;
    const { d3geo, countries, graticule } = world;
    const projection = d3geo
      .geoNaturalEarth1()
      .fitExtent(
        [
          [8, 6],
          [size.width - 8, size.height - 6],
        ],
        countries,
      );
    const path = d3geo.geoPath(projection);
    const project = (lon, lat) => projection([lon, lat]);
    return {
      landPath: path(countries),
      gridPath: path(graticule),
      project,
    };
  }, [world, size.width, size.height]);

  return (
    <div className="map-wrap">
      <div ref={containerRef} className="map-canvas">
        {error ? (
          <div className="map-loading">Map unavailable — no network reach to the basemap.</div>
        ) : !layout ? (
          <div className="map-loading">Loading map…</div>
        ) : (
          <svg
            className="world-map-svg"
            width={size.width}
            height={size.height}
            viewBox={`0 0 ${size.width} ${size.height}`}
          >
            <path className="world-map-grid" d={layout.gridPath} />
            <path className="world-map-land" d={layout.landPath} />

            {site?.lat != null && site?.lon != null
              ? (() => {
                  const point = layout.project(site.lon, site.lat);
                  if (!point) return null;
                  const alerting = site.alerts > 0;
                  return (
                    <g key="site">
                      {alerting ? (
                        <circle
                          className="world-map-pulse"
                          cx={point[0]}
                          cy={point[1]}
                          r={4.2}
                          style={{ stroke: "var(--map-alert)", animationDelay: "0s" }}
                        />
                      ) : null}
                      <circle
                        cx={point[0]}
                        cy={point[1]}
                        r={4.2}
                        style={{ fill: alerting ? "var(--map-alert)" : "var(--map-site)" }}
                      >
                        <title>
                          Gateway site — {site.city || "Unknown"}, {site.country || "—"}
                          {"\n"}
                          {site.requests || 0} req · {site.alerts || 0} alerts
                        </title>
                      </circle>
                    </g>
                  );
                })()
              : null}

            {publicSources.map((source) => {
              const point = layout.project(source.lon, source.lat);
              if (!point) return null;
              const alerting = source.alerts > 0;
              return (
                <g key={source.ip}>
                  {alerting ? (
                    <circle
                      className="world-map-pulse"
                      cx={point[0]}
                      cy={point[1]}
                      r={4}
                      style={{ stroke: "var(--map-alert)", animationDelay: `${pulseDelay(source.ip)}s` }}
                    />
                  ) : null}
                  <circle
                    className="world-map-dot"
                    cx={point[0]}
                    cy={point[1]}
                    r={alerting ? 4 : 2.6}
                    style={{ fill: alerting ? "var(--map-alert)" : "var(--map-public)" }}
                    onClick={() => router.push(`/ip/${encodeURIComponent(source.ip)}`)}
                  >
                    <title>
                      {source.ip} — {source.city || "Unknown"}, {source.country || "—"}
                      {"\n"}
                      {source.requests} req · {source.alerts} alerts
                    </title>
                  </circle>
                </g>
              );
            })}
          </svg>
        )}
      </div>
      {privateSources.length > 0 ? (
        <aside className="map-internal">
          <h3>Local / Docker</h3>
          <ul>
            {privateSources.slice(0, 6).map((row) => (
              <li key={row.ip}>
                <code>{row.ip}</code>
                <span>
                  {row.requests} req
                  {row.alerts ? ` · ${row.alerts} alert` : ""}
                </span>
              </li>
            ))}
          </ul>
        </aside>
      ) : null}
    </div>
  );
}
