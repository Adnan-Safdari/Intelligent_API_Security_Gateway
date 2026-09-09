"use client";

import { useEffect, useRef, useState } from "react";

export default function TrafficMap({ sources = [], site = null, theme = "dark" }) {
  const rootRef = useRef(null);
  const leafletRef = useRef(null);
  const mapRef = useRef(null);
  const layerRef = useRef(null);
  const tilesRef = useRef(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function init() {
      const leaflet = await import("leaflet");
      if (cancelled || !rootRef.current || mapRef.current) return;
      leafletRef.current = leaflet;
      mapRef.current = leaflet.map(rootRef.current, {
        zoomControl: true,
        attributionControl: true,
        worldCopyJump: true,
        scrollWheelZoom: true,
      });
      mapRef.current.setView([20, 10], 2);
      layerRef.current = leaflet.layerGroup().addTo(mapRef.current);
      setReady(true);
      setTimeout(() => mapRef.current?.invalidateSize(), 80);
    }

    init();
    return () => {
      cancelled = true;
      if (mapRef.current) {
        mapRef.current.remove();
        mapRef.current = null;
      }
      setReady(false);
    };
  }, []);

  useEffect(() => {
    const leaflet = leafletRef.current;
    const map = mapRef.current;
    if (!ready || !leaflet || !map) return;

    // CARTO's basemaps.cartocdn.com used to serve these keyless. It no longer
    // does -- every tile now comes back watermarked "API KEY REQUIRED" -- and
    // getting a key means an account this console has no business depending
    // on. Esri's Canvas basemaps are the replacement: free, no key, and still
    // a light/dark pair. Note the tile path is {z}/{y}/{x}, not {z}/{x}/{y} --
    // Esri's REST tile service orders row before column, the opposite of
    // CARTO's and most others'. Leaflet substitutes {x}/{y} by name, not
    // position, so writing them in this order is what makes it correct here
    // rather than a typo to "fix" later.
    const tileUrl =
      theme === "light"
        ? "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Light_Gray_Base/MapServer/tile/{z}/{y}/{x}"
        : "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}";

    if (tilesRef.current) {
      map.removeLayer(tilesRef.current);
    }
    tilesRef.current = leaflet
      .tileLayer(tileUrl, {
        attribution: "&copy; Esri",
        maxZoom: 8,
      })
      .addTo(map);
  }, [ready, theme]);

  useEffect(() => {
    const leaflet = leafletRef.current;
    const map = mapRef.current;
    if (!ready || !leaflet || !map || !layerRef.current) return;

    layerRef.current.clearLayers();

    const points = [];
    const publicSources = sources.filter((source) => !source.private && source.lat != null && source.lon != null);

    if (site?.lat != null && site?.lon != null) {
      const labPoint = [site.lat, site.lon];
      points.push(labPoint);
      // var() strings, not hex -- Leaflet sets these as inline style
      // properties on the underlying SVG path, and the browser resolves
      // var() there exactly like it would in a stylesheet. That means a
      // theme toggle repaints these correctly on its own, with no re-render
      // needed, unlike a resolved hex baked in once at draw time.
      const labColor = site.alerts > 0 ? "var(--map-alert)" : "var(--map-site)";
      leaflet
        .circleMarker(labPoint, {
          radius: Math.min(16, 8 + Math.sqrt(site.requests || 1) * 1.4),
          color: labColor,
          weight: 2,
          fillColor: labColor,
          fillOpacity: 0.28,
        })
        .bindPopup(
          `<strong>Gateway site</strong><br/>${site.city || "Unknown"}, ${site.country || "—"}<br/>Local / Docker: ${site.requests || 0} req · ${site.alerts || 0} alerts`,
        )
        .addTo(layerRef.current);

      for (const source of publicSources) {
        leaflet
          .polyline([labPoint, [source.lat, source.lon]], {
            color: source.alerts > 0 ? "var(--map-alert)" : "var(--map-site)",
            weight: 1,
            opacity: 0.35,
          })
          .addTo(layerRef.current);
      }
    }

    for (const source of publicSources) {
      const color = source.alerts > 0 ? "var(--map-alert)" : "var(--map-public)";
      leaflet
        .circleMarker([source.lat, source.lon], {
          radius: Math.min(16, 5 + Math.sqrt(source.requests) * 1.8),
          color,
          weight: 1.5,
          fillColor: color,
          fillOpacity: 0.62,
        })
        .bindPopup(
          `<strong>${source.ip}</strong><br/>${source.city || "Unknown"}, ${source.country || "—"}<br/>${source.requests} req · ${source.alerts} alerts`,
        )
        .addTo(layerRef.current);
      points.push([source.lat, source.lon]);
    }

    const fitKey = points.map((p) => p.join(":")).join("|");
    if (layerRef.current._iasgFitKey !== fitKey) {
      if (points.length === 1) {
        map.setView(points[0], 4);
      } else if (points.length > 1) {
        map.fitBounds(points, { padding: [36, 36], maxZoom: 5 });
      }
      layerRef.current._iasgFitKey = fitKey;
    }

    setTimeout(() => map.invalidateSize(), 80);
  }, [ready, sources, site]);

  const publicCount = sources.filter((s) => !s.private && s.lat != null).length;
  const privateSources = sources.filter((s) => s.private);

  return (
    <div className="map-wrap">
      <div ref={rootRef} className="map-canvas" />
      <div className="map-legend">
        <span>
          <i className="dot public" /> Public {publicCount}
        </span>
        <span>
          <i className="dot site" /> Gateway site
        </span>
        <span>
          <i className="dot alert" /> Alerting
        </span>
        <span>
          <i className="dot private" /> Private {privateSources.length}
        </span>
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
