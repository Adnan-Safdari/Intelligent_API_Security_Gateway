"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { PageHead } from "@/app/ui/chrome";
import { ACTION_TONE, actionLabel, formatTime } from "@/app/ui/format";
import { useLive } from "@/app/ui/store";

const COLUMNS = [
  { key: "id", label: "#", numeric: true },
  { key: "type", label: "Type" },
  { key: "ipCount", label: "IPs", numeric: true },
  { key: "events", label: "Events", numeric: true },
  { key: "confidence", label: "Confidence", numeric: true },
  { key: "lastAction", label: "Ended as" },
  { key: "status", label: "Status" },
  { key: "lastSeen", label: "Last seen" },
];

export default function HistoryPage() {
  const { history } = useLive();
  const [sort, setSort] = useState({ key: "lastSeen", dir: "desc" });
  const [query, setQuery] = useState("");

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const filtered = history.campaigns.filter(
      (c) =>
        !q ||
        c.type.toLowerCase().includes(q) ||
        c.status.toLowerCase().includes(q) ||
        String(c.id) === q,
    );

    return [...filtered].sort((a, b) => {
      const { key, dir } = sort;
      let x = a[key];
      let y = b[key];
      if (key === "id") {
        x = Number(x);
        y = Number(y);
      }
      if (key === "lastSeen") {
        x = new Date(x).getTime();
        y = new Date(y).getTime();
      }
      const cmp = typeof x === "string" ? x.localeCompare(y) : x - y;
      return dir === "asc" ? cmp : -cmp;
    });
  }, [history.campaigns, sort, query]);

  function sortBy(key) {
    setSort((prev) =>
      prev.key === key
        ? { key, dir: prev.dir === "asc" ? "desc" : "asc" }
        : { key, dir: "desc" },
    );
  }

  if (!history.available) {
    return (
      <>
        <PageHead title="History">The durable record of every campaign ever correlated.</PageHead>
        <article className="card">
          <p className="empty">
            No durable store configured. Set <code>IASG_POSTGRES_URL</code> and the agent
            keeps campaigns past a restart — without it they live in Redis under a
            24-hour TTL and a reboot loses them.
          </p>
        </article>
      </>
    );
  }

  return (
    <>
      <PageHead title="History">
        Every campaign ever correlated, kept in Postgres. The live pages show only the
        last 24 hours because that is all the correlator will merge into; nothing here is
        ever deleted.
      </PageHead>

      <section className="metrics narrow">
        {history.byType.map((row) => (
          <article key={row.type} className="metric">
            <p>{row.type}</p>
            <strong>{row.campaigns}</strong>
            <small>
              {row.events.toLocaleString()} events · avg confidence{" "}
              {row.avgConfidence.toFixed(2)}
              {row.contained ? ` · ${row.contained} contained` : ""}
            </small>
          </article>
        ))}
      </section>

      <article className="card table-card">
        <div className="card-head">
          <h2>All campaigns</h2>
          <div className="head-controls">
            <input
              type="search"
              className="search"
              placeholder="Filter by type, status or #id…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <span className="count">
              {rows.length}/{history.total}
            </span>
          </div>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                {COLUMNS.map((col) => (
                  <th
                    key={col.key}
                    className="sortable"
                    onClick={() => sortBy(col.key)}
                    title={`Sort by ${col.label}`}
                  >
                    {col.label}
                    {sort.key === col.key ? (
                      <span className="caret">{sort.dir === "asc" ? "▲" : "▼"}</span>
                    ) : null}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={COLUMNS.length} className="empty">
                    Nothing matches this filter.
                  </td>
                </tr>
              ) : (
                rows.map((c) => (
                  <tr key={c.id} className={c.status === "contained" ? "dim" : ""}>
                    <td className="mono">{c.id}</td>
                    <td>{c.type}</td>
                    <td className="mono">{c.ipCount}</td>
                    <td className="mono">{c.events}</td>
                    <td className="mono">{c.confidence.toFixed(2)}</td>
                    <td>
                      <span className={`risk ${ACTION_TONE[c.lastAction] || "low"}`}>
                        {actionLabel(c.lastAction)}
                      </span>
                    </td>
                    <td>
                      <span className={c.status === "contained" ? "tag good" : "tag"}>
                        {c.status}
                      </span>
                    </td>
                    <td className="mono">{formatTime(c.lastSeen)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </article>

      <p className="page-foot">
        Showing the most recent {history.campaigns.length} of {history.total}.{" "}
        <Link href="/campaigns">Active campaigns</Link> are on their own page.
      </p>
    </>
  );
}
