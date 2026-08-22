"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { useLive } from "./store";

/* Inline so the icon cannot arrive after the header it sits in. */
function SunIcon() {
  return (
    <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true" focusable="false">
      <circle cx="12" cy="12" r="4.2" fill="currentColor" />
      {[0, 45, 90, 135, 180, 225, 270, 315].map((deg) => (
        <rect
          key={deg}
          x="11.2"
          y="1.4"
          width="1.6"
          height="3.4"
          rx="0.8"
          fill="currentColor"
          transform={`rotate(${deg} 12 12)`}
        />
      ))}
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true" focusable="false">
      <path
        d="M20 14.2A8.2 8.2 0 0 1 9.8 4a8.4 8.4 0 1 0 10.2 10.2Z"
        fill="currentColor"
      />
    </svg>
  );
}

const NAV = [
  { href: "/", label: "Overview" },
  { href: "/campaigns", label: "Campaigns" },
  { href: "/policy", label: "Policy" },
  { href: "/events", label: "Events" },
  { href: "/history", label: "History" },
];

export function Shell({ children }) {
  const { overview, policies, campaigns, escalations, beat, paused, setPaused, updatedAt, toast, setToast } =
    useLive();
  const pathname = usePathname();
  const [theme, setTheme] = useState("dark");

  useEffect(() => {
    const stored = localStorage.getItem("iasg-theme");
    const next = stored === "light" || stored === "dark" ? stored : "dark";
    setTheme(next);
    document.documentElement.setAttribute("data-theme", next);
  }, []);

  function toggleTheme() {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    localStorage.setItem("iasg-theme", next);
    document.documentElement.setAttribute("data-theme", next);
  }

  // Counts that belong on the tab itself, so you can see there is something to
  // look at without opening the page.
  const badges = {
    "/campaigns": campaigns.filter((c) => c.status === "active").length,
    "/policy": policies.length,
  };

  return (
    <div className="app">
      <header className="top">
        <div className="brand">
          <span className="logo">IASG</span>
          <div>
            <strong>Operations</strong>
            <small>Intelligent API Security Gateway</small>
          </div>
        </div>

        <nav className="nav">
          {NAV.map((item) => {
            const active =
              item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={active ? "nav-link active" : "nav-link"}
              >
                {item.label}
                {badges[item.href] ? <em>{badges[item.href]}</em> : null}
              </Link>
            );
          })}
        </nav>

        <div className="top-actions">
          <button
            type="button"
            className={paused ? "icon-btn on" : "icon-btn"}
            onClick={() => setPaused((p) => !p)}
            title="Stop the 2.5s refresh while you read"
          >
            {paused ? "Resume" : "Pause"}
          </button>

          <button
            type="button"
            className="icon-btn"
            onClick={toggleTheme}
            title={theme === "dark" ? "Switch to light" : "Switch to dark"}
            aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
          >
            {theme === "dark" ? <SunIcon /> : <MoonIcon />}
          </button>
        </div>
      </header>

      <div className="statusbar">
        <span className={`dot ${overview.redis ? "on" : "off"}`} />
        {overview.redis ? "Redis connected" : "Redis unavailable"}
        <span className="sep" />
        {/* Liveness, not activity. A quiet network and a dead agent look
            identical without this, and they mean opposite things. */}
        <span className={`dot ${beat.alive ? (beat.late ? "late" : "on") : "off"}`} />
        {beat.alive
          ? beat.late
            ? `Agent late — ${beat.secondsAgo}s since last cycle`
            : `Agent live — cycled ${beat.secondsAgo}s ago`
          : "Agent not running"}
        {beat.alive && beat.dryRun ? " (dry run)" : ""}
        {beat.alive && beat.durable ? (
          <>
            <span className="sep" />
            Durable
          </>
        ) : null}
        <span className="sep" />
        {policies.length > 0
          ? `${policies.length} policy ${policies.length === 1 ? "key" : "keys"} in force`
          : "Detect-only"}
        {escalations.length ? (
          <>
            <span className="sep" />
            <span className="risk high">{escalations.length} escalated</span>
          </>
        ) : null}
        <span className="grow" />
        {paused ? "Paused" : updatedAt ? `Refreshed ${updatedAt.toLocaleTimeString([], { hour12: false })}` : "Connecting"}
      </div>

      {toast ? (
        <div className={`toast ${toast.tone}`} role="status">
          {toast.text}
          <button type="button" onClick={() => setToast(null)} aria-label="Dismiss">
            ×
          </button>
        </div>
      ) : null}

      <main>{children}</main>
    </div>
  );
}

export function PageHead({ title, children }) {
  return (
    <div className="page-head">
      <h1>{title}</h1>
      <p>{children}</p>
    </div>
  );
}
