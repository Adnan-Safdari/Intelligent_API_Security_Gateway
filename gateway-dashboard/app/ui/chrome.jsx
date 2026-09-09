"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { useLive } from "./store";
import {
  AdaptiveIcon,
  AgentIcon,
  CampaignsIcon,
  EscalatedIcon,
  EventsIcon,
  HistoryIcon,
  MoonIcon,
  OverviewIcon,
  PauseIcon,
  PolicyCountIcon,
  PolicyIcon,
  RedisIcon,
  ResumeIcon,
  SettingsIcon,
  SunIcon,
} from "./icons";

// One icon per section -- replaces the two hand-rolled sun/moon SVGs that
// used to live here, and gives nav something other than text-only labels.
const NAV = [
  { href: "/", label: "Overview", icon: OverviewIcon },
  { href: "/campaigns", label: "Campaigns", icon: CampaignsIcon },
  { href: "/policy", label: "Policy", icon: PolicyIcon },
  { href: "/adaptive", label: "Adaptive", icon: AdaptiveIcon },
  { href: "/events", label: "Events", icon: EventsIcon },
  { href: "/history", label: "History", icon: HistoryIcon },
  { href: "/settings", label: "Settings", icon: SettingsIcon },
];

export function Shell({ children }) {
  const { overview, policies, campaigns, escalations, beat, paused, setPaused, updatedAt, toast, setToast, flashEscalate } =
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
            const Icon = item.icon;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={active ? "nav-link active" : "nav-link"}
              >
                <Icon size={15} aria-hidden="true" />
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
            {paused ? <ResumeIcon size={15} /> : <PauseIcon size={15} />}
            {paused ? "Resume" : "Pause"}
          </button>

          <button
            type="button"
            className="icon-btn"
            onClick={toggleTheme}
            title={theme === "dark" ? "Switch to light" : "Switch to dark"}
            aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
          >
            {theme === "dark" ? <SunIcon size={16} /> : <MoonIcon size={16} />}
          </button>

        </div>
      </header>

      <div className="statusbar">
        <RedisIcon size={13} aria-hidden="true" />
        <span className={`dot ${overview.redis ? "on" : "off"}`} />
        {overview.redis ? "Redis connected" : "Redis unavailable"}
        <span className="sep" />
        {/* Liveness, not activity. A quiet network and a dead agent look
            identical without this, and they mean opposite things. */}
        <AgentIcon size={13} aria-hidden="true" />
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
        <PolicyCountIcon size={13} aria-hidden="true" />
        {policies.length > 0
          ? `${policies.length} policy ${policies.length === 1 ? "key" : "keys"} in force`
          : "Detect-only"}
        {escalations.length ? (
          <>
            <span className="sep" />
            <span className="risk high">
              <EscalatedIcon size={13} aria-hidden="true" />
              {escalations.length} escalated
            </span>
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

      {flashEscalate !== null ? (
        // Keyed so a second escalation while the first flash is still fading
        // remounts the element and restarts the animation, rather than
        // reusing a node CSS thinks is already mid-animation.
        <div key={flashEscalate} className="escalate-flash" aria-hidden="true" />
      ) : null}

      <main>{children}</main>
    </div>
  );
}

/**
 * Reset the console to a clean slate.
 *
 * Destructive, so it is two steps: a Settings-page control that opens a
 * dialog, and a dialog that will not act until you type the word the server
 * also demands.
 * On success it refreshes the live data, so the console visibly empties rather
 * than waiting for the next poll.
 */
export function ResetControl({ className = "icon-btn", label = "Reset console" }) {
  const { refresh, refreshHistory, setToast } = useLive();
  const [open, setOpen] = useState(false);
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return undefined;
    function escape(event) {
      if (event.key === "Escape" && !busy) close();
    }
    document.addEventListener("keydown", escape);
    return () => document.removeEventListener("keydown", escape);
  }, [open, busy]);

  function close() {
    setOpen(false);
    setConfirm("");
  }

  async function run() {
    setBusy(true);
    try {
      const res = await fetch("/api/admin/reset", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ confirm: "reset" }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        setToast({ tone: "bad", text: `reset failed: ${data.error || res.status}` });
        return;
      }
      const pg = data.postgres?.ok
        ? Object.values(data.postgres.cleared || {}).reduce((a, b) => a + b, 0)
        : 0;
      const keys = data.redis?.ok ? data.redis.removed : 0;
      const events = data.redis?.ok ? data.redis.trimmed : 0;
      setToast({
        tone: "good",
        text: `console reset — cleared ${pg} campaign record(s), ${events} event(s) and ${keys} live key(s)`,
      });
      close();
      // The live panels read Redis, but History reads Postgres on its own
      // slower cadence. Refresh both lanes now so a successful reset does not
      // leave deleted campaigns visible until the next 30-second history poll.
      await Promise.all([refresh(), refreshHistory()]);
    } catch (err) {
      setToast({ tone: "bad", text: `could not reach the server: ${err.message}` });
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <button
        type="button"
        className={className}
        onClick={() => setOpen(true)}
        title="Reset the console to a clean slate"
      >
        {label}
      </button>

      {open && typeof document !== "undefined"
        ? createPortal(
        <div className="modal-overlay" onMouseDown={() => !busy && close()}>
          <div
            className="modal-card"
            role="dialog"
            aria-modal="true"
            aria-labelledby="reset-dialog-title"
            onMouseDown={(e) => e.stopPropagation()}
          >
            <h2 id="reset-dialog-title">Reset the console?</h2>
            <p>
              This clears the campaign history in Postgres and the live telemetry
              in Redis — Overview, Events, Campaigns and History all go back to
              empty.
            </p>
            <p className="modal-note">
              To lift a current policy key, use Delete policy on the Policy page.
            </p>
            <p className="modal-note">
              Active policy blocks are left running; they expire on their own.
              This cannot be undone.
            </p>
            <label className="modal-label">
              Type <b>reset</b> to confirm
              <input
                type="text"
                value={confirm}
                autoFocus
                disabled={busy}
                onChange={(e) => setConfirm(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && confirm === "reset" && !busy) run();
                }}
                placeholder="reset"
              />
            </label>
            <div className="modal-actions">
              <button type="button" className="act" onClick={close} disabled={busy}>
                Cancel
              </button>
              <button
                type="button"
                className="act danger"
                onClick={run}
                disabled={busy || confirm !== "reset"}
              >
                {busy ? "Resetting…" : "Reset console"}
              </button>
            </div>
          </div>
        </div>,
        document.body,
      )
        : null}
    </>
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
