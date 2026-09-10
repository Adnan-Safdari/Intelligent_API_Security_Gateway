// Shared vocabulary. Everything here is pure, so both the shell and the pages
// can use it without either owning it.

// Colours are CSS variable references, not hex -- the same eight hexes used
// to serve both themes identically, tuned only against the dark background
// and under-contrasting on light's near-white one. --sig-* is defined once
// per theme in globals.css so a var() here just picks up whichever the
// current theme already resolved, the same way every other themed colour in
// this app works.
// Keys matched against gateway/internal/signals/evidence.go's SignalXxx
// constants -- this used to carry "brute_force" and "password_spraying",
// neither of which the gateway ever emits (the real constant is
// SignalBruteForce = "consecutive_failed_logins"; password_spraying is a
// control-plane campaign classification derived FROM brute-force evidence,
// never a signal id of its own). Both misses meant those events fell back
// to the raw id in muted grey everywhere a signal chip renders. Also added
// unknown_route_scanning, and enumeration_path_traversal.go's own two
// signal ids: its base "enumeration_path_traversal" (SignalTraversal) is
// appended to an event's fired[] alongside the more specific attack type
// (collector.go appends both whenever they differ), so a traversal hit
// carries two entries, not one -- "enumeration_path_traversal" plus
// "path_traversal", "enumeration", or the compound
// "path_traversal+enumeration" when a single session trips both patterns.
const SIGNAL_META = {
  api_flooding: { label: "Flood", color: "var(--sig-flood)" },
  sql_injection: { label: "SQLi", color: "var(--sig-sqli)" },
  consecutive_failed_logins: { label: "Brute force", color: "var(--sig-brute)" },
  unknown_route_scanning: { label: "Route scan", color: "var(--sig-spray)" },
  enumeration_path_traversal: { label: "Enum/trav", color: "var(--sig-enum-trav)" },
  path_traversal: { label: "Traversal", color: "var(--sig-traversal)" },
  enumeration: { label: "Enum", color: "var(--sig-enum)" },
  "path_traversal+enumeration": { label: "Traversal+Enum", color: "var(--sig-enum-trav)" },
  ip_reputation: { label: "Known bad", color: "var(--sig-reputation)" },
};

export function signalMeta(name) {
  return SIGNAL_META[name] || { label: name, color: "var(--muted)" };
}

// The eight detector labels, in the gateway's own order -- for a filter
// dropdown that needs the whole vocabulary up front rather than only the
// signals a given window of events happens to contain.
export const SIGNAL_OPTIONS = Object.values(SIGNAL_META).map((s) => s.label);

// The policy ladder, weakest to strongest. Colour tracks the rung so an
// escalation is visible without reading the label.
export const LADDER = ["monitor", "throttle", "temp_block", "escalate"];

export const ACTION_TONE = {
  monitor: "low",
  throttle: "mid",
  // An outcome rather than an action: the policy said throttle, and this
  // request was the one that went over the rate it allowed.
  rate_limited: "mid",
  temp_block: "high",
  temporary_block: "high",
  escalate: "high",
};

export function actionLabel(action) {
  return action ? action.replace(/_/g, " ") : "no action";
}

export function riskTone(score) {
  if (score >= 70) return "high";
  if (score >= 30) return "mid";
  return "low";
}

// Telemetry risk is an integer on a fixed 0-100 scale. Keep the UI safe for
// historical stream entries or malformed values as well as current gateway data.
export function clampRiskScore(value) {
  const score = Number(value);
  if (!Number.isFinite(score)) return 0;
  return Math.min(100, Math.max(0, Math.round(score)));
}

export function formatTtl(seconds) {
  if (seconds == null || seconds < 0) return "no expiry";
  if (seconds < 60) return `${seconds}s left`;
  return `${Math.round(seconds / 60)}m left`;
}

export function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleTimeString([], { hour12: false });
}

export function requestHistogram(events) {
  const buckets = Array.from({ length: 16 }, () => 0);
  if (!events.length) return buckets;
  const newest = new Date(events[0].ts).getTime();
  if (Number.isNaN(newest)) return buckets;
  const span = 16 * 60 * 1000;
  for (const event of events) {
    const t = new Date(event.ts).getTime();
    if (Number.isNaN(t)) continue;
    const idx = Math.min(15, Math.max(0, Math.floor(((newest - t) / span) * 16)));
    buckets[15 - idx] += 1;
  }
  return buckets;
}

/** One predicate for every event filter in the console, so they cannot drift. */
export function matchesEvent(event, needle) {
  if (!needle) return true;
  const q = needle.trim().toLowerCase();
  if (!q) return true;
  return (
    event.ip?.toLowerCase().includes(q) ||
    event.path?.toLowerCase().includes(q) ||
    event.method?.toLowerCase() === q ||
    event.userAgent?.toLowerCase().includes(q) ||
    (event.fired || []).some((f) => signalMeta(f).label.toLowerCase().includes(q))
  );
}
