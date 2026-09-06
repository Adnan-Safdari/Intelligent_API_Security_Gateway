// Shared vocabulary. Everything here is pure, so both the shell and the pages
// can use it without either owning it.

const SIGNAL_META = {
  api_flooding: { label: "Flood", color: "#c9842a" },
  sql_injection: { label: "SQLi", color: "#c43c51" },
  brute_force: { label: "Brute force", color: "#7c5cbf" },
  password_spraying: { label: "Spray", color: "#9a6bb8" },
  enumeration_path_traversal: { label: "Enum/trav", color: "#2a8f7c" },
  path_traversal: { label: "Traversal", color: "#2f7d9a" },
  enumeration: { label: "Enum", color: "#3d8a55" },
  ip_reputation: { label: "Known bad", color: "#b04a86" },
};

export function signalMeta(name) {
  return SIGNAL_META[name] || { label: name, color: "#6b7785" };
}

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
