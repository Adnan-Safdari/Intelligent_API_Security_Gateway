// Shared vocabulary. Everything here is pure, so both the shell and the pages
// can use it without either owning it.

// Colours are CSS variable references, not hex -- the same six hexes used
// to serve both themes identically, tuned only against the dark background
// and under-contrasting on light's near-white one. --sig-* is defined once
// per theme in globals.css so a var() here just picks up whichever the
// current theme already resolved, the same way every other themed colour in
// this app works.
//
// One entry per real gateway/internal/signals/*.go detector -- six, not the
// eight this used to carry. enumeration_path_traversal.go used to emit its
// base id in fired[] alongside a more specific attack-type string
// ("path_traversal" / "enumeration" / the compound), so the same detector
// firing once showed up as two differently-labelled, differently-coloured
// chips. Fixed at the source (gateway/internal/signals/collector.go now
// only ever appends the canonical Signal id); this is the display side of
// that fix, plus the vocabulary correction from an earlier pass
// ("brute_force"/"password_spraying" never matched anything the gateway
// emits -- the real constant is SignalBruteForce = "consecutive_failed_logins").
const SIGNAL_META = {
  api_flooding: { label: "API flooding", color: "var(--sig-flood)" },
  sql_injection: { label: "SQL injection", color: "var(--sig-sqli)" },
  consecutive_failed_logins: { label: "Brute force", color: "var(--sig-brute)" },
  unknown_route_scanning: { label: "Unknown-route scanning", color: "var(--sig-spray)" },
  object_enumeration: { label: "Object ID enumeration (BOLA)", color: "var(--sig-objenum)" },
  ownership_violation: { label: "Ownership check (BOLA)", color: "var(--sig-ownership)" },
  enumeration_path_traversal: { label: "Path traversal & enumeration", color: "var(--sig-enum-trav)" },
  ip_reputation: { label: "Known bad addresses", color: "var(--sig-reputation)" },
};

// Events recorded before the collector.go fix above can still carry the old,
// more-specific strings in their stored fired[] array -- this is what keeps
// them displaying correctly instead of falling back to a raw id in grey.
// New events never produce these; nothing new should ever key off them.
const LEGACY_SIGNAL_ALIASES = {
  path_traversal: "enumeration_path_traversal",
  enumeration: "enumeration_path_traversal",
  "path_traversal+enumeration": "enumeration_path_traversal",
};

function canonicalSignalId(name) {
  return LEGACY_SIGNAL_ALIASES[name] || name;
}

export function signalMeta(name) {
  return SIGNAL_META[canonicalSignalId(name)] || { label: name, color: "var(--muted)" };
}

// A historical event recorded before the fix above can carry BOTH the base
// id and a legacy attack-type string for the one detector that used to
// double-fire -- deduping by canonical id is what stops that from rendering
// as two badges for what was always a single match. Order is preserved from
// first appearance so a chip row doesn't reshuffle across events.
export function canonicalSignals(fired) {
  const seen = new Set();
  const out = [];
  for (const name of fired || []) {
    const id = canonicalSignalId(name);
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(id);
  }
  return out;
}

// The detector labels, in the gateway's own order -- for a filter
// dropdown that needs the whole vocabulary up front rather than only the
// signals a given window of events happens to contain.
export const SIGNAL_OPTIONS = Object.values(SIGNAL_META).map((s) => s.label);

// The policy ladder, weakest to strongest. Colour tracks the rung so an
// escalation is visible without reading the label. "temp_block" is the one
// canonical value used here and everywhere this dashboard writes an action.
export const LADDER = ["monitor", "throttle", "temp_block", "escalate"];

// control-plane/iasg/models.py writes "temporary_block" on the wire for
// adaptive/approved-sourced decisions and human overrides marked
// manual_override, but "temp_block" for everything else (including every
// action this dashboard itself submits) -- the gateway accepts both, but a
// dashboard comparing a stored policy's action against LADDER or another
// stored action needs one spelling, or a temporary_block policy shows a
// "change to temp_block" button offering what is already the current state.
export function normalizeAction(action) {
  return action === "temporary_block" ? "temp_block" : action;
}

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

const ACTION_LABELS = {
  monitor: "Monitor",
  throttle: "Throttle",
  temp_block: "Temporary block",
  escalate: "Escalate",
};

// One label per canonical action, however it's spelled in storage -- a
// temp_block and a temporary_block policy both read "Temporary block", not
// two different strings for what the gateway treats as the same action.
export function actionLabel(action) {
  if (!action) return "No action";
  const id = normalizeAction(action);
  return ACTION_LABELS[id] || id.replace(/_/g, " ");
}

// Mirrors control-plane/iasg/adaptive/risk.py's AnomalyObservation.reason --
// the precise cause when a policy carries no model score, so the UI never
// has to show a blank or guess at why. "scored" isn't listed: when the model
// did run, the caller shows the real number instead of this text.
const MODEL_STATUS_LABELS = {
  insufficient_history: "Not evaluated — baseline not ready",
  no_window_observed: "Not evaluated — no completed window yet",
  model_unavailable: "Model unavailable",
};

export function modelStatusLabel(status) {
  if (!status) return "Not evaluated — no model assessment recorded";
  return MODEL_STATUS_LABELS[status] || status.replace(/_/g, " ");
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

// Operational timestamps must describe one shared clock. Relying on each
// browser's local zone makes two operators looking at the same campaign read
// different incident times, so the console uses IST everywhere it renders one.
export const DISPLAY_TIME_ZONE = "Asia/Kolkata";
export const DISPLAY_TIME_ZONE_LABEL = "IST";

const IST_TIME_FORMATTER = new Intl.DateTimeFormat("en-IN", {
  timeZone: DISPLAY_TIME_ZONE,
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hourCycle: "h23",
});

export function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return IST_TIME_FORMATTER.format(date);
}

// A shape check only, for the IP filter shared across Events/Campaigns/
// Policy -- not a full RFC parse, just enough to reject garbage before it
// becomes a query param or a comparison nothing will ever match.
export function isValidIp(value) {
  const v = (value || "").trim();
  if (!v) return true; // empty means "no filter", not "invalid"
  const isV4 =
    /^\d{1,3}(\.\d{1,3}){3}$/.test(v) && v.split(".").every((o) => Number(o) <= 255);
  const isV6 = /^[0-9a-fA-F:]+$/.test(v) && v.includes(":");
  return isV4 || isV6;
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
