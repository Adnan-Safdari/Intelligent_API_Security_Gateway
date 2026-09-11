// Pure logic behind app/api/settings/route.js, split out so it can be unit
// tested without a Redis connection or an authenticated request -- both of
// which the route itself needs, but neither of which this logic touches.

// Anything outside this is structural: changing it means rebuilding the server,
// which a running gateway cannot do. Rejected rather than ignored, so a caller
// is never told a setting was applied when nothing reads it.
export const SECTIONS = [
  "rate_limit",
  "attack_detection",
  "brute_force",
  "unknown_route_scanning",
  "enumeration_path_traversal",
  "ip_reputation",
  "throttle",
  "block",
  "policy",
];

// Detector names the reflex will act on. Anything else in block.signals arms
// nothing, which looks identical to a typo, so it is refused.
//
// "path_traversal" used to be listed here too -- but the gateway's reflex
// matches fired evidence against ev.Signal, which for this detector is
// always "enumeration_path_traversal" (its more specific attack-type
// string, "path_traversal", never appears there). Listing it let an operator
// tick a checkbox that silently armed nothing, exactly the typo-shaped
// failure this allowlist exists to catch.
export const KNOWN_SIGNALS = [
  "api_flooding",
  "sql_injection",
  "enumeration_path_traversal",
  "ip_reputation",
];

/**
 * Splits the gateway's published settings blob into what the console can
 * edit (SECTIONS only) and what it can only display (everything else --
 * currently just adaptive_rate_limit, boot-time server wiring the gateway
 * reports for visibility but never accepts back).
 *
 * This split is what fixed a real bug: adaptive_rate_limit used to ride
 * along in the editable blob unfiltered, so it went GET -> draft -> POST
 * untouched, and validate() rejected the WHOLE save with "adaptive_rate_limit
 * cannot be changed while the gateway is running" -- even when the edit that
 * triggered the save had nothing to do with it.
 */
export function splitSettings(effective) {
  const { source = "file", ...rest } = effective || {};
  const settings = Object.fromEntries(
    Object.entries(rest).filter(([key]) => SECTIONS.includes(key)),
  );
  const readOnly = Object.fromEntries(
    Object.entries(rest).filter(([key]) => !SECTIONS.includes(key)),
  );
  return { settings, readOnly, source };
}

/**
 * Reject what the gateway would reject, and a few things it would silently
 * accept but nobody means: an unknown detector name in the signal list, a score
 * outside 0-100.
 *
 * Returns a message, or null when the settings are usable.
 */
export function validateSettings(s) {
  if (!s || typeof s !== "object") return "expected a settings object";

  for (const key of Object.keys(s)) {
    if (!SECTIONS.includes(key)) {
      return `${key} cannot be changed while the gateway is running — it is set in the config file`;
    }
  }

  // A whole block, never a patch. The gateway reads what arrives as the
  // complete enforcement config, so an omitted section is not "leave it alone"
  // -- it is "set every value in it to zero", which would quietly disarm a
  // detector. The page always sends what it was given, so this only catches a
  // hand-written request.
  const missing = SECTIONS.filter((name) => !s[name]);
  if (missing.length) {
    return `send the whole settings block — missing ${missing.join(", ")}`;
  }

  const rpm = s.rate_limit?.requests_per_minute;
  if (rpm !== undefined && (!Number.isInteger(rpm) || rpm < 1)) {
    return "rate_limit.requests_per_minute must be a whole number of at least 1";
  }

  const maxFailures = s.brute_force?.max_failures;
  if (maxFailures !== undefined && (!Number.isInteger(maxFailures) || maxFailures < 1)) {
    return "brute_force.max_failures must be a whole number of at least 1";
  }

  const window = s.brute_force?.window;
  if (window !== undefined && !isDuration(window)) {
    return `brute_force.window: ${JSON.stringify(window)} is not a duration like "60s" or "5m"`;
  }

  const scan = s.unknown_route_scanning;
  if (scan) {
    if (!Number.isInteger(scan.distinct_paths) || scan.distinct_paths < 2 ||
        !Number.isInteger(scan.max_paths_per_client) || scan.max_paths_per_client < scan.distinct_paths || scan.max_paths_per_client > 10000 ||
        !Number.isInteger(scan.max_clients) || scan.max_clients < 1 || scan.max_clients > 100000) {
      return "unknown_route_scanning limits must keep distinct paths within bounded client and path capacity";
    }
    if (!isDuration(scan.window)) return `unknown_route_scanning.window: ${JSON.stringify(scan.window)} is not a duration like "5m"`;
  }

  const duration = s.block?.duration;
  if (duration !== undefined && !isDuration(duration)) {
    return `block.duration: ${JSON.stringify(duration)} is not a duration like "60s" or "5m"`;
  }

  const minScore = s.block?.min_score;
  if (minScore !== undefined && (!Number.isInteger(minScore) || minScore < 0 || minScore > 100)) {
    return "block.min_score must be a whole number between 0 and 100";
  }

  const reputationScore = s.ip_reputation?.score;
  if (
    reputationScore !== undefined &&
    (!Number.isInteger(reputationScore) || reputationScore < 0 || reputationScore > 100)
  ) {
    return "ip_reputation.score must be a whole number between 0 and 100";
  }

  const cooldown = s.ip_reputation?.cooldown;
  if (cooldown !== undefined && !isDuration(cooldown)) {
    return `ip_reputation.cooldown: ${JSON.stringify(cooldown)} is not a duration like "5m"`;
  }

  const delay = s.throttle?.delay_ms;
  if (delay !== undefined && (!Number.isInteger(delay) || delay < 0)) {
    return "throttle.delay_ms must be a whole number of milliseconds";
  }

  const signals = s.block?.signals;
  if (signals !== undefined) {
    if (!Array.isArray(signals)) return "block.signals must be a list";
    for (const name of signals) {
      if (!KNOWN_SIGNALS.includes(name)) {
        return `block.signals: no detector is called ${JSON.stringify(name)} — it would arm nothing`;
      }
    }
  }

  const exempt = s.block?.exempt_cidrs;
  if (exempt !== undefined) {
    if (!Array.isArray(exempt)) return "block.exempt_cidrs must be a list";
    for (const entry of exempt) {
      if (!isCidrOrAddress(entry)) {
        return `block.exempt_cidrs: ${JSON.stringify(entry)} is not an address or CIDR range`;
      }
    }
  }

  return null;
}

// Go's time.ParseDuration. Compound values have to be accepted, not just the
// single-unit ones a person types: the gateway publishes durations through
// Duration.String(), which renders a minute as "1m0s". Refusing that would mean
// the page could not send back the value it was just given.
export function isDuration(value) {
  return typeof value === "string" && /^(\d+(\.\d+)?(ns|us|µs|ms|s|m|h))+$/.test(value.trim());
}

// A rough shape check only. The gateway parses these properly and refuses the
// whole change if one is wrong; this is here to catch the typo at the keyboard.
export function isCidrOrAddress(value) {
  if (typeof value !== "string" || value.trim() === "") return false;
  const [addr, bits, ...rest] = value.trim().split("/");
  if (rest.length) return false;
  if (bits !== undefined && !/^\d{1,3}$/.test(bits)) return false;
  const isV4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(addr);
  const isV6 = /^[0-9a-fA-F:]+$/.test(addr) && addr.includes(":");
  if (!isV4 && !isV6) return false;
  if (isV4 && addr.split(".").some((o) => Number(o) > 255)) return false;
  if (bits !== undefined && Number(bits) > (isV4 ? 32 : 128)) return false;
  return true;
}
