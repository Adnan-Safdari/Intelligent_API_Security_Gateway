import { getRedis } from "@/lib/redis";
import { require as requireRole } from "@/lib/auth";

export const dynamic = "force-dynamic";

/**
 * Live enforcement settings.
 *
 * GET    what the gateway is running, and where it came from
 * POST   put an override in force
 * DELETE drop the override, returning the gateway to its config file
 *
 * Two keys are involved, and the difference between them matters:
 *
 *   iasg:settings            what the console asked for
 *   iasg:settings:effective  what the gateway is actually enforcing, written
 *                            by the gateway itself on every apply
 *
 * The page reads the effective key, never the requested one. If the gateway
 * refused an override -- a duration that will not parse, a CIDR that will not
 * -- the two disagree, and showing the request would tell the operator their
 * change is live when it is not. The effective key carries a TTL, so a gateway
 * that has stopped stops claiming to enforce anything.
 */

const OVERRIDE_KEY = "iasg:settings";
const EFFECTIVE_KEY = "iasg:settings:effective";

// Anything outside this is structural: changing it means rebuilding the server,
// which a running gateway cannot do. Rejected rather than ignored, so a caller
// is never told a setting was applied when nothing reads it.
const SECTIONS = [
  "rate_limit",
  "attack_detection",
  "brute_force",
  "enumeration_path_traversal",
  "ip_reputation",
  "throttle",
  "block",
  "policy",
];

// Detector names the reflex will act on. Anything else in block.signals arms
// nothing, which looks identical to a typo, so it is refused.
const KNOWN_SIGNALS = [
  "api_flooding",
  "brute_force",
  "sql_injection",
  "path_traversal",
  "enumeration_path_traversal",
  "ip_reputation",
];

export async function GET() {
  const gate = await requireRole("admin");
  if (gate.denied) return gate.denied;

  let redis;
  try {
    redis = await getRedis();
  } catch (err) {
    return Response.json({ ok: false, error: `redis unavailable: ${err.message}` }, { status: 503 });
  }

  const [effectiveRaw, overrideRaw] = await Promise.all([
    redis.get(EFFECTIVE_KEY),
    redis.get(OVERRIDE_KEY),
  ]);

  if (!effectiveRaw) {
    // No gateway has published, so there is nothing trustworthy to edit. Saying
    // so beats rendering a form built from the override, which would let an
    // operator "change" settings nothing is reading.
    return Response.json({
      ok: false,
      error:
        "the gateway has not published its settings — it may be stopped, or built before live settings existed",
      overridePresent: Boolean(overrideRaw),
    }, { status: 503 });
  }

  const effective = parseJson(effectiveRaw);
  if (!effective) {
    return Response.json({ ok: false, error: "the gateway published settings that will not parse" }, { status: 502 });
  }

  const { source = "file", ...settings } = effective;
  return Response.json({ ok: true, settings, source });
}

export async function POST(request) {
  const gate = await requireRole("admin");
  if (gate.denied) return gate.denied;

  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ ok: false, error: "expected a JSON body" }, { status: 400 });
  }

  if (body.confirm !== "apply") {
    return Response.json({ ok: false, error: 'type "apply" to confirm' }, { status: 400 });
  }

  const settings = body.settings;
  const problem = validate(settings);
  if (problem) {
    return Response.json({ ok: false, error: problem }, { status: 400 });
  }

  let redis;
  try {
    redis = await getRedis();
  } catch (err) {
    return Response.json({ ok: false, error: `redis unavailable: ${err.message}` }, { status: 503 });
  }

  await redis.set(OVERRIDE_KEY, JSON.stringify(settings));
  console.log(`[admin] ${gate.user.username} changed the enforcement settings`);

  // The gateway validates independently and may still refuse. The page polls
  // the effective key afterwards to find out, so this only reports that the
  // request was stored.
  return Response.json({ ok: true, stored: true });
}

export async function DELETE() {
  const gate = await requireRole("admin");
  if (gate.denied) return gate.denied;

  let redis;
  try {
    redis = await getRedis();
  } catch (err) {
    return Response.json({ ok: false, error: `redis unavailable: ${err.message}` }, { status: 503 });
  }

  const removed = await redis.del(OVERRIDE_KEY);
  console.log(`[admin] ${gate.user.username} reverted the enforcement settings to the config file`);
  return Response.json({ ok: true, reverted: removed > 0 });
}

/**
 * Reject what the gateway would reject, and a few things it would silently
 * accept but nobody means: an unknown detector name in the signal list, a score
 * outside 0-100.
 *
 * Returns a message, or null when the settings are usable.
 */
function validate(s) {
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
function isDuration(value) {
  return typeof value === "string" && /^(\d+(\.\d+)?(ns|us|µs|ms|s|m|h))+$/.test(value.trim());
}

// A rough shape check only. The gateway parses these properly and refuses the
// whole change if one is wrong; this is here to catch the typo at the keyboard.
function isCidrOrAddress(value) {
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

function parseJson(raw) {
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}
