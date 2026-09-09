/**
 * Readers for everything the control plane writes.
 *
 * /api/overview reads what the gateway saw; these read what the agent
 * concluded about it. They live here rather than inside one route because more
 * than one route needs them -- the campaigns feed and the per-address
 * investigation view ask the same questions of the same keys.
 */

export const CAMPAIGN_PREFIX = "campaign:";
export const POLICY_PREFIX = "policy:";
export const FEEDBACK_PREFIX = "feedback:";
export const ALERT_STREAM = "iasg_alerts";

// Written at the end of every cycle with a TTL of a few intervals, so its
// absence means the agent stopped rather than that the network went quiet.
// Reads the same variable the control plane does, or setting IASG_HEARTBEAT_KEY
// on one side would leave the console permanently reporting a dead agent.
export const HEARTBEAT_KEY = process.env.IASG_HEARTBEAT_KEY || "iasg:heartbeat";

// The id counter lives under the campaign prefix but is not a campaign.
const COUNTER_KEY = `${CAMPAIGN_PREFIX}next_id`;

/**
 * SCAN rather than KEYS, which blocks the Redis server on a large keyspace.
 * Mirrors what the control plane's own store does.
 */
export async function scanKeys(redis, match) {
  const found = [];
  for await (const key of redis.scanIterator({ MATCH: match, COUNT: 500 })) {
    // node-redis 4 yields one key per step; 5 yields a batch.
    if (Array.isArray(key)) found.push(...key);
    else found.push(key);
  }
  return found;
}

export function parseJson(raw) {
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export async function readCampaigns(redis) {
  const keys = (await scanKeys(redis, `${CAMPAIGN_PREFIX}*`)).filter(
    (key) => key !== COUNTER_KEY,
  );
  if (keys.length === 0) return [];

  const rows = (await redis.mGet(keys)).map(parseJson).filter(Boolean);

  return rows
    .map((c) => ({
      id: c.campaign_id || "",
      type: c.type || "Unclassified Activity",
      severity: c.severity || "low",
      confidence: Number(c.confidence || 0),
      status: c.status || "active",
      ips: c.ips || [],
      events: Number(c.event_count || 0),
      reason: c.reason || "",
      stages: c.stages || [],
      // The three counters that show the agent adapting rather than just
      // classifying. Worth surfacing even when they are zero.
      rotations: Number(c.rotations || 0),
      persistence: Number(c.persistence || 0),
      quietCycles: Number(c.quiet_cycles || 0),
      lastAction: c.last_action || "",
      outcome: c.outcome || "",
      explanation: c.explanation || "",
      assessment: c.assessment || "",
      firstSeen: c.first_seen || null,
      lastSeen: c.last_seen || null,
    }))
    // Active first, then whatever the agent is most sure about.
    .sort((a, b) => {
      if (a.status !== b.status) return a.status === "active" ? -1 : 1;
      return b.confidence - a.confidence;
    });
}

export async function readPolicies(redis) {
  const keys = await scanKeys(redis, `${POLICY_PREFIX}*`);
  if (keys.length === 0) return [];

  // Values and their remaining life. Capped per cycle by the control plane,
  // so this stays a small number of round trips.
  const [values, ttls] = await Promise.all([
    redis.mGet(keys),
    Promise.all(keys.map((key) => redis.ttl(key))),
  ]);

  return keys
    .map((key, i) => {
      const decision = parseJson(values[i]);
      if (!decision) return null;
      return {
        key,
        policyId: decision.policy_id || key,
        ip: decision.target_identity || key.slice(POLICY_PREFIX.length).split(":")[0],
        scope: decision.scope || "client",
        method: decision.endpoint_scope?.method || decision.method || "",
        routeTemplate: decision.endpoint_scope?.route_template || decision.route || "",
        action: decision.action || "",
        campaignId: decision.campaign_id || "",
        confidence: Number(decision.confidence || 0),
        riskScore: Number(decision.risk_score || 0),
        reason: decision.reason || "",
        source: decision.source || "agent",
        issuedAt: decision.issued_at || null,
        issuedBy: decision.issued_by || "control-plane",
        mode: decision.mode || "automatic",
        baselineVersion: decision.baseline_version || "",
        configVersion: Number(decision.config_version || 0),
        modelVersion: decision.model_version || "",
        explanation: decision.explanation || {},
        // What Redis says is left, not what was originally asked for -- the
        // difference is the point of a policy that expires by itself.
        expiresIn: Number(ttls[i] ?? -1),
      };
    })
    .filter(Boolean)
    .sort((a, b) => b.confidence - a.confidence);
}

export async function readAlerts(redis) {
  try {
    const entries = await redis.xRevRange(ALERT_STREAM, "+", "-", { COUNT: 20 });
    return (entries || []).map((entry) => ({
      id: entry.id,
      campaignId: entry.message.campaign_id || "",
      type: entry.message.type || "",
      severity: entry.message.severity || "",
      confidence: Number(entry.message.confidence || 0),
      ipCount: Number(entry.message.ip_count || 0),
      action: entry.message.action || "",
      explanation: entry.message.explanation || "",
      lastSeen: entry.message.last_seen || null,
    }));
  } catch {
    // The stream only exists once something has escalated.
    return [];
  }
}

export async function readLearned(redis) {
  const keys = await scanKeys(redis, `${FEEDBACK_PREFIX}*`);
  if (keys.length === 0) return [];

  const values = await redis.mGet(keys);
  return keys
    .map((key, i) => {
      const tally = parseJson(values[i]);
      if (!tally) return null;
      const up = Number(tally.up || 0);
      const down = Number(tally.down || 0);
      if (!up && !down) return null;
      return {
        type: key.slice(FEEDBACK_PREFIX.length),
        up,
        down,
        // Matches feedback/memory.py: net corrections, and the agent only
        // shifts once the same direction wins twice.
        net: up - down,
      };
    })
    .filter(Boolean)
    .sort((a, b) => Math.abs(b.net) - Math.abs(a.net));
}

export async function readHeartbeat(redis) {
  const beat = parseJson(await redis.get(HEARTBEAT_KEY));
  if (!beat?.at) return { alive: false };

  const secondsAgo = Math.max(
    0,
    Math.round((Date.now() - new Date(beat.at).getTime()) / 1000),
  );
  return {
    alive: true,
    at: beat.at,
    secondsAgo,
    intervalSeconds: Number(beat.interval_seconds || 30),
    // A cycle that has not happened within two intervals is late, which is
    // worth showing before the key expires and the agent looks simply gone.
    late: secondsAgo > Number(beat.interval_seconds || 30) * 2,
    durable: Boolean(beat.durable),
    dryRun: Boolean(beat.dry_run),
    mode: beat.mode || "unknown",
    configVersion: Number(beat.config_version || 0),
    modelAvailable: Boolean(beat.model_available),
    modelError: beat.model_error || "",
    lastCycle: {
      evidence: Number(beat.evidence || 0),
      campaigns: Number(beat.campaigns || 0),
      policiesWritten: Number(beat.policies_written || 0),
    },
  };
}

/** One address's current enforcement, or null when it is not under policy. */
export async function readPolicyFor(redis, ip) {
  const policies = await readPolicies(redis);
  return policies.find((policy) => policy.ip === ip) || null;
}
