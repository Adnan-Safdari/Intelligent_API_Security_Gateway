export function parseStats(hash = {}) {
  const stats = {
    requests: Number(hash.requests || 0),
    alerts: Number(hash.alerts || 0),
    decisions: {},
    signals: {},
  };

  for (const [key, value] of Object.entries(hash)) {
    const count = Number(value || 0);
    if (key.startsWith("decision:")) {
      stats.decisions[key.slice("decision:".length)] = count;
    } else if (key.startsWith("signal:")) {
      stats.signals[key.slice("signal:".length)] = count;
    }
  }

  return stats;
}

/**
 * Fill in counters the gateway would have published, from the events we can see.
 *
 * `iasg:stats` is written by the Go gateway alone. Anything that puts evidence
 * on the stream without it -- the seeder, a replay, the gateway having been
 * restarted since the counters were last reset -- leaves the hash empty, and
 * the console then reported zero requests and zero alerts above a screen full
 * of attacks. Zero is a claim, and it was the wrong one.
 *
 * The gateway's own numbers always win where it published them: these are a
 * floor taken from the visible window, not a replacement.
 */
export function withDerivedStats(stats, events = []) {
  if (!events.length) return { ...stats, derived: false };

  const alerts = events.filter((e) => e.fired?.length).length;
  const signals = { ...stats.signals };
  const decisions = { ...stats.decisions };

  if (!Object.keys(signals).length) {
    for (const event of events) {
      for (const name of event.fired || []) {
        signals[name] = (signals[name] || 0) + 1;
      }
    }
  }

  if (!Object.keys(decisions).length) {
    for (const event of events) {
      const decision = event.decision || (event.status >= 400 ? "blocked" : "allow");
      decisions[decision] = (decisions[decision] || 0) + 1;
    }
  }

  // Only when the window actually contributed something the gateway did not
  // report. A real gateway with zero alerts is publishing a true count, and
  // calling that "visible window" mislabels it.
  const derived = events.length > stats.requests || alerts > stats.alerts;
  return {
    requests: Math.max(stats.requests, events.length),
    alerts: Math.max(stats.alerts, alerts),
    decisions,
    signals,
    // The UI says so when it is showing a window rather than a lifetime count.
    derived,
  };
}

export function parseEventMessage(message = {}) {
  const raw = message.event;
  if (!raw) {
    return null;
  }
  try {
    return JSON.parse(typeof raw === "string" ? raw : raw.toString());
  } catch {
    return null;
  }
}
