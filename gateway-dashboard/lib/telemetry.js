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
