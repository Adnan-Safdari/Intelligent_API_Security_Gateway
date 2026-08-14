export function isPrivateIP(ip = "") {
  if (!ip) return true;
  if (ip === "127.0.0.1" || ip === "::1" || ip === "localhost") return true;
  if (ip.startsWith("10.")) return true;
  if (ip.startsWith("192.168.")) return true;
  if (ip.startsWith("169.254.")) return true;
  const m = ip.match(/^172\.(\d+)\./);
  if (m) {
    const n = Number(m[1]);
    return n >= 16 && n <= 31;
  }
  return false;
}

const cache = globalThis.__iasgGeoCache || new Map();
globalThis.__iasgGeoCache = cache;

async function fetchJson(url, options = {}, timeoutMs = 1800) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export async function lookupSelfGeo() {
  if (cache.has("__self__")) return cache.get("__self__");
  const row = await fetchJson("http://ip-api.com/json/?fields=status,query,lat,lon,city,country,org");
  const self =
    row?.status === "success" && row.lat != null && row.lon != null
      ? { lat: row.lat, lon: row.lon, city: row.city || "", country: row.country || "", ip: row.query || "" }
      : null;
  cache.set("__self__", self);
  return self;
}

export async function lookupGeo(ips) {
  const unique = [...new Set(ips.filter((ip) => ip && !isPrivateIP(ip)))];
  const missing = unique.filter((ip) => !cache.has(ip));

  if (missing.length > 0) {
    const rows = await fetchJson(
      "http://ip-api.com/batch?fields=status,query,lat,lon,city,country,org",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(missing.slice(0, 80)),
      },
    );
    for (const row of rows || []) {
      if (row?.query) {
        cache.set(row.query, row.status === "success" ? row : { private: false });
      }
    }
  }

  return Object.fromEntries(unique.map((ip) => [ip, cache.get(ip) || null]));
}

export function summarizeSources(events = []) {
  const byIp = new Map();
  for (const event of events) {
    const ip = event.ip;
    if (!ip) continue;
    const current = byIp.get(ip) || { ip, requests: 0, alerts: 0, lastRisk: 0 };
    current.requests += 1;
    if (event.fired?.length) current.alerts += 1;
    current.lastRisk = Math.max(current.lastRisk, event.riskScore || 0);
    byIp.set(ip, current);
  }
  return [...byIp.values()].sort((a, b) => b.requests - a.requests);
}
