import { getRedis } from "@/lib/redis";
import { require as requireRole } from "@/lib/auth";
import { isPrivateIP, lookupGeo, lookupSelfGeo, summarizeSources } from "@/lib/geo";
import { parseEventMessage, parseStats, withDerivedStats } from "@/lib/telemetry";

export const dynamic = "force-dynamic";

export async function GET() {
  // Reading is still reading a security system: campaigns, policy in force and
  // raw client addresses are not public.
  const gate = await requireRole("viewer");
  if (gate.denied) return gate.denied;

  try {
    const redis = await getRedis();
    const [hash, stream, attackers] = await Promise.all([
      redis.hGetAll("iasg:stats"),
      redis.xRevRange("iasg:events", "+", "-", { COUNT: 80 }),
      redis.zRangeWithScores("iasg:attackers", 0, 9, { REV: true }),
    ]);

    const events = (stream || [])
      .map((entry) => {
        const event = parseEventMessage(entry.message);
        if (!event) return null;
        return { id: entry.id, ...event };
      })
      .filter(Boolean);

    const summarized = summarizeSources(events);
    const [geo, lab] = await Promise.all([
      lookupGeo(summarized.map((row) => row.ip)),
      lookupSelfGeo(),
    ]);
    const sources = summarized.map((row) => {
      const privateIP = isPrivateIP(row.ip);
      const loc = geo[row.ip];
      return {
        ...row,
        private: privateIP,
        lat: privateIP ? null : loc?.lat ?? null,
        lon: privateIP ? null : loc?.lon ?? null,
        city: privateIP ? "Private network" : loc?.city || "",
        country: privateIP ? "RFC1918" : loc?.country || "",
      };
    });

    const privateSources = sources.filter((row) => row.private);
    const site = lab
      ? {
          ...lab,
          requests: privateSources.reduce((sum, row) => sum + row.requests, 0),
          alerts: privateSources.reduce((sum, row) => sum + row.alerts, 0),
          ips: privateSources.map((row) => row.ip),
        }
      : null;

    // The zset is the gateway's. When it is empty -- seeded evidence, a replay
    // -- fall back to who is actually alerting in the window we can see.
    const ranked = (attackers || []).length
      ? attackers.map((row) => ({ ip: row.value, alerts: row.score }))
      : summarized
          .filter((row) => row.alerts > 0)
          // Sorted here, not inherited: summarizeSources orders by request
          // count, so taking its first ten could drop the loudest attacker.
          .sort((a, b) => b.alerts - a.alerts)
          .slice(0, 10)
          .map((row) => ({ ip: row.ip, alerts: row.alerts }));

    return Response.json({
      redis: true,
      stats: withDerivedStats(parseStats(hash), events),
      attackers: ranked,
      events,
      sources,
      site,
    });
  } catch (err) {
    return Response.json(
      {
        redis: false,
        error: err.message,
        stats: { requests: 0, alerts: 0, decisions: {}, signals: {} },
        attackers: [],
        events: [],
        sources: [],
        site: null,
      },
      { status: 200 },
    );
  }
}
