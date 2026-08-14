import { getRedis } from "@/lib/redis";
import { isPrivateIP, lookupGeo, lookupSelfGeo, summarizeSources } from "@/lib/geo";
import { parseEventMessage, parseStats } from "@/lib/telemetry";

export const dynamic = "force-dynamic";

export async function GET() {
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

    return Response.json({
      redis: true,
      stats: parseStats(hash),
      attackers: (attackers || []).map((row) => ({
        ip: row.value,
        alerts: row.score,
      })),
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
