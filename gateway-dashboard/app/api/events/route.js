import { getRedis } from "@/lib/redis";
import { require as requireRole } from "@/lib/auth";
import { parseEventMessage } from "@/lib/telemetry";
import { isValidIp } from "@/app/ui/format";

export const dynamic = "force-dynamic";

/**
 * The event stream, deeper than the live poll reads it.
 *
 * /api/overview deliberately reads a small slice: it runs every 2.5 seconds and
 * feeds the metrics and the map, which do not get better for being fed
 * thousands of rows. Investigation is the opposite -- it needs everything the
 * gateway still has, which the stream caps at storage.redis.stream_maxlen.
 * Splitting them means the console can look back without making the live poll
 * expensive.
 *
 *   /api/events?limit=500                newest 500
 *   /api/events?limit=500&before=ID       the 500 before that, for paging
 *   /api/events?limit=500&ip=203.0.113.5  the newest 500 FROM that address
 *
 * `ip` filters server-side rather than over whatever page happened to load,
 * so a rare address is still findable without loading the whole stream into
 * the browser first. Because a Redis stream has no secondary index on `ip`,
 * satisfying it means scanning raw entries past ones that don't match --
 * MAX_SCAN_BATCHES bounds how much of the stream one request will scan, so a
 * filter matching almost nothing costs one bounded request, not an unbounded
 * one; "load older" (the `before` cursor) picks the scan back up from
 * exactly where the previous call stopped, so a sparse match is still
 * reachable, one bounded page at a time.
 */

// Matches storage.redis.stream_maxlen in gateway/configs/config.yaml. Asking
// for more than the stream retains is not an error, it just returns less.
const MAX_LIMIT = 2000;
const DEFAULT_LIMIT = 250;
const MAX_SCAN_BATCHES = 8;

export async function GET(request) {
  const gate = await requireRole("viewer");
  if (gate.denied) return gate.denied;

  const params = new URL(request.url).searchParams;
  const requested = Number(params.get("limit"));
  const limit = Math.min(
    MAX_LIMIT,
    Math.max(1, Number.isFinite(requested) && requested > 0 ? requested : DEFAULT_LIMIT),
  );
  const before = params.get("before");
  // A malformed value is treated as no filter rather than a 400 -- this is a
  // read, and "show everything" is a safer failure here than an error page
  // mid-investigation. The dashboard's own IpFilterField never sends one.
  const ipParam = (params.get("ip") || "").trim();
  const ip = isValidIp(ipParam) ? ipParam : "";

  try {
    const redis = await getRedis();
    const total = await redis.xLen("iasg:events").catch(() => 0);

    const events = [];
    // "(" makes the range exclusive, so paging cannot return the row the
    // previous page ended on. Redis 6.2 and later.
    let cursor = before ? `(${before}` : "+";
    let lastSeenId = null;
    let reachedStart = false;

    for (let batch = 0; batch < MAX_SCAN_BATCHES && events.length < limit; batch++) {
      const entries = await redis.xRevRange("iasg:events", cursor, "-", { COUNT: limit });
      if (!entries || entries.length === 0) {
        reachedStart = true;
        break;
      }
      for (const entry of entries) {
        lastSeenId = entry.id;
        const event = parseEventMessage(entry.message);
        if (event && (!ip || event.ip === ip)) {
          events.push({ id: entry.id, ...event });
        }
        if (events.length >= limit) break;
      }
      cursor = `(${lastSeenId}`;
      // A short batch means the stream ran out, not that this call chose to
      // stop -- no amount of "load older" will find more after this.
      if (entries.length < limit) {
        reachedStart = true;
        break;
      }
    }

    return Response.json({
      redis: true,
      events,
      total,
      ip: ip || null,
      // Null only once the scan genuinely reached the start of the stream --
      // filling the page early, or hitting the scan cap with more stream
      // left, both still have more to look at.
      cursor: !reachedStart && lastSeenId ? lastSeenId : null,
    });
  } catch (err) {
    return Response.json(
      { redis: false, error: err.message, events: [], total: 0, cursor: null },
      { status: 200 },
    );
  }
}
