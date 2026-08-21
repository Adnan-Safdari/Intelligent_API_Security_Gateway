import { getRedis } from "@/lib/redis";
import { require as requireRole } from "@/lib/auth";
import { parseEventMessage } from "@/lib/telemetry";

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
 *   /api/events?limit=500            newest 500
 *   /api/events?limit=500&before=ID  the 500 before that, for paging
 */

// Matches storage.redis.stream_maxlen in gateway/configs/config.yaml. Asking
// for more than the stream retains is not an error, it just returns less.
const MAX_LIMIT = 2000;
const DEFAULT_LIMIT = 250;

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

  try {
    const redis = await getRedis();

    // "(" makes the range exclusive, so paging cannot return the row the
    // previous page ended on. Redis 6.2 and later.
    const end = before ? `(${before}` : "+";

    const [entries, total] = await Promise.all([
      redis.xRevRange("iasg:events", end, "-", { COUNT: limit }),
      redis.xLen("iasg:events").catch(() => 0),
    ]);

    const events = (entries || [])
      .map((entry) => {
        const event = parseEventMessage(entry.message);
        return event ? { id: entry.id, ...event } : null;
      })
      .filter(Boolean);

    return Response.json({
      redis: true,
      events,
      total,
      // A full page implies there may be another. A short one is the end of
      // the stream, and saying so lets the button disappear.
      cursor: entries?.length === limit ? entries[entries.length - 1].id : null,
    });
  } catch (err) {
    return Response.json(
      { redis: false, error: err.message, events: [], total: 0, cursor: null },
      { status: 200 },
    );
  }
}
