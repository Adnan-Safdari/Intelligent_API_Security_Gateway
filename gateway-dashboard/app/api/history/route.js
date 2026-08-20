import { getPool } from "@/lib/postgres";
import { require as requireRole } from "@/lib/auth";

export const dynamic = "force-dynamic";

// Live panels read Redis, which holds only the working set. This reads the
// record, so a campaign that ended last week is still here.
const RECENT = `
  SELECT campaign_id, type, severity, confidence, status, ips, stages,
         event_count, rotations, persistence, last_action, outcome,
         first_seen, last_seen
    FROM campaigns
   ORDER BY last_seen DESC
   LIMIT $1
`;

// One row per campaign type, which is the question worth asking of history:
// what keeps happening to us, and how hard did we have to hit it.
const BY_TYPE = `
  SELECT type,
         count(*)                          AS campaigns,
         sum(event_count)                  AS events,
         round(avg(confidence)::numeric, 2) AS avg_confidence,
         count(*) FILTER (WHERE status = 'contained') AS contained
    FROM campaigns
   GROUP BY type
   ORDER BY campaigns DESC, events DESC
`;

export async function GET(request) {
  // Reading is still reading a security system: campaigns, policy in force and
  // raw client addresses are not public.
  const gate = await requireRole("viewer");
  if (gate.denied) return gate.denied;

  const pool = getPool();
  if (!pool) {
    // Not an error. Durability is optional, and the console says so rather
    // than showing an empty panel that looks like "nothing ever happened".
    return Response.json({ available: false, campaigns: [], byType: [], total: 0 });
  }

  const limit = Math.min(
    Number(new URL(request.url).searchParams.get("limit") || 40) || 40,
    200,
  );

  try {
    const [recent, byType, total] = await Promise.all([
      pool.query(RECENT, [limit]),
      pool.query(BY_TYPE),
      pool.query("SELECT count(*)::int AS n FROM campaigns"),
    ]);

    return Response.json({
      available: true,
      total: total.rows[0]?.n ?? 0,
      campaigns: recent.rows.map((r) => ({
        id: String(r.campaign_id),
        type: r.type,
        severity: r.severity,
        confidence: Number(r.confidence),
        status: r.status,
        ipCount: (r.ips || []).length,
        stages: r.stages || [],
        events: r.event_count,
        rotations: r.rotations,
        persistence: r.persistence,
        lastAction: r.last_action || "",
        outcome: r.outcome || "",
        firstSeen: r.first_seen,
        lastSeen: r.last_seen,
      })),
      byType: byType.rows.map((r) => ({
        type: r.type,
        campaigns: Number(r.campaigns),
        events: Number(r.events),
        avgConfidence: Number(r.avg_confidence),
        contained: Number(r.contained),
      })),
    });
  } catch (err) {
    // The table may not exist yet if the agent has never run with Postgres on.
    return Response.json(
      { available: false, error: err.message, campaigns: [], byType: [], total: 0 },
      { status: 200 },
    );
  }
}
