import { getRedis } from "@/lib/redis";
import { require as requireRole } from "@/lib/auth";
import {
  readAlerts,
  readCampaigns,
  readHeartbeat,
  readLearned,
  readPolicies,
} from "@/lib/plane";

export const dynamic = "force-dynamic";

// The readers live in lib/plane.js because the per-address investigation view
// asks the same questions of the same keys.

const EMPTY = {
  campaigns: [],
  policies: [],
  alerts: [],
  learned: [],
};

export async function GET() {
  // Reading is still reading a security system: campaigns, policy in force and
  // raw client addresses are not public.
  const gate = await requireRole("viewer");
  if (gate.denied) return gate.denied;

  try {
    const redis = await getRedis();
    const [campaigns, policies, alerts, learned, heartbeat] = await Promise.all([
      readCampaigns(redis),
      readPolicies(redis),
      readAlerts(redis),
      readLearned(redis),
      readHeartbeat(redis),
    ]);

    return Response.json({
      redis: true,
      campaigns,
      policies,
      alerts,
      learned,
      heartbeat,
      active: campaigns.filter((c) => c.status === "active").length,
    });
  } catch (err) {
    // Same contract as /api/overview: degrade to empty rather than break the
    // page, and say which half is unavailable.
    return Response.json(
      {
        redis: false,
        error: err.message,
        ...EMPTY,
        heartbeat: { alive: false },
        active: 0,
      },
      { status: 200 },
    );
  }
}
