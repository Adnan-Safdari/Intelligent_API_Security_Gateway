import { getRedis } from "@/lib/redis";
import { require as requireRole } from "@/lib/auth";
import { POLICY_PREFIX } from "@/lib/plane";

export const dynamic = "force-dynamic";

// This removes only one validated policy:<ip> key. Unlike an override, it
// takes effect immediately; the agent can write a new policy next cycle if
// the campaign is still active.
export async function DELETE(_request, { params }) {
  const gate = await requireRole("operator");
  if (gate.denied) return gate.denied;

  const { address } = await params;
  const ip = decodeURIComponent(address || "").trim();
  if (!isAddress(ip)) {
    return Response.json({ ok: false, error: "not an IP address" }, { status: 400 });
  }

  try {
    const redis = await getRedis();
    const removed = await redis.del(`${POLICY_PREFIX}${ip}`);
    console.log(`[policy] ${gate.user.username} removed policy for ${ip}: ${removed ? "deleted" : "absent"}`);
    return Response.json({ ok: true, ip, removed: removed > 0 });
  } catch (err) {
    return Response.json({ ok: false, error: err.message }, { status: 503 });
  }
}

function isAddress(value) {
  const v4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (v4.test(value)) return value.split(".").every((part) => Number(part) <= 255);
  return /^[0-9a-fA-F:]+$/.test(value) && value.includes(":");
}
