import { require as requireRole } from "@/lib/auth";
import { readAdaptive } from "@/lib/adaptive";
import { getRedis } from "@/lib/redis";
import { readPolicies } from "@/lib/plane";

export const dynamic = "force-dynamic";

export async function GET() {
  const gate = await requireRole("viewer");
  if (gate.denied) return gate.denied;

  const durable = await readAdaptive();
  let activePolicies = [];
  let redis = true;
  try {
    activePolicies = await readPolicies(await getRedis());
  } catch {
    redis = false;
  }
  return Response.json({ ...durable, redis, activePolicies });
}
