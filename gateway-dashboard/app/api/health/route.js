import { getRedis } from "@/lib/redis";

export async function GET() {
  try {
    const redis = await getRedis();
    await redis.ping();
    return Response.json({ status: "ok", redis: true });
  } catch {
    return Response.json({ status: "degraded", redis: false }, { status: 503 });
  }
}
