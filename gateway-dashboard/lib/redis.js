import { createClient } from "redis";

const globalForRedis = globalThis;

export async function getRedis() {
  if (!globalForRedis.__iasgRedis) {
    const host = process.env.REDIS_HOST || "127.0.0.1";
    const port = process.env.REDIS_PORT || "6379";
    const client = createClient({
      url: `redis://${host}:${port}`,
      socket: {
        connectTimeout: 1500,
        reconnectStrategy: (retries) => Math.min(retries * 200, 2000),
      },
    });
    client.on("error", (err) => {
      console.error("redis:", err.message);
    });
    globalForRedis.__iasgRedis = client;
    globalForRedis.__iasgRedisReady = client.connect();
  }

  try {
    await globalForRedis.__iasgRedisReady;
  } catch (err) {
    globalForRedis.__iasgRedis = null;
    globalForRedis.__iasgRedisReady = null;
    throw err;
  }

  return globalForRedis.__iasgRedis;
}
