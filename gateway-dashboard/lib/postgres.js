import { Pool } from "pg";

const globalForPg = globalThis;

/**
 * The durable store, or null when there isn't one.
 *
 * Optional on purpose, exactly as it is for the control plane: without
 * IASG_POSTGRES_URL the console simply has no history to show, and every
 * live panel keeps working from Redis.
 */
export function getPool() {
  const url = process.env.IASG_POSTGRES_URL || process.env.DATABASE_URL;
  if (!url) return null;

  if (!globalForPg.__iasgPool) {
    const pool = new Pool({
      connectionString: url,
      max: 4,
      connectionTimeoutMillis: 2000,
      idleTimeoutMillis: 30_000,
    });
    // An idle client erroring out must not take the process with it.
    pool.on("error", (err) => console.error("postgres:", err.message));
    globalForPg.__iasgPool = pool;
  }

  return globalForPg.__iasgPool;
}
