import { getPool } from "@/lib/postgres";
import { require as requireRole } from "@/lib/auth";

export const dynamic = "force-dynamic";

/**
 * Throw away the durable record: campaigns and the agent's learned feedback.
 *
 * This exists because a demo needs a clean slate, and the alternative is
 * psql. It is deliberately narrow.
 *
 * What it will never touch:
 *
 *   users, sessions   Wiping these mid-session would sign everybody out and
 *                     drop the console back to /setup -- destroying the
 *                     accounts is not what "reset the data" means, and there
 *                     is already `npm run reset-accounts` for when it is.
 *   Redis             Live telemetry and policy keys are the gateway's, not
 *                     the record's. Policy expires by itself; deleting keys
 *                     from under the gateway is not a reset, it is enforcement
 *                     by another name.
 *
 * Admin only, and it asks the caller to name the thing being destroyed, so a
 * mis-click cannot do it.
 */

// Reset together or not at all: feedback refers to campaign types, so keeping
// one without the other leaves the agent learning from a record that is gone.
const TABLES = ["campaigns", "feedback"];

export async function POST(request) {
  const gate = await requireRole("admin");
  if (gate.denied) return gate.denied;

  const pool = getPool();
  if (!pool) {
    return Response.json(
      { ok: false, error: "no durable store configured (IASG_POSTGRES_URL unset)" },
      { status: 400 },
    );
  }

  let body = {};
  try {
    body = await request.json();
  } catch {
    /* an empty body fails the confirmation below, which is the right answer */
  }

  if (body.confirm !== "reset") {
    return Response.json(
      { ok: false, error: 'type "reset" to confirm' },
      { status: 400 },
    );
  }

  const client = await pool.connect();
  try {
    const before = {};
    for (const table of TABLES) {
      const { rows } = await client.query(`SELECT count(*)::int AS n FROM ${table}`);
      before[table] = rows[0].n;
    }

    // One transaction: a half-cleared record is worse than either state.
    await client.query("BEGIN");
    await client.query(`TRUNCATE ${TABLES.join(", ")}`);
    // Campaign numbering restarts, so the next demo reads #1 rather than #47.
    // Non-fatal: the sequence only exists once the control plane has created
    // it, and a reset before the agent has ever run is still a valid reset.
    await client
      .query("SELECT setval('campaign_id_seq', 1, false)")
      .catch(() => {});
    await client.query("COMMIT");

    console.log(
      `[admin] ${gate.user.username} reset the durable record:`,
      TABLES.map((t) => `${t}=${before[t]}`).join(" "),
    );

    return Response.json({ ok: true, cleared: before, tables: TABLES });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    return Response.json({ ok: false, error: err.message }, { status: 500 });
  } finally {
    client.release();
  }
}
