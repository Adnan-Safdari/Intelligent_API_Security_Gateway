import { cookies } from "next/headers";
import { SESSION_COOKIE, db, require as requireRole, sha256 } from "@/lib/auth";

export const dynamic = "force-dynamic";

/** Where this account is currently signed in. */
export async function GET() {
  const gate = await requireRole("viewer");
  if (gate.denied) return gate.denied;

  const pool = await db();
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  const here = token ? sha256(token) : "";

  const { rows } = await pool.query(
    `SELECT token_hash, created_at, expires_at, user_agent
       FROM sessions
      WHERE user_id = $1 AND expires_at > now()
      ORDER BY created_at DESC`,
    [gate.user.id],
  );

  return Response.json({
    ok: true,
    sessions: rows.map((row) => ({
      // The hash never leaves the server; the browser only needs to know which
      // row is the one it is reading this from.
      current: row.token_hash === here,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
      userAgent: row.user_agent || "",
    })),
  });
}

/** Sign out everywhere except here. */
export async function DELETE() {
  const gate = await requireRole("viewer");
  if (gate.denied) return gate.denied;

  const pool = await db();
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  const { rowCount } = await pool.query(
    "DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2",
    [gate.user.id, token ? sha256(token) : ""],
  );

  return Response.json({ ok: true, ended: rowCount });
}
