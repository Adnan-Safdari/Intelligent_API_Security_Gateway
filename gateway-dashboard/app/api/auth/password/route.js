import { cookies } from "next/headers";
import {
  SESSION_COOKIE,
  db,
  hashPassword,
  require as requireRole,
  sha256,
  verifyPassword,
} from "@/lib/auth";

export const dynamic = "force-dynamic";

/**
 * Change your own password.
 *
 * PATCH /api/users/[id] can also set a password, but it is admin only -- so
 * until now a viewer or an operator had no way to change their own, and asking
 * an admin to set it means the admin knows it. This asks for the current
 * password instead of the admin role, which is the right check for the person
 * who already knows it.
 */
export async function POST(request) {
  const gate = await requireRole("viewer");
  if (gate.denied) return gate.denied;

  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ ok: false, error: "expected JSON" }, { status: 400 });
  }

  const current = String(body.current || "");
  const next = String(body.next || "");

  if (next.length < 10) {
    return Response.json(
      { ok: false, error: "password must be at least 10 characters" },
      { status: 400 },
    );
  }
  if (next === current) {
    return Response.json(
      { ok: false, error: "that is the password you already have" },
      { status: 400 },
    );
  }

  const pool = await db();
  const { rows } = await pool.query("SELECT password_hash FROM users WHERE id = $1", [
    gate.user.id,
  ]);
  if (!rows.length) {
    return Response.json({ ok: false, error: "unknown user" }, { status: 404 });
  }

  // Knowing the current password is what authorises this. Without it, anyone
  // who found an unlocked screen could lock the real owner out.
  if (!(await verifyPassword(current, rows[0].password_hash))) {
    return Response.json(
      { ok: false, error: "current password is wrong" },
      { status: 403 },
    );
  }

  await pool.query("UPDATE users SET password_hash = $1 WHERE id = $2", [
    await hashPassword(next),
    gate.user.id,
  ]);

  // Every other session for this account dies with the old password -- that is
  // the point of changing it -- but not this one, or you would be signed out
  // by your own success.
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  const { rowCount } = await pool.query(
    "DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2",
    [gate.user.id, token ? sha256(token) : ""],
  );

  return Response.json({ ok: true, signedOutElsewhere: rowCount });
}
