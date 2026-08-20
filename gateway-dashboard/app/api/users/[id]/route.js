import { ROLES, db, hashPassword, require as requireRole } from "@/lib/auth";

export const dynamic = "force-dynamic";

/** Postgres compares this against a BIGINT; anything else is a 500, not a 400. */
function numeric(id) {
  return /^\d+$/.test(String(id));
}

/** The last enabled admin may not be removed or demoted, or nobody can administer. */
async function otherAdmins(pool, id) {
  const { rows } = await pool.query(
    "SELECT count(*)::int AS n FROM users WHERE role = 'admin' AND disabled = FALSE AND id <> $1",
    [id],
  );
  return rows[0].n;
}

export async function PATCH(request, { params }) {
  const gate = await requireRole("admin");
  if (gate.denied) return gate.denied;

  const { id } = await params;
  if (!numeric(id)) {
    return Response.json({ ok: false, error: "unknown user" }, { status: 404 });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ ok: false, error: "expected JSON" }, { status: 400 });
  }

  const pool = await db();

  if (body.role !== undefined) {
    if (!ROLES.includes(body.role)) {
      return Response.json({ ok: false, error: "unknown role" }, { status: 400 });
    }
    if (body.role !== "admin" && !(await otherAdmins(pool, id))) {
      return Response.json(
        { ok: false, error: "that is the last admin — promote someone else first" },
        { status: 409 },
      );
    }
    await pool.query("UPDATE users SET role = $1 WHERE id = $2", [body.role, id]);
  }

  if (body.disabled !== undefined) {
    if (body.disabled && !(await otherAdmins(pool, id))) {
      return Response.json(
        { ok: false, error: "that is the last admin — promote someone else first" },
        { status: 409 },
      );
    }
    await pool.query("UPDATE users SET disabled = $1 WHERE id = $2", [
      Boolean(body.disabled),
      id,
    ]);
    // Disabling someone should log them out, not wait for their session to age.
    if (body.disabled) {
      await pool.query("DELETE FROM sessions WHERE user_id = $1", [id]);
    }
  }

  if (body.password !== undefined) {
    if (String(body.password).length < 10) {
      return Response.json(
        { ok: false, error: "password must be at least 10 characters" },
        { status: 400 },
      );
    }
    await pool.query("UPDATE users SET password_hash = $1 WHERE id = $2", [
      await hashPassword(body.password),
      id,
    ]);
    // Every other session for that account dies with the old password.
    await pool.query("DELETE FROM sessions WHERE user_id = $1", [id]);
  }

  return Response.json({ ok: true });
}

export async function DELETE(_request, { params }) {
  const gate = await requireRole("admin");
  if (gate.denied) return gate.denied;

  const { id } = await params;
  if (!numeric(id)) {
    return Response.json({ ok: false, error: "unknown user" }, { status: 404 });
  }
  if (String(gate.user.id) === String(id)) {
    return Response.json(
      { ok: false, error: "you cannot delete your own account" },
      { status: 409 },
    );
  }

  const pool = await db();
  if (!(await otherAdmins(pool, id))) {
    return Response.json(
      { ok: false, error: "that is the last admin — promote someone else first" },
      { status: 409 },
    );
  }

  // Sessions cascade with the row.
  await pool.query("DELETE FROM users WHERE id = $1", [id]);
  return Response.json({ ok: true });
}
