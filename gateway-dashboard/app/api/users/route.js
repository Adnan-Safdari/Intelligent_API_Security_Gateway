import { ROLES, createUser, db, require as requireRole } from "@/lib/auth";

export const dynamic = "force-dynamic";

export async function GET() {
  const gate = await requireRole("admin");
  if (gate.denied) return gate.denied;

  const pool = await db();
  const { rows } = await pool.query(
    `SELECT id, username, role, disabled, created_at, last_login_at,
            (SELECT count(*)::int FROM sessions s
              WHERE s.user_id = users.id AND s.expires_at > now()) AS sessions
       FROM users ORDER BY username`,
  );

  return Response.json({
    ok: true,
    me: gate.user,
    users: rows.map((r) => ({
      id: String(r.id),
      username: r.username,
      role: r.role,
      disabled: r.disabled,
      sessions: r.sessions,
      createdAt: r.created_at,
      lastLoginAt: r.last_login_at,
    })),
  });
}

export async function POST(request) {
  const gate = await requireRole("admin");
  if (gate.denied) return gate.denied;

  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ ok: false, error: "expected JSON" }, { status: 400 });
  }

  if (!ROLES.includes(body.role)) {
    return Response.json(
      { ok: false, error: `role must be one of ${ROLES.join(", ")}` },
      { status: 400 },
    );
  }

  try {
    const user = await createUser(body);
    return Response.json({ ok: true, user: { ...user, id: String(user.id) } });
  } catch (err) {
    return Response.json({ ok: false, error: err.message }, { status: 400 });
  }
}
