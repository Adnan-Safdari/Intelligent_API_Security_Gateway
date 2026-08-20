import { cookies } from "next/headers";
import {
  SESSION_COOKIE,
  cookieOptions,
  createUser,
  login,
  userAgent,
  userCount,
} from "@/lib/auth";

export const dynamic = "force-dynamic";

/**
 * Create the first administrator.
 *
 * Open only while the users table is empty. Once anyone exists this is closed
 * for good, so it cannot be used to mint a second admin later.
 */
export async function POST(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ ok: false, error: "expected JSON" }, { status: 400 });
  }

  try {
    if ((await userCount()) > 0) {
      return Response.json(
        { ok: false, error: "setup has already been completed" },
        { status: 409 },
      );
    }

    await createUser({
      username: body.username,
      password: body.password,
      role: "admin",
    });

    // Sign them straight in; making someone log in immediately after choosing
    // a password only invites them to pick a memorable one.
    const result = await login(body.username, body.password, await userAgent());
    if (result.ok) {
      (await cookies()).set(SESSION_COOKIE, result.token, cookieOptions(result.expires));
    }
    return Response.json({ ok: true });
  } catch (err) {
    return Response.json({ ok: false, error: err.message }, { status: 400 });
  }
}

export async function GET() {
  try {
    return Response.json({ needed: (await userCount()) === 0 });
  } catch (err) {
    return Response.json({ needed: false, error: err.message }, { status: 503 });
  }
}
