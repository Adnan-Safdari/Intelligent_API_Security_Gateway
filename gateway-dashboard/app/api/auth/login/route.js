import { cookies } from "next/headers";
import { SESSION_COOKIE, cookieOptions, login, userAgent } from "@/lib/auth";

export const dynamic = "force-dynamic";

export async function POST(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ ok: false, error: "expected JSON" }, { status: 400 });
  }

  try {
    const result = await login(body.username, body.password, await userAgent());
    if (!result.ok) {
      // 401 for every failure, with the same message: which half was wrong is
      // not the caller's business.
      return Response.json({ ok: false, error: result.error }, { status: 401 });
    }

    (await cookies()).set(SESSION_COOKIE, result.token, cookieOptions(result.expires));
    return Response.json({ ok: true, user: result.user });
  } catch (err) {
    return Response.json({ ok: false, error: err.message }, { status: 503 });
  }
}
