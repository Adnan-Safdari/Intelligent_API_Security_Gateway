import { cookies } from "next/headers";
import { SESSION_COOKIE, destroySession } from "@/lib/auth";

export const dynamic = "force-dynamic";

export async function POST() {
  // Deleted server-side as well as in the browser, so a copied cookie dies too.
  await destroySession();
  (await cookies()).delete(SESSION_COOKIE);
  return Response.json({ ok: true });
}
