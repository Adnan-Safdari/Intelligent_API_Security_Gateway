import { redirect } from "next/navigation";
import { currentUser, userCount } from "@/lib/auth";
import { LiveProvider } from "@/app/ui/store";
import { Shell } from "@/app/ui/chrome";

/**
 * The gate for everything in the console.
 *
 * A server component, so the check happens before any of it is sent. The API
 * routes check again for themselves -- this stops a page being rendered, not a
 * request being made, and only one of those is authorisation.
 */
export default async function ConsoleLayout({ children }) {
  let needsSetup = false;
  try {
    needsSetup = (await userCount()) === 0;
  } catch (err) {
    // No database means no accounts, and a security console that runs
    // unauthenticated is worse than one that refuses to start.
    return (
      <div className="gate">
        <div className="gate-card">
          <h1>Console unavailable</h1>
          <p>{err.message}</p>
          <p className="form-note">
            Campaign memory and user accounts both live in Postgres. Set{" "}
            <code>IASG_POSTGRES_URL</code> and restart the dashboard.
          </p>
        </div>
      </div>
    );
  }

  if (needsSetup) redirect("/setup");

  const user = await currentUser();
  if (!user) redirect("/login");

  return (
    <LiveProvider me={user}>
      <Shell>{children}</Shell>
    </LiveProvider>
  );
}
