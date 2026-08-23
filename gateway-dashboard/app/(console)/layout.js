import { LiveProvider } from "@/app/ui/store";
import { Shell } from "@/app/ui/chrome";

// Auth removed: the console is open, so there is no gate here any more. It
// still renders per-request rather than at build time -- the live panels must
// never be prerendered, or a stale snapshot gets baked into the HTML.
export const dynamic = "force-dynamic";

// Every request runs as this identity. Admin so the action controls stay
// enabled; see lib/auth.js.
const OPEN_USER = { id: "0", username: "operator", role: "admin" };

export default function ConsoleLayout({ children }) {
  return (
    <LiveProvider me={OPEN_USER}>
      <Shell>{children}</Shell>
    </LiveProvider>
  );
}
