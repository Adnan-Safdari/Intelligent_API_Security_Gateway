/**
 * Auth removed — the console runs open.
 *
 * The login system (accounts, sessions, RBAC, the login and setup screens) was
 * taken out. This small stub is all that remains, so the API routes that used
 * to guard themselves keep a stable import instead of every one of them being
 * edited: `require()` now always authorises, as a full admin, with no session.
 *
 * To put authentication back, restore this file from git history and reinstate
 * the gate in app/(console)/layout.js and the account menu in app/ui/chrome.jsx.
 */

// The single identity every request runs as now. Admin so that overrides,
// reset and everything else stay available; the console is trusted because
// whoever can reach it is trusted.
const OPEN_USER = { id: "0", username: "operator", role: "admin" };

// Always authorises. The shape matches what the routes expect: a truthy
// `user` and no `denied`, so `if (gate.denied) return gate.denied;` falls
// through to the handler.
export async function require() {
  return { user: OPEN_USER };
}

// Kept for any caller that still asks who is signed in.
export async function currentUser() {
  return OPEN_USER;
}
