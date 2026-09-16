import assert from "node:assert/strict";
import test from "node:test";
import { MIN_EVENTS, setupChecks, suggestTemplate } from "../lib/setup-checks.mjs";

const event = (ip, path, extra = {}) => ({
  ip,
  method: "GET",
  path,
  routeTemplate: "/known",
  fired: [],
  ...extra,
});
const unmatched = (ip, path, extra = {}) => event(ip, path, { routeTemplate: "<unmatched>", ...extra });
const ids = (checks) => checks.map((c) => c.id);

test("a quiet gateway raises nothing", () => {
  assert.deepEqual(setupChecks([]), []);
});

test("traffic attributed to one private proxy is flagged", () => {
  const events = Array.from({ length: MIN_EVENTS }, () => event("172.18.0.5", "/known"));
  const [check] = setupChecks(events);

  assert.equal(check.id, "private-sources");
  assert.match(check.detail, /100% of the last 30 requests/);
  assert.match(check.detail, /trusted_proxies/);
  assert.deepEqual(check.items, [{ label: "172.18.0.5", value: "30 requests" }]);
});

test("a handful of local requests is not a deployment", () => {
  const events = Array.from({ length: MIN_EVENTS - 1 }, () => event("127.0.0.1", "/known"));
  assert.deepEqual(setupChecks(events), []);
});

test("mostly public clients are identified correctly", () => {
  const events = [
    ...Array.from({ length: 27 }, (_, i) => event(`203.0.113.${i + 1}`, "/known")),
    ...Array.from({ length: 3 }, () => event("10.0.0.2", "/known")),
  ];
  assert.deepEqual(setupChecks(events), []);
});

test("an endpoint several clients keep calling is a missing route", () => {
  const events = [];
  for (const ip of ["203.0.113.1", "203.0.113.2", "203.0.113.3"]) {
    for (let id = 1; id <= 3; id++) events.push(unmatched(ip, `/users/${id}`));
  }
  const checks = setupChecks(events);

  assert.deepEqual(ids(checks), ["missing-routes"]);
  assert.deepEqual(checks[0].items, [{ label: "GET /users/{id}", value: "9 requests · 3 clients" }]);
});

test("a scanner walking paths once each is not a missing route", () => {
  const events = Array.from({ length: 40 }, (_, i) => unmatched("198.51.100.7", `/probe-${i}`, {
    fired: i >= 7 ? ["unknown_route_scanning"] : [],
  }));
  assert.deepEqual(ids(setupChecks(events)), []);
});

test("a botnet probing one path once per address is not a missing route", () => {
  const events = Array.from({ length: 10 }, (_, i) => unmatched(`198.51.100.${i + 1}`, "/wp-login.php"));
  assert.deepEqual(ids(setupChecks(events)), []);
});

test("requests a path detector flagged never suggest a route", () => {
  const events = [];
  for (const ip of ["203.0.113.1", "203.0.113.2"]) {
    for (let i = 0; i < 5; i++) {
      events.push(unmatched(ip, "/.env", { fired: ["enumeration_path_traversal"] }));
    }
  }
  assert.deepEqual(ids(setupChecks(events)), []);
});

test("clients flagged as scanners because of the gap still reveal the route", () => {
  // The case this exists for: a real endpoint missing from the table makes its
  // own clients fire unknown_route_scanning. That must not hide it.
  const events = [];
  for (const ip of ["203.0.113.1", "203.0.113.2"]) {
    for (let id = 1; id <= 4; id++) {
      events.push(unmatched(ip, `/orders/${id}`, { fired: ["unknown_route_scanning"] }));
    }
  }
  assert.deepEqual(ids(setupChecks(events)), ["missing-routes"]);
});

test("only segments that look like identifiers become {id}", () => {
  assert.equal(suggestTemplate("/users/42/orders"), "/users/{id}/orders");
  assert.equal(suggestTemplate("/orders/3f2504e0-4f89-11d3-9a0c-0305e82c3301"), "/orders/{id}");
  assert.equal(suggestTemplate("/auth/password-reset-confirmation"), "/auth/password-reset-confirmation");
  assert.equal(suggestTemplate("/files/a1b2c3d4e5f6a7b8c9d0"), "/files/{id}");
});
