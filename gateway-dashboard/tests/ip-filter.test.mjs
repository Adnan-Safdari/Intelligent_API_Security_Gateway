import assert from "node:assert/strict";
import test from "node:test";
import { isValidIp } from "../app/ui/format.js";

test("isValidIp accepts a plain IPv4 address", () => {
  assert.ok(isValidIp("203.0.113.5"));
});

test("isValidIp accepts a plain IPv6 address", () => {
  assert.ok(isValidIp("2001:db8::1"));
});

test("isValidIp treats an empty string as 'no filter', not invalid", () => {
  assert.ok(isValidIp(""));
  assert.ok(isValidIp("   "));
});

test("isValidIp rejects an out-of-range IPv4 octet", () => {
  assert.ok(!isValidIp("203.0.999.5"));
});

test("isValidIp rejects garbage and injection-shaped input", () => {
  assert.ok(!isValidIp("'; DROP TABLE campaigns; --"));
  assert.ok(!isValidIp("not-an-ip"));
  assert.ok(!isValidIp("203.0.113.5/24")); // a CIDR range, not an exact address
});
