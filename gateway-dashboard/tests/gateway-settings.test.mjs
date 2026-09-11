import assert from "node:assert/strict";
import test from "node:test";
import {
  SECTIONS,
  isCidrOrAddress,
  isDuration,
  splitSettings,
  validateSettings,
} from "../lib/gateway-settings.mjs";

function fullSettings(overrides = {}) {
  const base = {
    rate_limit: { enabled: true, enforce: true, requests_per_minute: 800 },
    attack_detection: { enabled: true },
    brute_force: { enabled: true, max_failures: 12, window: "5m" },
    unknown_route_scanning: {
      enabled: true, window: "10m", distinct_paths: 8,
      max_paths_per_client: 200, max_clients: 500,
    },
    enumeration_path_traversal: { enabled: true },
    ip_reputation: { enabled: true, score: 70, cooldown: "15m" },
    throttle: { enabled: true, delay_ms: 0 },
    block: { enabled: true, signals: [], min_score: 60, exempt_cidrs: [], duration: "10m" },
    policy: { enabled: true },
  };
  return { ...base, ...overrides };
}

test("splitSettings puts adaptive_rate_limit in readOnly, never in the editable blob", () => {
  // Regression test: this field used to ride along in the editable settings
  // unfiltered, so a save touching an unrelated field failed with
  // "adaptive_rate_limit cannot be changed while the gateway is running".
  const effective = {
    source: "console",
    adaptive_rate_limit: { fallback_requests_per_minute: 300, burst: 50 },
    ...fullSettings(),
  };

  const { settings, readOnly, source } = splitSettings(effective);

  assert.equal(source, "console");
  assert.ok(!("adaptive_rate_limit" in settings));
  assert.deepEqual(readOnly.adaptive_rate_limit, { fallback_requests_per_minute: 300, burst: 50 });
  for (const section of SECTIONS) assert.ok(section in settings, `missing ${section}`);
});

test("a settings blob split by splitSettings always validates clean", () => {
  const { settings } = splitSettings({ source: "file", ...fullSettings() });
  assert.equal(validateSettings(settings), null);
});

test("validateSettings rejects a field outside SECTIONS", () => {
  const bad = { ...fullSettings(), adaptive_rate_limit: { burst: 1 } };
  assert.match(
    validateSettings(bad),
    /adaptive_rate_limit cannot be changed while the gateway is running/,
  );
});

test("validateSettings rejects a partial block -- omission is not 'leave alone'", () => {
  const { policy, ...missingPolicy } = fullSettings();
  assert.match(validateSettings(missingPolicy), /missing policy/);
});

test("validateSettings rejects an unknown block.signals entry (the path_traversal trap)", () => {
  const bad = fullSettings({ block: { ...fullSettings().block, signals: ["path_traversal"] } });
  assert.match(validateSettings(bad), /no detector is called "path_traversal"/);
});

test("validateSettings accepts the real block.signals vocabulary", () => {
  const ok = fullSettings({
    block: { ...fullSettings().block, signals: ["api_flooding", "enumeration_path_traversal"] },
  });
  assert.equal(validateSettings(ok), null);
});

test("validateSettings rejects a malformed duration", () => {
  const bad = fullSettings({ brute_force: { ...fullSettings().brute_force, window: "five minutes" } });
  assert.match(validateSettings(bad), /not a duration/);
});

test("isDuration accepts Go's compound Duration.String() form", () => {
  assert.ok(isDuration("1m0s"));
  assert.ok(isDuration("90s"));
  assert.ok(!isDuration("five minutes"));
});

test("isCidrOrAddress rejects an out-of-range octet and an oversized prefix", () => {
  assert.ok(isCidrOrAddress("203.0.113.0/24"));
  assert.ok(!isCidrOrAddress("203.0.999.0/24"));
  assert.ok(!isCidrOrAddress("203.0.113.0/99"));
});
