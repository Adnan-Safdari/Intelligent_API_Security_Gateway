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
    object_enumeration: {
      enabled: true, window: "5m", distinct_ids: 20,
      max_ids_per_client: 256, max_clients: 10000,
    },
    object_ownership: { enabled: true, on_unverifiable: "deny", max_body_bytes: 1048576 },
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

test("object_enumeration may be absent, for a gateway that predates it", () => {
  const settings = fullSettings();
  delete settings.object_enumeration;
  assert.equal(validateSettings(settings), null);
});

test("object_enumeration limits are bounded", () => {
  const bad = [
    { distinct_ids: 1 },
    { distinct_ids: 300, max_ids_per_client: 256 },
    { max_clients: 100001 },
    { window: "soon" },
  ];
  for (const change of bad) {
    const settings = fullSettings();
    settings.object_enumeration = { ...settings.object_enumeration, ...change };
    assert.match(validateSettings(settings) || "", /object_enumeration/, JSON.stringify(change));
  }
});

test("object_ownership may be absent and is bounded when present", () => {
  const absent = fullSettings();
  delete absent.object_ownership;
  assert.equal(validateSettings(absent), null);

  for (const change of [{ on_unverifiable: "sometimes" }, { max_body_bytes: 10 }, { max_body_bytes: 1.5 }]) {
    const settings = fullSettings();
    settings.object_ownership = { ...settings.object_ownership, ...change };
    assert.match(validateSettings(settings) || "", /object_ownership/, JSON.stringify(change));
  }
});
