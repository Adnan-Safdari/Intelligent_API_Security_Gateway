import assert from "node:assert/strict";
import test from "node:test";
import { isRoutineDockerHealthcheck } from "../lib/telemetry.js";

test("only a successful loopback Docker probe is treated as routine", () => {
  assert.ok(isRoutineDockerHealthcheck({
    ip: "::1",
    method: "GET",
    path: "/api/health",
    status: 200,
    userAgent: "IASG-Docker-Healthcheck",
    fired: [],
  }));
});

test("an attack against the health endpoint remains visible", () => {
  assert.ok(!isRoutineDockerHealthcheck({
    ip: "203.0.113.48",
    method: "GET",
    path: "/api/health",
    status: 200,
    userAgent: "IASG-Docker-Healthcheck",
    fired: ["sql_injection"],
  }));
});
