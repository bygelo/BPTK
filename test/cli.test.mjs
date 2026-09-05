// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const binPath = fileURLToPath(new URL("../bin/bptk.mjs", import.meta.url));

function run(argument = []) {
  return spawnSync(process.execPath, [binPath, ...argument], { encoding: "utf8" });
}

test("default command is an honest pre-alpha help surface", () => {
  const result = run();
  assert.equal(result.status, 0);
  assert.match(result.stdout, /roadmap tooling preview/);
  assert.match(result.stdout, /working name/);
  assert.match(result.stdout, /No game runtime exists/);
});

test("status JSON exposes the immutable roadmap snapshot", () => {
  const result = run(["status", "--json"]);
  const value = JSON.parse(result.stdout);
  assert.equal(result.status, 0);
  assert.equal(value.snapshot, true);
  assert.equal(value.count.accepted, 145);
  assert.equal(value.count.implemented, 46);
  assert.equal(value.count.passing, 0);
  assert.match(value.source.sha256, /^[a-f0-9]{64}$/);
});

test("doctor reports facts without claiming compatibility", () => {
  const result = run(["doctor", "--json"]);
  const value = JSON.parse(result.stdout);
  assert.equal(result.status, 0);
  assert.equal(value.runtime, "node");
  assert.ok(Array.isArray(value.capability));
  assert.match(value.scope, /compatibility is NOT tested/);
  assert.match(value.scope, /no game runtime exists/);
});

test("text commands retain the no-runtime boundary", () => {
  const statusResult = run(["status"]);
  const doctorResult = run(["doctor"]);
  assert.equal(statusResult.status, 0);
  assert.equal(doctorResult.status, 0);
  assert.match(statusResult.stdout, /not compatibility evidence/);
  assert.match(doctorResult.stdout, /compatibility is NOT tested/);
});

test("unknown input fails with usage", () => {
  const result = run(["port", "game.exe"]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Unknown command or option/);
  assert.match(result.stderr, /Usage:/);
});
