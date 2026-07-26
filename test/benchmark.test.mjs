// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const binPath = fileURLToPath(new URL("../bin/bptk.mjs", import.meta.url));

test("benchmark runs an ephemeral deterministic self-check without promoting blocked work", () => {
  const runValue = spawnSync(process.execPath, [binPath, "benchmark", "--json"], { encoding: "utf8" });
  assert.equal(runValue.status, 0);
  const report = JSON.parse(runValue.stdout);
  assert.equal(report.profile, "tooling_self_check");
  assert.equal(report.verdict, "pass");
  assert.equal(report.roadmap_promotion, false);
  assert.equal(report.check.every((entry) => entry.is_pass), true);
  assert.equal(report.blocker.includes("BPTK-001 legal approval is red"), true);
  assert.equal(report.blocker.includes("BPTK-002 corpus denominator is red"), true);
});
