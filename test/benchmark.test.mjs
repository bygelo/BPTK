// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { runPromotionSelfAudit } from "../lib/benchmark.mjs";

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

test("the promotion self-audit rejects every sabotage fixture", () => {
  const audit = runPromotionSelfAudit();
  assert.equal(audit.sabotage_count, 5);
  assert.equal(audit.all_rejected, true);
  for (const entry of audit.check) assert.equal(entry.is_rejected, true, `${entry.sabotage} leaked`);
});

test("each sabotage class is individually caught by its real predicate", () => {
  const audit = runPromotionSelfAudit();
  const byName = Object.fromEntries(audit.check.map((entry) => [entry.sabotage, entry.is_rejected]));
  assert.equal(byName.wrong_return, true);
  assert.equal(byName.out_of_tolerance_frame, true);
  assert.equal(byName.inflated_rating, true);
  assert.equal(byName.stale_provenance, true);
  assert.equal(byName.nondeterministic_replay, true);
});
