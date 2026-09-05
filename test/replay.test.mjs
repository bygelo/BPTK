// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// BPTK-055 / GS-010 — CPU-deterministic record & replay. A recorded run pins
// every declared nondeterminism source (virtual-monotonic clock, no host RNG,
// no host input, single-thread schedule) and captures the guest state hash at
// instruction-count checkpoints. Replaying re-derives them and must hash-match
// exactly, and the recompiler and interpreter must agree at every checkpoint —
// the foundation for cross-machine reproducibility. The literal second-machine
// leg and multi-threaded schedule determinism stay honestly red.

import assert from "node:assert/strict";
import { test } from "node:test";
import { recordRun, replayRun, PINNED_SOURCE } from "../lib/replay.mjs";

test("replay: two replays of a recorded run hash-match at every checkpoint", async () => {
  const record = await recordRun({ instruction_budget_count: 4096, checkpoint_count: 4 });
  assert.ok(record.checkpoint.length >= 4);
  const first = await replayRun(record);
  const second = await replayRun(record);
  assert.equal(first.is_match, true, `first replay mismatch: ${JSON.stringify(first.mismatch)}`);
  assert.equal(second.is_match, true, `second replay mismatch: ${JSON.stringify(second.mismatch)}`);
  assert.equal(first.mismatch.length, 0);
});

test("replay: the recompiler and interpreter agree at every checkpoint", async () => {
  const record = await recordRun({ instruction_budget_count: 4096, checkpoint_count: 4 });
  const replay = await replayRun(record);
  assert.equal(replay.cross_engine_match, true, "cross-engine determinism underpins cross-machine replay");
});

test("replay: no pinned nondeterminism source is read from the host environment", async () => {
  const record = await recordRun({ instruction_budget_count: 2048, checkpoint_count: 3 });
  assert.equal(record.is_host_source_free, true);
  assert.equal(record.pinned_source.clock, "virtual_monotonic");
  assert.equal(record.pinned_source.rng, "none");
  assert.equal(record.pinned_source.input, "none");
  assert.equal(PINNED_SOURCE.schedule, "single_thread");
});

test("replay: a tampered checkpoint hash is detected as a divergence", async () => {
  const record = await recordRun({ instruction_budget_count: 2048, checkpoint_count: 3 });
  record.checkpoint[1].state_hash = "0".repeat(64);
  const replay = await replayRun(record);
  assert.equal(replay.is_match, false);
  assert.ok(replay.mismatch.some((entry) => entry.instruction_count === record.checkpoint[1].instruction_count));
});

test("replay: the cross-machine and SMP legs stay honestly red", async () => {
  const record = await recordRun({ instruction_budget_count: 2048, checkpoint_count: 2 });
  const replay = await replayRun(record);
  assert.equal(replay.second_machine_verified, false);
  assert.ok(replay.blocker.length >= 2, "the second-machine and SMP-schedule blockers must be declared");
});
