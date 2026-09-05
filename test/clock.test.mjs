// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The guest clock and its frame pacer (BPTK-039 / BPTK-104). The vblank
// scheduler is deterministic over the one monotonic clock: a frame ready at a
// guest time presents on the next vertical-blank boundary, and a stall that
// misses one or more vblanks is counted as dropped rather than absorbed.

import assert from "node:assert/strict";
import { test } from "node:test";
import { createGuestClock, createFramePacer, clampDelta } from "../lib/clock.mjs";

test("the virtual clock advances only by the declared amount", () => {
  const clock = createGuestClock({ mode: "virtual_monotonic" });
  assert.equal(clock.elapsedGuestMs(), 0);
  clock.advanceVirtualMs(16);
  assert.equal(clock.elapsedGuestMs(), 16);
  assert.equal(clampDelta(1000, 100), 100, "a stall is clamped to the declared max delta");
  assert.equal(clampDelta(-5, 100), 0, "a backward delta is zero");
});

test("BPTK-104: the frame pacer syncs a frame to the next vblank boundary", () => {
  const pacer = createFramePacer({ refresh_hz: 60 });
  assert.ok(Math.abs(pacer.interval_ms - 1000 / 60) < 1e-9);
  // A frame ready before the first vblank presents on vblank 1 (16.67ms).
  assert.ok(Math.abs(pacer.deadlineMs(10) - 1000 / 60) < 1e-9);
  // A frame ready past the first vblank presents on vblank 2 (33.33ms).
  assert.ok(Math.abs(pacer.deadlineMs(20) - 2 * (1000 / 60)) < 1e-9);
  // A frame ready exactly on a boundary presents on that boundary.
  assert.ok(Math.abs(pacer.deadlineMs(1000 / 60) - 1000 / 60) < 1e-9);
});

test("BPTK-104: the pacer counts presented frames and reports dropped vblanks on a stall", () => {
  const pacer = createFramePacer({ refresh_hz: 60 });
  const interval = pacer.interval_ms;
  // Three frames on cadence: one per vblank.
  const a = pacer.present(interval * 1 - 1);
  const b = pacer.present(interval * 2 - 1);
  const c = pacer.present(interval * 3 - 1);
  assert.equal(a.dropped, 0);
  assert.equal(b.dropped, 0);
  assert.equal(c.dropped, 0);
  assert.equal(b.vblank_index - a.vblank_index, 1, "consecutive frames advance one vblank");
  // A stall of ~3 intervals drops the two vblanks it missed.
  const stalled = pacer.present(interval * 6 - 1);
  assert.equal(stalled.dropped, 2);
  assert.equal(stalled.is_on_cadence, false);
  const stats = pacer.stats();
  assert.equal(stats.presented_count, 4);
  assert.equal(stats.dropped_count, 2);
});

test("BPTK-104: the pacer reads its present time from the one guest clock", () => {
  const clock = createGuestClock({ mode: "virtual_monotonic" });
  const pacer = createFramePacer({ refresh_hz: 30 });
  clock.advanceVirtualMs(10);
  const first = pacer.presentFromClock(clock);
  clock.advanceVirtualMs(1000 / 30);
  const second = pacer.presentFromClock(clock);
  assert.equal(second.vblank_index - first.vblank_index, 1);
  assert.equal(second.dropped, 0);
});
