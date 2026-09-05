// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";
import { computeCompatibilityRating } from "../lib/report.mjs";

const provenance = { boots: "replay:aa", in_game: "replay:bb", playable: "replay:cc", complete: "replay:dd" };

test("the rating ladder grants each rung only on a passing, evidence-backed predicate", () => {
  const full = computeCompatibilityRating({ predicate: { boots: true, in_game: true, playable: true, complete: true }, provenance });
  assert.equal(full.rating, "complete");
  assert.equal(full.is_false_green, false);
  assert.equal(full.is_provenance_backed, true);

  const partial = computeCompatibilityRating({ predicate: { boots: true, in_game: true }, provenance });
  assert.equal(partial.rating, "in_game");
});

test("a passing higher rung above a failed lower rung never lifts the rating (no false green)", () => {
  // boots fails but playable "passes" — the contiguous ceiling is still broken.
  const gap = computeCompatibilityRating({ predicate: { boots: false, in_game: true, playable: true }, provenance });
  assert.equal(gap.rating, "broken");
  assert.equal(gap.is_false_green, false);
  assert.match(gap.stop_reason, /predicate for boots did not pass/);
});

test("a rung that passes its predicate but carries no evidence is not granted", () => {
  const unbacked = computeCompatibilityRating({ predicate: { boots: true, in_game: true }, provenance: { boots: "replay:aa" } });
  assert.equal(unbacked.rating, "boots");
  assert.match(unbacked.stop_reason, /no backing evidence/);
});

test("with no passing predicate the honest rating is broken", () => {
  const none = computeCompatibilityRating({ predicate: {}, provenance: {} });
  assert.equal(none.rating, "broken");
  assert.equal(none.rating_index, 0);
});
