// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// BPTK-052 / GS-007 — SSE packed-SIMD strict-fallback conformance. The
// interpreter's packed single/double arithmetic and 128-bit logical ops (the
// primary path) must agree lane-for-lane with an independent strict IEEE-754
// reference (the strict fallback) within the declared tolerance. The 80-bit
// x87 and AVX-256 legs are declared gaps, so the benchmark stays honestly red.

import assert from "node:assert/strict";
import { test } from "node:test";
import { benchmarkPackedSimd, PACKED_TOLERANCE_ULP } from "../lib/simd.mjs";

test("simd: every declared packed operation matches the strict fallback exactly", () => {
  const report = benchmarkPackedSimd();
  assert.ok(report.supported_count >= 8, "the packed single/double and logical battery is served");
  for (const operation of report.operation) {
    assert.equal(operation.is_supported, true, `${operation.name} was not served: ${operation.stop_reason}`);
    assert.equal(operation.matches_strict, true, `${operation.name} primary ${operation.primary_hex} != strict ${operation.strict_hex}`);
  }
  assert.equal(report.is_strict_fallback_matching, true);
  assert.equal(PACKED_TOLERANCE_ULP, 0, "the deterministic packed ops match to zero ULP");
});

test("simd: the 80-bit x87 and AVX-256 legs stay honestly red", () => {
  const report = benchmarkPackedSimd();
  assert.equal(report.covers_80bit_x87, false);
  assert.equal(report.covers_avx256, false);
  assert.equal(report.is_bar_cleared, false);
  assert.ok(report.blocker.length >= 2);
});
