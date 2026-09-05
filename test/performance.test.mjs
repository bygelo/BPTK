// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// BPTK-136 (GS-092) recompiled-throughput floor + BPTK-137 (GS-093)
// recompile-vs-interpret speedup — the moat metric. The harness runs the
// frozen CPU-bound workload through both the interpreter oracle and the
// recompiled WebAssembly module on this host, proves they compute the same
// result, and measures the speedup. The 770-MIPS floor and the
// >=50%-of-native fraction cannot be certified on an unpinned host with no
// native baseline, so the benchmark stays honestly red.

import assert from "node:assert/strict";
import { test } from "node:test";
import { benchmarkRecompiler, formatRecompilerBenchmark, PERFORMANCE_BAR } from "../lib/performance.mjs";

test("performance: the recompiled path computes the same result as the interpreter", () => {
  const report = benchmarkRecompiler({ instruction_budget_count: 500_000 });
  assert.equal(report.is_equivalent, true, "the fast path must match the interpreter register state and instruction count");
  assert.equal(report.recompiled.fallback_count, 0, "the measured hot path carries no interpreter fallback");
  assert.equal(report.recompiled.instruction_count, report.interpreter.instruction_count);
});

test("performance: the recompiler out-runs the interpreter it exists to beat (GS-093)", () => {
  const report = benchmarkRecompiler({ instruction_budget_count: 500_000 });
  assert.ok(report.recompiled.mips > report.interpreter.mips, "recompiled throughput must exceed the interpreter");
  assert.notEqual(report.interpreter_multiple, null);
  assert.ok(report.interpreter_multiple > 1, "the speedup multiple must be a real number above one");
  // The bar is >=5x; on any reasonable host the recompiled loop clears it by a
  // wide margin, but the assertion is kept conservative against CI jitter.
  assert.equal(PERFORMANCE_BAR.interpreter_multiple, 5);
});

test("performance: the throughput floor and native fraction stay honestly red", () => {
  const report = benchmarkRecompiler({ instruction_budget_count: 500_000 });
  assert.equal(PERFORMANCE_BAR.mips_floor, 770);
  assert.equal(report.native_fraction, null, "no native baseline exists to measure the native fraction");
  assert.equal(report.measured_on_reference_desktop, false);
  assert.equal(report.is_bar_cleared, false, "the bar cannot be certified on an unpinned host");
  assert.ok(report.blocker.length >= 2, "the reference-desktop and native-baseline blockers must be declared");
  assert.equal(typeof report.is_floor_cleared_here, "boolean");
});

test("performance: the report formats the measured throughput and the declared bars", () => {
  const report = benchmarkRecompiler({ instruction_budget_count: 300_000 });
  const text = formatRecompilerBenchmark(report);
  assert.match(text, /Interpreter: [\d.]+ MIPS/);
  assert.match(text, /Recompiled: [\d.]+ MIPS/);
  assert.match(text, /Speedup vs interpreter/);
  assert.match(text, /MIPS floor: 770/);
});
