// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// BPTK-056 / GS-011 — guest↔host ABI / import-thunk lowering. Every declared
// calling convention must clean the guest stack correctly, and the guest↔host
// crossing cost is measured as the real WebAssembly import call the recompiled
// path uses. The declared cost bar is a reference-desktop figure, so it is
// reported but not certified here — the benchmark stays honestly red.

import assert from "node:assert/strict";
import { test } from "node:test";
import { benchmarkAbi, lowerThunk, verifyStackCleanup, measureCrossing, CALLING_CONVENTION, CROSSING_COST_BAR_NANOSECOND } from "../lib/abi.mjs";

test("abi: every declared calling convention returns a balanced stack", () => {
  for (const convention of Object.keys(CALLING_CONVENTION)) {
    for (const argumentCount of [0, 1, 2, 5]) {
      const result = verifyStackCleanup(convention, argumentCount);
      assert.equal(result.is_balanced, true, `${convention}(${argumentCount}) left the stack unbalanced by ${result.esp_delta}`);
    }
  }
});

test("abi: stdcall and cdecl assign stack cleanup to the correct side", () => {
  const stdcall = lowerThunk({ convention: "stdcall", argument_count: 3 });
  assert.equal(stdcall.callee_cleanup_byte, 12);
  assert.equal(stdcall.caller_cleanup_byte, 0);
  const cdecl = lowerThunk({ convention: "cdecl", argument_count: 3 });
  assert.equal(cdecl.caller_cleanup_byte, 12);
  assert.equal(cdecl.callee_cleanup_byte, 0);
});

test("abi: the register conventions pass the first arguments in registers", () => {
  const fastcall = lowerThunk({ convention: "fastcall", argument_count: 5 });
  assert.equal(fastcall.register_argument, 2);
  assert.equal(fastcall.stack_argument, 3);
  assert.equal(fastcall.callee_cleanup_byte, 12);
  const thiscall = lowerThunk({ convention: "thiscall", argument_count: 4 });
  assert.equal(thiscall.register_argument, 1);
  assert.equal(thiscall.stack_argument, 3);
});

test("abi: the guest↔host crossing reaches host emulation every call", () => {
  const crossing = measureCrossing({ iteration: 200_000 });
  assert.equal(crossing.is_host_reached, true, "every crossing must reach the host");
  assert.equal(crossing.host_call_count, 200_000);
  assert.ok(crossing.nanosecond_per_crossing > 0);
});

test("abi: the benchmark reports the crossing cost against the declared bar, honestly red", () => {
  const report = benchmarkAbi({ iteration: 200_000 });
  assert.equal(report.is_every_convention_balanced, true);
  assert.equal(report.crossing_cost_bar_nanosecond, CROSSING_COST_BAR_NANOSECOND);
  assert.equal(report.measured_on_reference_desktop, false);
  assert.equal(report.is_bar_cleared, false, "the bar cannot be certified off the reference desktop");
  assert.ok(report.blocker.length >= 2);
});
