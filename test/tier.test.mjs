// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The TIERED runner conformance suite (runtime v2 milestone M3). lib/tier.mjs
// executes a guest program FUNCTION BY FUNCTION: a fully compilable function runs
// as real WebAssembly (lib/wasm64.mjs, the fast path), a function that hits a
// codegen fallback runs through the lib/lift64.mjs interpreter semantics, and
// control passes ACROSS that tier boundary over ONE shared guest state.
//
// Correctness is the whole point: the tiering must NOT change the result. Every
// case asserts runTiered's final registers/flags are bit-exact to running the
// WHOLE program through the pure lib/lift64.mjs interpreter (interpret), and that
// guest MEMORY is bit-exact to a whole-program interpreter reference (runTiered
// forced entirely onto the interpreter tier, which the same case first proves
// register/flag-identical to interpret — so its memory image is a trustworthy
// oracle for the surface interpret does not itself expose). The tier DECISIONS are
// asserted too: the compilable function must be chosen for WASM, the fallback
// function for the interpreter, with a real call crossing between them.
//
// The speed case runs a compute-heavy counted-loop sum: it asserts the WASM tier
// is chosen and the result is correct, then LOGS the measured interpreter-vs-WASM
// wall-time ratio (a strict clock assertion is flaky, so the tier CHOICE and the
// value are asserted, the ratio only reported).

import assert from "node:assert/strict";
import { test } from "node:test";
import { interpret } from "../lib/lift64.mjs";
import { runTiered } from "../lib/tier.mjs";

const loadBase = 0x140000000n;
const REG = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
const FLAG = ["cf", "pf", "af", "zf", "sf", "of"];

// Asserts every GPR and flag of a runTiered result equals the interpret() oracle.
function assertMatchesOracle(tiered, oracle, label) {
  for (const name of REG) {
    assert.equal(tiered.register[name], oracle.register[name], `${label}: reg ${name} tiered 0x${tiered.register[name].toString(16)} != oracle 0x${oracle.register[name].toString(16)}`);
  }
  for (const name of FLAG) {
    assert.equal(tiered.flag[name], oracle.flag[name], `${label}: flag ${name} tiered ${tiered.flag[name]} != oracle ${oracle.flag[name]}`);
  }
}

test("cross-tier: WASM entry (integer+SSE) calls an interpreter-tier fallback (rol), bit-exact", () => {
  // A (entry, 0x00): mov ecx,5; movd xmm0,ecx; paddd xmm0,xmm0; movd edx,xmm0;
  //                  call B; add eax,ecx; add eax,edx; ret
  // B (0x1B): mov eax,0x12345678; rol eax,8; ret   (rol → codegen fallback)
  const code = [
    0xb9, 0x05, 0x00, 0x00, 0x00,       // 0x00 mov ecx,5
    0x66, 0x0f, 0x6e, 0xc1,             // 0x05 movd xmm0,ecx
    0x66, 0x0f, 0xfe, 0xc0,             // 0x09 paddd xmm0,xmm0
    0x66, 0x0f, 0x7e, 0xc2,             // 0x0D movd edx,xmm0
    0xe8, 0x05, 0x00, 0x00, 0x00,       // 0x11 call B (target 0x1B)
    0x01, 0xc8,                         // 0x16 add eax,ecx
    0x01, 0xd0,                         // 0x18 add eax,edx
    0xc3,                               // 0x1A ret
    0xb8, 0x78, 0x56, 0x34, 0x12,       // 0x1B B: mov eax,0x12345678
    0xc1, 0xc0, 0x08,                   // 0x20 rol eax,8
    0xc3,                               // 0x23 ret
  ];
  const image = Buffer.from(code);
  const B = 0x1b;

  const oracle = interpret({ image, loadBase, entryRva: 0, budget: 4096 });
  assert.equal(oracle.stop_reason, "entry_return", `oracle stop_reason ${oracle.stop_reason} ${oracle.exception?.message ?? ""}`);

  // Whole-program interpreter reference (no separate entry for B, so A absorbs B
  // and the entire program runs on the interpreter tier) — proven register/flag
  // identical to interpret(), so its memory image is a trustworthy oracle.
  const wholeInterp = runTiered(image, { loadBase, entryRva: 0, budget: 100000 });
  assertMatchesOracle(wholeInterp, oracle, "whole-interp reference");
  assert.equal(wholeInterp.report.wasmFunctionRun, 0, "the reference run must be entirely interpreter-tier");
  assert.equal(wholeInterp.report.tier[0], "interp", "with B folded in, the entry is an interpreter-tier function");

  // Tiered run: A on the WASM tier, B on the interpreter tier, a real call across.
  const tiered = runTiered(image, { loadBase, entryRva: 0, functionEntry: [0, B], budget: 100000 });
  assert.equal(tiered.report.tier[0], "wasm", "the integer+SSE entry must be chosen for the WASM tier");
  assert.equal(tiered.report.tier[B], "interp", "the rol function must fall back to the interpreter tier");
  assert.ok(tiered.report.wasmFunctionRun >= 1, "at least one function ran on the WASM tier");
  assert.ok(tiered.report.interpFunctionRun >= 1, "at least one function ran on the interpreter tier");
  assert.ok(tiered.report.interpEntryRun.includes(B), "the fallback function ran on the interpreter tier at a cross-tier call");

  assertMatchesOracle(tiered, oracle, "cross-tier (WASM→interp)");
  assert.equal(tiered.register.rax, 0x34567821n, "rax = rol(0x12345678,8)=0x34567812, +ecx(5) +edx(10) = 0x34567821");
  // MEMORY bit-exact against the whole-interpreter reference — the pushed return
  // address (loadBase+0x16) is a stale qword on the guest stack in BOTH paths.
  assert.ok(tiered.memory.equals(wholeInterp.memory), "guest memory bit-exact between tiered and pure-interpreter runs");
  // balanced_rsp-8 holds the entry sentinel; the call pushes its return address
  // one qword below that, at balanced_rsp-16.
  const retAddrOff = Number((oracle.balanced_rsp - 16n) - loadBase);
  assert.equal(tiered.memory.readBigUInt64LE(retAddrOff), loadBase + 0x16n, "the cross-tier call's return address is bit-exact on the shared stack");
});

test("cross-tier reverse: interpreter-tier entry (rol) calls a WASM-tier leaf, bit-exact", () => {
  // A (entry, 0x00): mov eax,0x100; rol eax,4; call B; add eax,ecx; ret
  // B (0x10, WASM-tier leaf): mov ecx,7; ret
  const code = [
    0xb8, 0x00, 0x01, 0x00, 0x00,       // 0x00 mov eax,0x100
    0xc1, 0xc0, 0x04,                   // 0x05 rol eax,4  (interpreter fallback)
    0xe8, 0x03, 0x00, 0x00, 0x00,       // 0x08 call B (target 0x10)
    0x01, 0xc8,                         // 0x0D add eax,ecx
    0xc3,                               // 0x0F ret
    0xb9, 0x07, 0x00, 0x00, 0x00,       // 0x10 B: mov ecx,7
    0xc3,                               // 0x15 ret
  ];
  const image = Buffer.from(code);
  const B = 0x10;

  const oracle = interpret({ image, loadBase, entryRva: 0, budget: 4096 });
  assert.equal(oracle.stop_reason, "entry_return", `oracle stop_reason ${oracle.stop_reason}`);

  const wholeInterp = runTiered(image, { loadBase, entryRva: 0, budget: 100000 });
  assertMatchesOracle(wholeInterp, oracle, "reverse whole-interp reference");

  const tiered = runTiered(image, { loadBase, entryRva: 0, functionEntry: [0, B], budget: 100000 });
  assert.equal(tiered.report.tier[0], "interp", "the rol entry must fall back to the interpreter tier");
  assert.equal(tiered.report.tier[B], "wasm", "the compilable leaf must be chosen for the WASM tier");
  assert.ok(tiered.report.wasmEntryRun.includes(B), "the leaf ran on the WASM tier, called from the interpreter tier");

  assertMatchesOracle(tiered, oracle, "cross-tier (interp→WASM)");
  assert.equal(tiered.register.rax, 0x1007n, "rax = rol(0x100,4)=0x1000, + ecx(7) = 0x1007");
  assert.ok(tiered.memory.equals(wholeInterp.memory), "guest memory bit-exact between tiered and pure-interpreter runs");
});

test("speed: a compute-heavy counted-loop sum is chosen for the WASM tier and is correct", () => {
  // xor eax,eax; mov ecx,N; loop: add eax,ecx; dec ecx; jnz loop; ret  → sum 1..N
  const N = 100000;
  const code = [
    0x31, 0xc0,                                     // 0x00 xor eax,eax
    0xb9, N & 0xff, (N >> 8) & 0xff, (N >> 16) & 0xff, (N >> 24) & 0xff, // 0x02 mov ecx,N
    0x01, 0xc8,                                     // 0x07 add eax,ecx
    0xff, 0xc9,                                     // 0x09 dec ecx
    0x75, 0xfa,                                     // 0x0B jnz loop (rel -6 → 0x07)
    0xc3,                                           // 0x0D ret
  ];
  const image = Buffer.from(code);

  const t0 = performance.now();
  const oracle = interpret({ image, loadBase, entryRva: 0, budget: 5_000_000 });
  const interpMs = performance.now() - t0;
  assert.equal(oracle.stop_reason, "entry_return", "oracle completed the loop");

  const tiered = runTiered(image, { loadBase, entryRva: 0, functionEntry: [0], budget: 5_000_000, iterationCap: 5_000_000 });
  assert.equal(tiered.report.tier[0], "wasm", "the hot counted-loop function must be chosen for the WASM tier");
  assert.equal(tiered.report.wasmFunctionRun, 1, "exactly one function ran, on the WASM tier");
  assert.equal(tiered.report.interpInstruction, 0, "no interpreter instructions retired — the whole hot loop ran in WASM");

  assertMatchesOracle(tiered, oracle, "hot-loop");
  const expected = BigInt((N * (N + 1) / 2) >>> 0) & 0xffffffffn;
  assert.equal(tiered.register.rax, expected, `sum 1..${N} = ${expected} (32-bit)`);

  const wasmMs = tiered.report.wasmWallMs;
  const ratio = wasmMs > 0 ? (interpMs / wasmMs) : Infinity;
  process.stdout.write(`[tier] hot loop N=${N}: interpreter ${interpMs.toFixed(2)}ms vs WASM tier ${wasmMs.toFixed(2)}ms → ${ratio.toFixed(1)}x faster\n`);
});

test("report: tier counts and coverage are surfaced", () => {
  // Reuse the WASM→interp program to check the report shape.
  const code = [
    0xb9, 0x05, 0x00, 0x00, 0x00,       // 0x00 mov ecx,5
    0xe8, 0x03, 0x00, 0x00, 0x00,       // 0x05 call B (target 0x0D)
    0x01, 0xc8,                         // 0x0A add eax,ecx
    0xc3,                               // 0x0C ret
    0xb8, 0x78, 0x56, 0x34, 0x12,       // 0x0D B: mov eax,0x12345678
    0xc1, 0xc0, 0x08,                   // 0x12 rol eax,8
    0xc3,                               // 0x15 ret
  ];
  const image = Buffer.from(code);
  const tiered = runTiered(image, { loadBase, entryRva: 0, functionEntry: [0, 0x0d] });
  const r = tiered.report;
  assert.deepEqual(r.functionEntry, [0, 0x0d], "both function entries are reported");
  assert.equal(r.tier[0], "wasm");
  assert.equal(r.tier[0x0d], "interp");
  assert.equal(r.wasmFunctionRun + r.interpFunctionRun >= 2, true, "both tiers ran a function");
  assert.ok(r.interpInstruction > 0, "interpreter-tier instructions were counted");
  assert.ok(typeof r.wasmWallMs === "number" && typeof r.interpWallMs === "number", "per-tier wall-time is reported");
  assert.ok(r.coverage[0].emitted.length > 0, "the WASM-tier function reports emitted op coverage");
  process.stdout.write(`[tier] report: wasm functions ${r.wasmFunctionRun}, interp functions ${r.interpFunctionRun}, interp instructions ${r.interpInstruction}\n`);
});
