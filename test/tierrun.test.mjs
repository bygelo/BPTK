// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The 1:1 tiered-execution proof (runtime v2 milestone: one guest, two engines).
// lib/tierrun.mjs drives a mapped x86-64 image function-by-function over the
// SINGLE shared guest state lib/exec64.mjs buildGuestContext64 constructs. A
// pure-compute function (complete codegen, no import/indirect transfer) runs as a
// real WebAssembly module seeded from — and read back into — the live Machine;
// everything else runs through an instruction executor ported byte-for-byte from
// the pure interpreter. This suite asserts the whole tiered run's final
// architectural state is BIT-EXACT to pure interpretation, on a hand-built
// image AND on a real PuTTY x64 binary, and that the WASM tier genuinely carries
// state (at least one function actually runs WASM-tier). A divergence is a red
// test — never a tolerated difference.

import assert from "node:assert/strict";
import { test } from "node:test";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { resolveStageDir } from "../lib/corpus.mjs";
import { runImage64 } from "../lib/exec64.mjs";
import { mapPe64State } from "../lib/pe64.mjs";
import { createHleLayout } from "../lib/hle.mjs";
import { createGuestClock } from "../lib/clock.mjs";
import { runTieredImage } from "../lib/tierrun.mjs";
import { compileFunction } from "../lib/wasm64.mjs";
import { decodeStructured } from "../lib/lift64.mjs";

const MASK64 = (1n << 64n) - 1n;
const NAME = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
const FLAG = ["cf", "pf", "af", "zf", "sf", "of"];

function assertSameState(actual, expect, label) {
  for (const n of NAME) assert.equal(actual.register[n], expect.register[n], `${label}: reg ${n} tiered 0x${actual.register[n].toString(16)} != interp 0x${expect.register[n].toString(16)}`);
  for (const f of FLAG) assert.equal(actual.flag[f], expect.flag[f], `${label}: flag ${f} tiered ${actual.flag[f]} != interp ${expect.flag[f]}`);
  assert.equal(actual.rip, expect.rip, `${label}: rip tiered 0x${actual.rip.toString(16)} != interp 0x${expect.rip.toString(16)}`);
  assert.equal(actual.stop_reason, expect.stop_reason, `${label}: stop_reason tiered ${actual.stop_reason} != interp ${expect.stop_reason}`);
}

function assertSameMemory(actual, expect, label) {
  assert.equal(actual.region.length, expect.region.length, `${label}: region count differs`);
  for (let k = 0; k < actual.region.length; k += 1) {
    assert.equal(actual.region[k].base, expect.region[k].base, `${label}: region ${k} base differs`);
    assert.equal(Buffer.compare(actual.region[k].bytes, expect.region[k].bytes), 0, `${label}: region ${k} (base 0x${actual.region[k].base.toString(16)}) bytes diverge`);
  }
}

// -------------------- synthetic real-shaped image --------------------

// A hand-assembled PE-less image over the real multi-region layout (image at
// 0x140000000, a HIGH 140 TB stack). The entry function (interpreter tier) calls
// one pure-compute leaf (WASM tier: mov/add and a stack push/pop) and one leaf
// that uses a rotate the WASM codegen cannot emit (interpreter tier). The tiered
// run must reproduce pure interpretation exactly — registers, flags, rip, AND
// every region's bytes — while genuinely running the pure leaf as WebAssembly.
function buildSyntheticImage() {
  const img = Buffer.alloc(0x200);
  let p = 0;
  const at = (o) => { p = o; };
  const emit = (...b) => { for (const x of b) img[p++] = x; };
  // entry @0
  emit(0x48, 0xC7, 0xC1, 0x05, 0x00, 0x00, 0x00);   // mov rcx, 5
  emit(0x48, 0xC7, 0xC2, 0x03, 0x00, 0x00, 0x00);   // mov rdx, 3
  emit(0xE8, 0x2D, 0x00, 0x00, 0x00);               // call Fpure (0x40): next 0x13, rel 0x2D
  emit(0xE8, 0x68, 0x00, 0x00, 0x00);               // call Gfallback (0x80): next 0x18, rel 0x68
  emit(0xC3);                                       // ret (pops entry sentinel)
  // Fpure @0x40 — pure compute, emittable → WASM tier
  at(0x40);
  emit(0x51);                                        // push rcx
  emit(0x48, 0x89, 0xC8);                            // mov rax, rcx
  emit(0x48, 0x01, 0xD0);                            // add rax, rdx
  emit(0x48, 0x83, 0xC0, 0x07);                      // add rax, 7
  emit(0x59);                                        // pop rcx
  emit(0xC3);                                        // ret
  // Gfallback @0x80 — rotate the codegen cannot emit → interpreter tier
  at(0x80);
  emit(0x48, 0xC1, 0xC8, 0x04);                      // ror rax, 4
  emit(0xC3);                                        // ret
  return img;
}

test("1:1 synthetic — tiered run is bit-exact to pure interpretation, with a genuine WASM tier", () => {
  const image = buildSyntheticImage();
  const loadBase = 0x140000000n;
  const option = { image, loadBase, entryRva: 0, budget: 10000 };

  // The reference interpreter (lib/exec64.mjs runImage64) and the tiered runner's
  // own interpreter tier must agree — the anchor that the ported executor is the
  // real one.
  const oracle = runImage64(option);
  const pure = runTieredImage({ ...option, forceInterpreter: true });
  assert.equal(oracle.stop_reason, "entry_return", "the synthetic entry must return");
  assertSameState(pure, { register: oracle.register, flag: oracle.flag, rip: oracle.rip, stop_reason: oracle.stop_reason }, "interpreter-tier vs runImage64");

  // The tiered run (WASM fast path for the pure leaf) must equal pure
  // interpretation bit-for-bit, including every region's memory. wasmAudit
  // additionally re-derives each WASM-tier function through the interpreter and
  // asserts equality per invocation — a divergence throws.
  const tiered = runTieredImage({ ...option, wasmAudit: true });
  assertSameState(tiered, pure, "tiered vs interpreter");
  assertSameMemory(tiered, pure, "tiered vs interpreter");

  // At least one function actually ran WASM-tier; the fallback leaf ran
  // interpreter-tier — a real two-engine run over one state.
  assert.ok(tiered.tier_report.wasm_tier_function >= 1, "at least one WASM-tier function must be chosen");
  assert.equal(tiered.tier_report.wasm_tier_entry[0], `0x${(loadBase + 0x40n).toString(16)}`, "the pure leaf is the WASM-tier function");
  assert.ok(tiered.tier_report.interpreter_tier_function >= 1, "the rotate leaf must run interpreter-tier");
  // The computed result carries through both tiers: rax = ((5 + 3 + 7) ror 4).
  assert.equal(tiered.register.rax, 0xF000000000000000n, "the tiered result equals the interpreted result");
});

// -------------------- corpus-gated real binary: PuTTY x64 --------------------

const PUTTY_PATH = join(resolveStageDir(), "corpus-001", "package", "putty.exe");

// Builds the runImage64 / runTieredImage option for a mapped PE32+ image with the
// Win32 core HLE wired exactly as lib/exec64.mjs executeProbe64 wires it.
function puttyOption(mapped, budget) {
  const importSet = new Map();
  for (const entry of mapped.import ?? []) importSet.set((mapped.load_base + BigInt(entry.iat_slot_rva)) & MASK64, entry);
  const stackSizeByte = 0x40000;
  const stackLow = 0x7ff000000000 & 0xffffffff;
  const layout = createHleLayout({
    load_base: Number(mapped.load_base & MASK64),
    image_size_byte: mapped.image_size_byte ?? mapped.image.length,
    stack_base: stackLow,
    stack_end: stackLow + stackSizeByte,
  });
  return {
    image: mapped.image,
    loadBase: mapped.load_base,
    entryRva: mapped.entry_rva,
    budget,
    importSet,
    resourceRva: mapped.directory?.[2]?.rva ?? 0,
    hle: { layout, executableName: "putty.exe", clock: createGuestClock({ mode: "virtual_monotonic" }) },
  };
}

// A corpus-gated case must SKIP when its payload is absent, never return early —
// an early return prints a green tick for a test that asserted nothing, which is
// exactly how a real-binary regression reaches a reviewer marked passing. This is
// the guard shape test/live.test.mjs, test/sdl.test.mjs and test/exec64.test.mjs use.
const CORPUS_SKIP = existsSync(PUTTY_PATH) ? false : "corpus-001 not staged (set BPTK_CORPUS_STAGE)";

test("1:1 PuTTY x64 — tiered run is bit-exact to pure interpretation at a bounded budget", { skip: CORPUS_SKIP }, () => {
  const bytes = new Uint8Array(readFileSync(PUTTY_PATH));
  const mapped = mapPe64State(bytes);
  assert.equal(mapped.machine, "x86_64", "PuTTY is a PE32+ x86-64 image");

  // Anchor: the tiered runner's interpreter tier reproduces the reference
  // interpreter (lib/exec64.mjs runImage64) bit-for-bit deep into PuTTY's CRT
  // startup — same registers, flags, rip, stop, instruction count.
  const anchorBudget = 20000;
  const oracle = runImage64(puttyOption(mapped, anchorBudget));
  const interpAnchor = runTieredImage({ ...puttyOption(mapped, anchorBudget), forceInterpreter: true });
  assertSameState(interpAnchor, { register: oracle.register, flag: oracle.flag, rip: oracle.rip, stop_reason: oracle.stop_reason }, "PuTTY interpreter-tier vs runImage64");
  assert.equal(interpAnchor.instruction_count, oracle.instruction_count, "PuTTY interpreter tier consumes the budget identically to runImage64");

  // The whole-program proof: run PuTTY to its first natural frontier (the
  // CreateDialogParam specialization the tiered runner declines to drive, reached
  // after tens of thousands of instructions of real CRT startup) through BOTH the
  // tiered runner (WASM fast path where eligible) and its pure interpreter tier.
  // The final architectural state — registers, flags, rip, stop, AND every
  // region's memory — must be identical.
  const budget = 200000;
  const pure = runTieredImage({ ...puttyOption(mapped, budget), forceInterpreter: true });
  const tiered = runTieredImage(puttyOption(mapped, budget));

  assert.equal(pure.stop_reason, "tier_unsupported_specialization", "pure PuTTY startup reaches the dialog-creation frontier");
  assertSameState(tiered, pure, "PuTTY tiered vs interpreter");
  assertSameMemory(tiered, pure, "PuTTY tiered vs interpreter");

  // The WASM tier genuinely carried PuTTY state: real functions ran WASM-tier.
  assert.ok(tiered.tier_report.wasm_tier_function >= 1, "at least one PuTTY function must run WASM-tier");
  console.log(`tierrun PuTTY 1:1 @ ${budget} budget → stop ${tiered.stop_reason} at rip 0x${tiered.rip.toString(16)}; ` +
    `WASM-tier ${tiered.tier_report.wasm_tier_function} functions / ${tiered.tier_report.wasm_tier_invocation} invocations, ` +
    `interpreter-tier ${tiered.tier_report.interpreter_tier_function} functions / ${tiered.tier_report.interpreter_tier_instruction} instructions`);
});

// -------------------- resuming a WASM-tier function mid-flight --------------------
//
// An indirect jmp/call compiles as a return-to-dispatch terminator: the module
// computes the target, reports it as a resume rip and stops. That is only worth
// anything if the runner COMMITS the module's state and carries on from the resume
// rip — otherwise the function is compiled, run, exited and then re-interpreted from
// its entry, which is strictly slower than never tiering it. These two cases pin the
// commit decision from both sides: a resumable exit must be committed and continued,
// and a fault exit must be discarded, with pure interpretation as the oracle for both.

// entry calls F; F is a compilable function that reaches an INDIRECT call. The WASM
// tier runs F's prologue, computes the target, and hands back; the runner commits and
// resumes interpreting inside the callee, which returns INTO F's live frame, whose RET
// then returns into entry. Nothing about that sequence may differ from interpreting it.
function buildResumeImage() {
  const img = Buffer.alloc(0x200);
  let p = 0;
  const at = (o) => { p = o; };
  const emit = (...b) => { for (const x of b) img[p++] = x; };
  // entry @0
  emit(0x48, 0xC7, 0xC1, 0x05, 0x00, 0x00, 0x00);   // 0x00 mov rcx, 5
  emit(0x48, 0xC7, 0xC2, 0x03, 0x00, 0x00, 0x00);   // 0x07 mov rdx, 3
  emit(0xE8, 0x2D, 0x00, 0x00, 0x00);               // 0x0E call F (0x40): next 0x13, rel 0x2D
  emit(0xC3);                                       // 0x13 ret (pops the entry sentinel)
  // F @0x40 — compilable, but ends its first block at an indirect call
  at(0x40);
  emit(0x51);                                       // 0x40 push rcx
  emit(0x48, 0x89, 0xC8);                           // 0x41 mov rax, rcx
  emit(0x48, 0x01, 0xD0);                           // 0x44 add rax, rdx
  emit(0x48, 0x8D, 0x1D, 0x32, 0x00, 0x00, 0x00);   // 0x47 lea rbx,[rip+0x32] -> G (0x80)
  emit(0xFF, 0xD3);                                 // 0x4E call rbx           (returns to 0x50)
  emit(0x48, 0x83, 0xC0, 0x64);                     // 0x50 add rax, 100
  emit(0x59);                                       // 0x54 pop rcx
  emit(0xC3);                                       // 0x55 ret
  // G @0x80 — the indirect target
  at(0x80);
  emit(0x48, 0x83, 0xC0, 0x07);                     // 0x80 add rax, 7
  emit(0xC3);                                       // 0x84 ret
  return img;
}

test("1:1 synthetic — a WASM-tier function that exits at an indirect call resumes bit-exactly", () => {
  const image = buildResumeImage();
  const loadBase = 0x140000000n;
  const option = { image, loadBase, entryRva: 0, budget: 10000 };

  // The shape really is the one under test: F compiles COMPLETELY and its terminator
  // is an indirect call, so the WASM tier is genuinely entered and genuinely exits
  // mid-function. Without this the case could silently degrade to pure interpretation.
  const compiled = compileFunction(image, { loadBase, decodeStructured, entryRva: 0x40, guestLen: image.length + 0x100000 });
  assert.ok(compiled.complete, `F must compile completely — ${JSON.stringify(compiled.coverage.unsupported)}`);
  assert.ok(compiled.branchKind.includes("call_indirect"), "F must terminate a block at an indirect call");

  const oracle = runImage64(option);
  const pure = runTieredImage({ ...option, forceInterpreter: true });
  assert.equal(oracle.stop_reason, "entry_return", "the synthetic entry must return");
  assertSameState(pure, { register: oracle.register, flag: oracle.flag, rip: oracle.rip, stop_reason: oracle.stop_reason }, "interpreter-tier vs runImage64");

  const tiered = runTieredImage({ ...option, wasmAudit: true });
  assertSameState(tiered, pure, "resume: tiered vs interpreter");
  assertSameMemory(tiered, pure, "resume: tiered vs interpreter");

  // The resume really happened — the tier did not quietly route F to the interpreter.
  assert.ok(tiered.tier_report.wasm_tier_resume >= 1, "the indirect exit must be committed and resumed, not discarded");
  assert.equal(tiered.tier_report.wasm_tier_entry[0], `0x${(loadBase + 0x40n).toString(16)}`, "F is the WASM-tier function");
  // rax = (5 + 3) + 7 (in the indirect callee) + 100 (back in F, after the resume).
  assert.equal(tiered.register.rax, 115n, "every leg of the split execution contributed exactly once");
  assert.equal(tiered.register.rcx, 5n, "F's push/pop pair survived the resume, so its frame was the real one");
});

// F increments a MAPPED qword and then stores through an address no region maps.
// This is the case that decides whether a fault may be committed, and it is sharp
// BECAUSE the increment is not idempotent: if the tier applied it and the host then
// re-ran the block under the interpreter, the counter would read 2 instead of 1.
//
// The two engines now share ONE guest memory, so a run's stores cannot be un-done
// and re-running is not an option. lib/wasm64.mjs therefore stops the module AT the
// unmapped store, having performed none of its effects, and the host COMMITS that
// state and continues there — the interpreter performs the same store and faults on
// it. The increment happens exactly once, in the tier, and the final memory is
// bit-identical to pure interpretation. This case fails loudly if the module ever
// runs past its first out-of-region access, or if a fault is ever committed with a
// register file from anywhere but the faulting instruction's start.
function buildFaultImage() {
  const img = Buffer.alloc(0x200);
  let p = 0;
  const at = (o) => { p = o; };
  const emit = (...b) => { for (const x of b) img[p++] = x; };
  // entry @0
  emit(0xE8, 0x3B, 0x00, 0x00, 0x00);                                 // 0x00 call F (0x40): next 0x05, rel 0x3B
  emit(0xC3);                                                         // 0x05 ret
  // F @0x40
  at(0x40);
  emit(0x48, 0xFF, 0x44, 0x24, 0xF0);                                 // 0x40 inc qword [rsp-16]  (a MAPPED stack slot)
  emit(0x48, 0xBA, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00);   // 0x45 mov rdx, 0x30000000 (mapped by NO region)
  emit(0x48, 0x89, 0x02);                                             // 0x4F mov [rdx], rax
  emit(0xC3);                                                         // 0x52 ret
  return img;
}

test("1:1 synthetic — an out-of-region FAULT commits AT the fault and stays bit-exact", () => {
  const image = buildFaultImage();
  const loadBase = 0x140000000n;
  const option = { image, loadBase, entryRva: 0, budget: 10000 };

  const compiled = compileFunction(image, { loadBase, decodeStructured, entryRva: 0x40, guestLen: image.length + 0x100000 });
  assert.ok(compiled.complete, `F must compile completely — the unmapped store is a RUNTIME fault: ${JSON.stringify(compiled.coverage.unsupported)}`);

  const pure = runTieredImage({ ...option, forceInterpreter: true });
  const tiered = runTieredImage(option);
  assert.equal(pure.stop_reason, "fault", "the unmapped store faults under pure interpretation");
  assertSameState(tiered, pure, "fault-commit: tiered vs interpreter");
  // The memory comparison is the real assertion: the increment must appear exactly
  // once, whichever engine applied it.
  assertSameMemory(tiered, pure, "fault-commit: tiered vs interpreter");
  assert.equal(tiered.tier_report.wasm_tier_function, 1, "F really ran on the WASM tier up to the faulting store");
});

// The single-call case above proves one resume is exact. The pathological shape is
// the REPEATED one: a hot caller that re-enters the same indirect-exiting function
// on every iteration, so the tier compiles, runs, exits and resumes thousands of
// times over one guest state. That is where a cached module or a reused instance
// stops being an optimisation and starts being a source of stale bytes — this case
// caught exactly that (a cached region plan replaying the FIRST call's stack into
// every later invocation, which silently turned the caller's loop counter into an
// infinite loop). It is cheap to run and it must stay.
function buildHotIndirectImage(count, inner) {
  const img = Buffer.alloc(0x200);
  let p = 0;
  const at = (o) => { p = o; };
  const emit = (...b) => { for (const x of b) img[p++] = x; };
  // entry @0: mov ecx,count; L: push rcx; call F; pop rcx; dec ecx; jnz L; ret
  emit(0xb9, count & 0xff, (count >> 8) & 0xff, 0x00, 0x00); // 0x00 mov ecx,count
  emit(0x51);                                                // 0x05 L: push rcx
  emit(0xe8, 0x35, 0x00, 0x00, 0x00);                        // 0x06 call F (0x40)
  emit(0x59);                                                // 0x0B pop rcx
  emit(0xff, 0xc9);                                          // 0x0C dec ecx
  emit(0x75, 0xf5);                                          // 0x0E jnz L
  emit(0xc3);                                                // 0x10 ret
  // F @0x40: a real compiled loop, then an indirect call to G
  at(0x40);
  emit(0xba, inner & 0xff, (inner >> 8) & 0xff, 0x00, 0x00); // 0x40 mov edx,inner
  emit(0x48, 0x83, 0xc0, 0x01);                              // 0x45 M: add rax,1
  emit(0xff, 0xca);                                          // 0x49 dec edx
  emit(0x75, 0xf8);                                          // 0x4B jnz M
  emit(0x48, 0x8d, 0x1d, 0x2c, 0x00, 0x00, 0x00);            // 0x4D lea rbx,[rip+0x2c] -> G
  emit(0xff, 0xd3);                                          // 0x54 call rbx
  emit(0xc3);                                                // 0x56 ret
  // G @0x80
  at(0x80);
  emit(0x48, 0x83, 0xc0, 0x01);                              // 0x80 add rax,1
  emit(0xc3);                                                // 0x84 ret
  return img;
}

test("1:1 synthetic — a hot caller re-entering an indirect-exiting function resumes bit-exactly every time", () => {
  const count = 40;
  const inner = 25;
  const image = buildHotIndirectImage(count, inner);
  const loadBase = 0x140000000n;
  const option = { image, loadBase, entryRva: 0, budget: 200000 };

  const oracle = runImage64(option);
  const pure = runTieredImage({ ...option, forceInterpreter: true });
  assert.equal(oracle.stop_reason, "entry_return", "the hot caller must run to its own return");
  assertSameState(pure, { register: oracle.register, flag: oracle.flag, rip: oracle.rip, stop_reason: oracle.stop_reason }, "hot-indirect interpreter-tier vs runImage64");

  const tiered = runTieredImage(option);
  assertSameState(tiered, pure, "hot-indirect: tiered vs interpreter");
  assertSameMemory(tiered, pure, "hot-indirect: tiered vs interpreter");
  assert.equal(tiered.register.rax, BigInt(count * (inner + 1)), "every iteration of every invocation counted exactly once");
  assert.equal(tiered.tier_report.wasm_tier_resume, count, "the tier carried, and resumed from, all forty invocations");
  // The tier must be a real speed-up in WORK, not just in wall clock: the caller's
  // loop is interpreted, but the callee's inner loop ran entirely on the WASM tier,
  // so the tiered run executes far fewer interpreter instructions than pure does.
  assert.ok(tiered.tier_report.interpreter_tier_instruction * 4 < pure.tier_report.interpreter_tier_instruction,
    `the WASM tier must absorb most of the work (tiered ${tiered.tier_report.interpreter_tier_instruction} vs pure ${pure.tier_report.interpreter_tier_instruction} interpreted instructions)`);
});
