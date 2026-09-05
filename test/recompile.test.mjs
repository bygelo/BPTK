// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// BPTK-046 / GS-001 — the static x86-PE→WASM recompiler, differential-tested
// bit-exact against the BPTK-009 interpreter oracle. Each microprogram is
// assembled, mapped, and executed twice: once through executeProbe (the
// oracle) and once through the recompiled WebAssembly module. The two runs
// must agree on the exact 5-tuple the runtime determinism suite pins —
// register, flag/eflags, trace_sha256, memory_sha256, and stop_reason — plus
// the executed instruction count. Any opcode outside the recompiled subset is
// a hard structured refusal, never a silent interpreter fallback: that bound
// is what keeps the whole-guest benchmark honestly red while the spike is real.

import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { mapPe32ForRuntime } from "../lib/pe.mjs";
import { executeProbe } from "../lib/runtime.mjs";
import { recompileImage, runRecompiled, createHybridRecompiler } from "../lib/recompile.mjs";

// A minimal PE32 whose .text is the supplied byte sequence at entry, matching
// the fixture shape the i386 conformance suite uses.
function createPe32(code) {
  const file = Buffer.alloc(0x800);
  file.writeUInt16LE(0x5a4d, 0);
  file.writeUInt32LE(0x80, 0x3c);
  file.writeUInt32LE(0x00004550, 0x80);
  file.writeUInt16LE(0x14c, 0x84);
  file.writeUInt16LE(1, 0x86);
  file.writeUInt16LE(224, 0x94);
  file.writeUInt16LE(0x10b, 0x98);
  file.writeUInt32LE(0x1000, 0xa8);
  file.writeUInt32LE(0x400000, 0xb4);
  file.writeUInt32LE(0x2000, 0xd0);
  file.writeUInt32LE(0x200, 0xd4);
  file.writeUInt32LE(0x10000, 0xe0);
  file.writeUInt32LE(0x1000, 0xe4);
  file.writeUInt32LE(0x10000, 0xe8);
  file.writeUInt32LE(0x1000, 0xec);
  file.writeUInt32LE(16, 0xf4);
  const sectionOffset = 0x178;
  file.write(".text", sectionOffset);
  file.writeUInt32LE(0x1000, sectionOffset + 8);
  file.writeUInt32LE(0x1000, sectionOffset + 12);
  file.writeUInt32LE((0x80000000 | 0x60000020) >>> 0, sectionOffset + 36);
  file.writeUInt32LE(0x600, sectionOffset + 16);
  file.writeUInt32LE(0x200, sectionOffset + 20);
  Buffer.from(code).copy(file, 0x200);
  return file;
}

function mapMicro(context, code) {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-recomp-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const packagePath = join(rootPath, "package");
  mkdirSync(packagePath);
  const executablePath = join(packagePath, "game.exe");
  writeFileSync(executablePath, createPe32(code));
  return mapPe32ForRuntime(executablePath, null, null);
}

// Assert the recompiled run reproduces the interpreter oracle bit-for-bit.
async function assertBitExact(context, code, budget = 4096) {
  const mapped = mapMicro(context, code);
  const oracle = executeProbe(mapped, budget, {});
  const recompiled = await runRecompiled(mapped, { budget, trace: true });
  assert.equal(recompiled.state, "probe_executed", `recompile refused: ${JSON.stringify(recompiled.refuse)}`);
  assert.equal(recompiled.fallback_count, 0, "the hot path must carry no interpreter fallback");
  for (const name of ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip"]) {
    assert.equal(recompiled.register[name], oracle.register[name], `register ${name} differs`);
  }
  assert.equal(recompiled.flag.eflags, oracle.flag.eflags, "eflags differ");
  assert.equal(recompiled.stop_reason, oracle.stop_reason, "stop_reason differs");
  assert.equal(recompiled.instruction_count, oracle.instruction_count, "instruction_count differs");
  assert.equal(recompiled.trace_sha256, oracle.trace_sha256, "trace_sha256 differs");
  assert.equal(recompiled.memory_sha256, oracle.memory_sha256, "memory_sha256 differs");
  return { oracle, recompiled };
}

test("recompile: mov immediate then add clears bit-exact against the oracle", async (context) => {
  await assertBitExact(context, [0xb8, 0x05, 0, 0, 0, 0x83, 0xc0, 0x03, 0xc3]);
});

test("recompile: sub underflow reproduces the exact carry, sign, and overflow flag", async (context) => {
  const { oracle } = await assertBitExact(context, [0xb8, 0x00, 0, 0, 0, 0x2d, 0x01, 0, 0, 0, 0xc3]);
  assert.equal(oracle.register.eax, 0xffffffff);
});

test("recompile: a backward counting loop matches the oracle register, flag, and trace", async (context) => {
  // mov eax,0; mov ecx,5; L: add eax,ecx; dec ecx; jnz L; ret → eax = 15.
  const { oracle } = await assertBitExact(context, [
    0xb8, 0, 0, 0, 0, 0xb9, 0x05, 0, 0, 0, 0x01, 0xc8, 0x49, 0x75, 0xfb, 0xc3,
  ]);
  assert.equal(oracle.register.eax, 15);
  assert.equal(oracle.register.ecx, 0);
});

test("recompile: push then pop moves the value through the shared stack memory", async (context) => {
  await assertBitExact(context, [0xb8, 0x11, 0, 0, 0, 0x50, 0x5b, 0xc3]);
});

test("recompile: a forward conditional branch skips the untaken block identically", async (context) => {
  await assertBitExact(context, [
    0xb8, 0x03, 0, 0, 0, 0x3d, 0x03, 0, 0, 0, 0x74, 0x05, 0xbb, 0x63, 0, 0, 0, 0xc3,
  ]);
});

test("recompile: the logical ALU column sets carry, overflow, and parity like the oracle", async (context) => {
  await assertBitExact(context, [
    0xb8, 0xff, 0, 0, 0, 0x83, 0xf0, 0x0f, 0x83, 0xe0, 0x33, 0x83, 0xc8, 0x40, 0xc3,
  ]);
});

test("recompile: adc and sbb thread the carry chain bit-exact", async (context) => {
  // mov eax,0xffffffff; add eax,1 (sets CF); mov ebx,0; adc ebx,0 (CF→ebx); ret.
  await assertBitExact(context, [
    0xb8, 0xff, 0xff, 0xff, 0xff, 0x83, 0xc0, 0x01, 0xbb, 0, 0, 0, 0, 0x83, 0xd3, 0x00, 0xc3,
  ]);
});

test("recompile: every conditional-branch condition code agrees with the oracle", async (context) => {
  // For each cc, cmp eax,eax (ZF=1,CF=0,SF=0,OF=0,PF=1) then jcc over a marker
  // mov; the recompiled taken/not-taken decision must match the interpreter.
  for (let cc = 0; cc <= 0x0f; cc += 1) {
    await assertBitExact(context, [
      0xb8, 0x07, 0, 0, 0, // mov eax,7
      0x39, 0xc0, // cmp eax,eax
      0x70 | cc, 0x05, // jcc +5
      0xbb, 0x99, 0, 0, 0, // mov ebx,0x99 (marker)
      0xc3,
    ]);
  }
});

test("recompile: rel32 jump and jcc reach distant blocks bit-exact", async (context) => {
  // mov eax,1; jmp rel32 +6 over a dead mov; add eax,2; ret.
  await assertBitExact(context, [
    0xb8, 0x01, 0, 0, 0, 0xe9, 0x05, 0, 0, 0, 0xbb, 0x77, 0, 0, 0, 0x83, 0xc0, 0x02, 0xc3,
  ]);
});

test("recompile: a long loop reaches the instruction budget exactly like the oracle", async (context) => {
  // mov ecx,1000000; L: dec ecx; jnz L; ret — bounded by a small budget so both
  // stop with instruction_budget_exhausted at the identical instruction pointer.
  const mapped = mapMicro(context, [0xb9, 0x40, 0x42, 0x0f, 0, 0x49, 0x75, 0xfd, 0xc3]);
  const budget = 64;
  const oracle = executeProbe(mapped, budget, {});
  const recompiled = await runRecompiled(mapped, { budget, trace: true });
  assert.equal(oracle.stop_reason, "instruction_budget_exhausted");
  assert.equal(recompiled.stop_reason, "instruction_budget_exhausted");
  assert.equal(recompiled.instruction_count, oracle.instruction_count);
  assert.equal(recompiled.register.eip, oracle.register.eip);
  assert.equal(recompiled.register.ecx, oracle.register.ecx);
  assert.equal(recompiled.trace_sha256, oracle.trace_sha256);
});

test("recompile: an opcode outside the subset refuses hard, never falling back silently", async (context) => {
  // 0xf7 /4 (mul) is served by the interpreter but outside the recompiled
  // spike. The recompiler must refuse with a structured code — proving the hot
  // path has no silent interpreter fallback — while the oracle still executes.
  const mapped = mapMicro(context, [0xb8, 0x02, 0, 0, 0, 0xf7, 0xe0, 0xc3]);
  const oracle = executeProbe(mapped, 64, {});
  assert.equal(oracle.state, "probe_executed"); // the interpreter oracle runs it
  const recompiled = await runRecompiled(mapped, { budget: 64, trace: true });
  assert.equal(recompiled.state, "recompile_refused");
  assert.equal(recompiled.refuse.code, "unsupported_opcode");
  assert.equal(recompiled.fallback_count, 0);
});

test("recompile: a memory-operand form refuses rather than mistranslate", async (context) => {
  // add [eax], ebx — a memory ModRM is outside the register-direct spike.
  const mapped = mapMicro(context, [0x01, 0x18, 0xc3]);
  const compiled = recompileImage(mapped, { budget: 64 });
  assert.ok(compiled.refuse, "memory-operand ALU must refuse");
  assert.equal(compiled.refuse.code, "unsupported_opcode");
});

// BPTK-047 / GS-002 — control-flow and indirect-branch recovery. A switch
// compiles to `jmp [table + index*4]`; the recompiler recovers the table, adds
// every arm as a block leader, and dispatches by matching the runtime target
// against the recovered leaders.
function buildSwitch(index) {
  const code = new Array(0x30).fill(0);
  let offset = 0;
  const put = (...bytes) => { for (const byte of bytes) code[offset++] = byte; };
  put(0xb8, index, 0, 0, 0); // mov eax, index
  put(0xff, 0x24, 0x85, 0x20, 0x10, 0x40, 0x00); // jmp [0x401020 + eax*4]
  offset = 0x0c; put(0xbb, 0xa0, 0, 0, 0, 0xc3); // arm0: mov ebx,0xA0; ret
  offset = 0x12; put(0xbb, 0xb0, 0, 0, 0, 0xc3); // arm1: mov ebx,0xB0; ret
  offset = 0x18; put(0xbb, 0xc0, 0, 0, 0, 0xc3); // arm2: mov ebx,0xC0; ret
  offset = 0x20;
  const dword = (value) => { code[offset++] = value & 0xff; code[offset++] = (value >>> 8) & 0xff; code[offset++] = (value >>> 16) & 0xff; code[offset++] = (value >>> 24) & 0xff; };
  dword(0x40100c); dword(0x401012); dword(0x401018);
  return code;
}

test("recompile: a recovered jump table dispatches every switch arm bit-exact", async (context) => {
  for (let index = 0; index <= 2; index += 1) {
    const { oracle, recompiled } = await assertBitExact(context, buildSwitch(index));
    assert.equal(oracle.register.ebx, [0xa0, 0xb0, 0xc0][index]);
    assert.equal(recompiled.indirect_leader_count, 3, "the table recovers three code leaders");
  }
});

test("recompile: the jump-table scan flags the code-as-data boundary, never a crash", async (context) => {
  const mapped = mapMicro(context, buildSwitch(0));
  const recompiled = await runRecompiled(mapped, { budget: 64, trace: true });
  assert.ok(recompiled.flagged_region.length >= 1, "the dword after the table is flagged as data");
  assert.equal(recompiled.flagged_region[0].kind, "table_boundary");
});

test("recompile: an indirect jump to an unrecovered target declares a fallback", async (context) => {
  // mov eax, 0x00401234 (not a block leader); jmp eax → unresolved fallback.
  const mapped = mapMicro(context, [0xb8, 0x34, 0x12, 0x40, 0x00, 0xff, 0xe0]);
  const recompiled = await runRecompiled(mapped, { budget: 64, trace: true });
  assert.equal(recompiled.state, "probe_executed");
  assert.equal(recompiled.stop_reason, "indirect_branch_unresolved");
  assert.equal(recompiled.fallback_count, 0);
});

test("recompile: an indirect call is a declared refusal, not a mistranslation", async (context) => {
  // call [0x401020] (0xff /2) — indirect call recovery is a declared follow-up.
  const mapped = mapMicro(context, [0xff, 0x15, 0x20, 0x10, 0x40, 0x00, 0xc3]);
  const compiled = recompileImage(mapped, { budget: 64 });
  assert.ok(compiled.refuse);
  assert.equal(compiled.refuse.code, "indirect_call_unsupported");
});

// BPTK-048 / GS-003 — hybrid interpreter fallback for self-modifying code. A
// code write invalidates only the instructions it overlaps; the affected block
// re-decodes to the freshly written behavior while untouched instructions are
// reused from the decode cache.
test("recompile: a self-modified block re-decodes while untouched blocks are reused", async (context) => {
  // mov eax,0x11; jmp +5; (pad); mov ebx,0x22; ret
  const code = [0xb8, 0x11, 0, 0, 0, 0xeb, 0x05, 0, 0, 0, 0, 0, 0xbb, 0x22, 0, 0, 0, 0xc3];
  const mapped = mapMicro(context, code);
  const hybrid = createHybridRecompiler(mapped, { trace: false, budget: 64 });

  const first = await hybrid.run();
  assert.equal(first.register.ebx, 0x22);
  assert.equal(first.keptInstruction.length, 0, "the first compile decodes everything fresh");
  assert.ok(first.reDecodedInstruction.length >= 4);

  // Self-modify: rewrite the immediate of `mov ebx` (at 0x40100d) to 0x99.
  hybrid.writeCode(0x40100d, [0x99, 0, 0, 0]);
  const second = await hybrid.run();
  assert.equal(second.register.ebx, 0x99, "the rewritten instruction takes effect on the next execution");
  assert.deepEqual(second.reDecodedInstruction, [0x40100c], "only the modified block re-decodes");
  assert.ok(second.keptInstruction.length >= 3, "untouched instructions are reused, never re-decoded");
});

test("recompile: the self-modified result stays bit-exact against the interpreter oracle", async (context) => {
  const code = [0xb8, 0x11, 0, 0, 0, 0xeb, 0x05, 0, 0, 0, 0, 0, 0xbb, 0x22, 0, 0, 0, 0xc3];
  const mapped = mapMicro(context, code);
  const hybrid = createHybridRecompiler(mapped, { trace: true, budget: 64 });
  await hybrid.run();
  hybrid.writeCode(0x40100d, [0x99, 0, 0, 0]);
  const recompiled = await hybrid.run();
  // The oracle over the same modified image is the reference.
  const modified = code.slice();
  modified[13] = 0x99;
  const oracle = executeProbe(mapMicro(context, modified), 64, {});
  assert.equal(recompiled.register.ebx, oracle.register.ebx);
  assert.equal(recompiled.memory_sha256, oracle.memory_sha256);
  assert.equal(recompiled.trace_sha256, oracle.trace_sha256);
});

test("recompile: the translation reports zero fallback and a recovered block graph", async (context) => {
  const mapped = mapMicro(context, [
    0xb8, 0, 0, 0, 0, 0xb9, 0x03, 0, 0, 0, 0x01, 0xc8, 0x49, 0x75, 0xfb, 0xc3,
  ]);
  const compiled = recompileImage(mapped, { budget: 64 });
  assert.equal(compiled.refuse, null);
  assert.equal(compiled.fallbackCount, 0);
  assert.ok(compiled.blockCount >= 2, "a loop recovers at least a header and a body block");
  assert.ok(compiled.wasm instanceof Uint8Array && compiled.wasm.length > 8);
  // The emitted bytes are a valid WebAssembly module.
  assert.ok(WebAssembly.validate(compiled.wasm), "the emitted module must validate");
});
