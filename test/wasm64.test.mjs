// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The x86-64 → WebAssembly recompiler conformance suite (runtime v2 milestone
// M3). Every microprogram is a hand-assembled x86-64 byte sequence ending in
// RET. Each is lifted once (lib/lift64.mjs liftBlock) and then run through BOTH
// paths — the interpreter ORACLE (interpret) and the emitted WebAssembly module
// (lib/wasm64.mjs runBlock) — and their end states are asserted BIT-EXACT:
// every one of the sixteen 64-bit GPRs and all six architectural flags must be
// identical. That equivalence is the whole point of the fast path; a divergence
// is a red test, never a silently-tolerated difference. The module bytes are a
// real, instantiable WebAssembly binary (magic 00 61 73 6d, version 1) driven by
// Node's WebAssembly global — no interpreter is invoked inside the WASM path.
//
// The final case reports how many IR op kinds the codegen emits versus falls
// back on, and asserts a memory round-trip (store then load) agrees end to end.

import assert from "node:assert/strict";
import { test } from "node:test";
import { interpret, liftBlock, decodeStructured, executeSse, materializeFlag } from "../lib/lift64.mjs";
import { compileBlock, runBlock, compileFunction, runFunction } from "../lib/wasm64.mjs";

const loadBase = 0x140000000n;
const REG = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
const FLAG = ["cf", "pf", "af", "zf", "sf", "of"];

// Confirms the emitted bytes are a genuine WebAssembly module before trusting
// any state comparison: right magic, right version, and instantiable.
function assertRealModule(bytes) {
  assert.ok(bytes instanceof Uint8Array, "module bytes must be a Uint8Array");
  assert.deepEqual([...bytes.slice(0, 4)], [0x00, 0x61, 0x73, 0x6d], "WASM magic 00 61 73 6d");
  assert.deepEqual([...bytes.slice(4, 8)], [0x01, 0x00, 0x00, 0x00], "WASM version 1");
  assert.ok(WebAssembly.validate(bytes), "emitted module must pass WebAssembly.validate");
}

// Lifts + runs a microprogram through interpreter and WASM, asserting bit-exact
// register and flag agreement. Returns the (agreeing) coverage report.
function assertEquivalent(code, label) {
  const image = Buffer.from(code);
  const oracle = interpret({ image, loadBase, entryRva: 0, budget: 4096 });
  assert.equal(oracle.stop_reason, "entry_return", `${label}: oracle stop_reason ${oracle.stop_reason} ${JSON.stringify(oracle.exception)}`);

  const block = liftBlock(image, 0);
  const compiled = compileBlock(block, { loadBase, guestLen: image.length + 0x10000 });
  assertRealModule(compiled.bytes);

  const jit = runBlock(block, { image, loadBase });
  assert.ok(jit.complete, `${label}: codegen incomplete — fell back on ${JSON.stringify(jit.coverage.unsupported)}`);

  for (const name of REG) {
    assert.equal(jit.register[name], oracle.register[name], `${label}: reg ${name} WASM 0x${jit.register[name].toString(16)} != oracle 0x${oracle.register[name].toString(16)}`);
  }
  for (const name of FLAG) {
    assert.equal(jit.flag[name], oracle.flag[name], `${label}: flag ${name} WASM ${jit.flag[name]} != oracle ${oracle.flag[name]}`);
  }
  return jit;
}

const coverage = new Set();
function cover(jit) {
  for (const kind of jit.coverage.emitted) coverage.add(kind);
}

test("mov/add: eax=8 with exact add flags", () => {
  // mov eax,5; mov ecx,3; add eax,ecx; ret
  cover(assertEquivalent([0xb8, 0x05, 0x00, 0x00, 0x00, 0xb9, 0x03, 0x00, 0x00, 0x00, 0x01, 0xc8, 0xc3], "mov/add"));
});

test("add with carry-out and overflow: 0xffffffff + 1", () => {
  // mov eax,0xffffffff; add eax,1; ret  — CF set, result 0, ZF set
  cover(assertEquivalent([0xb8, 0xff, 0xff, 0xff, 0xff, 0x83, 0xc0, 0x01, 0xc3], "add-carry"));
});

test("64-bit add carry: imm64 near wrap + register", () => {
  // mov rax,0xffffffffffffffff; mov rcx,2; add rax,rcx; ret  — 64-bit CF path
  cover(assertEquivalent([0x48, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x48, 0xc7, 0xc1, 0x02, 0x00, 0x00, 0x00, 0x48, 0x01, 0xc8, 0xc3], "add64-carry"));
});

test("sub/cmp: signed overflow and borrow flags", () => {
  // mov eax,1; mov ecx,2; sub eax,ecx; ret  — borrow: CF set, SF set, result 0xffffffff
  cover(assertEquivalent([0xb8, 0x01, 0x00, 0x00, 0x00, 0xb9, 0x02, 0x00, 0x00, 0x00, 0x29, 0xc8, 0xc3], "sub-borrow"));
});

test("adc/sbb: carry chained across two ops", () => {
  // mov eax,0xffffffff; add eax,1 (CF=1); mov ebx,0; adc ebx,0 (ebx=1); ret
  cover(assertEquivalent([0xb8, 0xff, 0xff, 0xff, 0xff, 0x83, 0xc0, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x83, 0xd3, 0x00, 0xc3], "adc-chain"));
});

test("logic: and/or/xor clear CF/OF and set PF/ZF/SF", () => {
  // mov eax,0xff00ff00; and eax,0x0f0f0f0f; or eax,0x11; xor eax,0x11; ret
  cover(assertEquivalent([0xb8, 0x00, 0xff, 0x00, 0xff, 0x25, 0x0f, 0x0f, 0x0f, 0x0f, 0x83, 0xc8, 0x11, 0x83, 0xf0, 0x11, 0xc3], "logic"));
});

test("test: flags without writeback", () => {
  // mov eax,0; test eax,eax; ret  — ZF set, dst unchanged
  cover(assertEquivalent([0xb8, 0x00, 0x00, 0x00, 0x00, 0x85, 0xc0, 0xc3], "test"));
});

test("shl/shr/sar: shift results and CF/OF", () => {
  // mov eax,0x80000001; shl eax,1; ret  — CF from top bit, OF from sign change
  cover(assertEquivalent([0xb8, 0x01, 0x00, 0x00, 0x80, 0xd1, 0xe0, 0xc3], "shl"));
  // mov eax,0xf0; shr eax,4; ret
  cover(assertEquivalent([0xb8, 0xf0, 0x00, 0x00, 0x00, 0xc1, 0xe8, 0x04, 0xc3], "shr"));
  // mov eax,0x80000000; sar eax,4; ret  — arithmetic sign fill
  cover(assertEquivalent([0xb8, 0x00, 0x00, 0x00, 0x80, 0xc1, 0xf8, 0x04, 0xc3], "sar"));
  // shift by CL
  // mov eax,1; mov cl,5; shl eax,cl; ret
  cover(assertEquivalent([0xb8, 0x01, 0x00, 0x00, 0x00, 0xb1, 0x05, 0xd3, 0xe0, 0xc3], "shl-cl"));
});

test("inc/dec: CF preserved, other flags recomputed", () => {
  // mov eax,0x7fffffff; add eax,1 (CF=0,OF=1); inc eax; ret  — inc keeps CF, sets OF=0
  cover(assertEquivalent([0xb8, 0xff, 0xff, 0xff, 0x7f, 0x83, 0xc0, 0x01, 0xff, 0xc0, 0xc3], "inc"));
  // mov eax,1; dec eax; ret  — ZF set
  cover(assertEquivalent([0xb8, 0x01, 0x00, 0x00, 0x00, 0xff, 0xc8, 0xc3], "dec"));
});

test("neg/not: negation flags and bitwise complement", () => {
  // mov eax,5; neg eax; ret  — CF set (nonzero), result -5
  cover(assertEquivalent([0xb8, 0x05, 0x00, 0x00, 0x00, 0xf7, 0xd8, 0xc3], "neg"));
  // mov eax,0x0f0f0f0f; not eax; ret
  cover(assertEquivalent([0xb8, 0x0f, 0x0f, 0x0f, 0x0f, 0xf7, 0xd0, 0xc3], "not"));
});

test("movzx/movsx/movsxd: width extension", () => {
  // mov eax,0x80; movzx ecx,al; ret
  cover(assertEquivalent([0xb8, 0x80, 0x00, 0x00, 0x00, 0x0f, 0xb6, 0xc8, 0xc3], "movzx"));
  // mov eax,0x80; movsx ecx,al; ret  — sign extend byte
  cover(assertEquivalent([0xb8, 0x80, 0x00, 0x00, 0x00, 0x0f, 0xbe, 0xc8, 0xc3], "movsx"));
  // mov eax,0xffffffff; movsxd rcx,eax; ret  — sign extend dword to qword
  cover(assertEquivalent([0xb8, 0xff, 0xff, 0xff, 0xff, 0x48, 0x63, 0xc8, 0xc3], "movsxd"));
});

test("lea: register+index+disp and rip-relative", () => {
  // mov rax,4; mov rcx,0x10; lea rdx,[rax+rcx*2+8]; ret
  cover(assertEquivalent([0x48, 0xc7, 0xc0, 0x04, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc1, 0x10, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x54, 0x48, 0x08, 0xc3], "lea"));
  // lea rax,[rip+0x100]; ret
  cover(assertEquivalent([0x48, 0x8d, 0x05, 0x00, 0x01, 0x00, 0x00, 0xc3], "lea-rip"));
});

test("imul2/imul3: two- and three-operand signed multiply", () => {
  // mov eax,7; mov ecx,6; imul eax,ecx; ret  — eax=42
  cover(assertEquivalent([0xb8, 0x07, 0x00, 0x00, 0x00, 0xb9, 0x06, 0x00, 0x00, 0x00, 0x0f, 0xaf, 0xc1, 0xc3], "imul2"));
  // mov ecx,5; imul eax,ecx,9; ret  — eax=45
  cover(assertEquivalent([0xb9, 0x05, 0x00, 0x00, 0x00, 0x6b, 0xc1, 0x09, 0xc3], "imul3"));
  // imul with overflow: mov eax,0x10000; imul eax,eax; ret  — CF/OF set
  cover(assertEquivalent([0xb8, 0x00, 0x00, 0x01, 0x00, 0x0f, 0xaf, 0xc0, 0xc3], "imul-overflow"));
});

test("push/pop: stack traffic balances rsp", () => {
  // mov rax,0x1234; push rax; pop rcx; ret  — rcx=rax, rsp balanced
  cover(assertEquivalent([0x48, 0xc7, 0xc0, 0x34, 0x12, 0x00, 0x00, 0x50, 0x59, 0xc3], "push/pop"));
});

test("memory: store to stack then load back (guest memory round-trip)", () => {
  // mov rax,0x1122334455667788; mov [rsp-8],rax; mov rcx,[rsp-8]; ret
  const code = [
    0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // mov rax,imm64
    0x48, 0x89, 0x44, 0x24, 0xf8, // mov [rsp-8],rax
    0x48, 0x8b, 0x4c, 0x24, 0xf8, // mov rcx,[rsp-8]
    0xc3,
  ];
  const jit = assertEquivalent(code, "mem-roundtrip");
  cover(jit);
  // The loaded value proves the round-trip; also inspect the WASM memory bytes
  // directly to confirm the store landed (a real memory, not a register-only path).
  const image = Buffer.from(code);
  const stackTop = loadBase + BigInt(image.length + 0x10000 - 16);
  const addr = stackTop - 8n - 8n; // [rsp-8] where rsp = stackTop-8
  const offset = Number(addr - loadBase);
  const dv = new DataView(jit.memory.buffer, jit.memory.byteOffset, jit.memory.byteLength);
  assert.equal(dv.getBigUint64(offset, true), 0x1122334455667788n, "stored qword must be present in WASM guest memory");
  assert.equal(jit.register.rcx, 0x1122334455667788n, "loaded value round-trips into rcx");
});

test("byte/high8 lanes: al/ah partial-width writes preserve the rest", () => {
  // mov eax,0x11223344; mov al,0xff; mov ah,0x55; add al,1; ret
  cover(assertEquivalent([0xb8, 0x44, 0x33, 0x22, 0x11, 0xb0, 0xff, 0xb4, 0x55, 0x04, 0x01, 0xc3], "byte-lanes"));
});

test("coverage: report emitted IR op kinds and the interpret fallbacks", () => {
  // A block with a deferred control transfer (indirect jmp) proves the codegen
  // stops honestly at the first op it cannot emit rather than faking it.
  // mov eax,1; jmp rax (ff e0); ret
  const image = Buffer.from([0xb8, 0x01, 0x00, 0x00, 0x00, 0xff, 0xe0, 0xc3]);
  const block = liftBlock(image, 0);
  const compiled = compileBlock(block, { loadBase, guestLen: image.length + 0x10000 });
  assertRealModule(compiled.bytes);
  assert.equal(compiled.complete, false, "an indirect jmp must be an honest fallback, not emitted");
  assert.ok(compiled.coverage.unsupported.some((u) => u.reason === "control_flow"), "the jmpIndirect must be named as a control-flow fallback");
  assert.ok(compiled.coverage.emitted.includes("mov"), "the mov before the branch is still compiled");

  const kinds = [...coverage].sort();
  // Distinct node.op kinds emitted (alu:*/shift:* collapse to their base op).
  const baseOps = new Set(kinds.map((k) => k.split(":")[0]));
  process.stdout.write(`\n[wasm64] emitted IR op kinds (${baseOps.size}): ${[...baseOps].sort().join(", ")}\n`);
  process.stdout.write(`[wasm64] emitted variants (${kinds.length}): ${kinds.join(", ")}\n`);
  process.stdout.write("[wasm64] interpret fallbacks (honest, deferred to later milestone): jcc/jmp/call/ret-branch, div/mul-pair, rotate, 64-bit imul overflow, sse, x87, string\n");
  assert.ok(baseOps.size >= 12, `expected the codegen to emit at least 12 IR op kinds, got ${baseOps.size}`);
});

// -------------------- multi-block control-flow (compileFunction) --------------------
//
// Each microprogram below has REAL intra-function control flow — a forward
// conditional skip, a backward counted loop, an if/else register select, and a
// multi-block fall-through chain. Every one is run through BOTH the interpreter
// oracle and the emitted MULTI-BLOCK WASM module (a `(block (loop (block…
// (br_table))))` dispatch over a current-block index), and the sixteen GPRs plus
// six flags are asserted BIT-EXACT. The block graph is recovered from lift64's
// decoder; the branch condition is evaluated from the same flag locals the
// straight-line codegen already matches. A bounded-loop case proves the iteration
// cap stops a runaway, and two shapes the codegen does not model (a direct call
// and an indirect jmp) are asserted to be honest, named fallbacks.

const cflowShape = new Set();
const cflowBranch = new Set();

// Reads a little-endian guest qword out of the WASM module's memory copy at a
// full guest virtual address (loadBase-relative). Used to inspect the exact
// stack bytes a call/ret touched.
function stackQword(jit, guestAddr) {
  const offset = Number(guestAddr - loadBase);
  const dv = new DataView(jit.memory.buffer, jit.memory.byteOffset, jit.memory.byteLength);
  return dv.getBigUint64(offset, true);
}

// The initial guest rsp the seedState / interpreter set up: the sentinel sits at
// rsp0, and the first pushed return address lands one slot below (rsp0 - 8).
function initialRsp(code) {
  const stackTop = loadBase + BigInt(code.length + 0x10000 - 16);
  return stackTop - 8n;
}

// Lifts-and-interprets the whole function (oracle) and runs the multi-block WASM
// module, asserting bit-exact register + flag agreement and an OK run status.
function assertFunctionEquivalent(code, label) {
  const image = Buffer.from(code);
  const oracle = interpret({ image, loadBase, entryRva: 0, budget: 4096 });
  assert.equal(oracle.stop_reason, "entry_return", `${label}: oracle stop_reason ${oracle.stop_reason} ${oracle.exception?.message ?? ""}`);

  const compiled = compileFunction(image, { loadBase, decodeStructured, guestLen: image.length + 0x10000 });
  assertRealModule(compiled.bytes);
  assert.ok(compiled.complete, `${label}: codegen incomplete — fell back on ${JSON.stringify(compiled.coverage.unsupported)}`);
  assert.ok(compiled.blockCount >= 2, `${label}: expected a multi-block function, got ${compiled.blockCount} block(s)`);

  const jit = runFunction(image, { image, loadBase, decodeStructured });
  assert.equal(jit.statusName, "ok", `${label}: run status ${jit.statusName}, expected ok`);

  for (const name of REG) {
    assert.equal(jit.register[name], oracle.register[name], `${label}: reg ${name} WASM 0x${jit.register[name].toString(16)} != oracle 0x${oracle.register[name].toString(16)}`);
  }
  for (const name of FLAG) {
    assert.equal(jit.flag[name], oracle.flag[name], `${label}: flag ${name} WASM ${jit.flag[name]} != oracle ${oracle.flag[name]}`);
  }
  cflowShape.add(label);
  for (const kind of jit.branchKind) cflowBranch.add(kind);
  return { jit, compiled };
}

test("multi-block: forward conditional branch skips a block (jcc not-taken vs taken)", () => {
  // mov eax,1; test eax,eax; jne skip; mov eax,7; skip: ret  — jne IS taken (ZF=0), eax stays 1
  assertFunctionEquivalent([0xb8, 0x01, 0x00, 0x00, 0x00, 0x85, 0xc0, 0x75, 0x05, 0xb8, 0x07, 0x00, 0x00, 0x00, 0xc3], "fwd-skip-taken");
  // mov eax,0; test eax,eax; jne skip; mov eax,7; skip: ret  — jne NOT taken (ZF=1), eax becomes 7
  const { jit } = assertFunctionEquivalent([0xb8, 0x00, 0x00, 0x00, 0x00, 0x85, 0xc0, 0x75, 0x05, 0xb8, 0x07, 0x00, 0x00, 0x00, 0xc3], "fwd-skip-nottaken");
  assert.equal(jit.register.rax, 7n, "the not-taken path must run the skipped block (eax=7)");
});

test("multi-block: backward loop sums 1..N (Jcc + a counter)", () => {
  // mov eax,0; mov ecx,5; loop: add eax,ecx; dec ecx; jnz loop; ret  — eax = 5+4+3+2+1 = 15
  const { jit, compiled } = assertFunctionEquivalent([0xb8, 0x00, 0x00, 0x00, 0x00, 0xb9, 0x05, 0x00, 0x00, 0x00, 0x01, 0xc8, 0xff, 0xc9, 0x75, 0xfa, 0xc3], "backward-loop");
  assert.equal(jit.register.rax, 15n, "the counted loop must sum 1..5 = 15");
  assert.equal(jit.register.rcx, 0n, "the loop counter must reach 0");
  assert.ok(compiled.branchKind.includes("jcc"), "the backward branch is a jcc");
});

test("multi-block: if/else selects a register value (jg + jmp join)", () => {
  // mov eax,10; cmp eax,5; jg L1; mov ebx,100; jmp done; L1: mov ebx,200; done: ret  — eax>5 so ebx=200
  const { jit, compiled } = assertFunctionEquivalent([0xb8, 0x0a, 0x00, 0x00, 0x00, 0x83, 0xf8, 0x05, 0x7f, 0x07, 0xbb, 0x64, 0x00, 0x00, 0x00, 0xeb, 0x05, 0xbb, 0xc8, 0x00, 0x00, 0x00, 0xc3], "if-else-taken");
  assert.equal(jit.register.rbx, 200n, "eax>5 selects the L1 arm (ebx=200)");
  assert.ok(compiled.branchKind.includes("jmp"), "the then-arm jumps over the else-arm");
  // mov eax,3; cmp eax,5; jg L1; mov ebx,100; jmp done; L1: mov ebx,200; done: ret  — eax<5 so ebx=100
  const other = assertFunctionEquivalent([0xb8, 0x03, 0x00, 0x00, 0x00, 0x83, 0xf8, 0x05, 0x7f, 0x07, 0xbb, 0x64, 0x00, 0x00, 0x00, 0xeb, 0x05, 0xbb, 0xc8, 0x00, 0x00, 0x00, 0xc3], "if-else-nottaken");
  assert.equal(other.jit.register.rbx, 100n, "eax<5 selects the fall-through arm (ebx=100)");
});

test("multi-block: fall-through chain of four blocks", () => {
  // mov eax,1; cmp eax,1; jne X; mov ecx,2; cmp ecx,2; jne X; mov edx,3; X: ret
  // Neither jne is taken, so control falls straight through all four blocks.
  const { jit, compiled } = assertFunctionEquivalent([
    0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
    0x83, 0xf8, 0x01,             // cmp eax,1
    0x75, 0x0f,                   // jne X
    0xb9, 0x02, 0x00, 0x00, 0x00, // mov ecx,2
    0x83, 0xf9, 0x02,             // cmp ecx,2
    0x75, 0x05,                   // jne X
    0xba, 0x03, 0x00, 0x00, 0x00, // mov edx,3
    0xc3,                         // X: ret
  ], "fallthrough-chain");
  assert.equal(compiled.blockCount, 4, "the two jne targets split the run into four blocks");
  assert.equal(jit.register.rax, 1n);
  assert.equal(jit.register.rcx, 2n);
  assert.equal(jit.register.rdx, 3n);
  assert.ok(compiled.branchKind.includes("fallthrough"), "a split straight-line run terminates as a fall-through");
});

test("multi-block: memory + loop — sum an array in guest memory (store then reload each step)", () => {
  // A loop that also touches guest memory, proving the multi-block path shares the
  // interpreter's linear memory. mov ecx,3; mov eax,0; loop: dec ecx; mov [rsp-8],ecx;
  // add eax,[rsp-8]; test ecx,ecx; jnz loop; ret  — eax = 2+1+0 = 3
  const { jit } = assertFunctionEquivalent([
    0xb9, 0x03, 0x00, 0x00, 0x00,       // mov ecx,3
    0xb8, 0x00, 0x00, 0x00, 0x00,       // mov eax,0
    0xff, 0xc9,                         // loop: dec ecx
    0x48, 0x89, 0x4c, 0x24, 0xf8,       // mov [rsp-8],rcx
    0x48, 0x03, 0x44, 0x24, 0xf8,       // add rax,[rsp-8]
    0x85, 0xc9,                         // test ecx,ecx
    0x75, 0xf0,                         // jnz loop (rel -16 back to dec)
    0xc3,                               // ret
  ], "mem-loop");
  assert.equal(jit.register.rax, 3n, "the memory-touching loop accumulates 2+1+0 = 3");
});

test("multi-block: iteration cap stops a runaway loop (budget_exhausted, no hang)", () => {
  // L: jmp L  (an infinite guest loop). The bounded dispatch must stop and report
  // budget_exhausted rather than hanging the module.
  const image = Buffer.from([0xeb, 0xfe]);
  const compiled = compileFunction(image, { loadBase, decodeStructured, guestLen: image.length + 0x10000, iterationCap: 1000 });
  assertRealModule(compiled.bytes);
  assert.ok(compiled.complete, "an in-function jmp self-loop is a compilable (if non-terminating) shape");
  const jit = runFunction(image, { image, loadBase, decodeStructured, iterationCap: 1000 });
  assert.equal(jit.statusName, "budget_exhausted", "the iteration cap must stop the runaway with a budget status");
  // A second run with a different cap still terminates (the cap is honored, not luck).
  const jit2 = runFunction(image, { image, loadBase, decodeStructured, iterationCap: 5 });
  assert.equal(jit2.statusName, "budget_exhausted", "a smaller cap also stops the runaway");
});

// -------------------- direct calls across guest functions (CALL/RET) --------------------
//
// A `call rel32/rel8` (E8/near) to another lifted guest function in the compiled
// set now compiles to real cross-function control flow: the call pushes the
// return address on the SAME guest stack (rsp-=8, store next-rip) and transfers
// to the callee entry block; the callee's RET pops that address and dispatches
// back. Every microprogram below runs through BOTH the interpreter oracle and the
// multi-block WASM module, asserting bit-exact GPRs + flags AND the exact stack
// bytes the call/ret touched (interpret() writes loadBase+returnRva at [rsp] on a
// call — the identical value the codegen stores at the identical guest address).

test("call: leaf returns a value in eax, caller uses it (bit-exact stack push/pop)", () => {
  // call leaf; add eax,8; ret   leaf: mov eax,42; ret   → eax = 42 + 8 = 50
  const code = [
    0xe8, 0x04, 0x00, 0x00, 0x00, // 0x00 call leaf (target 0x09)
    0x83, 0xc0, 0x08,             // 0x05 add eax,8
    0xc3,                         // 0x08 ret (entry frame)
    0xb8, 0x2a, 0x00, 0x00, 0x00, // 0x09 leaf: mov eax,42
    0xc3,                         // 0x0e ret
  ];
  const { jit, compiled } = assertFunctionEquivalent(code, "call-leaf");
  assert.equal(jit.register.rax, 50n, "eax = leaf result (42) + 8 = 50");
  assert.ok(compiled.branchKind.includes("call"), "the E8 direct call is emitted as a real call");
  // The call pushed the return address (loadBase + 0x05) at rsp0-8; after the
  // balanced call/ret it remains as a stale qword — the exact byte the oracle wrote.
  assert.equal(stackQword(jit, initialRsp(code) - 8n), loadBase + 0x05n, "return address pushed on the guest stack is bit-exact");
});

test("call: nested A→B→C, each frame's return address on the stack (bit-exact)", () => {
  // A: call B; ret   B: call C; add eax,1; ret   C: mov eax,10; ret  → eax = 10 + 1 = 11
  const code = [
    0xe8, 0x01, 0x00, 0x00, 0x00, // 0x00 A: call B (target 0x06)
    0xc3,                         // 0x05 A: ret
    0xe8, 0x04, 0x00, 0x00, 0x00, // 0x06 B: call C (target 0x0f)
    0x83, 0xc0, 0x01,             // 0x0b B: add eax,1
    0xc3,                         // 0x0e B: ret
    0xb8, 0x0a, 0x00, 0x00, 0x00, // 0x0f C: mov eax,10
    0xc3,                         // 0x14 C: ret
  ];
  const { jit, compiled } = assertFunctionEquivalent(code, "call-nested");
  assert.equal(jit.register.rax, 11n, "C returns 10, B adds 1, A returns → eax = 11");
  assert.equal(compiled.blockCount, 5, "A, B, C entries + two return-resume blocks");
  const rsp0 = initialRsp(code);
  assert.equal(stackQword(jit, rsp0 - 8n), loadBase + 0x05n, "A→B return address (loadBase+0x05) on the stack");
  assert.equal(stackQword(jit, rsp0 - 16n), loadBase + 0x0bn, "B→C return address (loadBase+0x0b) one frame deeper");
});

test("call: leaf invoked inside a counted loop (call in a back-edge, bit-exact)", () => {
  // mov ecx,3; mov eax,0; loop: call add5; dec ecx; jnz loop; ret   add5: add eax,5; ret
  const code = [
    0xb9, 0x03, 0x00, 0x00, 0x00, // 0x00 mov ecx,3
    0xb8, 0x00, 0x00, 0x00, 0x00, // 0x05 mov eax,0
    0xe8, 0x05, 0x00, 0x00, 0x00, // 0x0a loop: call add5 (target 0x14)
    0xff, 0xc9,                   // 0x0f dec ecx
    0x75, 0xf7,                   // 0x11 jnz loop (rel -9 → 0x0a)
    0xc3,                         // 0x13 ret
    0x83, 0xc0, 0x05,             // 0x14 add5: add eax,5
    0xc3,                         // 0x17 ret
  ];
  const { jit, compiled } = assertFunctionEquivalent(code, "call-in-loop");
  assert.equal(jit.register.rax, 15n, "the leaf adds 5 on each of 3 iterations → eax = 15");
  assert.equal(jit.register.rcx, 0n, "the loop counter reaches 0");
  assert.ok(compiled.branchKind.includes("call") && compiled.branchKind.includes("jcc"), "a call inside a jcc loop");
  // The last iteration pushed the return address (loadBase+0x0f) at rsp0-8.
  assert.equal(stackQword(jit, initialRsp(code) - 8n), loadBase + 0x0fn, "the last call's return address is on the stack");
});

test("call: recursive factorial with self-recursion, deep frames on the stack (bit-exact)", () => {
  // entry: mov ecx,5; call fact; ret
  // fact: cmp ecx,1; jg rec; mov eax,1; ret   rec: push rcx; dec ecx; call fact; pop rcx; imul eax,ecx; ret
  const code = [
    0xb9, 0x05, 0x00, 0x00, 0x00, // 0x00 mov ecx,5
    0xe8, 0x01, 0x00, 0x00, 0x00, // 0x05 call fact (target 0x0b)
    0xc3,                         // 0x0a ret
    0x83, 0xf9, 0x01,             // 0x0b fact: cmp ecx,1
    0x7f, 0x06,                   // 0x0e jg rec (target 0x16)
    0xb8, 0x01, 0x00, 0x00, 0x00, // 0x10 mov eax,1
    0xc3,                         // 0x15 ret (base case)
    0x51,                         // 0x16 rec: push rcx
    0xff, 0xc9,                   // 0x17 dec ecx
    0xe8, 0xed, 0xff, 0xff, 0xff, // 0x19 call fact (target 0x0b, rel -19)
    0x59,                         // 0x1e pop rcx
    0x0f, 0xaf, 0xc1,             // 0x1f imul eax,ecx
    0xc3,                         // 0x22 ret
  ];
  const { jit, compiled } = assertFunctionEquivalent(code, "call-recursive");
  assert.equal(jit.register.rax, 120n, "5! = 120, bit-exact through five recursive frames");
  assert.equal(jit.register.rcx, 5n, "the restored counter equals the input");
  assert.ok(compiled.branchKind.includes("call"), "the self-recursive call is a real direct call");
  // The four recursive re-invocations each pushed the same return address
  // (loadBase+0x1e) below the entry frame's saved return (loadBase+0x0a).
  const rsp0 = initialRsp(code);
  assert.equal(stackQword(jit, rsp0 - 8n), loadBase + 0x0an, "the entry→fact return address is at the top frame");
  assert.equal(stackQword(jit, rsp0 - 24n), loadBase + 0x1en, "a recursive fact→fact return address sits deeper on the stack");
});

test("call: runaway recursion is bounded by the iteration cap (budget_exhausted, no hang)", () => {
  // call self; ret  — an infinite direct recursion. The bounded dispatch must stop
  // with budget_exhausted rather than hanging or faulting on stack growth.
  const image = Buffer.from([0xe8, 0xfb, 0xff, 0xff, 0xff, 0xc3]); // call 0 (self); ret
  const compiled = compileFunction(image, { loadBase, decodeStructured, guestLen: image.length + 0x10000, iterationCap: 1000 });
  assertRealModule(compiled.bytes);
  assert.ok(compiled.complete, "an infinite self-recursion is a compilable (non-terminating) call shape");
  assert.ok(compiled.branchKind.includes("call"), "the recursive edge is a real call");
  const jit = runFunction(image, { image, loadBase, decodeStructured, iterationCap: 1000 });
  assert.equal(jit.statusName, "budget_exhausted", "the iteration cap stops the runaway recursion");
  // A tighter cap also stops it (the cap is honored, not luck).
  const jit2 = runFunction(image, { image, loadBase, decodeStructured, iterationCap: 5 });
  assert.equal(jit2.statusName, "budget_exhausted", "a smaller cap also stops the runaway recursion");
});

// -------------------- external HLE import-call boundary (WASM import) --------------------
//
// A `call` to a target OUTSIDE the compiled set is an HLE import. With a bound host
// callback the codegen now emits a REAL WASM import call: spill the register file +
// flags to the shared memory, call (import "env" "hostCall" (func (param i64)
// (result i32))) with the target VA, then reload — the host performs the effect
// over the same memory and writes e.g. rax back. Each microprogram is run through
// BOTH the interpreter ORACLE (the external effect realized by an IN-IMAGE stub the
// interpreter naturally calls) and the WASM module (the SAME image, with those stub
// addresses marked external so the WASM path routes them through hostCall). The two
// are asserted bit-exact on GPRs, flags, AND the pushed return-address stack bytes.
// The callback is also asserted to OBSERVE the correct spilled guest state.

// Runs the image through the interpreter (stub reached in-image) and the WASM module
// (stubs at externalRva routed through hostCall), asserting bit-exact GPRs + flags.
function assertExternalEquivalent(code, externalRva, hostCall, label) {
  const image = Buffer.from(code);
  const oracle = interpret({ image, loadBase, entryRva: 0, budget: 4096 });
  assert.equal(oracle.stop_reason, "entry_return", `${label}: oracle stop_reason ${oracle.stop_reason} ${oracle.exception?.message ?? ""}`);

  const compiled = compileFunction(image, { loadBase, decodeStructured, guestLen: image.length + 0x10000, hostCall, externalRva });
  assertRealModule(compiled.bytes);
  assert.ok(compiled.complete, `${label}: codegen incomplete — fell back on ${JSON.stringify(compiled.coverage.unsupported)}`);
  assert.ok(compiled.usesHost, `${label}: the module must import and call the host boundary`);
  assert.ok(compiled.branchKind.includes("call_external"), `${label}: an external call boundary must be emitted`);

  const jit = runFunction(image, { image, loadBase, decodeStructured, hostCall, externalRva });
  assert.equal(jit.statusName, "ok", `${label}: run status ${jit.statusName}, expected ok`);
  for (const name of REG) {
    assert.equal(jit.register[name], oracle.register[name], `${label}: reg ${name} WASM 0x${jit.register[name].toString(16)} != oracle 0x${oracle.register[name].toString(16)}`);
  }
  for (const name of FLAG) {
    assert.equal(jit.flag[name], oracle.flag[name], `${label}: flag ${name} WASM ${jit.flag[name]} != oracle ${oracle.flag[name]}`);
  }
  return { jit, compiled };
}

test("external call: host sets rax, caller uses it (mov ecx,5; call ext; add eax,ecx → 105)", () => {
  // The interpreter runs the in-image stub `mov eax,100; ret` at 0x0D; the WASM path
  // marks 0x0D external, so the call routes through hostCall (which sets rax=100).
  const code = [
    0xb9, 0x05, 0x00, 0x00, 0x00, // 0x00 mov ecx,5
    0xe8, 0x03, 0x00, 0x00, 0x00, // 0x05 call ext (target 0x0D)
    0x01, 0xc8,                   // 0x0A add eax,ecx
    0xc3,                         // 0x0C ret (entry frame)
    0xb8, 0x64, 0x00, 0x00, 0x00, // 0x0D ext: mov eax,100  (interpreter-side stub)
    0xc3,                         // 0x12 ret
  ];
  let observed = null;
  const hostCall = (targetAddr, ctx) => {
    observed = ctx.readReg("rcx"); // the host must SEE the spilled guest state
    ctx.writeReg("rax", 100n);
    return 0;
  };
  const { jit } = assertExternalEquivalent(code, [0x0d], hostCall, "ext-rax");
  assert.equal(jit.register.rax, 105n, "eax = host result (100) + ecx (5) = 105");
  assert.equal(jit.register.rcx, 5n, "ecx is preserved across the import boundary");
  assert.equal(observed, 5n, "the host callback observed ecx=5 from the register file before setting rax");
  // The call pushed the return address (loadBase+0x0A) at rsp0-8; after the balanced
  // boundary it remains as a stale qword — the exact byte the interpreter wrote.
  assert.equal(stackQword(jit, initialRsp(code) - 8n), loadBase + 0x0an, "the import-call return address is bit-exact on the guest stack");
});

test("external call: two import calls in sequence (each host effect distinct, bit-exact)", () => {
  const code = [
    0xb9, 0x05, 0x00, 0x00, 0x00, // 0x00 mov ecx,5
    0xe8, 0x08, 0x00, 0x00, 0x00, // 0x05 call extA (target 0x12)
    0xe8, 0x09, 0x00, 0x00, 0x00, // 0x0A call extB (target 0x18)
    0x01, 0xcb,                   // 0x0F add ebx,ecx
    0xc3,                         // 0x11 ret
    0xb8, 0x64, 0x00, 0x00, 0x00, // 0x12 extA: mov eax,100
    0xc3,                         // 0x17 ret
    0xbb, 0xc8, 0x00, 0x00, 0x00, // 0x18 extB: mov ebx,200
    0xc3,                         // 0x1D ret
  ];
  const vaA = loadBase + 0x12n;
  const vaB = loadBase + 0x18n;
  const seen = [];
  const hostCall = (targetAddr, ctx) => {
    if (targetAddr === vaA) { seen.push(["A", ctx.readReg("rcx")]); ctx.writeReg("rax", 100n); return 0; }
    if (targetAddr === vaB) { seen.push(["B", ctx.readReg("rax")]); ctx.writeReg("rbx", 200n); return 0; }
    return 1;
  };
  const { jit } = assertExternalEquivalent(code, [0x12, 0x18], hostCall, "ext-seq");
  assert.equal(jit.register.rax, 100n, "extA set rax=100");
  assert.equal(jit.register.rbx, 205n, "extB set rbx=200, then add ebx,ecx → 205");
  assert.deepEqual(seen, [["A", 5n], ["B", 100n]], "the host observed ecx=5 at the first boundary and rax=100 at the second");
});

test("external call: import call inside a counted loop (host accumulates, bit-exact)", () => {
  // mov ecx,3; mov eax,0; loop: call ext; dec ecx; jnz loop; ret   ext: lea eax,[rax+5]; ret
  // The stub uses LEA (no flag effect) so the host mock is identical at every step;
  // the only flag-defining op is `dec ecx`, matched by both paths.
  const code = [
    0xb9, 0x03, 0x00, 0x00, 0x00, // 0x00 mov ecx,3
    0xb8, 0x00, 0x00, 0x00, 0x00, // 0x05 mov eax,0
    0xe8, 0x05, 0x00, 0x00, 0x00, // 0x0A loop: call ext (target 0x14)
    0xff, 0xc9,                   // 0x0F dec ecx
    0x75, 0xf7,                   // 0x11 jnz loop (rel -9 → 0x0A)
    0xc3,                         // 0x13 ret
    0x8d, 0x40, 0x05,             // 0x14 ext: lea eax,[rax+5]
    0xc3,                         // 0x17 ret
  ];
  let firstObserved = null;
  let calls = 0;
  const hostCall = (targetAddr, ctx) => {
    if (calls === 0) firstObserved = ctx.readReg("rax");
    calls += 1;
    ctx.writeReg("rax", (ctx.readReg("rax") + 5n) & 0xffffffffn); // lea eax,[rax+5] zero-extends
    return 0;
  };
  const { jit } = assertExternalEquivalent(code, [0x14], hostCall, "ext-loop");
  assert.equal(jit.register.rax, 15n, "three import calls accumulate 5+5+5 = 15");
  assert.equal(jit.register.rcx, 0n, "the loop counter reaches 0");
  assert.equal(calls, 3, "the host boundary ran once per loop iteration");
  assert.equal(firstObserved, 0n, "the host observed eax=0 at the first iteration");
});

test("external call: an unhandled host call (nonzero status) returns an honest fallback", () => {
  // The same shape as ext-rax, but the host reports 'unhandled' (nonzero). The module
  // must return the fallback status rather than a wrong result.
  const code = [
    0xb9, 0x05, 0x00, 0x00, 0x00, // mov ecx,5
    0xe8, 0x03, 0x00, 0x00, 0x00, // call ext (target 0x0D)
    0x01, 0xc8,                   // add eax,ecx
    0xc3,                         // ret
    0xb8, 0x64, 0x00, 0x00, 0x00, // ext: mov eax,100
    0xc3,                         // ret
  ];
  const image = Buffer.from(code);
  const hostCall = () => 1; // never handled
  const compiled = compileFunction(image, { loadBase, decodeStructured, guestLen: image.length + 0x10000, hostCall, externalRva: [0x0d] });
  assertRealModule(compiled.bytes);
  assert.ok(compiled.complete, "the boundary is emitted (completeness is a compile-time property)");
  const jit = runFunction(image, { image, loadBase, decodeStructured, hostCall, externalRva: [0x0d] });
  assert.equal(jit.statusName, "fallback", "an unhandled host call must fall back, never return a wrong result");
});

test("external call: without a host binding it stays an honest, named fallback", () => {
  // No hostCall bound → the external target is NOT emitted as an import call; it
  // remains the honest control_call_external fallback (unchanged prior behavior).
  const code = [
    0xb9, 0x05, 0x00, 0x00, 0x00,
    0xe8, 0x03, 0x00, 0x00, 0x00,
    0x01, 0xc8, 0xc3,
    0xb8, 0x64, 0x00, 0x00, 0x00, 0xc3,
  ];
  const image = Buffer.from(code);
  const compiled = compileFunction(image, { loadBase, decodeStructured, guestLen: image.length + 0x10000, externalRva: [0x0d] });
  assert.equal(compiled.complete, false, "no host binding → the external call is a fallback");
  assert.ok(compiled.coverage.unsupported.some((u) => u.reason === "control_call_external"), "named control_call_external");
});

test("multi-block: unmodelled call shapes are honest, named fallbacks (indirect, external, indirect jmp)", () => {
  // An indirect (computed-target) call is not modelled — an honest named fallback.
  const indImage = Buffer.from([0xb8, 0x01, 0x00, 0x00, 0x00, 0xff, 0xd0, 0xc3]); // mov eax,1; call rax; ret
  const indCompiled = compileFunction(indImage, { loadBase, decodeStructured, guestLen: indImage.length + 0x10000 });
  assertRealModule(indCompiled.bytes);
  assert.equal(indCompiled.complete, false, "an indirect call must be an honest fallback, not emitted");
  assert.ok(indCompiled.coverage.unsupported.some((u) => u.reason === "control_call_indirect"), "the indirect call must be named control_call_indirect");
  assert.equal(runFunction(indImage, { image: indImage, loadBase, decodeStructured }).statusName, "fallback", "a fallback module reports the fallback status");

  // A direct call whose target is outside the compiled set (e.g. an HLE import
  // thunk) stays an honest fallback — no HLE binding is attempted here.
  const extImage = Buffer.from([0xe8, 0x00, 0x10, 0x00, 0x00, 0xc3]); // call +0x1000 (out of image); ret
  const extCompiled = compileFunction(extImage, { loadBase, decodeStructured, guestLen: extImage.length + 0x10000 });
  assertRealModule(extCompiled.bytes);
  assert.equal(extCompiled.complete, false, "a call outside the compiled set must be an honest fallback");
  assert.ok(extCompiled.coverage.unsupported.some((u) => u.reason === "control_call_external"), "the external call must be named control_call_external");
  assert.equal(runFunction(extImage, { image: extImage, loadBase, decodeStructured }).statusName, "fallback", "the external-call fallback module reports fallback");

  // An indirect jmp (computed target) is likewise a named fallback.
  const jmpImage = Buffer.from([0xb8, 0x01, 0x00, 0x00, 0x00, 0xff, 0xe0, 0xc3]); // mov eax,1; jmp rax; ret
  const jmpCompiled = compileFunction(jmpImage, { loadBase, decodeStructured, guestLen: jmpImage.length + 0x10000 });
  assertRealModule(jmpCompiled.bytes);
  assert.equal(jmpCompiled.complete, false, "an indirect jmp must be an honest fallback");
  assert.ok(jmpCompiled.coverage.unsupported.some((u) => u.reason === "control_jmpIndirect"), "the indirect jmp must be named");
});

test("multi-block: coverage report — control-flow shapes and branch kinds", () => {
  const shape = [...cflowShape].sort();
  const branch = [...cflowBranch].sort();
  process.stdout.write(`\n[wasm64] multi-block control-flow shapes bit-exact (${shape.length}): ${shape.join(", ")}\n`);
  process.stdout.write(`[wasm64] branch kinds emitted (${branch.length}): ${branch.join(", ")}\n`);
  process.stdout.write("[wasm64] direct CALL/RET across guest functions is bit-exact incl. the pushed return-address stack bytes\n");
  process.stdout.write("[wasm64] branch kinds on honest fallback: indirect call (control_call_indirect), external call (control_call_external), indirect jmp, computed/out-of-function targets\n");
  // conditional (jcc), unconditional (jmp), fall-through, ret, and direct call
  // must all appear as real emitted, bit-exact branch kinds.
  for (const kind of ["jcc", "jmp", "fallthrough", "ret", "call"]) {
    assert.ok(branch.includes(kind), `expected branch kind ${kind} to be exercised bit-exact`);
  }
  assert.ok(shape.length >= 4, `expected at least 4 distinct control-flow shapes, got ${shape.length}`);
});

// -------------------- SSE / SSE2 packed SIMD (v128 codegen) --------------------
//
// Each microprogram below is a straight-line run of SSE/SSE2 ops ending in RET,
// with all xmm/GPR inputs seeded through options (so the program itself is pure
// SIMD). Every one is executed TWICE: once by the interpreter ORACLE — the exact
// exported executeSse lib/lift64.mjs's interpret() drives, run against a faithful
// machine shim — and once by the emitted WebAssembly module (real v128 SIMD, the
// 0xFD opcode family). All sixteen 128-bit xmm registers AND the sixteen GPRs are
// asserted BIT-EXACT, and the flags are asserted untouched (SSE defines none).

const MASK64_T = (1n << 64n) - 1n;
const MASK128_T = (1n << 128n) - 1n;
const XMM = Array.from({ length: 16 }, (_, i) => i);
const DEFAULT_FLAG_T = { cf: false, pf: true, af: false, zf: true, sf: false, of: false };

// A faithful stand-in for lib/lift64.mjs's (unexported) Machine, exposing exactly
// the surface executeSse touches: the xmm/GPR files, guest memory, and the operand
// primitives — replicated byte-for-byte so the oracle here is the same oracle
// interpret() runs, just seeded directly rather than through GPR setup ops.
class MachineShim {
  constructor(mem, loadBase) {
    this.mem = mem;
    this.loadBase = loadBase;
    this.reg = new Array(16).fill(0n);
    this.xmm = new Array(16).fill(0n);
  }
  translate(address, sizeByte) {
    const offset = address - this.loadBase;
    if (offset < 0n || offset + BigInt(sizeByte) > BigInt(this.mem.length)) throw new Error(`guest address 0x${address.toString(16)} outside memory`);
    return Number(offset);
  }
  readMem(address, sizeByte) {
    const off = this.translate(address, sizeByte);
    let v = 0n;
    for (let i = 0; i < sizeByte; i += 1) v |= BigInt(this.mem[off + i]) << (8n * BigInt(i));
    return v;
  }
  writeMem(address, sizeByte, value) {
    const off = this.translate(address, sizeByte);
    for (let i = 0; i < sizeByte; i += 1) this.mem[off + i] = Number((value >> (8n * BigInt(i))) & 0xffn);
  }
  readReg(operand) {
    const raw = this.reg[operand.index];
    if (operand.size === 64) return raw & MASK64_T;
    if (operand.size === 32) return raw & 0xffffffffn;
    if (operand.size === 16) return raw & 0xffffn;
    if (operand.high8) return (raw >> 8n) & 0xffn;
    return raw & 0xffn;
  }
  writeReg(operand, value) {
    const index = operand.index;
    if (operand.size === 64) this.reg[index] = value & MASK64_T;
    else if (operand.size === 32) this.reg[index] = value & 0xffffffffn;
    else if (operand.size === 16) this.reg[index] = (this.reg[index] & ~0xffffn & MASK64_T) | (value & 0xffffn);
    else if (operand.high8) this.reg[index] = (this.reg[index] & ~0xff00n & MASK64_T) | ((value & 0xffn) << 8n);
    else this.reg[index] = (this.reg[index] & ~0xffn & MASK64_T) | (value & 0xffn);
  }
  effectiveAddress(mem, nextRip) {
    let addr = 0n;
    if (mem.rip_relative) addr = nextRip + BigInt(mem.disp);
    else {
      if (mem.base !== null) addr += this.reg[mem.base];
      if (mem.index !== null) addr += this.reg[mem.index] * BigInt(mem.scale);
      addr += BigInt(mem.disp);
    }
    return addr & MASK64_T;
  }
}

const REG_INDEX = Object.fromEntries(REG.map((name, i) => [name, i]));

// Runs the interpreter oracle over an SSE-only microprogram: seed the shim, step
// each lifted SSE node through executeSse (the exact interpret() dispatch), stop
// at RET. Returns the end-of-run xmm file, GPR file, and guest memory.
function runSseOracle(image, { register = {}, xmm = {} }) {
  const guestLen = image.length + 0x10000;
  const mem = Buffer.alloc(guestLen);
  Buffer.from(image).copy(mem, 0);
  const machine = new MachineShim(mem, loadBase);
  // seedState sets rsp to the same near-stack-top value the interpreter uses, so
  // the oracle must default rsp identically before any per-test overrides.
  const stackTop = loadBase + BigInt(image.length + 0x10000 - 16);
  machine.reg[4] = stackTop - 8n;
  for (const [name, value] of Object.entries(register)) machine.reg[REG_INDEX[name]] = BigInt(value) & MASK64_T;
  for (const [i, value] of Object.entries(xmm)) machine.xmm[Number(i)] = BigInt(value) & MASK128_T;

  const block = liftBlock(image, 0);
  for (const node of block.node) {
    if (node.op === "ret") { machine.reg[4] = (machine.reg[4] + BigInt(8 + (node.pop || 0))) & MASK64_T; break; }
    if (node.op !== "sse") throw new Error(`runSseOracle: non-SSE op ${node.op} in an SSE microprogram`);
    const nextRip = loadBase + BigInt(node.address) + BigInt(node.length);
    executeSse(machine, node, nextRip);
  }
  return { xmm: machine.xmm.map((v) => v & MASK128_T), register: machine.reg.map((v) => v & MASK64_T), memory: mem };
}

const sseCoverage = new Set();

// Lifts + runs an SSE microprogram through the interpreter oracle and the emitted
// v128 WASM module, asserting bit-exact xmm (all 128 bits) + GPR agreement and
// untouched flags. Returns the (agreeing) jit result and its coverage.
function assertSseEquivalent(code, seed, label) {
  const image = Buffer.from(code);
  const oracle = runSseOracle(image, seed);

  const block = liftBlock(image, 0);
  const compiled = compileBlock(block, { loadBase, guestLen: image.length + 0x10000 });
  assertRealModule(compiled.bytes);

  const jit = runBlock(block, { image, loadBase, register: seed.register ?? {}, xmm: seed.xmm ?? {} });
  assert.ok(jit.complete, `${label}: codegen incomplete — fell back on ${JSON.stringify(jit.coverage.unsupported)}`);

  for (const i of XMM) {
    assert.equal(jit.xmm[i], oracle.xmm[i], `${label}: xmm${i} WASM 0x${jit.xmm[i].toString(16)} != oracle 0x${oracle.xmm[i].toString(16)}`);
  }
  for (let i = 0; i < 16; i += 1) {
    assert.equal(jit.register[REG[i]], oracle.register[i], `${label}: reg ${REG[i]} WASM 0x${jit.register[REG[i]].toString(16)} != oracle 0x${oracle.register[i].toString(16)}`);
  }
  for (const name of FLAG) {
    assert.equal(jit.flag[name], DEFAULT_FLAG_T[name], `${label}: SSE must not touch flag ${name}`);
  }
  for (const kind of jit.coverage.emitted) if (kind.startsWith("sse:")) sseCoverage.add(kind);
  return jit;
}

// A fixed pair of 128-bit test patterns for the packed-lane ops (chosen so every
// lane width sees distinct signed/unsigned lanes, carries, and sign bits).
const PAT_A = 0x0011223344556677_8899aabbccddeeffn;
const PAT_B = 0xfedcba9876543210_0123456789abcdefn;

test("sse: movd gpr→xmm zero-extends into the low dword (66 0F 6E)", () => {
  // movd xmm1, eax; ret  — xmm1 = eax, upper 96 bits zero
  assertSseEquivalent([0x66, 0x0f, 0x6e, 0xc8, 0xc3], { register: { rax: 0xdeadbeefn }, xmm: { 1: PAT_A } }, "movd-load");
});

test("sse: movd xmm→gpr extracts the low dword (66 0F 7E), and movq round-trips", () => {
  // movd eax, xmm1; ret  — eax = low dword of xmm1 (zero-extended into rax)
  assertSseEquivalent([0x66, 0x0f, 0x7e, 0xc8, 0xc3], { xmm: { 1: PAT_A } }, "movd-store");
  // movq xmm2, xmm3; ret (F3 0F 7E)  — low 64 bits, upper cleared
  assertSseEquivalent([0xf3, 0x0f, 0x7e, 0xd3, 0xc3], { xmm: { 3: PAT_B } }, "movq-load");
});

test("sse: pxor xmm,xmm clears to zero (66 0F EF)", () => {
  const jit = assertSseEquivalent([0x66, 0x0f, 0xef, 0xd2, 0xc3], { xmm: { 2: PAT_A } }, "pxor-zero");
  assert.equal(jit.xmm[2], 0n, "pxor xmm2,xmm2 must zero the register");
});

test("sse: bitwise pand/pandn/por across lanes (66 0F DB/DF/EB)", () => {
  assertSseEquivalent([0x66, 0x0f, 0xdb, 0xc1, 0xc3], { xmm: { 0: PAT_A, 1: PAT_B } }, "pand");
  assertSseEquivalent([0x66, 0x0f, 0xdf, 0xc1, 0xc3], { xmm: { 0: PAT_A, 1: PAT_B } }, "pandn");
  assertSseEquivalent([0x66, 0x0f, 0xeb, 0xc1, 0xc3], { xmm: { 0: PAT_A, 1: PAT_B } }, "por");
});

test("sse: packed add at every lane width (paddb/w/d/q)", () => {
  for (const [op, label] of [[0xfc, "paddb"], [0xfd, "paddw"], [0xfe, "paddd"], [0xd4, "paddq"]]) {
    assertSseEquivalent([0x66, 0x0f, op, 0xc1, 0xc3], { xmm: { 0: PAT_A, 1: PAT_B } }, label);
  }
  // psubd too, to exercise the subtract path with borrows across lanes
  assertSseEquivalent([0x66, 0x0f, 0xfa, 0xc1, 0xc3], { xmm: { 0: PAT_A, 1: PAT_B } }, "psubd");
});

test("sse: packed compare eq/gt with signed lane semantics (pcmpeqd/pcmpgtd)", () => {
  const same = 0x00000001_00000001_00000001_00000001n;
  assertSseEquivalent([0x66, 0x0f, 0x76, 0xc1, 0xc3], { xmm: { 0: PAT_A, 1: same } }, "pcmpeqd");
  // pcmpgtb is signed: mixes lanes above/below to prove sign handling
  assertSseEquivalent([0x66, 0x0f, 0x64, 0xc1, 0xc3], { xmm: { 0: PAT_A, 1: PAT_B } }, "pcmpgtb");
});

test("sse: pshufd broadcast and general permute (66 0F 70 /ib)", () => {
  // pshufd xmm0, xmm1, 0x00  — broadcast lane 0 to all four dwords
  const jit = assertSseEquivalent([0x66, 0x0f, 0x70, 0xc1, 0x00, 0xc3], { xmm: { 1: PAT_A } }, "pshufd-broadcast");
  const lane0 = PAT_A & 0xffffffffn;
  assert.equal(jit.xmm[0], lane0 | (lane0 << 32n) | (lane0 << 64n) | (lane0 << 96n), "pshufd imm8=0 broadcasts dword 0");
  // pshufd xmm0, xmm1, 0x1b  — reverse the four dwords (3,2,1,0)
  assertSseEquivalent([0x66, 0x0f, 0x70, 0xc1, 0x1b, 0xc3], { xmm: { 1: PAT_A } }, "pshufd-reverse");
});

test("sse: immediate shifts psll/psrl/psra clamp at the lane width", () => {
  // pslld xmm0, 4 (66 0F 72 /6 ib)
  assertSseEquivalent([0x66, 0x0f, 0x72, 0xf0, 0x04, 0xc3], { xmm: { 0: PAT_A } }, "pslld-imm");
  // psrlw xmm0, 3 (66 0F 71 /2 ib)
  assertSseEquivalent([0x66, 0x0f, 0x71, 0xd0, 0x03, 0xc3], { xmm: { 0: PAT_A } }, "psrlw-imm");
  // psrad xmm0, 5 (66 0F 72 /4 ib) — arithmetic, sign-fills
  assertSseEquivalent([0x66, 0x0f, 0x72, 0xe0, 0x05, 0xc3], { xmm: { 0: PAT_B } }, "psrad-imm");
  // pslld xmm0, 40 — an over-width count must ZERO the lanes (WASM masks; codegen clamps)
  const jit = assertSseEquivalent([0x66, 0x0f, 0x72, 0xf0, 0x28, 0xc3], { xmm: { 0: PAT_A } }, "pslld-overwidth");
  assert.equal(jit.xmm[0], 0n, "pslld by 40 (> 32) must zero every dword lane");
});

test("sse: register-count shift pslld xmm,xmm with an over-width count (66 0F F2)", () => {
  // pslld xmm0, xmm1 with xmm1 low = 3 → shift each dword left by 3
  assertSseEquivalent([0x66, 0x0f, 0xf2, 0xc1, 0xc3], { xmm: { 0: PAT_A, 1: 3n } }, "pslld-reg");
  // pslld xmm0, xmm1 with xmm1 low = 100 (> 32) → all lanes zero
  const jit = assertSseEquivalent([0x66, 0x0f, 0xf2, 0xc1, 0xc3], { xmm: { 0: PAT_A, 1: 100n } }, "pslld-reg-overwidth");
  assert.equal(jit.xmm[0], 0n, "a register shift count > lane width must zero the lanes");
});

test("sse: whole-register byte shift pslldq/psrldq (66 0F 73 /7,/3 ib)", () => {
  assertSseEquivalent([0x66, 0x0f, 0x73, 0xf8, 0x03, 0xc3], { xmm: { 0: PAT_A } }, "pslldq-3");
  assertSseEquivalent([0x66, 0x0f, 0x73, 0xd8, 0x05, 0xc3], { xmm: { 0: PAT_A } }, "psrldq-5");
});

test("sse: pmullw, pmuludq, punpck, and pack (multiply + interleave + saturate)", () => {
  assertSseEquivalent([0x66, 0x0f, 0xd5, 0xc1, 0xc3], { xmm: { 0: PAT_A, 1: PAT_B } }, "pmullw");
  assertSseEquivalent([0x66, 0x0f, 0xf4, 0xc1, 0xc3], { xmm: { 0: PAT_A, 1: PAT_B } }, "pmuludq");
  assertSseEquivalent([0x66, 0x0f, 0x60, 0xc1, 0xc3], { xmm: { 0: PAT_A, 1: PAT_B } }, "punpcklbw");
  assertSseEquivalent([0x66, 0x0f, 0x6a, 0xc1, 0xc3], { xmm: { 0: PAT_A, 1: PAT_B } }, "punpckhdq");
  assertSseEquivalent([0x66, 0x0f, 0x63, 0xc1, 0xc3], { xmm: { 0: PAT_A, 1: PAT_B } }, "packsswb");
  assertSseEquivalent([0x66, 0x0f, 0x67, 0xc1, 0xc3], { xmm: { 0: PAT_A, 1: PAT_B } }, "packuswb");
});

test("sse: sign-mask extracts (movmskps, pmovmskb) and pextrw into a GPR", () => {
  // movmskps eax, xmm1 (0F 50) — 4 float sign bits into eax
  assertSseEquivalent([0x0f, 0x50, 0xc1, 0xc3], { xmm: { 1: PAT_B } }, "movmskps");
  // pmovmskb eax, xmm1 (66 0F D7) — 16 byte sign bits into eax
  const jit = assertSseEquivalent([0x66, 0x0f, 0xd7, 0xc1, 0xc3], { xmm: { 1: PAT_B } }, "pmovmskb");
  let mask = 0n;
  for (let i = 0; i < 16; i += 1) if (((PAT_B >> BigInt(i * 8 + 7)) & 1n) === 1n) mask |= 1n << BigInt(i);
  assert.equal(jit.register.rax, mask, "pmovmskb gathers the 16 byte sign bits");
  // pextrw eax, xmm1, 3 (66 0F C5 /r ib)
  assertSseEquivalent([0x66, 0x0f, 0xc5, 0xc1, 0x03, 0xc3], { xmm: { 1: PAT_A } }, "pextrw");
});

test("sse: lane moves movhlps/movlhps and the SSE3 dup moves", () => {
  assertSseEquivalent([0x0f, 0x12, 0xc1, 0xc3], { xmm: { 0: PAT_A, 1: PAT_B } }, "movhlps");     // 0F 12 (reg form)
  assertSseEquivalent([0x0f, 0x16, 0xc1, 0xc3], { xmm: { 0: PAT_A, 1: PAT_B } }, "movlhps");     // 0F 16 (reg form)
  assertSseEquivalent([0xf2, 0x0f, 0x12, 0xc1, 0xc3], { xmm: { 1: PAT_A } }, "movddup");         // F2 0F 12
  assertSseEquivalent([0xf3, 0x0f, 0x12, 0xc1, 0xc3], { xmm: { 1: PAT_A } }, "movsldup");        // F3 0F 12
  assertSseEquivalent([0xf3, 0x0f, 0x16, 0xc1, 0xc3], { xmm: { 1: PAT_A } }, "movshdup");        // F3 0F 16
});

test("sse: xmm memory round-trip — movdqa store then reload (real WASM v128 memory)", () => {
  // movdqa [rsi], xmm0; movdqa xmm3, [rsi]; ret  — store 128 bits, load them back
  const code = [
    0x66, 0x0f, 0x7f, 0x06, // movdqa [rsi], xmm0
    0x66, 0x0f, 0x6f, 0x1e, // movdqa xmm3, [rsi]
    0xc3,
  ];
  const image = Buffer.from(code);
  // Point rsi at a zeroed stack slot well inside guest memory.
  const target = loadBase + BigInt(image.length + 0x10000 - 0x100);
  const jit = assertSseEquivalent(code, { register: { rsi: target }, xmm: { 0: PAT_A } }, "movdqa-roundtrip");
  assert.equal(jit.xmm[3], PAT_A, "the reloaded xmm3 must equal the stored xmm0");
  // Inspect the raw WASM memory bytes: the 128-bit pattern must be present, little-endian.
  const offset = Number(target - loadBase);
  const dv = new DataView(jit.memory.buffer, jit.memory.byteOffset, jit.memory.byteLength);
  assert.equal(dv.getBigUint64(offset, true), PAT_A & MASK64_T, "stored low qword present in WASM memory");
  assert.equal(dv.getBigUint64(offset + 8, true), (PAT_A >> 64n) & MASK64_T, "stored high qword present in WASM memory");
});

test("sse: movss/movsd scalar merge and load semantics", () => {
  // movss xmm0, xmm1 (F3 0F 10) — merge low 32, preserve upper 96 of xmm0
  const jit = assertSseEquivalent([0xf3, 0x0f, 0x10, 0xc1, 0xc3], { xmm: { 0: PAT_A, 1: PAT_B } }, "movss-merge");
  assert.equal(jit.xmm[0], (PAT_A & ~0xffffffffn & MASK128_T) | (PAT_B & 0xffffffffn), "movss reg-reg merges the low dword, preserves the rest");
  // movsd xmm0, xmm1 (F2 0F 10) — merge low 64, preserve upper 64
  assertSseEquivalent([0xf2, 0x0f, 0x10, 0xc1, 0xc3], { xmm: { 0: PAT_A, 1: PAT_B } }, "movsd-merge");
});

test("sse: honest fallback for the float horizontal/interleaved ops (hadd/hsub/addsub)", () => {
  // haddps xmm0, xmm1 (F2 0F 7C) — an SSE3 float horizontal add. WASM cannot
  // express its exact IEEE lane pairing 1:1, so it MUST stay a named fallback,
  // never a wrong-lane emission.
  const image = Buffer.from([0xf2, 0x0f, 0x7c, 0xc1, 0xc3]);
  const block = liftBlock(image, 0);
  const compiled = compileBlock(block, { loadBase, guestLen: image.length + 0x10000 });
  assertRealModule(compiled.bytes);
  assert.equal(compiled.complete, false, "haddps must be an honest fallback, not emitted");
  assert.ok(compiled.coverage.unsupported.some((u) => u.reason === "sse_hadd"), "the float horizontal add must be named sse_hadd");
});

test("sse: coverage report — v128 op kinds emitted bit-exact vs honest fallbacks", () => {
  const emitted = [...sseCoverage].map((k) => k.slice(4)).sort();
  process.stdout.write(`\n[wasm64] SSE ops emitted bit-exact as v128 (${emitted.length}): ${emitted.join(", ")}\n`);
  process.stdout.write("[wasm64] SSE ops kept as honest named fallbacks (float IEEE lane pairing): hadd, hsub, addsub\n");
  // The mission's required op families must all appear as real, bit-exact emissions.
  for (const kind of ["movd_load", "movd_store", "bitwise", "padd", "psub", "pcmpeq", "pcmpgt", "pshufd", "psll", "psrl", "psra", "pslldq", "pmullw", "pmuludq", "punpckl", "punpckh", "packsswb", "movmskps", "pmovmskb", "pextrw", "movhlps", "movlhps", "movss", "movsd", "mov128"]) {
    assert.ok(sseCoverage.has(`sse:${kind}`), `expected SSE op ${kind} to be emitted bit-exact`);
  }
  assert.ok(emitted.length >= 20, `expected at least 20 distinct SSE op kinds emitted, got ${emitted.length}`);
});

// -------------------- compact multi-region address space (64-bit sparse map) --------------------
//
// The real runtime maps a SPARSE 64-bit guest space — image at ~0x140000000, a
// HIGH stack at ~0x7ff000000000, an HLE arena at ~0xF8000000 — not one flat 4 GiB
// block. lib/wasm64.mjs now packs each region back-to-back into ONE 32-bit WASM
// memory and translates every guest access through a region map, so a compiled
// function can address the real space bit-exact. The oracle here is a faithful
// MULTI-REGION interpreter that reuses lib/lift64.mjs's exact flag engine
// (materializeFlag) and decoder (decodeStructured); it is first CROSS-CHECKED
// against lib/lift64.mjs interpret() on a flat program so its fidelity is proven,
// then used as the reference for the sparse layouts the flat interpreter cannot
// represent (a stack at 140 TB overflows a flat buffer). Each microprogram is run
// through BOTH the oracle and the WASM module and asserted bit-exact on all
// sixteen GPRs, six flags, and every region's post-run bytes.

const RSP = 4;
const MASK64_MR = (1n << 64n) - 1n;
const mrSizeMask = (bit) => (1n << BigInt(bit)) - 1n;
const mrSign = (bit) => 1n << BigInt(bit - 1);
const mrSigned = (value, fromBit) => {
  const m = mrSizeMask(fromBit);
  const v = value & m;
  return (v & mrSign(fromBit)) ? v - (1n << BigInt(fromBit)) : v;
};

// A multi-region guest machine mirroring lib/exec64.mjs's Machine surface: a list
// of { base, size, mem } regions, byte-addressed by guest VA through locate(). It
// records a flagSource descriptor identical to the interpreter's and materializes
// the six flags through the SHARED lib/lift64.mjs materializeFlag, so its flag
// results cannot diverge from the oracle the WASM path targets.
class MultiRegionMachine {
  constructor(region) {
    this.region = region; // [{ base: BigInt, size: Number, mem: Buffer, kind }]
    this.reg = new Array(16).fill(0n);
    this.rip = 0n;
    this.flagSource = null;
  }
  flags() { return materializeFlag(this.flagSource); }
  locate(address, sizeByte) {
    for (const r of this.region) {
      const end = r.base + BigInt(r.size);
      if (address >= r.base && address + BigInt(sizeByte) <= end) return { mem: r.mem, off: Number(address - r.base) };
    }
    throw new Error(`guest address 0x${address.toString(16)} is outside the mapped regions`);
  }
  readMem(address, sizeByte) {
    const { mem, off } = this.locate(address, sizeByte);
    let v = 0n;
    for (let i = 0; i < sizeByte; i += 1) v |= BigInt(mem[off + i]) << (8n * BigInt(i));
    return v;
  }
  writeMem(address, sizeByte, value) {
    const { mem, off } = this.locate(address, sizeByte);
    for (let i = 0; i < sizeByte; i += 1) mem[off + i] = Number((value >> (8n * BigInt(i))) & 0xffn);
  }
  readReg(op) {
    const raw = this.reg[op.index];
    if (op.size === 64) return raw & MASK64_MR;
    if (op.size === 32) return raw & 0xffffffffn;
    if (op.size === 16) return raw & 0xffffn;
    if (op.high8) return (raw >> 8n) & 0xffn;
    return raw & 0xffn;
  }
  writeReg(op, value) {
    const i = op.index;
    if (op.size === 64) this.reg[i] = value & MASK64_MR;
    else if (op.size === 32) this.reg[i] = value & 0xffffffffn;
    else if (op.size === 16) this.reg[i] = (this.reg[i] & ~0xffffn & MASK64_MR) | (value & 0xffffn);
    else if (op.high8) this.reg[i] = (this.reg[i] & ~0xff00n & MASK64_MR) | ((value & 0xffn) << 8n);
    else this.reg[i] = (this.reg[i] & ~0xffn & MASK64_MR) | (value & 0xffn);
  }
  effectiveAddress(mem, nextRip) {
    let addr = 0n;
    if (mem.rip_relative) addr = nextRip + BigInt(mem.disp);
    else {
      if (mem.base !== null) addr += this.reg[mem.base];
      if (mem.index !== null) addr += this.reg[mem.index] * BigInt(mem.scale);
      addr += BigInt(mem.disp);
    }
    return addr & MASK64_MR;
  }
  readOperand(op, nextRip) {
    if (op.kind === "imm") return op.value & mrSizeMask(op.size);
    if (op.kind === "reg") return this.readReg(op);
    return this.readMem(this.effectiveAddress(op, nextRip), op.size / 8);
  }
  writeOperand(op, value, nextRip) {
    if (op.kind === "reg") this.writeReg(op, value);
    else this.writeMem(this.effectiveAddress(op, nextRip), op.size / 8, value);
  }
}

// The guest condition-code table, ported verbatim from lib/lift64.mjs
// conditionHolds (which the library does not export). Its fidelity is not taken
// on trust: the cross-check test below runs a jcc/call/indirect program through
// BOTH this shim and lib/lift64.mjs interpret() and asserts they agree.
function mrConditionHolds(cc, f) {
  switch (cc) {
    case 0: return f.of;
    case 1: return !f.of;
    case 2: return f.cf;
    case 3: return !f.cf;
    case 4: return f.zf;
    case 5: return !f.zf;
    case 6: return f.cf || f.zf;
    case 7: return !(f.cf || f.zf);
    case 8: return f.sf;
    case 9: return !f.sf;
    case 10: return f.pf;
    case 11: return !f.pf;
    case 12: return f.sf !== f.of;
    case 13: return f.sf === f.of;
    case 14: return f.zf || f.sf !== f.of;
    default: return !(f.zf || f.sf !== f.of);
  }
}

// One node of the multi-region reference, ported verbatim from lib/exec64.mjs's
// executeNode/executeAlu (the integer subset the microprograms use). Returns true
// when the entry frame's RET unwound (the sentinel), else false.
function mrExecNode(m, node, nextRip, sentinel) {
  const size = node.size;
  switch (node.op) {
    case "nop": m.rip = nextRip; return false;
    case "mov": m.writeOperand(node.dst, m.readOperand(node.src, nextRip), nextRip); m.rip = nextRip; return false;
    case "movzx": m.writeReg(node.dst, m.readOperand(node.src, nextRip) & mrSizeMask(node.srcSize)); m.rip = nextRip; return false;
    case "movsx": m.writeReg(node.dst, mrSigned(m.readOperand(node.src, nextRip), node.srcSize) & mrSizeMask(node.size)); m.rip = nextRip; return false;
    case "movsxd": m.writeReg(node.dst, mrSigned(m.readOperand(node.src, nextRip), 32) & mrSizeMask(node.size)); m.rip = nextRip; return false;
    case "lea": m.writeReg(node.dst, m.effectiveAddress(node.src, nextRip) & mrSizeMask(node.size)); m.rip = nextRip; return false;
    case "alu": {
      const mask = mrSizeMask(size);
      const a = m.readOperand(node.dst, nextRip) & mask;
      const b = m.readOperand(node.src, nextRip) & mask;
      let result; let flag;
      switch (node.aluOp) {
        case "add": result = (a + b) & mask; flag = { kind: "add", size, a, b, cin: 0n, result }; break;
        case "adc": { const cin = m.flags().cf ? 1n : 0n; result = (a + b + cin) & mask; flag = { kind: "add", size, a, b, cin, result }; break; }
        case "sub": case "cmp": result = (a - b) & mask; flag = { kind: "sub", size, a, b, cin: 0n, result }; break;
        case "sbb": { const cin = m.flags().cf ? 1n : 0n; result = (a - b - cin) & mask; flag = { kind: "sub", size, a, b, cin, result }; break; }
        case "and": case "test": result = a & b & mask; flag = { kind: "logic", size, a, result }; break;
        case "or": result = (a | b) & mask; flag = { kind: "logic", size, a, result }; break;
        case "xor": result = (a ^ b) & mask; flag = { kind: "logic", size, a, result }; break;
        default: throw new Error(`mr: unhandled alu ${node.aluOp}`);
      }
      m.flagSource = flag;
      if (node.writeBack) m.writeOperand(node.dst, result, nextRip);
      m.rip = nextRip; return false;
    }
    case "inc": case "dec": {
      const mask = mrSizeMask(size);
      const a = m.readOperand(node.dst, nextRip) & mask;
      const result = node.op === "inc" ? (a + 1n) & mask : (a - 1n) & mask;
      const cfKeep = m.flags().cf;
      m.flagSource = { kind: node.op, size, a, result, cfKeep };
      m.writeOperand(node.dst, result, nextRip);
      m.rip = nextRip; return false;
    }
    case "push": {
      const sizeByte = size / 8;
      const value = m.readOperand(node.src, nextRip) & mrSizeMask(size);
      m.reg[RSP] = (m.reg[RSP] - BigInt(sizeByte)) & MASK64_MR;
      m.writeMem(m.reg[RSP], sizeByte, value);
      m.rip = nextRip; return false;
    }
    case "pop": {
      const sizeByte = size / 8;
      const value = m.readMem(m.reg[RSP], sizeByte);
      m.reg[RSP] = (m.reg[RSP] + BigInt(sizeByte)) & MASK64_MR;
      m.writeOperand(node.dst, value, nextRip);
      m.rip = nextRip; return false;
    }
    case "jmp": m.rip = nextRip + node.rel; return false;
    case "jcc": m.rip = mrConditionHolds(node.cc, m.flags()) ? nextRip + node.rel : nextRip; return false;
    case "call": {
      m.reg[RSP] = (m.reg[RSP] - 8n) & MASK64_MR;
      m.writeMem(m.reg[RSP], 8, nextRip);
      m.rip = nextRip + node.rel; return false;
    }
    case "callIndirect": {
      // Target FIRST (it may read through rsp), then the return-address push.
      const target = m.readOperand(node.src, nextRip) & MASK64_MR;
      m.reg[RSP] = (m.reg[RSP] - 8n) & MASK64_MR;
      m.writeMem(m.reg[RSP], 8, nextRip);
      m.rip = target; return false;
    }
    case "jmpIndirect": m.rip = m.readOperand(node.src, nextRip) & MASK64_MR; return false;
    case "ret": {
      const target = m.readMem(m.reg[RSP], 8);
      m.reg[RSP] = (m.reg[RSP] + 8n + BigInt(node.pop)) & MASK64_MR;
      m.rip = target;
      return target === sentinel;
    }
    default: throw new Error(`mr: unhandled op ${node.op}`);
  }
}

// Runs one microprogram through the multi-region reference. `regionSpec` is the
// SAME [{ base, size, kind }] list handed to wasm64. Seeds identically to
// lib/wasm64.mjs seedStatePlan (image into the image region, rsp/sentinel in the
// stack region). Returns end-of-run GPRs, flags, and each region's bytes.
function interpretMultiRegion(image, regionSpec, { loadBase, register = {}, entryRva = 0, budget = 4096 }) {
  const region = regionSpec.map((r) => ({ base: BigInt.asUintN(64, BigInt(r.base)), size: Number(r.size), kind: r.kind ?? "region", mem: Buffer.alloc(Number(r.size)) }));
  for (const r of region) {
    if (r.kind === "image" || r.kind === "flat") Buffer.from(image).copy(r.mem, 0, 0, Math.min(image.length, r.size));
    else if (regionSpec.find((s) => BigInt.asUintN(64, BigInt(s.base)) === r.base)?.init) {
      const init = regionSpec.find((s) => BigInt.asUintN(64, BigInt(s.base)) === r.base).init;
      Buffer.from(init).copy(r.mem, 0, 0, Math.min(init.length, r.size));
    }
  }
  const m = new MultiRegionMachine(region);
  const stk = region.find((r) => r.kind === "stack") ?? region[0];
  const img = region.find((r) => r.kind === "image" || r.kind === "flat") ?? region[0];
  const stackTop = BigInt.asUintN(64, stk.base + BigInt(stk.size - 16));
  const rsp0 = BigInt.asUintN(64, stackTop - 8n);
  const sentinel = 0xdead000000000000n | (BigInt(loadBase) & 0xffffn);
  m.writeMem(rsp0, 8, sentinel);
  m.reg[RSP] = rsp0;
  for (const [name, value] of Object.entries(register)) m.reg[REG_INDEX[name]] = BigInt(value) & MASK64_MR;
  m.rip = BigInt.asUintN(64, BigInt(loadBase) + BigInt(entryRva));

  let stopped = false;
  for (let n = 0; n < budget; n += 1) {
    const rvaOff = Number(m.rip - img.base);
    const node = decodeStructured(img.mem, rvaOff);
    const nextRip = BigInt.asUintN(64, m.rip + BigInt(node.length));
    if (mrExecNode(m, node, nextRip, sentinel)) { stopped = true; break; }
  }
  assert.ok(stopped, "multi-region oracle: the program must reach the entry RET within budget");
  const registerOut = {};
  for (let i = 0; i < 16; i += 1) registerOut[REG[i]] = m.reg[i] & MASK64_MR;
  return { register: registerOut, flag: m.flags(), region };
}

// Lifts+runs a microprogram through the multi-region oracle AND the WASM module
// (both with the SAME region map), asserting bit-exact GPRs, flags, and per-region
// bytes plus an OK run status.
function assertMultiRegionEquivalent(code, regionSpec, seed, label) {
  const image = Buffer.from(code);
  const oracle = interpretMultiRegion(image, regionSpec, { loadBase, ...seed });

  const compiled = compileFunction(image, { loadBase, decodeStructured, region: regionSpec, register: seed.register });
  assertRealModule(compiled.bytes);
  assert.ok(compiled.complete, `${label}: codegen incomplete — fell back on ${JSON.stringify(compiled.coverage.unsupported)}`);
  assert.ok(compiled.plan.multi, `${label}: the plan must be a true multi-region map`);

  const jit = runFunction(image, { image, loadBase, decodeStructured, region: regionSpec, register: seed.register });
  assert.equal(jit.statusName, "ok", `${label}: run status ${jit.statusName}, expected ok`);

  for (const name of REG) {
    assert.equal(jit.register[name], oracle.register[name], `${label}: reg ${name} WASM 0x${jit.register[name].toString(16)} != oracle 0x${oracle.register[name].toString(16)}`);
  }
  for (const name of FLAG) {
    assert.equal(jit.flag[name], oracle.flag[name], `${label}: flag ${name} WASM ${jit.flag[name]} != oracle ${oracle.flag[name]}`);
  }
  for (let i = 0; i < jit.region.length; i += 1) {
    assert.deepEqual([...jit.region[i].bytes], [...oracle.region[i].mem], `${label}: region ${i} (${jit.region[i].kind}) bytes diverge`);
  }
  return jit;
}

// The sparse layout the real runtime uses (scaled down): image at loadBase, a HIGH
// stack at 0x7ff000000000, and an HLE-style arena at 0xF8000000.
const IMAGE_BASE = loadBase;
const STACK_BASE = 0x7ff000000000n;
const ARENA_BASE = 0xf8000000n;
const sparseLayout = (image) => [
  { base: IMAGE_BASE, size: Math.max(image.length + 16, 0x1000), kind: "image" },
  { base: STACK_BASE, size: 0x10000, kind: "stack" },
  { base: ARENA_BASE, size: 0x1000, kind: "arena" },
];

test("multi-region cross-check: the oracle agrees with lib/lift64 interpret() on a flat program", () => {
  // mov eax,5; mov ecx,3; add eax,ecx; dec ecx; ret — arithmetic that sets flags.
  const code = [0xb8, 0x05, 0x00, 0x00, 0x00, 0xb9, 0x03, 0x00, 0x00, 0x00, 0x01, 0xc8, 0xff, 0xc9, 0xc3];
  const image = Buffer.from(code);
  const flatOracle = interpret({ image, loadBase, entryRva: 0, budget: 4096 });
  assert.equal(flatOracle.stop_reason, "entry_return");
  // The SAME program through the multi-region reference with a single flat region
  // (image+stack contiguous at loadBase) must land on identical GPRs and flags —
  // proving the reference's fidelity before it is trusted for the sparse layouts.
  const region = [{ base: loadBase, size: image.length + 0x10000, kind: "image" }];
  const mr = interpretMultiRegion(image, region, { loadBase });
  for (const name of REG) assert.equal(mr.register[name], flatOracle.register[name], `cross-check reg ${name}`);
  for (const name of FLAG) assert.equal(mr.flag[name], flatOracle.flag[name], `cross-check flag ${name}`);
});

test("multi-region: stack push/pop at a HIGH base (0x7ff000000000) round-trips — the case that traps a flat memory", () => {
  // mov rax,0x1234; push rax; pop rcx; ret — rsp lives at ~140 TB, far outside any
  // flat 4 GiB image+stack; the region map packs it compactly so the access lands.
  const code = [0x48, 0xc7, 0xc0, 0x34, 0x12, 0x00, 0x00, 0x50, 0x59, 0xc3];
  const image = Buffer.from(code);
  const region = sparseLayout(image);
  const jit = assertMultiRegionEquivalent(code, region, {}, "high-stack-pushpop");
  assert.equal(jit.register.rcx, 0x1234n, "pop rcx must recover the pushed rax");
  assert.equal(jit.register.rax, 0x1234n, "rax is preserved across the balanced push/pop");
  // The pushed qword must sit in the STACK region's compact bytes at rsp0-8.
  const stackTopVA = STACK_BASE + BigInt(0x10000 - 16);
  const pushedOff = Number((stackTopVA - 8n - 8n) - STACK_BASE);
  const stackRegion = jit.region.find((r) => r.kind === "stack");
  const dv = new DataView(stackRegion.bytes.buffer, stackRegion.bytes.byteOffset, stackRegion.bytes.byteLength);
  assert.equal(dv.getBigUint64(pushedOff, true), 0x1234n, "the pushed value lands in the high stack region's compact bytes");
});

test("multi-region: image (rip-relative) load and stack (rsp-relative) store in one function", () => {
  // mov rax,[rip+disp] (reads an 8-byte constant embedded in the image tail);
  // mov [rsp-8],rax (writes it to the high stack); mov rcx,[rsp-8] (reads it back).
  // The rip-relative access resolves to the IMAGE region, the rsp accesses to the
  // STACK region — two different regions in the same block.
  // Layout: at 0x00 lea/mov rip-relative to the constant at 0x1a.
  const code = [
    0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00, // 0x00 mov rax,[rip+0x10] → 0x07+0x10 = 0x17
    0x48, 0x89, 0x44, 0x24, 0xf8,             // 0x07 mov [rsp-8],rax
    0x48, 0x8b, 0x4c, 0x24, 0xf8,             // 0x0c mov rcx,[rsp-8]
    0xc3,                                     // 0x11 ret
    0x00, 0x00, 0x00, 0x00, 0x00,             // 0x12 padding
    0xef, 0xbe, 0xad, 0xde, 0x0d, 0xf0, 0xed, 0xfe, // 0x17 constant 0xfeedf00ddeadbeef
  ];
  const image = Buffer.from(code);
  const region = sparseLayout(image);
  const jit = assertMultiRegionEquivalent(code, region, {}, "image-load-stack-store");
  assert.equal(jit.register.rax, 0xfeedf00ddeadbeefn, "rip-relative load pulls the image constant");
  assert.equal(jit.register.rcx, 0xfeedf00ddeadbeefn, "the stack store/reload round-trips the value");
});

test("multi-region: a computed pointer lands in the ARENA region", () => {
  // mov rdx, arenaBase (imm64); mov rax,0xcafe; mov [rdx+8],rax; mov rcx,[rdx+8]; ret
  // rdx is a fully computed pointer whose value only the runtime dispatch can place;
  // it resolves to the arena region, not the image or stack.
  const arenaAddr = ARENA_BASE;
  const code = [
    0x48, 0xba, ...[...Array(8)].map((_, i) => Number((arenaAddr >> BigInt(8 * i)) & 0xffn)), // mov rdx,arenaBase
    0x48, 0xc7, 0xc0, 0xfe, 0xca, 0x00, 0x00, // mov rax,0xcafe
    0x48, 0x89, 0x42, 0x08,                   // mov [rdx+8],rax
    0x48, 0x8b, 0x4a, 0x08,                   // mov rcx,[rdx+8]
    0xc3,                                     // ret
  ];
  const image = Buffer.from(code);
  const region = sparseLayout(image);
  const jit = assertMultiRegionEquivalent(code, region, {}, "arena-computed-pointer");
  assert.equal(jit.register.rcx, 0xcafen, "the value written through the arena pointer reads back");
  const arenaRegion = jit.region.find((r) => r.kind === "arena");
  const dv = new DataView(arenaRegion.bytes.buffer, arenaRegion.bytes.byteOffset, arenaRegion.bytes.byteLength);
  assert.equal(dv.getBigUint64(8, true), 0xcafen, "the store landed in the arena region's compact bytes at offset 8");
});

test("multi-region: an out-of-region access is an honest fallback, never a wrapped access", () => {
  // mov rdx,0x30000000 (a VA in NO mapped region); mov rax,[rdx]; ret. The dispatch
  // finds no region → sets the fault flag → the module returns 'fallback' rather
  // than reading a wrong/wrapped byte. The interpreter oracle would fault too.
  const badAddr = 0x30000000n; // between arena (0xF8000000) and image, mapped by none
  const code = [
    0x48, 0xba, ...[...Array(8)].map((_, i) => Number((badAddr >> BigInt(8 * i)) & 0xffn)), // mov rdx,badAddr
    0x48, 0x8b, 0x02, // mov rax,[rdx]
    0xc3,             // ret
  ];
  const image = Buffer.from(code);
  const region = sparseLayout(image);
  const compiled = compileFunction(image, { loadBase, decodeStructured, region });
  assertRealModule(compiled.bytes);
  assert.ok(compiled.complete, "the shape is compilable; the unmapped access is a RUNTIME fault, not a compile-time one");
  assert.ok(compiled.plan.multi, "the layout is a true multi-region map");
  const jit = runFunction(image, { image, loadBase, decodeStructured, region });
  assert.equal(jit.statusName, "fallback", "an out-of-region access must report an honest fallback");
  // The oracle confirms the access is genuinely unmapped (it throws on locate).
  assert.throws(() => interpretMultiRegion(image, region, { loadBase }), /outside the mapped regions/, "the reference machine also rejects the unmapped VA");
});

test("multi-region: the single flat region is the degenerate case (function path unchanged)", () => {
  // A one-region map at loadBase must behave exactly like the historical flat path:
  // mov eax,5; mov ecx,3; add eax,ecx; ret through both the flat interpreter and the
  // WASM module with an explicit single region.
  const code = [0xb8, 0x05, 0x00, 0x00, 0x00, 0xb9, 0x03, 0x00, 0x00, 0x00, 0x01, 0xc8, 0xc3];
  const image = Buffer.from(code);
  const flatOracle = interpret({ image, loadBase, entryRva: 0, budget: 4096 });
  const region = [{ base: loadBase, size: image.length + 0x10000, kind: "image" }];
  const compiled = compileFunction(image, { loadBase, decodeStructured, region });
  assert.equal(compiled.plan.multi, false, "a single region at loadBase collapses to the flat fast path");
  const jit = runFunction(image, { image, loadBase, decodeStructured, region });
  assert.equal(jit.statusName, "ok");
  for (const name of REG) assert.equal(jit.register[name], flatOracle.register[name], `degenerate reg ${name}`);
  for (const name of FLAG) assert.equal(jit.flag[name], flatOracle.flag[name], `degenerate flag ${name}`);
});

// -------------------- resume rip: where the interpreter continues --------------------
//
// A WASM tier is only useful if it can STOP mid-run and hand control back. Every
// exit the module can take now reports a RESUME RIP: the exact guest virtual
// address lib/lift64.mjs's interpreter would execute next, written to an 8-byte
// `ripBase` scratch slot and surfaced as `resumeRip`. The tests below prove the
// address is right by CONTINUING interpretation from it over the module's own
// end-of-run state and asserting the final state is bit-identical to interpreting
// the whole program with no WASM tier at all.
//
// HONESTY NOTE. Two of the exits carry a state the host can resume FROM:
// budget-exhausted (the cap fires at a block boundary, before any of that block
// ran) and an unhandled import (the module undoes its own return-address push and
// resumes at the call). The out-of-region FAULT exit does NOT: the faulting access
// itself was redirected to a trap page, so a store was lost and the state is
// already wrong. Its resumeRip names the block whose body faulted, which is
// resume-correct only against the PRE-run state — so the fault exit is asserted on
// the address alone, and the host must keep discarding the run (as lib/tierrun.mjs
// does) rather than resuming from it.

const RESUME_SENTINEL = 0xdead000000000000n | (loadBase & 0xffffn);
const flatRegion = (image) => [{ base: loadBase, size: image.length + 0x10000, kind: "flat" }];

// Continues the multi-region reference machine from an arbitrary rip over a
// SEEDED state: the module's post-run guest memory, GPRs and flags. This is
// exactly what a host would do at a tier exit.
function resumeFrom(image, jit, rip, budget = 8192) {
  const size = image.length + 0x10000;
  const region = [{ base: loadBase, size, kind: "flat", mem: Buffer.from(jit.memory.subarray(0, size)) }];
  const m = new MultiRegionMachine(region);
  for (let i = 0; i < 16; i += 1) m.reg[i] = jit.register[REG[i]] & MASK64_MR;
  m.flagSource = { kind: "explicit", value: { ...jit.flag } };
  m.rip = BigInt.asUintN(64, rip);

  let stopped = false;
  for (let n = 0; n < budget; n += 1) {
    const node = decodeStructured(region[0].mem, Number(m.rip - loadBase));
    const nextRip = BigInt.asUintN(64, m.rip + BigInt(node.length));
    if (mrExecNode(m, node, nextRip, RESUME_SENTINEL)) { stopped = true; break; }
  }
  assert.ok(stopped, "resume: the continued interpretation must reach the entry RET within budget");
  const register = {};
  for (let i = 0; i < 16; i += 1) register[REG[i]] = m.reg[i] & MASK64_MR;
  return { register, flag: m.flags(), memory: region[0].mem };
}

// Asserts a tier-exit resume reaches the SAME final state as interpreting the
// whole program: all sixteen GPRs, all six flags, and every guest memory byte.
function assertResumeEquivalent(image, jit, label) {
  const oracle = interpretMultiRegion(image, flatRegion(image), { loadBase });
  const resumed = resumeFrom(image, jit, jit.resumeRip);
  for (const name of REG) {
    assert.equal(resumed.register[name], oracle.register[name], `${label}: resumed reg ${name} 0x${resumed.register[name].toString(16)} != pure-interpretation 0x${oracle.register[name].toString(16)}`);
  }
  for (const name of FLAG) {
    assert.equal(resumed.flag[name], oracle.flag[name], `${label}: resumed flag ${name} ${resumed.flag[name]} != pure-interpretation ${oracle.flag[name]}`);
  }
  assert.deepEqual([...resumed.memory], [...oracle.region[0].mem], `${label}: resumed guest memory diverges from pure interpretation`);
}

test("resume: the reference shim's jcc/call/indirect agree with lib/lift64 interpret()", () => {
  // mov ecx,2; mov eax,0; L: add eax,3; dec ecx; jnz L; lea rdx,[rip+7]; call rdx;
  // jmp +0; ret   ext: add eax,7; ret — exercises jcc (taken + not-taken),
  // callIndirect through a register, and the matching ret, all in one flat program.
  const code = [
    0xb9, 0x02, 0x00, 0x00, 0x00,             // 0x00 mov ecx,2
    0xb8, 0x00, 0x00, 0x00, 0x00,             // 0x05 mov eax,0
    0x83, 0xc0, 0x03,                         // 0x0A L: add eax,3
    0xff, 0xc9,                               // 0x0D dec ecx
    0x75, 0xf9,                               // 0x0F jnz L
    0x48, 0x8d, 0x15, 0x05, 0x00, 0x00, 0x00, // 0x11 lea rdx,[rip+5] -> 0x1D
    0xff, 0xd2,                               // 0x18 call rdx
    0xc3,                                     // 0x1A ret (entry frame)
    0x90, 0x90,                               // 0x1B pad
    0x83, 0xc0, 0x07,                         // 0x1D ext: add eax,7
    0xc3,                                     // 0x20 ret
  ];
  const image = Buffer.from(code);
  const flat = interpret({ image, loadBase, entryRva: 0, budget: 4096 });
  assert.equal(flat.stop_reason, "entry_return", `flat oracle stop_reason ${flat.stop_reason}`);
  const shim = interpretMultiRegion(image, flatRegion(image), { loadBase });
  for (const name of REG) assert.equal(shim.register[name], flat.register[name], `shim reg ${name} diverges from lib/lift64 interpret()`);
  for (const name of FLAG) assert.equal(shim.flag[name], flat.flag[name], `shim flag ${name} diverges from lib/lift64 interpret()`);
  assert.equal(flat.register.rax, 13n, "3+3 from the loop then +7 from the indirectly-called leaf");
});

test("resume: a single block reports the address after its emitted prefix", () => {
  // mov eax,1; rol eax,1; ret — `rol` is an honest codegen fallback, so the prefix
  // stops at 0x05 and that is exactly where the interpreter must pick up.
  const code = [0xb8, 0x01, 0x00, 0x00, 0x00, 0xd1, 0xc0, 0xc3];
  const image = Buffer.from(code);
  const jit = runBlock(liftBlock(image, 0), { image, loadBase });
  assert.equal(jit.complete, false, "rol is not emittable — the prefix must stop honestly");
  assert.equal(jit.resumeRip, loadBase + 0x05n, "resumeRip is the VA of the first instruction the codegen could not emit");
  assert.equal(jit.register.rax, 1n, "everything before the stop did run");
});

test("resume: a single block that runs to RET reports the address that RET popped", () => {
  const code = [0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]; // mov eax,1; ret
  const image = Buffer.from(code);
  const jit = runBlock(liftBlock(image, 0), { image, loadBase });
  assert.ok(jit.complete, "the whole block is emittable");
  assert.equal(jit.resumeRip, RESUME_SENTINEL, "a RET resumes at the popped return address (here the entry sentinel)");
});

test("resume: a function that runs to the entry RET reports the popped sentinel", () => {
  const code = [
    0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
    0x85, 0xc0,                   // test eax,eax
    0x74, 0x02,                   // jz +2
    0xff, 0xc0,                   // inc eax
    0xc3,                         // ret
  ];
  const image = Buffer.from(code);
  const jit = runFunction(image, { image, loadBase, decodeStructured });
  assert.equal(jit.statusName, "ok");
  assert.equal(jit.resumeRip, RESUME_SENTINEL, "the OK exit reports the address the entry RET popped");
});

test("resume: a budget-exhausted loop resumes at a block boundary and finishes bit-exact", () => {
  // mov ecx,4; mov eax,0; L: dec ecx; mov [rsp-8],rcx; add rax,[rsp-8]; test ecx,ecx;
  // jnz L; ret — a terminating loop that the iteration cap cuts short.
  const code = [
    0xb9, 0x04, 0x00, 0x00, 0x00,       // 0x00 mov ecx,4
    0xb8, 0x00, 0x00, 0x00, 0x00,       // 0x05 mov eax,0
    0xff, 0xc9,                         // 0x0A L: dec ecx
    0x48, 0x89, 0x4c, 0x24, 0xf8,       // 0x0C mov [rsp-8],rcx
    0x48, 0x03, 0x44, 0x24, 0xf8,       // 0x11 add rax,[rsp-8]
    0x85, 0xc9,                         // 0x16 test ecx,ecx
    0x75, 0xf0,                         // 0x18 jnz L
    0xc3,                               // 0x1A ret
  ];
  const image = Buffer.from(code);
  const compiled = compileFunction(image, { loadBase, decodeStructured, guestLen: image.length + 0x10000, iterationCap: 3 });
  assert.ok(compiled.complete, "the loop is a fully compilable shape");
  const jit = runFunction(image, { image, loadBase, decodeStructured, iterationCap: 3 });
  assert.equal(jit.statusName, "budget_exhausted", "the cap must fire before the loop finishes");
  // The cap fires at a block boundary: resumeRip is one of the CFG's block starts.
  const startVa = new Set([loadBase, loadBase + 0x0an, loadBase + 0x1an]);
  assert.ok(startVa.has(jit.resumeRip), `resumeRip 0x${jit.resumeRip.toString(16)} must be a block start VA`);
  assert.notEqual(jit.register.rax, 6n, "the run really did stop early (the finished sum is 3+2+1+0 = 6)");
  assertResumeEquivalent(image, jit, "budget-resume");
  assert.equal(resumeFrom(image, jit, jit.resumeRip).register.rax, 6n, "continuing from resumeRip completes the sum");
});

test("resume: an unhandled import resumes AT the call, with the pushed frame undone", () => {
  // mov ecx,5; call ext; add eax,ecx; ret   ext: mov eax,100; ret
  // The WASM path treats 0x0D as an import boundary; the host declines to handle
  // it, so the module must undo its return-address push and resume at the call.
  const code = [
    0xb9, 0x05, 0x00, 0x00, 0x00, // 0x00 mov ecx,5
    0xe8, 0x03, 0x00, 0x00, 0x00, // 0x05 call ext (target 0x0D)
    0x01, 0xc8,                   // 0x0A add eax,ecx
    0xc3,                         // 0x0C ret
    0xb8, 0x64, 0x00, 0x00, 0x00, // 0x0D ext: mov eax,100
    0xc3,                         // 0x12 ret
  ];
  const image = Buffer.from(code);
  const hostCall = () => 1; // always "unhandled"
  const jit = runFunction(image, { image, loadBase, decodeStructured, hostCall, externalRva: [0x0d] });
  assert.equal(jit.statusName, "fallback", "an unhandled host call is an honest fallback");
  assert.equal(jit.resumeRip, loadBase + 0x05n, "resumeRip is the CALL's own VA, so the interpreter re-executes it");
  assert.equal(jit.register.rsp, initialRsp(code), "the speculative return-address push is undone (rsp back to pre-call)");
  assert.equal(jit.register.rcx, 5n, "everything before the boundary really did run on the WASM tier");
  assertResumeEquivalent(image, jit, "import-resume");
});

test("resume: an out-of-region fault reports the faulting block's start VA", () => {
  // mov eax,1; jmp L; L: mov rdx,badAddr; mov rax,[rdx]; ret — the fault happens in
  // the SECOND block, so resumeRip must name that block, not the function entry.
  const badAddr = 0x30000000n;
  const code = [
    0xb8, 0x01, 0x00, 0x00, 0x00, // 0x00 mov eax,1
    0xeb, 0x00,                   // 0x05 jmp +0 -> 0x07
    0x48, 0xba, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, // 0x07 mov rdx,badAddr
    0x48, 0x8b, 0x02,             // 0x11 mov rax,[rdx]
    0xc3,                         // 0x14 ret
  ];
  const image = Buffer.from(code);
  const region = sparseLayout(image);
  const compiled = compileFunction(image, { loadBase, decodeStructured, region });
  assert.ok(compiled.complete, "the shape compiles; the unmapped access is a RUNTIME fault");
  assert.equal(compiled.blockCount, 2, "the jmp splits the function into two blocks");
  const jit = runFunction(image, { image, loadBase, decodeStructured, region });
  assert.equal(jit.statusName, "fallback", "an out-of-region access must report an honest fallback");
  assert.equal(jit.resumeRip, loadBase + 0x07n, "resumeRip names the block whose body faulted");
});

test("resume: a compile-time fallback module resumes at the function entry", () => {
  const image = Buffer.from([0x0f, 0x0b, 0xc3]); // ud2; ret — an unserved opcode
  const compiled = compileFunction(image, { loadBase, decodeStructured, guestLen: image.length + 0x10000 });
  assert.equal(compiled.complete, false, "an unserved opcode is a compile-time fallback");
  const jit = runFunction(image, { image, loadBase, decodeStructured });
  assert.equal(jit.statusName, "fallback");
  assert.equal(jit.resumeRip, loadBase, "nothing ran, so the interpreter resumes at the entry VA");
});
