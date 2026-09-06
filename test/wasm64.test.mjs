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
import { interpret, liftBlock, decodeStructured } from "../lib/lift64.mjs";
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

test("multi-block: unmodelled shapes are honest, named fallbacks (call, indirect jmp)", () => {
  // A direct call is not modelled — the whole function is an honest fallback.
  const callImage = Buffer.from([0xe8, 0x00, 0x00, 0x00, 0x00, 0xc3]); // call +0; ret
  const callCompiled = compileFunction(callImage, { loadBase, decodeStructured, guestLen: callImage.length + 0x10000 });
  assertRealModule(callCompiled.bytes);
  assert.equal(callCompiled.complete, false, "a direct call must be an honest fallback, not emitted");
  assert.ok(callCompiled.coverage.unsupported.some((u) => u.reason === "control_call"), "the call must be named as a control-flow fallback");
  assert.equal(runFunction(callImage, { image: callImage, loadBase, decodeStructured }).statusName, "fallback", "a fallback module reports the fallback status");

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
  process.stdout.write("[wasm64] branch kinds on honest fallback: call/callIndirect, jmpIndirect, computed/out-of-function targets\n");
  // conditional (jcc), unconditional (jmp), fall-through, and ret must all appear.
  for (const kind of ["jcc", "jmp", "fallthrough", "ret"]) {
    assert.ok(branch.includes(kind), `expected branch kind ${kind} to be exercised bit-exact`);
  }
  assert.ok(shape.length >= 4, `expected at least 4 distinct control-flow shapes, got ${shape.length}`);
});
