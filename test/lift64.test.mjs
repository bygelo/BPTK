// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The x86-64 lifter conformance suite (runtime v2 milestone M2). Every
// microprogram is a hand-assembled x86-64 byte sequence whose full end state —
// the affected 64-bit registers and the six architectural flags — is frozen
// here as a literal reference derived by hand from the instruction semantics
// (two's-complement integer arithmetic and the SDM flag definitions), never
// from running the implementation. The IR interpreter oracle executes the
// lifted program and the comparison is bit-exact: red until the lifter matches.
//
// The final case cross-checks the independent structured decode against
// lib/x64decode.mjs over a real x86-64 `.text` slice (plink.exe, MIT freeware,
// read-only): for every instruction this file SERVES, length and mnemonic class
// must agree, and it reports the served fraction.

import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { test } from "node:test";
import { decodeStructured, interpret, liftBlock } from "../lib/lift64.mjs";
import { decodeX64Instruction } from "../lib/x64decode.mjs";
import { mapPe64State } from "../lib/pe64.mjs";

const loadBase = 0x140000000n;
const plinkPath = "/Users/angelonrevelo/Code/bptk-corpus/stage/corpus-002/package/plink.exe";

function run(code, option = {}) {
  const image = Buffer.from(code);
  return interpret({ image, loadBase, entryRva: 0, budget: 4096, ...option });
}

const FLAG_DEFAULT = { cf: false, pf: false, af: false, zf: false, sf: false, of: false };

function assertState(report, expected) {
  assert.equal(report.stop_reason, expected.stop_reason ?? "entry_return", `stop_reason with exception ${JSON.stringify(report.exception)}`);
  for (const [name, value] of Object.entries(expected.register ?? {})) {
    assert.equal(report.register[name], BigInt(value), `register ${name}: 0x${report.register[name].toString(16)} != 0x${BigInt(value).toString(16)}`);
  }
  if (expected.flag) {
    // `flagExact: false` checks only the listed flags — used where the SDM
    // leaves the rest architecturally undefined (IMUL/MUL), so the reference
    // freezes only the defined fields rather than inventing undefined state.
    const base = expected.flagExact === false ? {} : FLAG_DEFAULT;
    for (const [name, value] of Object.entries({ ...base, ...expected.flag })) {
      assert.equal(report.flag[name], value, `flag ${name}: ${report.flag[name]} != ${value}`);
    }
  }
}

test("microprogram: mov/add compute eax=8 with the exact add flags", () => {
  // mov eax,5; mov ecx,3; add eax,ecx; ret
  const report = run([0xb8, 0x05, 0x00, 0x00, 0x00, 0xb9, 0x03, 0x00, 0x00, 0x00, 0x01, 0xc8, 0xc3]);
  assertState(report, {
    register: { rax: 8n, rcx: 3n },
    flag: { cf: false, pf: false, af: false, zf: false, sf: false, of: false },
  });
});

test("microprogram: a rip-relative LEA computes next-instruction-relative address", () => {
  // lea rax,[rip+0x100]; ret — the address is (loadBase + 7) + 0x100.
  const report = run([0x48, 0x8d, 0x05, 0x00, 0x01, 0x00, 0x00, 0xc3]);
  assertState(report, { register: { rax: loadBase + 7n + 0x100n } });
});

test("microprogram: a Jcc loop sums 1..5 to 15 and exits on the zero flag", () => {
  // mov eax,0; mov ecx,5; L: add eax,ecx; dec ecx; jnz L; ret
  const report = run([0xb8, 0x00, 0x00, 0x00, 0x00, 0xb9, 0x05, 0x00, 0x00, 0x00, 0x01, 0xc8, 0xff, 0xc9, 0x75, 0xfa, 0xc3]);
  assertState(report, {
    register: { rax: 15n, rcx: 0n },
    flag: { zf: true, pf: true, cf: false, sf: false, of: false, af: false },
  });
});

test("microprogram: a 64-bit push/pop round-trips the value and rebalances the stack", () => {
  // mov rax,0x123456789abcdef0; push rax; pop rcx; ret
  const report = run([0x48, 0xb8, 0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, 0x50, 0x59, 0xc3]);
  assertState(report, { register: { rax: 0x123456789abcdef0n, rcx: 0x123456789abcdef0n } });
  assert.equal(report.register.rsp, report.balanced_rsp, "the stack pointer must return to its balanced value");
});

test("microprogram: a signed two-operand IMUL computes -5 * 6 = -30", () => {
  // mov eax,-5; mov ecx,6; imul eax,ecx; ret
  const report = run([0xb8, 0xfb, 0xff, 0xff, 0xff, 0xb9, 0x06, 0x00, 0x00, 0x00, 0x0f, 0xaf, 0xc1, 0xc3]);
  assertState(report, {
    register: { rax: 0xffffffe2n, rcx: 6n },
    flag: { cf: false, of: false },
    flagExact: false,
  });
});

test("microprogram: MOVZX zero-extends and MOVSX sign-extends the byte lane", () => {
  // mov eax,0xff; movzx ecx,al; movsx edx,al; ret
  const report = run([0xb8, 0xff, 0x00, 0x00, 0x00, 0x0f, 0xb6, 0xc8, 0x0f, 0xbe, 0xd0, 0xc3]);
  assertState(report, { register: { rax: 0xffn, rcx: 0xffn, rdx: 0xffffffffn } });
});

test("microprogram: a three-operand IMUL sign-extends its immediate and MOVSXD widens a dword", () => {
  // mov ecx,7; imul eax,ecx,-3 (6b c1 fd); movsxd rdx,eax; ret — eax=-21, rdx sign-extends.
  const report = run([0xb9, 0x07, 0x00, 0x00, 0x00, 0x6b, 0xc1, 0xfd, 0x48, 0x63, 0xd0, 0xc3]);
  assertState(report, { register: { rax: 0xffffffebn, rcx: 7n, rdx: 0xffffffffffffffebn } });
});

test("microprogram: CMP then SETcc records the ordered comparison and a taken conditional branch", () => {
  // mov eax,3; cmp eax,5; setl cl (0f 9c c1); jl +2; mov al,0; ret — al keeps 3, cl=1.
  const report = run([0xb8, 0x03, 0x00, 0x00, 0x00, 0x83, 0xf8, 0x05, 0x0f, 0x9c, 0xc1, 0x7c, 0x02, 0xb0, 0x00, 0xc3]);
  assertState(report, { register: { rax: 3n, rcx: 1n } });
});

// A little-endian imm64 encoding and the `mov rax, imm64` that loads it, used to
// seed an xmm register through `movq xmm, rax`; the SSE end state is read back
// out to a GPR (movq / pmovmskb) so the frozen reference is an integer literal.
function le8(value) {
  const byte = [];
  let v = BigInt.asUintN(64, value);
  for (let i = 0; i < 8; i += 1) { byte.push(Number(v & 0xffn)); v >>= 8n; }
  return byte;
}
const movRax = (value) => [0x48, 0xb8, ...le8(value)];

test("SSE: movq builds [lo,hi] via punpcklqdq and pshufd extracts each 64-bit lane", () => {
  // movq xmm0,rax(lo); movq xmm1,rax(hi); punpcklqdq xmm0,xmm1 → xmm0=[lo,hi].
  // movq rcx,xmm0 reads the low lane; pshufd xmm2,xmm0,0xEE lifts the high lane.
  const report = run([
    ...movRax(0x1111111122222222n), 0x66, 0x48, 0x0f, 0x6e, 0xc0,
    ...movRax(0x3333333344444444n), 0x66, 0x48, 0x0f, 0x6e, 0xc8,
    0x66, 0x0f, 0x6c, 0xc1,
    0x66, 0x48, 0x0f, 0x7e, 0xc1,
    0x66, 0x0f, 0x70, 0xd0, 0xee,
    0x66, 0x48, 0x0f, 0x7e, 0xd2,
    0xc3,
  ]);
  assertState(report, { register: { rcx: 0x1111111122222222n, rdx: 0x3333333344444444n } });
});

test("SSE: pxor of 0xFFFF… and 0x0F0F… yields 0xF0F0… lane-for-lane", () => {
  const report = run([
    ...movRax(0xFFFFFFFFFFFFFFFFn), 0x66, 0x48, 0x0f, 0x6e, 0xc0,
    ...movRax(0x0F0F0F0F0F0F0F0Fn), 0x66, 0x48, 0x0f, 0x6e, 0xc8,
    0x66, 0x0f, 0xef, 0xc1, // pxor xmm0,xmm1
    0x66, 0x48, 0x0f, 0x7e, 0xc1, // movq rcx,xmm0
    0xc3,
  ]);
  assertState(report, { register: { rcx: 0xF0F0F0F0F0F0F0F0n } });
});

test("SSE2: paddd adds packed dwords without carry across lane boundaries", () => {
  // [1,2] + [0x10,0x0A] = [0x11,0x0C] → low 64 = 0x0000000C_00000011.
  const report = run([
    ...movRax(0x0000000200000001n), 0x66, 0x48, 0x0f, 0x6e, 0xc0,
    ...movRax(0x0000000A00000010n), 0x66, 0x48, 0x0f, 0x6e, 0xc8,
    0x66, 0x0f, 0xfe, 0xc1, // paddd xmm0,xmm1
    0x66, 0x48, 0x0f, 0x7e, 0xc1,
    0xc3,
  ]);
  assertState(report, { register: { rcx: 0x0000000C00000011n } });
});

test("SSE2: pcmpeqb of a register with its own copy sets every byte, pmovmskb reads 0xFFFF", () => {
  const report = run([
    ...movRax(0x0123456789ABCDEFn), 0x66, 0x48, 0x0f, 0x6e, 0xc0,
    0x66, 0x0f, 0x6f, 0xc8, // movdqa xmm1,xmm0
    0x66, 0x0f, 0x74, 0xc1, // pcmpeqb xmm0,xmm1
    0x66, 0x0f, 0xd7, 0xc0, // pmovmskb eax,xmm0
    0xc3,
  ]);
  assertState(report, { register: { rax: 0xFFFFn } });
});

test("SSE2: pshufd with imm 0x1B reverses the four dwords", () => {
  // xmm0 = [1,2,3,4]; pshufd ...,0x1B selects dwords 3,2,1,0 → [4,3,2,1].
  const report = run([
    ...movRax(0x0000000200000001n), 0x66, 0x48, 0x0f, 0x6e, 0xc0,
    ...movRax(0x0000000400000003n), 0x66, 0x48, 0x0f, 0x6e, 0xc8,
    0x66, 0x0f, 0x6c, 0xc1, // punpcklqdq xmm0,xmm1 → [1,2,3,4]
    0x66, 0x0f, 0x70, 0xc8, 0x1b, // pshufd xmm1,xmm0,0x1B
    0x66, 0x48, 0x0f, 0x7e, 0xc9, // movq rcx,xmm1 (low = [4,3])
    0x66, 0x0f, 0x70, 0xd1, 0xee, // pshufd xmm2,xmm1,0xEE (high lane down)
    0x66, 0x48, 0x0f, 0x7e, 0xd2, // movq rdx,xmm2 (= [2,1])
    0xc3,
  ]);
  assertState(report, { register: { rcx: 0x0000000300000004n, rdx: 0x0000000100000002n } });
});

test("SSE2: psllq by an immediate 4 shifts the quadword left", () => {
  const report = run([
    ...movRax(0x1n), 0x66, 0x48, 0x0f, 0x6e, 0xc0,
    0x66, 0x0f, 0x73, 0xf0, 0x04, // psllq xmm0,4
    0x66, 0x48, 0x0f, 0x7e, 0xc1,
    0xc3,
  ]);
  assertState(report, { register: { rcx: 0x10n } });
});

test("SSE: movss merges the low dword and preserves the upper bits of the destination", () => {
  // xmm0 low64 = 0xFFFFFFFFFFFFFFFF; movd xmm1,0x11111111; movss xmm0,xmm1
  // replaces only the low dword → 0xFFFFFFFF_11111111.
  const report = run([
    ...movRax(0xFFFFFFFFFFFFFFFFn), 0x66, 0x48, 0x0f, 0x6e, 0xc0,
    ...movRax(0x11111111n), 0x66, 0x0f, 0x6e, 0xc8, // movd xmm1,eax
    0xf3, 0x0f, 0x10, 0xc1, // movss xmm0,xmm1
    0x66, 0x48, 0x0f, 0x7e, 0xc1,
    0xc3,
  ]);
  assertState(report, { register: { rcx: 0xFFFFFFFF11111111n } });
});

test("CPUID leaf 0 reports the vendor and leaf 1 reports exactly the emulated feature bits", () => {
  const leaf0 = run([0xb8, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xa2, 0xc3]);
  assertState(leaf0, { register: { rax: 1n, rbx: 0x756e6547n, rdx: 0x49656e69n, rcx: 0x6c65746en } });
  const leaf1 = run([0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0xa2, 0xc3]);
  // EDX = FPU|TSC|CMOV|MMX|FXSR|SSE|SSE2 = bits 0,4,15,23,24,25,26 = 0x07808011.
  assertState(leaf1, { register: { rax: 0x6a0n, rbx: 0n, rcx: 0n, rdx: 0x07808011n } });
});

test("CMPXCHG stores the source when the accumulator matches and loads the destination when it does not", () => {
  // eax=5, ecx=5, edx=9; cmpxchg ecx,edx → equal, ZF=1, ecx=9, eax unchanged.
  const equal = run([0xb8, 0x05, 0x00, 0x00, 0x00, 0xb9, 0x05, 0x00, 0x00, 0x00, 0xba, 0x09, 0x00, 0x00, 0x00, 0x0f, 0xb1, 0xd1, 0xc3]);
  assertState(equal, { register: { rax: 5n, rcx: 9n }, flag: { zf: true, pf: true } });
  // eax=5, ecx=7 → unequal, ZF=0, eax=7 (the destination), ecx unchanged. The
  // flags are CMP(5,7): result 0xFFFFFFFE → CF, SF, AF set; PF clear (odd byte).
  const unequal = run([0xb8, 0x05, 0x00, 0x00, 0x00, 0xb9, 0x07, 0x00, 0x00, 0x00, 0xba, 0x09, 0x00, 0x00, 0x00, 0x0f, 0xb1, 0xd1, 0xc3]);
  assertState(unequal, { register: { rax: 7n, rcx: 7n }, flag: { zf: false, cf: true, sf: true, pf: false, af: true } });
});

test("REP STOSB fills a byte run and retires one counted instruction per element", () => {
  // ecx=4; al=0xAB; rdi=rsp-0x40; rep stosb; mov edx,[rdi-4] → 0xABABABAB, ecx=0.
  const report = run([0xb9, 0x04, 0x00, 0x00, 0x00, 0xb0, 0xab, 0x48, 0x89, 0xe7, 0x48, 0x83, 0xef, 0x40, 0xf3, 0xaa, 0x8b, 0x57, 0xfc, 0xc3]);
  assertState(report, { register: { rdx: 0xABABABABn, rcx: 0n } });
});

test("bit ops, scans, exchange-add, byte swap and accumulator sign-extend are bit-exact", () => {
  // bts eax,3; bts eax,5 → 0x28.
  assertState(run([0xb8, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xba, 0xe8, 0x03, 0x0f, 0xba, 0xe8, 0x05, 0xc3]), { register: { rax: 0x28n } });
  // rax=0x100; bsf rcx,rax → 8; bsr rdx,rax → 8.
  assertState(run([0x48, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x0f, 0xbc, 0xc8, 0x48, 0x0f, 0xbd, 0xd0, 0xc3]), { register: { rcx: 8n, rdx: 8n } });
  // xchg eax,ecx swaps 0x11 and 0x22.
  assertState(run([0xb8, 0x11, 0x00, 0x00, 0x00, 0xb9, 0x22, 0x00, 0x00, 0x00, 0x87, 0xc8, 0xc3]), { register: { rax: 0x22n, rcx: 0x11n } });
  // bswap rax reverses the byte order of the quadword.
  assertState(run([0x48, 0xb8, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x48, 0x0f, 0xc8, 0xc3]), { register: { rax: 0xefcdab8967452301n } });
  // eax=0xFFFFFFFF; cdqe sign-extends to the full 64-bit accumulator.
  assertState(run([0xb8, 0xff, 0xff, 0xff, 0xff, 0x48, 0x98, 0xc3]), { register: { rax: 0xFFFFFFFFFFFFFFFFn } });
});

test("the lifter splits a straight-line run into a basic block terminated by its branch", () => {
  const block = liftBlock(Buffer.from([0xb8, 0x05, 0x00, 0x00, 0x00, 0x01, 0xc8, 0x74, 0x02, 0xc3]), 0);
  assert.equal(block.node.length, 3, "the block ends at the Jcc, not before or after");
  assert.equal(block.node[0].mnemonic, "mov");
  assert.equal(block.node[2].control, "jcc");
  assert.equal(block.terminator, "jcc");
});

test("the lifter refuses an unserved opcode as a structured node, never a wrong lift", () => {
  const node = decodeStructured(Buffer.from([0x0f, 0x0b, 0xc3]), 0); // ud2
  assert.equal(node.served, false);
  assert.equal(node.op, "unsupported");
  const report = run([0x0f, 0x0b, 0xc3]);
  assert.equal(report.stop_reason, "unsupported_opcode");
  assert.equal(report.exception.opcode, 0x0f0b);
});

// -------------------- x87 FPU conformance --------------------
// Each x87 microprogram is hand-encoded and its end state frozen from the
// instruction semantics: an FP result is written to the stack and read back into
// a GPR so the assertion is on exact IEEE bits, never on a float print.

test("x87: FLD1 twice then FADDP yields exactly 2.0 (0x4000000000000000)", () => {
  // fld1; fld1; faddp st1,st0; fstp qword[rsp-8]; mov rax,[rsp-8]; ret
  const report = run([0xd9, 0xe8, 0xd9, 0xe8, 0xde, 0xc1, 0xdd, 0x5c, 0x24, 0xf8, 0x48, 0x8b, 0x44, 0x24, 0xf8, 0xc3]);
  assertState(report, { register: { rax: 0x4000000000000000n } });
});

test("x87: FILD/FMULP/FISTP computes 6*7=42 through the register stack", () => {
  // mov dword[rsp-4],6; mov dword[rsp-8],7; fild [rsp-4]; fild [rsp-8];
  // fmulp st1,st0; fistp dword[rsp-16]; mov eax,[rsp-16]; ret
  const report = run([
    0xc7, 0x44, 0x24, 0xfc, 0x06, 0x00, 0x00, 0x00,
    0xc7, 0x44, 0x24, 0xf8, 0x07, 0x00, 0x00, 0x00,
    0xdb, 0x44, 0x24, 0xfc,
    0xdb, 0x44, 0x24, 0xf8,
    0xde, 0xc9,
    0xdb, 0x5c, 0x24, 0xf0,
    0x8b, 0x44, 0x24, 0xf0,
    0xc3,
  ]);
  assertState(report, { register: { rax: 42n } });
});

test("x87: FDIV st0,st1 with FILD operands computes 20/4=5", () => {
  // mov dword[rsp-4],20; mov dword[rsp-8],4; fild [rsp-8]; fild [rsp-4];
  // fdiv st0,st1; fistp dword[rsp-16]; mov eax,[rsp-16]; ret
  const report = run([
    0xc7, 0x44, 0x24, 0xfc, 0x14, 0x00, 0x00, 0x00,
    0xc7, 0x44, 0x24, 0xf8, 0x04, 0x00, 0x00, 0x00,
    0xdb, 0x44, 0x24, 0xf8,
    0xdb, 0x44, 0x24, 0xfc,
    0xd8, 0xf1,
    0xdb, 0x5c, 0x24, 0xf0,
    0x8b, 0x44, 0x24, 0xf0,
    0xc3,
  ]);
  assertState(report, { register: { rax: 5n } });
});

test("x87: FLD m32 then FSTP m32 round-trips the single-real bits of 1.5", () => {
  // mov dword[rsp-4],0x3fc00000; fld dword[rsp-4]; fstp dword[rsp-8]; mov eax,[rsp-8]; ret
  const report = run([
    0xc7, 0x44, 0x24, 0xfc, 0x00, 0x00, 0xc0, 0x3f,
    0xd9, 0x44, 0x24, 0xfc,
    0xd9, 0x5c, 0x24, 0xf8,
    0x8b, 0x44, 0x24, 0xf8,
    0xc3,
  ]);
  assertState(report, { register: { rax: 0x3fc00000n } });
});

test("x87: FLD m80 then FSTP m80 preserves the double identity of 1.5", () => {
  // Store 1.5 as f64, load it, FSTP to m80, FLD the m80 back, FSTP to f64, read.
  // mov rax,0x3ff8000000000000; mov [rsp-8],rax; fld qword[rsp-8];
  // fstp tbyte[rsp-24]; fld tbyte[rsp-24]; fstp qword[rsp-40]; mov rax,[rsp-40]; ret
  const report = run([
    0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x3f,
    0x48, 0x89, 0x44, 0x24, 0xf8,
    0xdd, 0x44, 0x24, 0xf8,
    0xdb, 0x7c, 0x24, 0xe8,
    0xdb, 0x6c, 0x24, 0xe8,
    0xdd, 0x5c, 0x24, 0xd8,
    0x48, 0x8b, 0x44, 0x24, 0xd8,
    0xc3,
  ]);
  assertState(report, { register: { rax: 0x3ff8000000000000n } });
});

test("x87: FCOMI sets EFLAGS greater (1.0 vs 0.0) — CF=ZF=PF=0", () => {
  // fldz; fld1; fcomi st0,st1; ret  (st0=1.0, st1=0.0)
  const report = run([0xd9, 0xee, 0xd9, 0xe8, 0xdb, 0xf1, 0xc3]);
  assert.equal(report.flag.cf, false);
  assert.equal(report.flag.zf, false);
  assert.equal(report.flag.pf, false);
});

test("x87: FCOMI sets ZF when the operands are equal (1.0 vs 1.0)", () => {
  // fld1; fld1; fcomi st0,st1; ret
  const report = run([0xd9, 0xe8, 0xd9, 0xe8, 0xdb, 0xf1, 0xc3]);
  assert.equal(report.flag.zf, true);
  assert.equal(report.flag.cf, false);
  assert.equal(report.flag.pf, false);
});

test("x87: FCOMPP then FNSTSW AX reports the C3 (equal) condition code", () => {
  // fld1; fld1; fcompp; fnstsw ax; ret  -> AX = C3 (0x4000), top back to 0
  const report = run([0xd9, 0xe8, 0xd9, 0xe8, 0xde, 0xd9, 0xdf, 0xe0, 0xc3]);
  assertState(report, { register: { rax: 0x4000n } });
});

test("x87: FLDCW then FNSTCW round-trips the control word", () => {
  // mov word[rsp-2],0x0f7f; fldcw [rsp-2]; fnstcw [rsp-4]; movzx eax,word[rsp-4]; ret
  const report = run([
    0x66, 0xc7, 0x44, 0x24, 0xfe, 0x7f, 0x0f,
    0xd9, 0x6c, 0x24, 0xfe,
    0xd9, 0x7c, 0x24, 0xfc,
    0x0f, 0xb7, 0x44, 0x24, 0xfc,
    0xc3,
  ]);
  assertState(report, { register: { rax: 0x0f7fn } });
});

test("x87: FXCH swaps st0 and st1, FSUBR computes the reversed difference", () => {
  // fild [rsp-4]=10; fild [rsp-8]=3; fxch st1; fsubrp st1,st0 -> (10-3)=7
  // fld order: after two filds st0=3, st1=10; fxch -> st0=10, st1=3;
  // fsubrp st1,st0 -> st1 = st0 - st1 = 10-3 = 7, pop -> st0=7
  const report = run([
    0xc7, 0x44, 0x24, 0xfc, 0x0a, 0x00, 0x00, 0x00,
    0xc7, 0x44, 0x24, 0xf8, 0x03, 0x00, 0x00, 0x00,
    0xdb, 0x44, 0x24, 0xfc,
    0xdb, 0x44, 0x24, 0xf8,
    0xd9, 0xc9,
    0xde, 0xe1,
    0xdb, 0x5c, 0x24, 0xf0,
    0x8b, 0x44, 0x24, 0xf0,
    0xc3,
  ]);
  assertState(report, { register: { rax: 7n } });
});

test("cross-check: the structured decode agrees with x64decode on every served plink instruction", () => {
  if (!existsSync(plinkPath)) {
    // The staged corpus is read-only and optional in a stripped checkout.
    return;
  }
  const state = mapPe64State(plinkPath);
  const text = state.section.find((entry) => entry.name === ".text");
  assert.ok(text, "plink must carry a .text section");
  const slice = state.image.subarray(text.virtual_address, text.virtual_address + text.mapped_size_byte);

  let decodedCount = 0;
  let servedCount = 0;
  let disagreeCount = 0;
  const disagreeSample = [];
  let offset = 0;
  while (offset < slice.length) {
    const reference = decodeX64Instruction(slice, offset);
    const mine = decodeStructured(slice, offset);
    decodedCount += 1;
    if (mine.served) {
      servedCount += 1;
      // The cross-check binds only where BOTH decoders serve: x64decode does not
      // decode the SSE/SSE2 map (nor CPUID/CMPXCHG), so where it refuses there is
      // nothing to agree on — this file's structured decode is the authority for
      // the length there. Where the reference DOES serve, length and mnemonic
      // must match exactly, as before.
      if (reference.is_served && (mine.length !== reference.length || mine.mnemonic !== reference.mnemonic)) {
        disagreeCount += 1;
        if (disagreeSample.length < 8) disagreeSample.push({ offset, mine: mine.mnemonic, mineLength: mine.length, reference: reference.mnemonic, referenceLength: reference.length });
      }
    }
    // Advance by this file's length when it serves (its decode spans the full
    // instruction, including SSE the reference under-advances); else follow the
    // reference so the sweep still steps past an opcode neither file serves.
    offset += mine.served ? mine.length : reference.length;
  }

  const servedFraction = servedCount / decodedCount;
  // eslint-disable-next-line no-console
  console.log(`lift64 plink .text cross-check: decoded ${decodedCount}, served ${servedCount} (${(servedFraction * 100).toFixed(1)}%), disagreements ${disagreeCount}`);
  assert.equal(disagreeCount, 0, `served instructions must agree with x64decode: ${JSON.stringify(disagreeSample)}`);
  assert.ok(servedFraction >= 0.5, `the structured decode served only ${(servedFraction * 100).toFixed(1)}% of the plink .text sweep`);
});
