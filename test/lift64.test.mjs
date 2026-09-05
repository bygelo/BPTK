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
      const lengthAgree = mine.length === reference.length;
      const mnemonicAgree = reference.is_served && mine.mnemonic === reference.mnemonic;
      if (!lengthAgree || !mnemonicAgree) {
        disagreeCount += 1;
        if (disagreeSample.length < 8) disagreeSample.push({ offset, mine: mine.mnemonic, mineLength: mine.length, reference: reference.mnemonic, referenceLength: reference.length });
      }
    }
    offset += reference.length;
  }

  const servedFraction = servedCount / decodedCount;
  // eslint-disable-next-line no-console
  console.log(`lift64 plink .text cross-check: decoded ${decodedCount}, served ${servedCount} (${(servedFraction * 100).toFixed(1)}%), disagreements ${disagreeCount}`);
  assert.equal(disagreeCount, 0, `served instructions must agree with x64decode: ${JSON.stringify(disagreeSample)}`);
  assert.ok(servedFraction >= 0.5, `the structured decode served only ${(servedFraction * 100).toFixed(1)}% of the plink .text sweep`);
});
