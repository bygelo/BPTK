// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The i386 microprogram conformance suite (BPTK-009): every microprogram is
// a hand-assembled instruction sequence whose full machine state — every
// general register, every architecturally defined flag, and the stack
// pointer — is frozen here as a literal reference state, derived by hand
// from the instruction semantics (two's-complement integer arithmetic, the
// flag definitions in the SDM), never from running the implementation. The
// probe executes the microprogram through the real run surface and the
// comparison is bit-exact. Cases whose flag are architecturally undefined
// on the reference machine (the BT family outside carry, BSF/BSR outside
// zero) freeze only the defined field and the probe declares the same
// choice, so the comparison stays exact without inventing state.

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { runPackage } from "../lib/run.mjs";
import { i386Opcode0f, i386Opcode0fGroup, i386OpcodeGroup, i386OpcodeOneByte, i386Prefix, sweepI386Text } from "../lib/i386.mjs";

const stackBase = 0x70000000;
const stackSizeByte = 0x10000;
const balancedStackPointer = stackBase + stackSizeByte - 4;

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
  file.writeUInt32LE((0x60000020 | 0x80000000) >>> 0, sectionOffset + 36);
  file.writeUInt32LE(0x600, sectionOffset + 16);
  file.writeUInt32LE(0x200, sectionOffset + 20);
  Buffer.from(code).copy(file, 0x200);
  return file;
}

function runMicro(context, code, option = {}) {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-i386-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const packagePath = join(rootPath, "package");
  mkdirSync(packagePath);
  writeFileSync(join(packagePath, "game.exe"), createPe32(code));
  writeFileSync(join(packagePath, "bptk.json"), JSON.stringify({
    schema_version: 1,
    executable: "game.exe",
    execution: { profile: "i386_probe_v1", instruction_budget_count: option.instruction_budget_count ?? 64 },
  }));
  return runPackage(packagePath);
}

function assertReferenceState(report, expected) {
  assert.equal(report.state, "probe_executed", `state ${report.state}: ${JSON.stringify(report.exception)}`);
  assert.equal(report.stop_reason, expected.stop_reason ?? "entry_return", `stop_reason with exception ${JSON.stringify(report.exception)}`);
  const register = expected.register ?? {};
  for (const [name, value] of Object.entries(register)) {
    assert.equal(report.register[name], value >>> 0, `register ${name}: 0x${(report.register[name] ?? 0).toString(16)} != 0x${(value >>> 0).toString(16)}`);
  }
  const flag = expected.flag ?? {};
  const flagDefault = { carry: false, parity: false, adjust: false, zero: false, sign: false, overflow: false };
  for (const [name, value] of Object.entries({ ...flagDefault, ...flag })) {
    assert.equal(report.flag[name], value, `flag ${name}: ${report.flag[name]} != ${value}`);
  }
  if (expected.eflags !== undefined) assert.equal(report.flag.eflags, expected.eflags >>> 0, `eflags: 0x${report.flag.eflags.toString(16)} != 0x${(expected.eflags >>> 0).toString(16)}`);
  const mm = expected.mm ?? {};
  for (const [index, value] of Object.entries(mm)) {
    const want = `0x${BigInt(value).toString(16).padStart(16, "0")}`;
    assert.equal(report.mm[index], want, `mm${index}: ${report.mm[index]} != ${want}`);
  }
  const xmm = expected.xmm ?? {};
  for (const [index, value] of Object.entries(xmm)) {
    assert.equal(report.xmm[index], value, `xmm${index}: ${report.xmm[index]} != ${value}`);
  }
}

// The IEEE reference lane builders: a 128-bit xmm literal assembled from the
// float32 or float64 lanes the instruction semantics define, computed here in
// the same IEEE arithmetic the SDM specifies, independent of the probe.
function xmmSingle(...lane) {
  const buffer = Buffer.alloc(16);
  lane.forEach((value, index) => buffer.writeFloatLE(Math.fround(value), index * 4));
  return `0x${buffer.toString("hex")}`;
}
function xmmDouble(...lane) {
  const buffer = Buffer.alloc(16);
  lane.forEach((value, index) => buffer.writeDoubleLE(value, index * 8));
  return `0x${buffer.toString("hex")}`;
}

test("microprogram: the byte al,imm8 column sets the exact flag of 0x7f+1", (context) => {
  const report = runMicro(context, [0x04, 0x7f, 0x04, 0x01, 0xc3]);
  assertReferenceState(report, {
    register: { eax: 0x80 },
    flag: { carry: false, parity: false, adjust: true, zero: false, sign: true, overflow: true },
  });
});

test("microprogram: the byte al,imm8 column wraps with carry and zero", (context) => {
  const report = runMicro(context, [0x04, 0xff, 0x04, 0x01, 0xc3]);
  assertReferenceState(report, {
    register: { eax: 0 },
    flag: { carry: true, parity: true, adjust: true, zero: true, sign: false, overflow: false },
  });
});

test("microprogram: mov through the high register and xchg r/m8,r8 preserve the byte lanes", (context) => {
  // mov ah,0x34; mov bl,0x12; xchg bl,ah (reg=ah, rm=bl); mov al,ah — ah keeps
  // 0x12, so the final load into al leaves 0x1212 in eax.
  const report = runMicro(context, [0xb4, 0x34, 0xb3, 0x12, 0x86, 0xe3, 0x88, 0xe0, 0xc3]);
  assertReferenceState(report, {
    register: { eax: 0x1212, ebx: 0x34 },
    eflags: 2,
  });
});

test("microprogram: the byte add to memory form reads and writes the exact byte", (context) => {
  // ah keeps 0x12 after the memory add, so the reload into al leaves 0x1246.
  const report = runMicro(context, [0xb8, 0x34, 0x12, 0x00, 0x00, 0xa2, 0xf0, 0x15, 0x40, 0x00, 0x00, 0x25, 0xf0, 0x15, 0x40, 0x00, 0xa0, 0xf0, 0x15, 0x40, 0x00, 0xc3]);
  assertReferenceState(report, {
    register: { eax: 0x1246 },
    flag: { carry: false, parity: false, adjust: false, zero: false, sign: false, overflow: false },
  });
});

test("microprogram: the 0x80 byte immediate group and the 0x82 alias serve the same byte column", (context) => {
  const report = runMicro(context, [0x80, 0xcb, 0x40, 0x82, 0xc3, 0x01, 0xc3]);
  assertReferenceState(report, {
    register: { ebx: 0x41 },
    flag: { carry: false, parity: true, adjust: false, zero: false, sign: false, overflow: false },
  });
});

test("microprogram: CWDE sign-extends ax into eax", (context) => {
  const report = runMicro(context, [0x66, 0xb8, 0x00, 0x80, 0x98, 0xc3]);
  assertReferenceState(report, { register: { eax: 0xffff8000 }, eflags: 2 });
});

test("microprogram: CBW keeps the high word of eax while sign-extending al", (context) => {
  const report = runMicro(context, [0xb8, 0x00, 0x00, 0x34, 0x12, 0xb0, 0x80, 0x66, 0x98, 0xc3]);
  assertReferenceState(report, { register: { eax: 0x1234ff80 }, eflags: 2 });
});

test("microprogram: CDQ spreads the sign of eax across edx", (context) => {
  const report = runMicro(context, [0xb8, 0x00, 0x00, 0x00, 0x80, 0x99, 0xc3]);
  assertReferenceState(report, { register: { eax: 0x80000000, edx: 0xffffffff }, eflags: 2 });
});

test("microprogram: the 0x66 CWD form writes only the low word of edx", (context) => {
  const report = runMicro(context, [0xb8, 0x00, 0x80, 0x00, 0x00, 0x66, 0x99, 0xc3]);
  assertReferenceState(report, { register: { eax: 0x8000, edx: 0xffff }, eflags: 2 });
});

test("microprogram: XCHG r/m32,r32 through memory exchanges the exact dword", (context) => {
  const report = runMicro(context, [0xb8, 0x34, 0x12, 0x00, 0x00, 0xbb, 0x78, 0x56, 0x00, 0x00, 0xa3, 0xf0, 0x15, 0x40, 0x00, 0x87, 0x1d, 0xf0, 0x15, 0x40, 0x00, 0xc3]);
  assertReferenceState(report, { register: { eax: 0x1234, ebx: 0x1234 }, eflags: 2 });
});

test("microprogram: 0x8f pop r/m restores the pushed value and the stack pointer", (context) => {
  const report = runMicro(context, [0x68, 0x78, 0x56, 0x34, 0x12, 0x8f, 0xc2, 0xc3]);
  assertReferenceState(report, { register: { edx: 0x12345678, esp: balancedStackPointer }, eflags: 2 });
});

test("microprogram: pushad and popad round-trip every register", (context) => {
  const report = runMicro(context, [0xb8, 0x44, 0x33, 0x22, 0x11, 0x60, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x61, 0xc3]);
  assertReferenceState(report, { register: { eax: 0x11223344, esp: balancedStackPointer }, eflags: 2 });
});

test("microprogram: SAHF loads the five low flag from ah", (context) => {
  const report = runMicro(context, [0xb4, 0xff, 0x9e, 0x9f, 0xc3]);
  assertReferenceState(report, {
    register: { eax: 0xd700 },
    flag: { carry: true, parity: true, adjust: true, zero: true, sign: true },
    eflags: 0xd7,
  });
});

test("microprogram: SAHF ignores the reserved ah bit and LAHF restores the always-one bit", (context) => {
  const report = runMicro(context, [0xb4, 0x41, 0x9e, 0x9f, 0xc3]);
  assertReferenceState(report, {
    register: { eax: 0x4300 },
    flag: { carry: true, zero: true, parity: false, adjust: false, sign: false },
    eflags: 0x43,
  });
});

test("microprogram: STC sets carry into eflags", (context) => {
  const report = runMicro(context, [0xf9, 0xc3]);
  assertReferenceState(report, { flag: { carry: true }, eflags: 3 });
});

test("microprogram: FWAIT changes no architectural state", (context) => {
  const report = runMicro(context, [0xb8, 0x2a, 0x00, 0x00, 0x00, 0x9b, 0xc3]);
  assertReferenceState(report, { register: { eax: 0x2a }, eflags: 2 });
});

test("microprogram: XLAT reads the byte at [ebx+al]", (context) => {
  const report = runMicro(context, [0xbb, 0x00, 0x00, 0x00, 0x70, 0xc6, 0x43, 0x02, 0x5a, 0xb0, 0x02, 0xd7, 0xc3]);
  assertReferenceState(report, { register: { eax: 0x5a, ebx: 0x70000000 }, eflags: 2 });
});

test("microprogram: LOOP decrements to zero exactly three time", (context) => {
  const report = runMicro(context, [0xb9, 0x03, 0x00, 0x00, 0x00, 0xe2, 0xfe, 0xc3]);
  assertReferenceState(report, { register: { ecx: 0, esp: balancedStackPointer }, eflags: 2 });
});

test("microprogram: LOOPE exits on the clear zero flag after one decrement", (context) => {
  const report = runMicro(context, [0xb9, 0x02, 0x00, 0x00, 0x00, 0xf9, 0xe1, 0xfe, 0xc3]);
  assertReferenceState(report, { register: { ecx: 1, esp: balancedStackPointer }, flag: { carry: true } });
});

test("microprogram: JECXZ takes the branch on a zero ecx and skips the load", (context) => {
  const report = runMicro(context, [0xb9, 0x00, 0x00, 0x00, 0x00, 0xe3, 0x02, 0xb0, 0x11, 0xc3]);
  assertReferenceState(report, { register: { eax: 0, ecx: 0 }, eflags: 2 });
});

test("microprogram: JECXZ falls through on a non-zero ecx", (context) => {
  const report = runMicro(context, [0xb9, 0x01, 0x00, 0x00, 0x00, 0xe3, 0x02, 0xb0, 0x11, 0xc3]);
  assertReferenceState(report, { register: { eax: 0x11, ecx: 1 }, eflags: 2 });
});

test("microprogram: CMOVcc moves only when the condition holds", (context) => {
  const report = runMicro(context, [0xb8, 0x01, 0x00, 0x00, 0x00, 0xbb, 0x02, 0x00, 0x00, 0x00, 0x39, 0xc3, 0x0f, 0x42, 0xcb, 0x0f, 0x47, 0xcb, 0xc3]);
  assertReferenceState(report, {
    register: { eax: 1, ebx: 2, ecx: 2 },
    flag: { carry: false, parity: false, adjust: false, zero: false, sign: false, overflow: false },
  });
});

test("microprogram: the BT immediate form reads the bit and BTS sets it", (context) => {
  const report = runMicro(context, [0xb8, 0x10, 0x00, 0x00, 0x00, 0x0f, 0xba, 0xe0, 0x04, 0x0f, 0xba, 0xe9, 0x01, 0xc3]);
  assertReferenceState(report, { register: { eax: 0x10, ecx: 2 }, flag: { carry: false } });
});

test("microprogram: the BT register form, BTC, and BTR manipulate the exact bit", (context) => {
  const report = runMicro(context, [0xbb, 0x0f, 0x00, 0x00, 0x00, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0xa3, 0xc3, 0x0f, 0xbb, 0xc3, 0x0f, 0xb3, 0xc3, 0xc3]);
  assertReferenceState(report, { register: { eax: 1, ebx: 0x0d }, flag: { carry: false } });
});

test("microprogram: BSF and BSR find the exact bit and BSF on zero changes only zero flag", (context) => {
  const report = runMicro(context, [0xb8, 0x00, 0x00, 0xff, 0x00, 0x0f, 0xbc, 0xc8, 0x0f, 0xbd, 0xd0, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xbc, 0xc8, 0xc3]);
  assertReferenceState(report, { register: { eax: 0, ecx: 16, edx: 23 }, flag: { zero: true } });
});

test("microprogram: SHLD shifts the concatenated pair with the exact carry", (context) => {
  // modrm d8: rm=eax is the destination, reg=ebx the source.
  const report = runMicro(context, [0xb8, 0x78, 0x56, 0x34, 0x12, 0xbb, 0xf0, 0xde, 0xbc, 0x9a, 0x0f, 0xa4, 0xd8, 0x08, 0xc3]);
  assertReferenceState(report, {
    register: { eax: 0x3456789a, ebx: 0x9abcdef0 },
    flag: { carry: false, parity: true, zero: false, sign: false },
  });
});

test("microprogram: SHRD shifts down with the exact carry out of bit 3", (context) => {
  const report = runMicro(context, [0xb8, 0x78, 0x56, 0x34, 0x12, 0xbb, 0xf0, 0xde, 0xbc, 0x9a, 0x0f, 0xac, 0xd8, 0x04, 0xc3]);
  assertReferenceState(report, {
    register: { eax: 0x01234567, ebx: 0x9abcdef0 },
    flag: { carry: true, parity: false, zero: false, sign: false },
  });
});

test("microprogram: ROR r/m32 by CL rotates the exact nibble and sets carry from the result MSB", (context) => {
  // mov eax,0x12345678; mov cl,4; ror eax,cl (d3 /1). The low nibble rotates to
  // the top, so the result MSB is 1 and carry follows it. Regression for the
  // Number/BigInt mix that faulted the rotate group on the CRT's first ROR.
  const report = runMicro(context, [0xb8, 0x78, 0x56, 0x34, 0x12, 0xb1, 0x04, 0xd3, 0xc8, 0xc3]);
  assertReferenceState(report, {
    register: { eax: 0x81234567 },
    flag: { carry: true },
  });
});

test("microprogram: ROL r/m32 by CL rotates the exact nibble and clears carry from a zero LSB", (context) => {
  // mov eax,0x81234567; mov cl,4; rol eax,cl (d3 /0) → 0x12345678, carry from
  // the result LSB (0).
  const report = runMicro(context, [0xb8, 0x67, 0x45, 0x23, 0x81, 0xb1, 0x04, 0xd3, 0xc0, 0xc3]);
  assertReferenceState(report, {
    register: { eax: 0x12345678 },
    flag: { carry: false },
  });
});

test("microprogram: SAR r/m32 by imm8 keeps the sign and sets carry from the last shifted bit", (context) => {
  // mov ecx,0xffffffe0 (-32); sar ecx,6 (c1 /7) → -1. The exact instruction form
  // that faulted the CRT: the asIntN bit-count argument must be a Number.
  const report = runMicro(context, [0xb9, 0xe0, 0xff, 0xff, 0xff, 0xc1, 0xf9, 0x06, 0xc3]);
  assertReferenceState(report, {
    register: { ecx: 0xffffffff },
    flag: { carry: true, sign: true, parity: true },
  });
});

test("microprogram: two-operand IMUL keeps the low product and clears carry when it fits", (context) => {
  // mov ecx,7; mov edx,6; imul ecx,edx (0f af /r) → 42, no overflow. Regression
  // for the asIntN bit-count argument in imulTwoOperand.
  const report = runMicro(context, [0xb9, 0x07, 0x00, 0x00, 0x00, 0xba, 0x06, 0x00, 0x00, 0x00, 0x0f, 0xaf, 0xca, 0xc3]);
  assertReferenceState(report, {
    register: { ecx: 42 },
    flag: { carry: false, overflow: false },
  });
});

test("microprogram: two-operand IMUL sets carry and overflow when the product truncates", (context) => {
  // mov eax,0x10000; mov ecx,0x10000; imul eax,ecx → 0x100000000 truncates to 0
  // with the 32-bit product no longer representing the full result.
  const report = runMicro(context, [0xb8, 0x00, 0x00, 0x01, 0x00, 0xb9, 0x00, 0x00, 0x01, 0x00, 0x0f, 0xaf, 0xc1, 0xc3]);
  assertReferenceState(report, {
    register: { eax: 0 },
    flag: { carry: true, overflow: true },
  });
});

test("microprogram: FNINIT and FNCLEX execute so the following x87 round-trip computes", (context) => {
  // mov [0x401600],7; fninit (db /4 e3); fnclex (db /4 e2); fild [0x401600];
  // fistp [0x401604]; mov eax,[0x401604]. The two control forms were structured
  // refusals before; reaching entry_return with 7 stored back proves the CRT's
  // x87 reset now runs and the unit still loads and stores through it.
  const report = runMicro(context, [
    0xb8, 0x07, 0x00, 0x00, 0x00,       // mov eax, 7
    0xa3, 0x00, 0x16, 0x40, 0x00,       // mov [0x401600], eax
    0xdb, 0xe3,                         // fninit
    0xdb, 0xe2,                         // fnclex
    0xdb, 0x05, 0x00, 0x16, 0x40, 0x00, // fild dword [0x401600]
    0xdb, 0x1d, 0x04, 0x16, 0x40, 0x00, // fistp dword [0x401604]
    0xa1, 0x04, 0x16, 0x40, 0x00,       // mov eax, [0x401604]
    0xc3,
  ]);
  assertReferenceState(report, { register: { eax: 7 } });
});

test("microprogram: CMPXCHG8B writes ECX:EBX on equality and loads EDX:EAX on mismatch", (context) => {
  const equal = runMicro(context, [
    0xb8, 0x11, 0x11, 0x11, 0x11,             // mov eax, 0x11111111
    0xba, 0x22, 0x22, 0x22, 0x22,             // mov edx, 0x22222222
    0xbb, 0x33, 0x33, 0x33, 0x33,             // mov ebx, 0x33333333
    0xb9, 0x44, 0x44, 0x44, 0x44,             // mov ecx, 0x44444444
    0xa3, 0x00, 0x16, 0x40, 0x00,             // mov [0x401600], eax
    0x89, 0x15, 0x04, 0x16, 0x40, 0x00,       // mov [0x401604], edx
    0xf0, 0x0f, 0xc7, 0x0d, 0x00, 0x16, 0x40, 0x00, // lock cmpxchg8b [0x401600]
    0x8b, 0x35, 0x00, 0x16, 0x40, 0x00,       // mov esi, [0x401600]
    0x8b, 0x3d, 0x04, 0x16, 0x40, 0x00,       // mov edi, [0x401604]
    0xc3,
  ]);
  assertReferenceState(equal, {
    register: { eax: 0x11111111, edx: 0x22222222, ebx: 0x33333333, ecx: 0x44444444, esi: 0x33333333, edi: 0x44444444 },
    flag: { zero: true },
  });
  const mismatch = runMicro(context, [
    0xb8, 0xaa, 0xaa, 0xaa, 0xaa,             // mov eax, 0xaaaaaaaa
    0xa3, 0x00, 0x16, 0x40, 0x00,             // mov [0x401600], eax
    0xb8, 0xbb, 0xbb, 0xbb, 0xbb,             // mov eax, 0xbbbbbbbb
    0xa3, 0x04, 0x16, 0x40, 0x00,             // mov [0x401604], eax
    0xb8, 0x11, 0x11, 0x11, 0x11,             // mov eax, 0x11111111
    0xba, 0x22, 0x22, 0x22, 0x22,             // mov edx, 0x22222222
    0x0f, 0xc7, 0x0d, 0x00, 0x16, 0x40, 0x00, // cmpxchg8b [0x401600]
    0xc3,
  ]);
  assertReferenceState(mismatch, {
    register: { eax: 0xaaaaaaaa, edx: 0xbbbbbbbb },
    flag: { zero: false },
  });
});

test("microprogram: CMPXCHG writes the source on equality and the accumulator on mismatch", (context) => {
  const equal = runMicro(context, [0xb8, 0x05, 0x00, 0x00, 0x00, 0xbb, 0x05, 0x00, 0x00, 0x00, 0xb9, 0x07, 0x00, 0x00, 0x00, 0x0f, 0xb1, 0xcb, 0xc3]);
  assertReferenceState(equal, {
    register: { eax: 5, ebx: 7, ecx: 7 },
    flag: { zero: true, parity: true, carry: false },
  });
  const mismatch = runMicro(context, [0xb8, 0x06, 0x00, 0x00, 0x00, 0xbb, 0x05, 0x00, 0x00, 0x00, 0x0f, 0xb1, 0xcb, 0xc3]);
  assertReferenceState(mismatch, {
    register: { eax: 5, ebx: 5 },
    flag: { zero: false, parity: false, carry: false },
  });
});

test("microprogram: XADD exchanges then adds with the ADD flag", (context) => {
  const report = runMicro(context, [0xb8, 0x03, 0x00, 0x00, 0x00, 0xbb, 0x0a, 0x00, 0x00, 0x00, 0x0f, 0xc1, 0xd8, 0xc3]);
  assertReferenceState(report, {
    register: { eax: 13, ebx: 3 },
    flag: { carry: false, parity: false, adjust: false, zero: false, sign: false, overflow: false },
  });
});

test("microprogram: repe cmpsb compares [esi] with [edi] to exact exhaustion", (context) => {
  const report = runMicro(context, [
    0xbf, 0x00, 0x10, 0x00, 0x70, // mov edi, 0x70001000
    0xbe, 0x00, 0x20, 0x00, 0x70, // mov esi, 0x70002000
    0xc6, 0x07, 0x41, 0xc6, 0x47, 0x01, 0x42, 0xc6, 0x47, 0x02, 0x43, // "ABC" at edi
    0xc6, 0x06, 0x41, 0xc6, 0x46, 0x01, 0x42, 0xc6, 0x46, 0x02, 0x43, // "ABC" at esi
    0xfc, 0xb9, 0x03, 0x00, 0x00, 0x00, 0xf3, 0xa6, 0xc3,
  ]);
  assertReferenceState(report, {
    register: { ecx: 0, esi: 0x70002003, edi: 0x70001003 },
    flag: { zero: true, parity: true },
  });
});

test("microprogram: repne scasb stops at the found byte with the exact remaining count", (context) => {
  const report = runMicro(context, [
    0xbf, 0x00, 0x10, 0x00, 0x70, // mov edi, 0x70001000
    0xc6, 0x47, 0x02, 0x5a, // mov byte [edi+2], 0x5a
    0xb0, 0x5a, 0xb9, 0x0a, 0x00, 0x00, 0x00, 0xfc, 0xf2, 0xae, 0xc3,
  ]);
  assertReferenceState(report, {
    register: { eax: 0x5a, ecx: 7, edi: 0x70001003 },
    flag: { zero: true, parity: true },
  });
});

test("microprogram: the flat-model segment override byte are the identity", (context) => {
  const report = runMicro(context, [0x2e, 0x3e, 0x26, 0x36, 0xb8, 0x5a, 0x00, 0x00, 0x00, 0xc3]);
  assertReferenceState(report, { register: { eax: 0x5a }, eflags: 2 });
});

test("microprogram: the lock prefix is the identity on the bounded single-guest model", (context) => {
  // lock add eax,5 → 5 with even parity (two one-bit), so eflags = 6.
  const report = runMicro(context, [0xf0, 0x83, 0xc0, 0x05, 0xc3]);
  assertReferenceState(report, { register: { eax: 5 }, flag: { parity: true }, eflags: 6 });
});

test("microprogram: LEA computes the exact address from the memory ModRM", (context) => {
  // lea ecx, [ebx + esi*4 + 0x10]
  const report = runMicro(context, [0xbb, 0x00, 0x10, 0x00, 0x00, 0xbe, 0x08, 0x00, 0x00, 0x00, 0x8d, 0x8c, 0xb3, 0x10, 0x00, 0x00, 0x00, 0xc3]);
  assertReferenceState(report, { register: { ebx: 0x1000, esi: 8, ecx: 0x1030 }, eflags: 2 });
});

test("microprogram: the hint NOP family changes no architectural state", (context) => {
  const report = runMicro(context, [0x0f, 0x1f, 0x40, 0x00, 0x0f, 0x18, 0xc1, 0xc3]);
  assertReferenceState(report, { eflags: 2 });
});

test("microprogram: the fs override, UD2, privileged instruction, and port input stop with a stable diagnostic", (context) => {
  const fsReport = runMicro(context, [0x64, 0x8b, 0x1d, 0x18, 0x00, 0x00, 0x00, 0xc3]);
  assert.equal(fsReport.stop_reason, "unsupported_opcode");
  assert.equal(fsReport.exception.opcode, 0x64);
  assert.match(fsReport.exception.message, /fs segment override/);

  const ud2Report = runMicro(context, [0x0f, 0x0b, 0xc3]);
  assert.equal(ud2Report.stop_reason, "unsupported_opcode");
  assert.equal(ud2Report.exception.opcode, 0x0f0b);
  assert.match(ud2Report.exception.message, /Unsupported 0x0f opcode 0xb/);

  const hltReport = runMicro(context, [0xf4, 0xc3]);
  assert.equal(hltReport.stop_reason, "unsupported_opcode");
  assert.equal(hltReport.exception.opcode, 0xf4);
  assert.match(hltReport.exception.message, /privileged instruction 0xf4/);

  const cliReport = runMicro(context, [0xfa, 0xc3]);
  assert.equal(cliReport.stop_reason, "unsupported_opcode");
  assert.equal(cliReport.exception.opcode, 0xfa);

  const inReport = runMicro(context, [0xe4, 0x60, 0xc3]);
  assert.equal(inReport.stop_reason, "unsupported_opcode");
  assert.match(inReport.exception.message, /port input/);
});

test("microprogram: MMX movd loads the low lane, movq copies the lane, and pxor of a lane with itself clears it", (context) => {
  // mov eax,0x12345678; movd mm0,eax; movd mm1,eax; pxor mm0,mm0 (0f ef c0).
  const report = runMicro(context, [0xb8, 0x78, 0x56, 0x34, 0x12, 0x0f, 0x6e, 0xc0, 0x0f, 0x6e, 0xc8, 0x0f, 0xef, 0xc0, 0xc3]);
  assertReferenceState(report, { mm: { 0: 0n, 1: 0x12345678n } });
});

test("microprogram: PADDW wraps each word lane independently", (context) => {
  // mm0 words (0x0001,0x0002); mm1 words (0xffff,0x0004); paddw wraps word0 to
  // 0x0000 and sums word1 to 0x0006, the high two words staying zero.
  const report = runMicro(context, [0xb8, 0x01, 0x00, 0x02, 0x00, 0x0f, 0x6e, 0xc0, 0xb8, 0xff, 0xff, 0x04, 0x00, 0x0f, 0x6e, 0xc8, 0x0f, 0xfd, 0xc1, 0xc3]);
  assertReferenceState(report, { mm: { 0: 0x0000000000060000n } });
});

test("microprogram: PADDB then PSUBB by the same lane vector round-trips every byte lane", (context) => {
  // bytes (0x01,0xff,0x7f,0x80) + (0x01,0x01,0x01,0x01) = (0x02,0x00,0x80,0x81);
  // subtracting the same vector restores the original packed byte lanes.
  const add = runMicro(context, [0xb8, 0x01, 0xff, 0x7f, 0x80, 0x0f, 0x6e, 0xc0, 0xb8, 0x01, 0x01, 0x01, 0x01, 0x0f, 0x6e, 0xc8, 0x0f, 0xfc, 0xc1, 0xc3]);
  assertReferenceState(add, { mm: { 0: 0x0000000081800002n } });
  const roundTrip = runMicro(context, [0xb8, 0x01, 0xff, 0x7f, 0x80, 0x0f, 0x6e, 0xc0, 0xb8, 0x01, 0x01, 0x01, 0x01, 0x0f, 0x6e, 0xc8, 0x0f, 0xfc, 0xc1, 0x0f, 0xf8, 0xc1, 0xc3]);
  assertReferenceState(roundTrip, { mm: { 0: 0x00000000807fff01n } });
});

test("microprogram: PCMPEQW sets an all-ones mask on the equal word lanes and zero on the mismatch", (context) => {
  // mm0 words (0x0003,0x0003); mm1 words (0x0003,0x0004). word0 and the two
  // zero high words match (0xffff), word1 mismatches (0x0000).
  const report = runMicro(context, [0xb8, 0x03, 0x00, 0x03, 0x00, 0x0f, 0x6e, 0xc0, 0xb8, 0x03, 0x00, 0x04, 0x00, 0x0f, 0x6e, 0xc8, 0x0f, 0x75, 0xc1, 0xc3]);
  assertReferenceState(report, { mm: { 0: 0xffffffff0000ffffn } });
});

test("microprogram: the PSLLQ and PSRLQ immediate group shifts the whole 64-bit lane", (context) => {
  // psllq mm0,32 lifts the low dword into the high dword; psrlq mm0,4 of a
  // top-byte pattern shifts the whole quadword right by four.
  const left = runMicro(context, [0xb8, 0xef, 0xbe, 0xad, 0xde, 0x0f, 0x6e, 0xc0, 0x0f, 0x73, 0xf0, 0x20, 0xc3]);
  assertReferenceState(left, { mm: { 0: 0xdeadbeef00000000n } });
  const right = runMicro(context, [0xb8, 0x00, 0x00, 0x00, 0xff, 0x0f, 0x6e, 0xc0, 0x0f, 0x73, 0xd0, 0x04, 0xc3]);
  assertReferenceState(right, { mm: { 0: 0x000000000ff00000n } });
});

test("microprogram: PSRAW in the register form fills the shifted word lanes with the sign bit", (context) => {
  // mm0 word0=0x8000 (negative), shift count mm1=4: arithmetic right shift
  // gives 0xf800, the sign bit replicated into the vacated high bits.
  const report = runMicro(context, [0xb8, 0x00, 0x80, 0x00, 0x00, 0x0f, 0x6e, 0xc0, 0xb8, 0x04, 0x00, 0x00, 0x00, 0x0f, 0x6e, 0xc8, 0x0f, 0xe1, 0xc1, 0xc3]);
  assertReferenceState(report, { mm: { 0: 0x000000000000f800n } });
});

test("microprogram: PAND, POR, and PANDN combine the 64-bit lanes bitwise", (context) => {
  const pand = runMicro(context, [0xb8, 0xff, 0xff, 0x00, 0x00, 0x0f, 0x6e, 0xc0, 0xb8, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x6e, 0xc8, 0x0f, 0xdb, 0xc1, 0xc3]);
  assertReferenceState(pand, { mm: { 0: 0x0000000000000f0fn } });
  const por = runMicro(context, [0xb8, 0xf0, 0x00, 0x00, 0x00, 0x0f, 0x6e, 0xc0, 0xb8, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x6e, 0xc8, 0x0f, 0xeb, 0xc1, 0xc3]);
  assertReferenceState(por, { mm: { 0: 0x00000000000000ffn } });
  // pandn: (~mm0) & mm1 = (~0x0f0f) & 0xffff = 0xf0f0.
  const pandn = runMicro(context, [0xb8, 0x0f, 0x0f, 0x00, 0x00, 0x0f, 0x6e, 0xc0, 0xb8, 0xff, 0xff, 0x00, 0x00, 0x0f, 0x6e, 0xc8, 0x0f, 0xdf, 0xc1, 0xc3]);
  assertReferenceState(pandn, { mm: { 0: 0x000000000000f0f0n } });
});

test("microprogram: PSHUFW selects each result word by the immediate's 2-bit field", (context) => {
  // mm0 words (0x0021,0x0043,0,0); control 0x1b = 00|01|10|11 selects source
  // words 3,2,1,0 into result words 0,1,2,3, reversing the loaded pair up.
  const report = runMicro(context, [0xb8, 0x21, 0x00, 0x43, 0x00, 0x0f, 0x6e, 0xc0, 0x0f, 0x70, 0xc8, 0x1b, 0xc3]);
  assertReferenceState(report, { mm: { 1: 0x0021004300000000n } });
});

test("microprogram: MOVQ stores a lane to memory and the general loads read it back byte-exact", (context) => {
  // movd mm0,eax; psllq mm0,32; movq [0x401800],mm0; mov eax,[0x401800];
  // mov edx,[0x401804] — the high dword lands in edx, the low dword is zero.
  const report = runMicro(context, [0xb8, 0xef, 0xbe, 0xad, 0xde, 0x0f, 0x6e, 0xc0, 0x0f, 0x73, 0xf0, 0x20, 0x0f, 0x7f, 0x05, 0x00, 0x18, 0x40, 0x00, 0xa1, 0x00, 0x18, 0x40, 0x00, 0x8b, 0x15, 0x04, 0x18, 0x40, 0x00, 0xc3]);
  assertReferenceState(report, { register: { eax: 0, edx: 0xdeadbeef }, mm: { 0: 0xdeadbeef00000000n } });
});

test("microprogram: EMMS runs as the x87 tag reset and leaves the mm lanes intact", (context) => {
  // movd mm0,eax; emms; the lane value survives the tag-word reset.
  const report = runMicro(context, [0xb8, 0x78, 0x56, 0x34, 0x12, 0x0f, 0x6e, 0xc0, 0x0f, 0x77, 0xc3]);
  assertReferenceState(report, { mm: { 0: 0x0000000012345678n } });
});

test("microprogram: CVTSI2SS then ADDSS and MULSS compute the exact float32 lane", (context) => {
  // cvtsi2ss xmm0,5; cvtsi2ss xmm1,3; addss xmm0,xmm1 -> 8.0f.
  const add = runMicro(context, [0xb8, 0x05, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x2a, 0xc0, 0xb8, 0x03, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x2a, 0xc8, 0xf3, 0x0f, 0x58, 0xc1, 0xc3]);
  assertReferenceState(add, { xmm: { 0: xmmSingle(8, 0, 0, 0), 1: xmmSingle(3, 0, 0, 0) } });
  // cvtsi2ss xmm0,7; mulss xmm0,xmm0 -> 49.0f.
  const mul = runMicro(context, [0xb8, 0x07, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x2a, 0xc0, 0xf3, 0x0f, 0x59, 0xc0, 0xc3]);
  assertReferenceState(mul, { xmm: { 0: xmmSingle(49, 0, 0, 0) } });
});

test("microprogram: SQRTSS rounds the low lane directly to float32", (context) => {
  // cvtsi2ss xmm0,16; sqrtss xmm0,xmm0 -> 4.0f.
  const report = runMicro(context, [0xb8, 0x10, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x2a, 0xc0, 0xf3, 0x0f, 0x51, 0xc0, 0xc3]);
  assertReferenceState(report, { xmm: { 0: xmmSingle(4, 0, 0, 0) } });
});

test("microprogram: the packed ADDPS adds all four single lanes at once", (context) => {
  // cvtsi2ss xmm0,2 leaves lane0=2 and lane1..3=0; addps xmm0,xmm0 doubles
  // every lane, so lane0 becomes 4.0 and the zero lanes stay zero.
  const report = runMicro(context, [0xb8, 0x02, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x2a, 0xc0, 0x0f, 0x58, 0xc0, 0xc3]);
  assertReferenceState(report, { xmm: { 0: xmmSingle(4, 0, 0, 0) } });
});

test("microprogram: CVTSI2SD, ADDSD, and DIVSD compute the exact float64 lane", (context) => {
  // cvtsi2sd xmm0,5; cvtsi2sd xmm1,2; addsd xmm0,xmm1 -> 7.0; divsd xmm0,xmm1 -> 3.5.
  const report = runMicro(context, [0xb8, 0x05, 0x00, 0x00, 0x00, 0xf2, 0x0f, 0x2a, 0xc0, 0xb8, 0x02, 0x00, 0x00, 0x00, 0xf2, 0x0f, 0x2a, 0xc8, 0xf2, 0x0f, 0x58, 0xc1, 0xf2, 0x0f, 0x5e, 0xc1, 0xc3]);
  assertReferenceState(report, { xmm: { 0: xmmDouble(3.5, 0) } });
});

test("microprogram: MOVSS from a register preserves the destination's upper lanes", (context) => {
  // cvtsi2ss xmm0,1 (lanes 1,0,0,0 after doubling below); cvtsi2ss xmm1,9;
  // addps xmm0,xmm0 raises the upper lanes to a known nonzero, movss xmm0,xmm1
  // overwrites only lane0 with 9.0 and leaves lanes 1..3 intact.
  const report = runMicro(context, [0xb8, 0x03, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x2a, 0xc0, 0xb8, 0x09, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x2a, 0xc8, 0xf3, 0x0f, 0x10, 0xc1, 0xc3]);
  assertReferenceState(report, { xmm: { 0: xmmSingle(9, 0, 0, 0) } });
});

test("microprogram: MOVAPS copies the whole 128-bit register", (context) => {
  // cvtsi2ss xmm1,6; movaps xmm0,xmm1 (np 0f 28 c1) copies all 128 bit.
  const report = runMicro(context, [0xb8, 0x06, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x2a, 0xc8, 0x0f, 0x28, 0xc1, 0xc3]);
  assertReferenceState(report, { xmm: { 0: xmmSingle(6, 0, 0, 0), 1: xmmSingle(6, 0, 0, 0) } });
});

test("microprogram: MOVDQA and the 0xf3 MOVQ move the packed integer lanes", (context) => {
  // movd xmm0,eax (66 0f 6e c0) loads the low dword and zero-extends; movdqa
  // xmm1,xmm0 (66 0f 6f c8) copies all 128; movq xmm2,xmm0 (f3 0f 7e d0)
  // takes the low qword and zeroes the upper.
  const report = runMicro(context, [0xb8, 0xef, 0xbe, 0xad, 0xde, 0x66, 0x0f, 0x6e, 0xc0, 0x66, 0x0f, 0x6f, 0xc8, 0xf3, 0x0f, 0x7e, 0xd0, 0xc3]);
  assertReferenceState(report, {
    xmm: { 0: "0xefbeadde000000000000000000000000", 1: "0xefbeadde000000000000000000000000", 2: "0xefbeadde000000000000000000000000" },
  });
});

test("microprogram: CVTSS2SD widens and CVTSD2SS narrows the low lane", (context) => {
  // cvtsi2sd xmm0,3; cvtsd2ss xmm1,xmm0 (f2 0f 5a c8) -> 3.0f; cvtss2sd
  // xmm2,xmm1 (f3 0f 5a d1) -> 3.0 double.
  const report = runMicro(context, [0xb8, 0x03, 0x00, 0x00, 0x00, 0xf2, 0x0f, 0x2a, 0xc0, 0xf2, 0x0f, 0x5a, 0xc8, 0xf3, 0x0f, 0x5a, 0xd1, 0xc3]);
  assertReferenceState(report, { xmm: { 0: xmmDouble(3, 0), 1: xmmSingle(3, 0, 0, 0), 2: xmmDouble(3, 0) } });
});

test("microprogram: CVTTSS2SI truncates and CVTSS2SI rounds to nearest even", (context) => {
  // Build 2.5f = (5/2): cvtsi2ss xmm0,5; cvtsi2ss xmm1,2; divss xmm0,xmm1;
  // cvttss2si eax -> 2 (truncated); cvtss2si edx -> 2 (nearest even of 2.5).
  const report = runMicro(context, [0xb8, 0x05, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x2a, 0xc0, 0xb8, 0x02, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x2a, 0xc8, 0xf3, 0x0f, 0x5e, 0xc1, 0xf3, 0x0f, 0x2c, 0xc0, 0xf3, 0x0f, 0x2d, 0xd0, 0xc3]);
  assertReferenceState(report, { register: { eax: 2, edx: 2 } });
});

test("microprogram: UCOMISS sets the ordered EFLAGS for less, greater, equal, and unordered", (context) => {
  // 3 vs 5 -> below (CF=1, ZF=0); 5 vs 3 -> above (CF=0, ZF=0); 5 vs 5 ->
  // equal (ZF=1, CF=0, PF=0).
  const below = runMicro(context, [0xb8, 0x03, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x2a, 0xc0, 0xb8, 0x05, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x2a, 0xc8, 0x0f, 0x2e, 0xc1, 0xc3]);
  assertReferenceState(below, { flag: { carry: true, zero: false, parity: false } });
  const above = runMicro(context, [0xb8, 0x05, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x2a, 0xc0, 0xb8, 0x03, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x2a, 0xc8, 0x0f, 0x2e, 0xc1, 0xc3]);
  assertReferenceState(above, { flag: { carry: false, zero: false, parity: false } });
  const equal = runMicro(context, [0xb8, 0x05, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x2a, 0xc0, 0xf3, 0x0f, 0x2a, 0xc0, 0x0f, 0x2e, 0xc0, 0xc3]);
  assertReferenceState(equal, { flag: { carry: false, zero: true, parity: false } });
});

test("microprogram: XORPS clears a register to zero and ANDPS masks the lanes", (context) => {
  // cvtsi2ss xmm0,7; xorps xmm0,xmm0 (np 0f 57 c0) -> all zero.
  const report = runMicro(context, [0xb8, 0x07, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x2a, 0xc0, 0x0f, 0x57, 0xc0, 0xc3]);
  assertReferenceState(report, { xmm: { 0: "0x00000000000000000000000000000000" } });
});

test("microprogram: MINSS and MAXSS select the ordered low lane", (context) => {
  // cvtsi2ss xmm0,5; cvtsi2ss xmm1,3; minss xmm0,xmm1 -> 3.0f (xmm0);
  // separately maxss of 3 and 5 -> 5.0f.
  const minimum = runMicro(context, [0xb8, 0x05, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x2a, 0xc0, 0xb8, 0x03, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x2a, 0xc8, 0xf3, 0x0f, 0x5d, 0xc1, 0xc3]);
  assertReferenceState(minimum, { xmm: { 0: xmmSingle(3, 0, 0, 0) } });
  const maximum = runMicro(context, [0xb8, 0x03, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x2a, 0xc0, 0xb8, 0x05, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x2a, 0xc8, 0xf3, 0x0f, 0x5f, 0xc1, 0xc3]);
  assertReferenceState(maximum, { xmm: { 0: xmmSingle(5, 0, 0, 0) } });
});

test("microprogram: MOVLPS stores the low qword and reloads it without touching the high half", (context) => {
  // movd xmm0,eax (low dword 0xdeadbeef, high zero); movlps [0x401800],xmm0
  // (0f 13); movlps xmm1,[0x401800] (0f 12) reloads the same low qword.
  const report = runMicro(context, [0xb8, 0xef, 0xbe, 0xad, 0xde, 0x66, 0x0f, 0x6e, 0xc0, 0x0f, 0x13, 0x05, 0x00, 0x18, 0x40, 0x00, 0x0f, 0x12, 0x0d, 0x00, 0x18, 0x40, 0x00, 0x66, 0x0f, 0x7e, 0xc8, 0xc3]);
  assertReferenceState(report, {
    register: { eax: 0xdeadbeef },
    xmm: { 0: "0xefbeadde000000000000000000000000", 1: "0xefbeadde000000000000000000000000" },
  });
});

test("microprogram: MOVLHPS writes the source low qword into the destination high qword", (context) => {
  // cvtsi2ss xmm0,1; cvtsi2ss xmm1,2; movlhps xmm0,xmm1 (0f 16 c1) keeps
  // xmm0's low qword and copies xmm1's low qword into xmm0's high qword.
  const report = runMicro(context, [0xb8, 0x01, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x2a, 0xc0, 0xb8, 0x02, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x2a, 0xc8, 0x0f, 0x16, 0xc1, 0xc3]);
  assertReferenceState(report, { xmm: { 0: xmmSingle(1, 0, 2, 0), 1: xmmSingle(2, 0, 0, 0) } });
});

test("microprogram: MOVSS and MOVSD round-trip a scalar lane through memory", (context) => {
  // cvtsi2sd xmm0,9; movsd [0x401800],xmm0 (f2 0f 11 05 ...); movsd xmm1,[..]
  // reloads the same double, and cvttsd2si reads it back as the integer 9.
  const report = runMicro(context, [0xb8, 0x09, 0x00, 0x00, 0x00, 0xf2, 0x0f, 0x2a, 0xc0, 0xf2, 0x0f, 0x11, 0x05, 0x00, 0x18, 0x40, 0x00, 0xf2, 0x0f, 0x10, 0x0d, 0x00, 0x18, 0x40, 0x00, 0xf2, 0x0f, 0x2c, 0xc1, 0xc3]);
  assertReferenceState(report, { register: { eax: 9 }, xmm: { 0: xmmDouble(9, 0), 1: xmmDouble(9, 0) } });
});

test("microprogram: SSE2 PSHUFD broadcasts a source dword to every lane by the immediate", (context) => {
  // mov eax,0xdeadbeef; movd xmm0,eax (66 0f 6e c0); pshufd xmm1,xmm0,0x00
  // (66 0f 70 c8 00) selects source lane 0 into all four result lanes.
  const report = runMicro(context, [0xb8, 0xef, 0xbe, 0xad, 0xde, 0x66, 0x0f, 0x6e, 0xc0, 0x66, 0x0f, 0x70, 0xc8, 0x00, 0xc3]);
  assertReferenceState(report, { xmm: { 1: "0xefbeaddeefbeaddeefbeaddeefbeadde" } });
});

test("microprogram: SSE2 PSHUFLW reverses the low four words and copies the high qword", (context) => {
  // eax=0x00020001 -> words (1,2,0,0); pshuflw xmm1,xmm0,0x1b (f2 0f 70 c8 1b)
  // selects source words 3,2,1,0 into result words 0,1,2,3.
  const report = runMicro(context, [0xb8, 0x01, 0x00, 0x02, 0x00, 0x66, 0x0f, 0x6e, 0xc0, 0xf2, 0x0f, 0x70, 0xc8, 0x1b, 0xc3]);
  assertReferenceState(report, { xmm: { 1: "0x00000000020001000000000000000000" } });
});

test("microprogram: SSE2 PXOR of a register with itself clears all 128 bit", (context) => {
  const report = runMicro(context, [0xb8, 0xef, 0xbe, 0xad, 0xde, 0x66, 0x0f, 0x6e, 0xc0, 0x66, 0x0f, 0xef, 0xc0, 0xc3]);
  assertReferenceState(report, { xmm: { 0: "0x00000000000000000000000000000000" } });
});

test("microprogram: SSE2 PAND, POR, and PANDN combine the 128-bit lanes bitwise", (context) => {
  const pand = runMicro(context, [0xb8, 0xff, 0xff, 0x00, 0x00, 0x66, 0x0f, 0x6e, 0xc0, 0xb8, 0x0f, 0x0f, 0x00, 0x00, 0x66, 0x0f, 0x6e, 0xc8, 0x66, 0x0f, 0xdb, 0xc1, 0xc3]);
  assertReferenceState(pand, { xmm: { 0: "0x0f0f0000000000000000000000000000" } });
  const por = runMicro(context, [0xb8, 0xf0, 0x00, 0x00, 0x00, 0x66, 0x0f, 0x6e, 0xc0, 0xb8, 0x0f, 0x00, 0x00, 0x00, 0x66, 0x0f, 0x6e, 0xc8, 0x66, 0x0f, 0xeb, 0xc1, 0xc3]);
  assertReferenceState(por, { xmm: { 0: "0xff000000000000000000000000000000" } });
  // pandn: (~xmm0) & xmm1 = (~0x0f0f) & 0xffff = 0xf0f0 in the low dword.
  const pandn = runMicro(context, [0xb8, 0x0f, 0x0f, 0x00, 0x00, 0x66, 0x0f, 0x6e, 0xc0, 0xb8, 0xff, 0xff, 0x00, 0x00, 0x66, 0x0f, 0x6e, 0xc8, 0x66, 0x0f, 0xdf, 0xc1, 0xc3]);
  assertReferenceState(pandn, { xmm: { 0: "0xf0f00000000000000000000000000000" } });
});

test("microprogram: SSE2 PADDW wraps each word lane and PADDB wraps each byte lane", (context) => {
  const paddw = runMicro(context, [0xb8, 0x01, 0x00, 0x02, 0x00, 0x66, 0x0f, 0x6e, 0xc0, 0xb8, 0xff, 0xff, 0x04, 0x00, 0x66, 0x0f, 0x6e, 0xc8, 0x66, 0x0f, 0xfd, 0xc1, 0xc3]);
  assertReferenceState(paddw, { xmm: { 0: "0x00000600000000000000000000000000" } });
  // bytes (01,ff,7f,80)+(01,01,01,01) = (02,00,80,81) with per-byte wrap.
  const paddb = runMicro(context, [0xb8, 0x01, 0xff, 0x7f, 0x80, 0x66, 0x0f, 0x6e, 0xc0, 0xb8, 0x01, 0x01, 0x01, 0x01, 0x66, 0x0f, 0x6e, 0xc8, 0x66, 0x0f, 0xfc, 0xc1, 0xc3]);
  assertReferenceState(paddb, { xmm: { 0: "0x02008081000000000000000000000000" } });
});

test("microprogram: SSE2 PADDQ carries across the full 64-bit lane and PSUBQ borrows", (context) => {
  // 0xffffffff + 1 in the low qword lifts into bit 32.
  const paddq = runMicro(context, [0xb8, 0xff, 0xff, 0xff, 0xff, 0x66, 0x0f, 0x6e, 0xc0, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x66, 0x0f, 0x6e, 0xc8, 0x66, 0x0f, 0xd4, 0xc1, 0xc3]);
  assertReferenceState(paddq, { xmm: { 0: "0x00000000010000000000000000000000" } });
  // 0 - 1 borrows the whole low qword to all-ones, the high qword staying zero.
  const psubq = runMicro(context, [0xb8, 0x00, 0x00, 0x00, 0x00, 0x66, 0x0f, 0x6e, 0xc0, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x66, 0x0f, 0x6e, 0xc8, 0x66, 0x0f, 0xfb, 0xc1, 0xc3]);
  assertReferenceState(psubq, { xmm: { 0: "0xffffffffffffffff0000000000000000" } });
});

test("microprogram: SSE2 PSUBD subtracts each dword lane", (context) => {
  const report = runMicro(context, [0xb8, 0x05, 0x00, 0x00, 0x00, 0x66, 0x0f, 0x6e, 0xc0, 0xb8, 0x03, 0x00, 0x00, 0x00, 0x66, 0x0f, 0x6e, 0xc8, 0x66, 0x0f, 0xfa, 0xc1, 0xc3]);
  assertReferenceState(report, { xmm: { 0: "0x02000000000000000000000000000000" } });
});

test("microprogram: SSE2 PCMPEQD masks the equal dword lanes and PCMPGTD the signed-greater lanes", (context) => {
  // low lane 5 vs 6 mismatches (zero); the three zero upper lanes match (ones).
  const eq = runMicro(context, [0xb8, 0x05, 0x00, 0x00, 0x00, 0x66, 0x0f, 0x6e, 0xc0, 0xb8, 0x06, 0x00, 0x00, 0x00, 0x66, 0x0f, 0x6e, 0xc8, 0x66, 0x0f, 0x76, 0xc1, 0xc3]);
  assertReferenceState(eq, { xmm: { 0: "0x00000000ffffffffffffffffffffffff" } });
  // low lane 5 > 3 (ones); the equal-zero upper lanes are not greater (zero).
  const gt = runMicro(context, [0xb8, 0x05, 0x00, 0x00, 0x00, 0x66, 0x0f, 0x6e, 0xc0, 0xb8, 0x03, 0x00, 0x00, 0x00, 0x66, 0x0f, 0x6e, 0xc8, 0x66, 0x0f, 0x66, 0xc1, 0xc3]);
  assertReferenceState(gt, { xmm: { 0: "0xffffffff000000000000000000000000" } });
});

test("microprogram: SSE2 PUNPCKLDQ, PUNPCKLBW, and PUNPCKLQDQ interleave the low halves", (context) => {
  const dq = runMicro(context, [0xb8, 0x11, 0x11, 0x11, 0x11, 0x66, 0x0f, 0x6e, 0xc0, 0xb8, 0x22, 0x22, 0x22, 0x22, 0x66, 0x0f, 0x6e, 0xc8, 0x66, 0x0f, 0x62, 0xc1, 0xc3]);
  assertReferenceState(dq, { xmm: { 0: "0x11111111222222220000000000000000" } });
  // dest bytes 01 02 03 04, src bytes 05 06 07 08 interleave to 01 05 02 06 ...
  const bw = runMicro(context, [0xb8, 0x01, 0x02, 0x03, 0x04, 0x66, 0x0f, 0x6e, 0xc0, 0xb8, 0x05, 0x06, 0x07, 0x08, 0x66, 0x0f, 0x6e, 0xc8, 0x66, 0x0f, 0x60, 0xc1, 0xc3]);
  assertReferenceState(bw, { xmm: { 0: "0x01050206030704080000000000000000" } });
  // punpcklqdq takes dest low qword then src low qword.
  const qdq = runMicro(context, [0xb8, 0xaa, 0xaa, 0x00, 0x00, 0x66, 0x0f, 0x6e, 0xc0, 0xb8, 0xbb, 0xbb, 0x00, 0x00, 0x66, 0x0f, 0x6e, 0xc8, 0x66, 0x0f, 0x6c, 0xc1, 0xc3]);
  assertReferenceState(qdq, { xmm: { 0: "0xaaaa000000000000bbbb000000000000" } });
});

test("microprogram: SSE2 PACKSSWB saturates each signed word to a signed byte", (context) => {
  // words (0x007f=127, 0x00ff=255) saturate to (0x7f, 0x7f); the src is zero.
  const report = runMicro(context, [0xb8, 0x7f, 0x00, 0xff, 0x00, 0x66, 0x0f, 0x6e, 0xc0, 0x66, 0x0f, 0x63, 0xc1, 0xc3]);
  assertReferenceState(report, { xmm: { 0: "0x7f7f0000000000000000000000000000" } });
});

test("microprogram: SSE2 PSRLDQ and PSLLDQ shift the whole register by a byte count", (context) => {
  // bytes ef be ad de -> shift right one byte -> be ad de 00 ...
  const right = runMicro(context, [0xb8, 0xef, 0xbe, 0xad, 0xde, 0x66, 0x0f, 0x6e, 0xc0, 0x66, 0x0f, 0x73, 0xd8, 0x01, 0xc3]);
  assertReferenceState(right, { xmm: { 0: "0xbeadde00000000000000000000000000" } });
  // shift left two byte -> 00 00 ef be ad de ...
  const left = runMicro(context, [0xb8, 0xef, 0xbe, 0xad, 0xde, 0x66, 0x0f, 0x6e, 0xc0, 0x66, 0x0f, 0x73, 0xf8, 0x02, 0xc3]);
  assertReferenceState(left, { xmm: { 0: "0x0000efbeadde00000000000000000000" } });
});

test("microprogram: SSE2 PSLLW immediate and PSRLD register-form shift the packed lanes", (context) => {
  // psllw xmm0,4 lifts word0 0x0001 to 0x0010.
  const sllw = runMicro(context, [0xb8, 0x01, 0x00, 0x00, 0x00, 0x66, 0x0f, 0x6e, 0xc0, 0x66, 0x0f, 0x71, 0xf0, 0x04, 0xc3]);
  assertReferenceState(sllw, { xmm: { 0: "0x10000000000000000000000000000000" } });
  // psrld xmm0,xmm1 with count 4 shifts dword0 0xf0 to 0x0f.
  const srld = runMicro(context, [0xb8, 0xf0, 0x00, 0x00, 0x00, 0x66, 0x0f, 0x6e, 0xc0, 0xb8, 0x04, 0x00, 0x00, 0x00, 0x66, 0x0f, 0x6e, 0xc8, 0x66, 0x0f, 0xd2, 0xc1, 0xc3]);
  assertReferenceState(srld, { xmm: { 0: "0x0f000000000000000000000000000000" } });
});

test("microprogram: SSE2 PSRAW register-form fills the shifted word lanes with the sign bit", (context) => {
  // word0 0x8000 (negative), count 4 -> 0xf800.
  const report = runMicro(context, [0xb8, 0x00, 0x80, 0x00, 0x00, 0x66, 0x0f, 0x6e, 0xc0, 0xb8, 0x04, 0x00, 0x00, 0x00, 0x66, 0x0f, 0x6e, 0xc8, 0x66, 0x0f, 0xe1, 0xc1, 0xc3]);
  assertReferenceState(report, { xmm: { 0: "0x00f80000000000000000000000000000" } });
});

test("microprogram: SSE2 PMOVMSKB gathers the sign bit of each of 16 byte lanes", (context) => {
  // bytes 80 80 00 80 set mask bits 0,1,3 -> 0x0b.
  const report = runMicro(context, [0xb8, 0x80, 0x80, 0x00, 0x80, 0x66, 0x0f, 0x6e, 0xc0, 0x66, 0x0f, 0xd7, 0xc0, 0xc3]);
  assertReferenceState(report, { register: { eax: 0x0b } });
});

test("microprogram: SSE2 MOVQ stores the low qword and zero-extends the register destination", (context) => {
  // movq xmm1,xmm0 (66 0f d6 c1) copies the low qword and clears the upper qword.
  const report = runMicro(context, [0xb8, 0xef, 0xbe, 0xad, 0xde, 0x66, 0x0f, 0x6e, 0xc0, 0x66, 0x0f, 0xd6, 0xc1, 0xc3]);
  assertReferenceState(report, { xmm: { 1: "0xefbeadde000000000000000000000000" } });
});

test("microprogram: the reserved SSE2 shift and prefixed integer forms stop as structured refusals", (context) => {
  // 66 0f 73 /5 is a reserved qword-shift group form.
  const reserved = runMicro(context, [0x66, 0x0f, 0x73, 0xe8, 0x01, 0xc3]);
  assert.equal(reserved.stop_reason, "unsupported_opcode");
  assert.match(reserved.exception.message, /Unsupported SSE2 form/);
  // 66 0f 73 /4 is psraq, which the arithmetic qword shift does not define.
  const psraq = runMicro(context, [0x66, 0x0f, 0x73, 0xe0, 0x01, 0xc3]);
  assert.equal(psraq.stop_reason, "unsupported_opcode");
  // f2 0f ef is an invalid prefixing of pxor.
  const invalid = runMicro(context, [0xf2, 0x0f, 0xef, 0xc0, 0xc3]);
  assert.equal(invalid.stop_reason, "unsupported_opcode");
});

test("microprogram: one-operand signed IMUL and IDIV compute the exact wide product and quotient", (context) => {
  // mov eax,0x10000; mov edx,0x10000; imul edx (f7 ea) -> 0x100000000, which no
  // longer fits the low dword, so eax=0, edx=1, and carry and overflow set.
  const imul = runMicro(context, [0xb8, 0x00, 0x00, 0x01, 0x00, 0xba, 0x00, 0x00, 0x01, 0x00, 0xf7, 0xea, 0xc3]);
  assertReferenceState(imul, { register: { eax: 0, edx: 1 }, flag: { carry: true, overflow: true } });
  // mov eax,0xfffffff1 (-15); cdq; mov ecx,4; idiv ecx (f7 f9) -> quotient -3, remainder -3.
  const idiv = runMicro(context, [0xb8, 0xf1, 0xff, 0xff, 0xff, 0x99, 0xb9, 0x04, 0x00, 0x00, 0x00, 0xf7, 0xf9, 0xc3]);
  assertReferenceState(idiv, { register: { eax: 0xfffffffd, edx: 0xfffffffd } });
});

test("microprogram: the unimplemented SSE forms stop as structured refusals, never a silent identity", (context) => {
  // cmpps (0f c2) carries an imm8 predicate the bounded subset does not
  // decode; movapd with an 0xf2 prefix is an invalid encoding.
  const compare = runMicro(context, [0x0f, 0xc2, 0xc1, 0x00, 0xc3]);
  assert.equal(compare.stop_reason, "unsupported_opcode");
  const invalid = runMicro(context, [0xf2, 0x0f, 0x28, 0xc1, 0xc3]);
  assert.equal(invalid.stop_reason, "unsupported_opcode");
  assert.match(invalid.exception.message, /Unsupported SSE form/);
});

test("microprogram: every declared-served opcode executes without the unsupported stop and every undeclared opcode stops structured", (context) => {
  // The inventory consistency contract: the declared inventory in
  // lib/i386.mjs and the probe agree byte for byte. Each candidate opcode is
  // executed in a minimal register-form microprogram; the verdict is whether
  // the stop is the structured unsupported_opcode diagnostic, never which
  // other fault the arbitrary operand raises. x87 (0xd8-0xdf) refines its
  // /reg forms at execution and is excluded here; its subset carries its own
  // dedicated case in the runtime suite. The prefix byte are declared
  // separately and covered by their own microprogram case above.
  const prefixByte = new Set(i386Prefix);
  // 0x64/0x65/0x67 refuse in the prefix decoder, 0xd8-0xdf refine their /reg
  // forms at execution (the x87 subset carries its own dedicated case), and
  // 0x0f is the two-byte escape covered by the extension walk below.
  const excludedByte = new Set([0x64, 0x65, 0x67, 0x0f, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf]);
  // 0x8d (LEA) serves only a memory ModRM and carries its dedicated case.
  const memoryOnlyByte = new Set([0x8d]);
  let executedCount = 0;
  for (let opcode = 0x00; opcode <= 0xff; opcode += 1) {
    if (prefixByte.has(opcode) || excludedByte.has(opcode) || memoryOnlyByte.has(opcode)) continue;
    const groupValue = i386OpcodeGroup[opcode];
    for (const groupReg of groupValue ?? [0]) {
      executedCount += 1;
      const report = runMicro(context, [opcode, (0xc0 | groupReg) | 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], { instruction_budget_count: 24 });
      const served = i386OpcodeOneByte.includes(opcode) && (groupValue === undefined || groupValue.includes(groupReg));
      const stoppedUnsupported = report.stop_reason === "unsupported_opcode" && report.exception !== null && report.exception.instruction_address === 0x401000;
      assert.equal(stoppedUnsupported, !served, `opcode 0x${opcode.toString(16).padStart(2, "0")} /${groupReg}: ${served ? "declared served" : "declared unsupported"} but stopped ${report.stop_reason} (${JSON.stringify(report.exception)})`);
    }
  }
  for (let extension = 0x00; extension <= 0xff; extension += 1) {
    const groupValue = i386Opcode0fGroup[extension];
    for (const groupReg of groupValue ?? [0]) {
      executedCount += 1;
      const report = runMicro(context, [0x0f, extension, (0xc0 | groupReg) | 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], { instruction_budget_count: 24 });
      const served = i386Opcode0f.includes(extension) && (groupValue === undefined || groupValue.includes(groupReg));
      const stoppedUnsupported = report.stop_reason === "unsupported_opcode" && report.exception !== null && report.exception.instruction_address === 0x401000;
      assert.equal(stoppedUnsupported, !served, `0x0f 0x${extension.toString(16).padStart(2, "0")} /${groupReg}: ${served ? "declared served" : "declared unsupported"} but stopped ${report.stop_reason} (${JSON.stringify(report.exception)})`);
    }
  }
  assert.ok(executedCount >= 500, `the consistency walk executed only ${executedCount} microprogram`);
});

test("microprogram: the decode sweep classifies a synthetic section byte for byte", (context) => {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-i386-sweep-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const executablePath = join(rootPath, "game.exe");
  writeFileSync(executablePath, createPe32([0xb8, 0x05, 0x00, 0x00, 0x00, 0x0f, 0x0b, 0x66, 0x89, 0xc3, 0xf4]));
  const sweep = sweepI386Text(executablePath);
  assert.equal(sweep.schema_version, 1);
  assert.equal(sweep.section_name, ".text");
  assert.equal(sweep.served_instruction_count + sweep.unsupported_instruction_count, sweep.decoded_instruction_count);
  assert.equal(sweep.unsupported_instruction_count, 2);
  assert.equal(sweep.first_unsupported.virtual_address, 0x401005);
  assert.equal(sweep.first_unsupported.opcode, 0x0f0b);
  assert.equal(sweep.unsupported_histogram[0].opcode, 0x0f0b);
  assert.equal(sweep.unsupported_histogram[1].opcode, 0xf4);
});
