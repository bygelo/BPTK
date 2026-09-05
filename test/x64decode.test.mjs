// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { test } from "node:test";
import { decodeX64Instruction } from "../lib/x64decode.mjs";
import { mapPe64State } from "../lib/pe64.mjs";

// A staged, lawful (MIT) freeware x86-64 binary for the linear-sweep corpus.
const PLINK_PATH = "/Users/angelonrevelo/Code/bptk-corpus/stage/corpus-002/package/plink.exe";
const MAX_INSTRUCTION_BYTE_GUARD = 15; // stop the sweep a full instruction short of the section end

function decode(...byte) {
  return decodeX64Instruction(Uint8Array.from(byte), 0);
}

// Asserts exact length, mnemonic, operand, and served flag on a hand encoding.
function assertServed(byte, length, mnemonic, operand) {
  const result = decodeX64Instruction(Uint8Array.from(byte), 0);
  assert.equal(result.is_served, true, `expected served: ${mnemonic} ${operand}`);
  assert.equal(result.length, length, `length for ${mnemonic} ${operand}`);
  assert.equal(result.mnemonic, mnemonic, `mnemonic for ${operand}`);
  assert.equal(result.operand, operand, `operand for ${mnemonic}`);
}

test("decodes MOV register and memory forms with REX.W", () => {
  assertServed([0x48, 0x89, 0xe5], 3, "mov", "rbp, rsp"); // mov rbp, rsp
  assertServed([0x89, 0xd8], 2, "mov", "eax, ebx"); // 32-bit default operand size
  assertServed([0x88, 0xc1], 2, "mov", "cl, al"); // byte form (88 = MOV Eb,Gb)
  assertServed([0x8b, 0x03], 2, "mov", "eax, [rbx]"); // MOV Gv, Ev (memory source)
  assertServed([0x48, 0x89, 0x44, 0x24, 0x08], 5, "mov", "[rsp+0x8], rax"); // SIB + disp8
  assertServed([0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00], 7, "mov", "rax, 0x1"); // C7 /0 Iz
  assertServed([0xc6, 0x00, 0x2a], 3, "mov", "[rax], 0x2a"); // C6 /0 Ib
});

test("decodes MOV immediate-to-register including the imm64 form", () => {
  assertServed([0xb8, 0x04, 0x00, 0x00, 0x00], 5, "mov", "eax, 0x4"); // B8 imm32
  assertServed([0xb1, 0x0a], 2, "mov", "cl, 0xa"); // B0-B7 imm8
  assertServed([0x48, 0xb8, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00], 10, "mov", "rax, 0xdeadbeef"); // REX.W imm64
  assertServed([0x66, 0xb8, 0x34, 0x12], 4, "mov", "ax, 0x1234"); // 0x66 imm16
});

test("decodes the arithmetic grid across all six encodings", () => {
  assertServed([0x01, 0xd8], 2, "add", "eax, ebx"); // ADD Ev, Gv
  assertServed([0x03, 0x18], 2, "add", "ebx, [rax]"); // ADD Gv, Ev
  assertServed([0x00, 0xc1], 2, "add", "cl, al"); // ADD Eb, Gb
  assertServed([0x04, 0x05], 2, "add", "al, 0x5"); // ADD AL, Ib
  assertServed([0x05, 0x0a, 0x00, 0x00, 0x00], 5, "add", "eax, 0xa"); // ADD eAX, Iz
  assertServed([0x48, 0x29, 0xc3], 3, "sub", "rbx, rax"); // SUB Ev, Gv with REX.W
  assertServed([0x31, 0xc0], 2, "xor", "eax, eax"); // XOR
  assertServed([0x21, 0xd1], 2, "and", "ecx, edx"); // AND
  assertServed([0x09, 0xc8], 2, "or", "eax, ecx"); // OR
  assertServed([0x39, 0xd8], 2, "cmp", "eax, ebx"); // CMP
});

test("decodes the 0x80/0x81/0x83 immediate-group forms", () => {
  assertServed([0x48, 0x83, 0xec, 0x20], 4, "sub", "rsp, 0x20"); // group1 /5 Ib sign-extended
  assertServed([0x83, 0xc0, 0x01], 3, "add", "eax, 0x1"); // group1 /0 Ib
  assertServed([0x81, 0xe1, 0xff, 0x00, 0x00, 0x00], 6, "and", "ecx, 0xff"); // group1 /4 Iz
  assertServed([0x80, 0x38, 0x00], 3, "cmp", "[rax], 0x0"); // 0x80 /7 Ib on memory
});

test("decodes LEA including RIP-relative addressing", () => {
  assertServed([0x48, 0x8d, 0x05, 0x10, 0x00, 0x00, 0x00], 7, "lea", "rax, [rip+0x10]"); // RIP-relative disp32
  assertServed([0x48, 0x8d, 0x05, 0xf0, 0xff, 0xff, 0xff], 7, "lea", "rax, [rip-0x10]"); // negative RIP disp
  assertServed([0x48, 0x8d, 0x4c, 0x24, 0x08], 5, "lea", "rcx, [rsp+0x8]"); // SIB base+disp8
  assertServed([0x48, 0x8d, 0x04, 0x8b], 4, "lea", "rax, [rbx+rcx*4]"); // SIB scale/index
  const registerLea = decode(0x48, 0x8d, 0xc0); // LEA with a register source is illegal
  assert.equal(registerLea.is_served, false);
});

test("decodes PUSH and POP families", () => {
  assertServed([0x55], 1, "push", "rbp"); // PUSH r64
  assertServed([0x5d], 1, "pop", "rbp"); // POP r64
  assertServed([0x41, 0x57], 2, "push", "r15"); // REX.B extends the register
  assertServed([0x6a, 0x05], 2, "push", "0x5"); // PUSH Ib
  assertServed([0x68, 0x00, 0x01, 0x00, 0x00], 5, "push", "0x100"); // PUSH Iz
  assertServed([0xff, 0x30], 2, "push", "[rax]"); // FF /6 PUSH Ev
  assertServed([0x8f, 0x00], 2, "pop", "[rax]"); // 8F /0 POP Ev
});

test("decodes TEST forms", () => {
  assertServed([0x85, 0xc0], 2, "test", "eax, eax"); // TEST Ev, Gv
  assertServed([0x84, 0xc9], 2, "test", "cl, cl"); // TEST Eb, Gb
  assertServed([0xa8, 0x01], 2, "test", "al, 0x1"); // TEST AL, Ib
  assertServed([0xa9, 0xff, 0x00, 0x00, 0x00], 5, "test", "eax, 0xff"); // TEST eAX, Iz
  assertServed([0xf6, 0xc1, 0x03], 3, "test", "cl, 0x3"); // F6 /0 TEST Eb, Ib
});

test("decodes INC/DEC/CALL/JMP indirect groups", () => {
  assertServed([0xfe, 0xc0], 2, "inc", "al"); // FE /0 INC Eb
  assertServed([0xfe, 0xc9], 2, "dec", "cl"); // FE /1 DEC Eb
  assertServed([0x48, 0xff, 0xc0], 3, "inc", "rax"); // FF /0 INC Ev
  assertServed([0xff, 0xc9], 2, "dec", "ecx"); // FF /1 DEC Ev
  assertServed([0xff, 0xd0], 2, "call", "rax"); // FF /2 CALL Ev
  assertServed([0xff, 0x25, 0x00, 0x00, 0x00, 0x00], 6, "jmp", "[rip+0x0]"); // FF /4 JMP through IAT
});

test("decodes MOVZX/MOVSX/MOVSXD widening loads", () => {
  assertServed([0x0f, 0xb6, 0xc0], 3, "movzx", "eax, al"); // MOVZX Gv, Eb
  assertServed([0x0f, 0xb7, 0xc0], 3, "movzx", "eax, ax"); // MOVZX Gv, Ew
  assertServed([0x48, 0x0f, 0xbe, 0xc3], 4, "movsx", "rax, bl"); // MOVSX Gv, Eb (REX.W)
  assertServed([0x0f, 0xbf, 0xc3], 3, "movsx", "eax, bx"); // MOVSX Gv, Ew
  assertServed([0x48, 0x63, 0xc3], 3, "movsxd", "rax, ebx"); // MOVSXD (movslq)
});

test("decodes shift group 2 by imm, by one, and by CL", () => {
  assertServed([0x48, 0xc1, 0xe0, 0x04], 4, "shl", "rax, 0x4"); // C1 /4 Ib
  assertServed([0xd1, 0xf8], 2, "sar", "eax, 1"); // D1 /7 by 1
  assertServed([0x48, 0xd3, 0xe8], 3, "shr", "rax, cl"); // D3 /5 by CL
  assertServed([0xc0, 0xe1, 0x02], 3, "shl", "cl, 0x2"); // C0 /4 byte Ib
});

test("decodes the IMUL/MUL/DIV/IDIV group and NEG/NOT", () => {
  assertServed([0xf7, 0xe1], 2, "mul", "ecx"); // F7 /4 MUL
  assertServed([0x48, 0xf7, 0xf9], 3, "idiv", "rcx"); // F7 /7 IDIV with REX.W
  assertServed([0xf7, 0xf1], 2, "div", "ecx"); // F7 /6 DIV
  assertServed([0xf7, 0xd8], 2, "neg", "eax"); // F7 /3 NEG
  assertServed([0xf6, 0xd0], 2, "not", "al"); // F6 /2 NOT
  assertServed([0x0f, 0xaf, 0xc3], 3, "imul", "eax, ebx"); // two-operand IMUL
  assertServed([0x6b, 0xc3, 0x0a], 3, "imul", "eax, ebx, 0xa"); // IMUL Gv, Ev, Ib
});

test("decodes control-flow: CALL, JMP, Jcc, RET, LEAVE, NOP, ENDBR", () => {
  assertServed([0xe8, 0x00, 0x00, 0x00, 0x00], 5, "call", "0x0"); // CALL rel32
  assertServed([0xe9, 0x05, 0x00, 0x00, 0x00], 5, "jmp", "0x5"); // JMP rel32
  assertServed([0xeb, 0xfe], 2, "jmp", "-0x2"); // JMP rel8 (self)
  assertServed([0x74, 0x10], 2, "je", "0x10"); // JE rel8
  assertServed([0x0f, 0x85, 0x00, 0x01, 0x00, 0x00], 6, "jne", "0x100"); // JNE rel32
  assertServed([0xc3], 1, "ret", ""); // RET
  assertServed([0xc2, 0x08, 0x00], 3, "ret", "0x8"); // RET imm16
  assertServed([0xc9], 1, "leave", ""); // LEAVE
  assertServed([0x90], 1, "nop", ""); // NOP
  assertServed([0xf3, 0x0f, 0x1e, 0xfa], 4, "endbr64", ""); // ENDBR64
  assertServed([0x0f, 0x1f, 0x40, 0x00], 4, "nop", "[rax]"); // multi-byte NOP (disp8=0 present, length 4)
});

test("decodes CMOVcc and SETcc", () => {
  assertServed([0x48, 0x0f, 0x44, 0xc3], 4, "cmove", "rax, rbx"); // CMOVE
  assertServed([0x0f, 0x95, 0xc0], 3, "setne", "al"); // SETNE Eb
});

test("honors the 0x66 operand-size and 0x67 address-size prefixes", () => {
  assertServed([0x66, 0x01, 0xd8], 3, "add", "ax, bx"); // 16-bit operand size
  // 0x67 makes the base register 32-bit for the memory operand.
  assertServed([0x67, 0x8b, 0x00], 3, "mov", "eax, [eax]");
});

test("refuses an unserved opcode honestly with a bounded length", () => {
  // 0x0F 0x10 (MOVUPS) is outside the integer subset: no wrong length, no guess.
  const sse = decode(0x0f, 0x10, 0xc0);
  assert.equal(sse.is_served, false);
  assert.equal(sse.mnemonic, "(unserved)");
  assert.equal(sse.operand, "0f 10");
  assert.ok(sse.length >= 1 && sse.length <= 15);
  // A lone 0xF4 (HLT) is unserved but still advances at least one byte.
  const hlt = decode(0xf4);
  assert.equal(hlt.is_served, false);
  assert.ok(hlt.length >= 1);
});

test("never reads past the buffer end (truncation is bounded)", () => {
  // A REX.W + C7 with a missing immediate must not read out of range.
  const truncated = decode(0x48, 0xc7, 0xc0, 0x01);
  assert.equal(truncated.is_served, false);
  assert.ok(truncated.length >= 1 && truncated.length <= 4);
  // A bare prefix at the very end returns a bounded, unserved result.
  const bareRex = decode(0x48);
  assert.ok(bareRex.length >= 1);
  assert.equal(bareRex.is_served, false);
});

test("rejects an out-of-range offset argument", () => {
  assert.throws(() => decodeX64Instruction(Uint8Array.from([0x90]), 5), RangeError);
  assert.throws(() => decodeX64Instruction(null, 0), TypeError);
});

test("linear-sweeps a real x86-64 .text section with bounded lengths and a reported served fraction", () => {
  if (!existsSync(PLINK_PATH)) {
    // The staged corpus is a local, non-redistributable fixture; skip cleanly
    // where it is absent rather than fail the portable gate.
    console.log("x64decode sweep: staged plink.exe absent, skipping corpus sweep");
    return;
  }
  const state = mapPe64State(PLINK_PATH);
  assert.equal(state.machine, "x86_64");
  const text = state.section.find((entry) => entry.name === ".text");
  assert.ok(text, "the PE32+ image exposes a .text section");
  const sectionEnd = text.virtual_address + text.virtual_size_byte;

  let offset = state.entry_rva;
  assert.ok(offset >= text.virtual_address && offset < sectionEnd, "entry lies inside .text");

  const instructionBudget = 512;
  let served = 0;
  let total = 0;
  let maxLength = 0;
  while (total < instructionBudget && offset < sectionEnd - MAX_INSTRUCTION_BYTE_GUARD) {
    const result = decodeX64Instruction(state.image, offset);
    assert.ok(result.length >= 1 && result.length <= 15, `bounded length at rva 0x${offset.toString(16)}`);
    assert.ok(offset + result.length <= sectionEnd, "a decoded instruction stays within .text");
    if (result.is_served) served += 1;
    if (result.length > maxLength) maxLength = result.length;
    total += 1;
    offset += result.length;
  }

  assert.ok(total > 200, `swept a meaningful window (${total} instruction)`);
  const servedFraction = served / total;
  console.log(`x64decode sweep: ${served}/${total} served (${(servedFraction * 100).toFixed(1)}%) over plink.exe .text, max length ${maxLength} byte`);
  assert.ok(servedFraction > 0 && servedFraction <= 1, "served fraction is a proper ratio");
  // A real compiler-emitted prologue/leaf region is integer-heavy; a decoder
  // that genuinely reads it clears half. This is an honesty floor, not a claim
  // of full x86-64 coverage.
  assert.ok(servedFraction > 0.5, `served fraction ${servedFraction.toFixed(3)} clears the honesty floor`);
});
