// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// A bounded, pure x86-64 instruction decoder for runtime v2 (the front of the
// lifter, doc/runtime-v2-scope.md §2 "(C) lifter"). It decodes the common
// integer/branch/call subset of x86-64 — correct length and operands — and
// refuses everything else *honestly*: `is_served: false` with the raw opcode,
// never a wrong length or a silent guess. It executes nothing and touches no
// run surface; the IR lifter and WASM codegen milestones consume this.
//
// The single export decodeX64Instruction(bytes, offset) returns
//   { length, mnemonic, operand, is_served }
// with singular field names per the repository convention. `length` is always a
// bounded 1..15 byte count so a linear sweep can advance safely across a real
// `.text` section without crashing, even where the opcode is not served.

const MAX_INSTRUCTION_BYTE = 15; // the architectural maximum x86-64 instruction length

const GROUP1_NAME = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"];
const GROUP2_NAME = ["rol", "ror", "rcl", "rcr", "shl", "shr", "shl", "sar"];
const GROUP3_NAME = ["test", "test", "not", "neg", "mul", "imul", "div", "idiv"];
const CONDITION_NAME = ["o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l", "ge", "le", "g"];

const NAME8 = ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"];
const NAME8_LEGACY = ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"];
const NAME16 = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"];
const NAME32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"];
const NAME64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];

// A sentinel thrown when a needed byte lies past the buffer end; the top-level
// decoder catches it and returns a bounded, honestly-unserved result rather than
// reading out of range or crashing a linear sweep near a section boundary.
class TruncationError extends Error {}

function gprName(index, sizeBit, rexPresent) {
  if (sizeBit === 8) {
    if (!rexPresent && index >= 4 && index <= 7) return NAME8_LEGACY[index];
    return NAME8[index];
  }
  if (sizeBit === 16) return NAME16[index];
  if (sizeBit === 32) return NAME32[index];
  return NAME64[index];
}

function hex(value) {
  const magnitude = value < 0 ? -value : value;
  return `${value < 0 ? "-" : ""}0x${magnitude.toString(16)}`;
}

// A forward cursor over the byte buffer with bounded reads. Every read past the
// buffer end throws TruncationError so no decode ever reads out of range.
class Cursor {
  constructor(bytes, start) {
    this.bytes = bytes;
    this.start = start;
    this.pos = start;
  }

  get length() {
    return this.pos - this.start;
  }

  u8() {
    if (this.pos >= this.bytes.length) throw new TruncationError("byte past buffer end");
    return this.bytes[this.pos++];
  }

  i8() {
    return (this.u8() << 24) >> 24;
  }

  u16() {
    return this.u8() | (this.u8() << 8);
  }

  u32() {
    const value = this.u8() | (this.u8() << 8) | (this.u8() << 16) | (this.u8() << 24);
    return value >>> 0;
  }

  i32() {
    return this.u32() | 0;
  }

  u64() {
    const low = BigInt(this.u32());
    const high = BigInt(this.u32());
    return (high << 32n) | low;
  }
}

// Decodes the ModRM byte (already the cursor's next byte) plus any SIB and
// displacement, returning the register-field index, the r/m operand string, and
// the mod field. The r/m string uses `rmSizeBit` register naming when it is a
// direct register (mod=3) and address-size naming for memory bases and indexes.
function decodeModRM(cursor, rexR, rexX, rexB, rmSizeBit, addrBit, rexPresent) {
  const modrm = cursor.u8();
  const mod = modrm >> 6;
  const reg = ((modrm >> 3) & 7) | (rexR ? 8 : 0);
  const rmLow = modrm & 7;

  if (mod === 3) {
    return { mod, reg, rmText: gprName(rmLow | (rexB ? 8 : 0), rmSizeBit, rexPresent) };
  }

  // RIP-relative: mod=00, rm=101 (before REX.B). A disp32 relative to the next
  // instruction — the defining x86-64 addressing mode.
  if (mod === 0 && rmLow === 5) {
    const disp = cursor.i32();
    return { mod, reg, rmText: `[rip${disp < 0 ? "" : "+"}${hex(disp)}]` };
  }

  let base = null;
  let index = null;
  let scale = 1;
  let haveDisp = false;
  let dispIsAbsolute = false;

  if (rmLow === 4) {
    // SIB byte.
    const sib = cursor.u8();
    scale = 1 << (sib >> 6);
    const indexField = ((sib >> 3) & 7) | (rexX ? 8 : 0);
    const baseField = (sib & 7) | (rexB ? 8 : 0);
    if (indexField !== 4) index = gprName(indexField, addrBit, rexPresent); // index=100 → no index
    if ((sib & 7) === 5 && mod === 0) {
      // No base register; a bare disp32 (plus any index).
      dispIsAbsolute = true;
    } else {
      base = gprName(baseField, addrBit, rexPresent);
    }
  } else {
    base = gprName(rmLow | (rexB ? 8 : 0), addrBit, rexPresent);
  }

  let disp = 0;
  if (mod === 1) {
    disp = cursor.i8();
    haveDisp = true;
  } else if (mod === 2 || dispIsAbsolute) {
    disp = cursor.i32();
    haveDisp = true;
  }

  let inner = "";
  if (base !== null) inner += base;
  if (index !== null) inner += `${inner ? "+" : ""}${index}${scale > 1 ? `*${scale}` : ""}`;
  if (haveDisp && (disp !== 0 || inner === "")) {
    inner += `${inner && disp >= 0 ? "+" : ""}${hex(disp)}`;
  }
  return { mod, reg, rmText: `[${inner}]` };
}

// Decodes one instruction. Returns null when the opcode is outside the served
// subset, so the caller can attach the raw opcode to an honest refusal.
function decodeServed(cursor, state) {
  const { rexW, rexR, rexX, rexB, has66, rexPresent } = state;
  const addrBit = state.has67 ? 32 : 64;
  const opBit = rexW ? 64 : has66 ? 16 : 32;
  const stackBit = has66 ? 16 : 64; // push/pop/call default to 64-bit operand size
  const izByte = opBit === 16 ? 2 : 4; // Iz: imm16 for 16-bit operand size, else imm32

  const opcode = cursor.u8();

  const arith = (formName, direction, sizeBit) => {
    const info = decodeModRM(cursor, rexR, rexX, rexB, sizeBit, addrBit, rexPresent);
    const regText = gprName(info.reg, sizeBit, rexPresent);
    const operand = direction === "eg" ? `${info.rmText}, ${regText}` : `${regText}, ${info.rmText}`;
    return { mnemonic: formName, operand };
  };

  // The 0x00–0x3D arithmetic grid: eight operations, six encodings each.
  if (opcode <= 0x3d && (opcode & 7) <= 5 && (opcode >> 3) <= 7) {
    const name = GROUP1_NAME[opcode >> 3];
    const column = opcode & 7;
    if (column === 0) return arith(name, "eg", 8);
    if (column === 1) return arith(name, "eg", opBit);
    if (column === 2) return arith(name, "ge", 8);
    if (column === 3) return arith(name, "ge", opBit);
    if (column === 4) return { mnemonic: name, operand: `al, ${hex(cursor.u8())}` };
    if (column === 5) {
      const imm = izByte === 2 ? cursor.u16() : cursor.u32();
      return { mnemonic: name, operand: `${gprName(0, opBit, rexPresent)}, ${hex(imm)}` };
    }
  }

  // 0x50–0x57 PUSH r64 / 0x58–0x5F POP r64.
  if (opcode >= 0x50 && opcode <= 0x5f) {
    const reg = (opcode & 7) | (rexB ? 8 : 0);
    return { mnemonic: opcode < 0x58 ? "push" : "pop", operand: gprName(reg, stackBit, rexPresent) };
  }

  if (opcode === 0x63) {
    // MOVSXD Gv, Ev — the x86-64 sign-extending load (movslq).
    const info = decodeModRM(cursor, rexR, rexX, rexB, 32, addrBit, rexPresent);
    return { mnemonic: "movsxd", operand: `${gprName(info.reg, opBit, rexPresent)}, ${info.rmText}` };
  }

  if (opcode === 0x68) return { mnemonic: "push", operand: hex(izByte === 2 ? cursor.u16() : cursor.i32()) };
  if (opcode === 0x6a) return { mnemonic: "push", operand: hex(cursor.i8()) };

  if (opcode === 0x69 || opcode === 0x6b) {
    // IMUL Gv, Ev, Iz/Ib.
    const info = decodeModRM(cursor, rexR, rexX, rexB, opBit, addrBit, rexPresent);
    const imm = opcode === 0x6b ? cursor.i8() : izByte === 2 ? cursor.u16() : cursor.i32();
    return { mnemonic: "imul", operand: `${gprName(info.reg, opBit, rexPresent)}, ${info.rmText}, ${hex(imm)}` };
  }

  // 0x70–0x7F Jcc rel8.
  if (opcode >= 0x70 && opcode <= 0x7f) {
    const disp = cursor.i8();
    return { mnemonic: `j${CONDITION_NAME[opcode - 0x70]}`, operand: hex(disp) };
  }

  // 0x80/0x81/0x83 group 1: immediate arithmetic.
  if (opcode === 0x80 || opcode === 0x81 || opcode === 0x83) {
    const sizeBit = opcode === 0x80 ? 8 : opBit;
    const info = decodeModRM(cursor, rexR, rexX, rexB, sizeBit, addrBit, rexPresent);
    const name = GROUP1_NAME[info.reg & 7];
    let imm;
    if (opcode === 0x80 || opcode === 0x83) imm = opcode === 0x80 ? cursor.u8() : cursor.i8();
    else imm = izByte === 2 ? cursor.u16() : cursor.i32();
    return { mnemonic: name, operand: `${info.rmText}, ${hex(imm)}` };
  }

  // 0x84/0x85 TEST E,G.
  if (opcode === 0x84 || opcode === 0x85) return arith("test", "eg", opcode === 0x84 ? 8 : opBit);

  // 0x88–0x8B MOV.
  if (opcode === 0x88) return arith("mov", "eg", 8);
  if (opcode === 0x89) return arith("mov", "eg", opBit);
  if (opcode === 0x8a) return arith("mov", "ge", 8);
  if (opcode === 0x8b) return arith("mov", "ge", opBit);

  if (opcode === 0x8d) {
    // LEA Gv, M — the reg field is the destination; the r/m is always memory.
    const info = decodeModRM(cursor, rexR, rexX, rexB, opBit, addrBit, rexPresent);
    if (info.mod === 3) return null; // LEA with a register source is illegal
    return { mnemonic: "lea", operand: `${gprName(info.reg, opBit, rexPresent)}, ${info.rmText}` };
  }

  if (opcode === 0x8f) {
    // group 1A: POP Ev (/0).
    const info = decodeModRM(cursor, rexR, rexX, rexB, stackBit, addrBit, rexPresent);
    if ((info.reg & 7) !== 0) return null;
    return { mnemonic: "pop", operand: info.rmText };
  }

  if (opcode === 0x90) return { mnemonic: state.hasF3 ? "pause" : "nop", operand: "" };

  // 0xA8/0xA9 TEST AL/eAX, imm.
  if (opcode === 0xa8) return { mnemonic: "test", operand: `al, ${hex(cursor.u8())}` };
  if (opcode === 0xa9) return { mnemonic: "test", operand: `${gprName(0, opBit, rexPresent)}, ${hex(izByte === 2 ? cursor.u16() : cursor.u32())}` };

  // 0xB0–0xB7 MOV r8, Ib.
  if (opcode >= 0xb0 && opcode <= 0xb7) {
    const reg = (opcode & 7) | (rexB ? 8 : 0);
    return { mnemonic: "mov", operand: `${gprName(reg, 8, rexPresent)}, ${hex(cursor.u8())}` };
  }

  // 0xB8–0xBF MOV r16/32/64, Iv (imm64 when REX.W).
  if (opcode >= 0xb8 && opcode <= 0xbf) {
    const reg = (opcode & 7) | (rexB ? 8 : 0);
    const imm = opBit === 16 ? cursor.u16() : rexW ? cursor.u64() : cursor.u32();
    const immText = typeof imm === "bigint" ? `0x${imm.toString(16)}` : hex(imm);
    return { mnemonic: "mov", operand: `${gprName(reg, opBit, rexPresent)}, ${immText}` };
  }

  // 0xC0/0xC1 group 2 shift by Ib; 0xD0/0xD1 by 1; 0xD2/0xD3 by CL.
  if (opcode === 0xc0 || opcode === 0xc1 || (opcode >= 0xd0 && opcode <= 0xd3)) {
    const sizeBit = opcode === 0xc0 || opcode === 0xd0 || opcode === 0xd2 ? 8 : opBit;
    const info = decodeModRM(cursor, rexR, rexX, rexB, sizeBit, addrBit, rexPresent);
    const name = GROUP2_NAME[info.reg & 7];
    let amount;
    if (opcode === 0xc0 || opcode === 0xc1) amount = hex(cursor.u8());
    else if (opcode === 0xd0 || opcode === 0xd1) amount = "1";
    else amount = "cl";
    return { mnemonic: name, operand: `${info.rmText}, ${amount}` };
  }

  if (opcode === 0xc2) return { mnemonic: "ret", operand: hex(cursor.u16()) };
  if (opcode === 0xc3) return { mnemonic: "ret", operand: "" };

  // 0xC6/0xC7 group 11: MOV E, imm (/0).
  if (opcode === 0xc6 || opcode === 0xc7) {
    const sizeBit = opcode === 0xc6 ? 8 : opBit;
    const info = decodeModRM(cursor, rexR, rexX, rexB, sizeBit, addrBit, rexPresent);
    if ((info.reg & 7) !== 0) return null;
    const imm = opcode === 0xc6 ? cursor.u8() : izByte === 2 ? cursor.u16() : cursor.i32();
    return { mnemonic: "mov", operand: `${info.rmText}, ${hex(imm)}` };
  }

  if (opcode === 0xc9) return { mnemonic: "leave", operand: "" };

  if (opcode === 0xe8) return { mnemonic: "call", operand: hex(cursor.i32()) };
  if (opcode === 0xe9) return { mnemonic: "jmp", operand: hex(cursor.i32()) };
  if (opcode === 0xeb) return { mnemonic: "jmp", operand: hex(cursor.i8()) };

  // 0xF6/0xF7 group 3: TEST/NOT/NEG/MUL/IMUL/DIV/IDIV.
  if (opcode === 0xf6 || opcode === 0xf7) {
    const sizeBit = opcode === 0xf6 ? 8 : opBit;
    const info = decodeModRM(cursor, rexR, rexX, rexB, sizeBit, addrBit, rexPresent);
    const sub = info.reg & 7;
    const name = GROUP3_NAME[sub];
    if (sub <= 1) {
      const imm = opcode === 0xf6 ? cursor.u8() : izByte === 2 ? cursor.u16() : cursor.i32();
      return { mnemonic: name, operand: `${info.rmText}, ${hex(imm)}` };
    }
    return { mnemonic: name, operand: info.rmText };
  }

  // 0xFE group 4: INC/DEC Eb.
  if (opcode === 0xfe) {
    const info = decodeModRM(cursor, rexR, rexX, rexB, 8, addrBit, rexPresent);
    const sub = info.reg & 7;
    if (sub > 1) return null;
    return { mnemonic: sub === 0 ? "inc" : "dec", operand: info.rmText };
  }

  // 0xFF group 5: INC/DEC/CALL/JMP/PUSH.
  if (opcode === 0xff) {
    const sub = ((cursor.bytes[cursor.pos] ?? 0) >> 3) & 7;
    const sizeBit = sub === 0 || sub === 1 ? opBit : stackBit;
    const info = decodeModRM(cursor, rexR, rexX, rexB, sizeBit, addrBit, rexPresent);
    if (sub === 0) return { mnemonic: "inc", operand: info.rmText };
    if (sub === 1) return { mnemonic: "dec", operand: info.rmText };
    if (sub === 2) return { mnemonic: "call", operand: info.rmText };
    if (sub === 4) return { mnemonic: "jmp", operand: info.rmText };
    if (sub === 6) return { mnemonic: "push", operand: info.rmText };
    return null; // /3 far call, /5 far jmp: honestly unserved
  }

  if (opcode === 0x0f) return decodeTwoByte(cursor, state, addrBit, opBit);

  return null;
}

// Two-byte 0x0F opcodes: Jcc rel32, MOVZX/MOVSX, CMOVcc, SETcc, IMUL, NOP/ENDBR.
function decodeTwoByte(cursor, state, addrBit, opBit) {
  const { rexR, rexX, rexB, rexPresent } = state;
  const op2 = cursor.u8();

  const modrmForm = (mnemonic, rmSizeBit, regSizeBit) => {
    const info = decodeModRM(cursor, rexR, rexX, rexB, rmSizeBit, addrBit, rexPresent);
    return { mnemonic, operand: `${gprName(info.reg, regSizeBit, rexPresent)}, ${info.rmText}` };
  };

  // 0F 1E /7 FA = ENDBR64, /7 FB = ENDBR32 (with F3); otherwise a reserved hint.
  if (op2 === 0x1e) {
    const modrm = cursor.u8();
    if (state.hasF3 && modrm === 0xfa) return { mnemonic: "endbr64", operand: "" };
    if (state.hasF3 && modrm === 0xfb) return { mnemonic: "endbr32", operand: "" };
    return { mnemonic: "nop", operand: "" };
  }

  // 0F 1F /0 NOP Ev — the multi-byte alignment NOP.
  if (op2 === 0x1f) {
    const info = decodeModRM(cursor, rexR, rexX, rexB, opBit, addrBit, rexPresent);
    return { mnemonic: "nop", operand: info.rmText };
  }

  // 0F 40–4F CMOVcc Gv, Ev.
  if (op2 >= 0x40 && op2 <= 0x4f) return modrmForm(`cmov${CONDITION_NAME[op2 - 0x40]}`, opBit, opBit);

  // 0F 80–8F Jcc rel32.
  if (op2 >= 0x80 && op2 <= 0x8f) {
    const disp = cursor.i32();
    return { mnemonic: `j${CONDITION_NAME[op2 - 0x80]}`, operand: hex(disp) };
  }

  // 0F 90–9F SETcc Eb.
  if (op2 >= 0x90 && op2 <= 0x9f) {
    const info = decodeModRM(cursor, rexR, rexX, rexB, 8, addrBit, rexPresent);
    return { mnemonic: `set${CONDITION_NAME[op2 - 0x90]}`, operand: info.rmText };
  }

  if (op2 === 0xaf) return modrmForm("imul", opBit, opBit);

  if (op2 === 0xb6) return modrmForm("movzx", 8, opBit);
  if (op2 === 0xb7) return modrmForm("movzx", 16, opBit);
  if (op2 === 0xbe) return modrmForm("movsx", 8, opBit);
  if (op2 === 0xbf) return modrmForm("movsx", 16, opBit);

  // 0F A4/A5 SHLD and 0F AC/AD SHRD Ev, Gv, {imm8 | CL} — double shifts. The low
  // opcode of each pair carries an imm8 count; the high opcode counts in CL.
  if (op2 === 0xa4 || op2 === 0xa5 || op2 === 0xac || op2 === 0xad) {
    const mnemonic = op2 <= 0xa5 ? "shld" : "shrd";
    const info = decodeModRM(cursor, rexR, rexX, rexB, opBit, addrBit, rexPresent);
    const reg = gprName(info.reg, opBit, rexPresent);
    const count = (op2 === 0xa4 || op2 === 0xac) ? hex(cursor.u8()) : "cl";
    return { mnemonic, operand: `${info.rmText}, ${reg}, ${count}` };
  }

  return null;
}

// Decodes exactly one x86-64 instruction beginning at `offset` in `bytes`
// (a Buffer or Uint8Array). Returns { length, mnemonic, operand, is_served }:
//  - length: a bounded 1..15 byte count, always safe to advance a linear sweep
//    by, even for an unserved opcode (where it is the prefix+opcode span).
//  - mnemonic: the lowercase mnemonic, or "(unserved)" / "(truncated)".
//  - operand: the decoded operand string (Intel order, destination first).
//  - is_served: true only when the length AND operands are both correct.
export function decodeX64Instruction(bytes, offset = 0) {
  if (!bytes || typeof bytes.length !== "number") {
    throw new TypeError("decodeX64Instruction requires a byte buffer");
  }
  if (!Number.isInteger(offset) || offset < 0 || offset >= bytes.length) {
    throw new RangeError("decodeX64Instruction offset is outside the buffer");
  }

  const cursor = new Cursor(bytes, offset);
  const state = { has66: false, has67: false, hasF2: false, hasF3: false, hasLock: false, hasSegment: false, rexPresent: false, rexW: false, rexR: false, rexX: false, rexB: false };

  try {
    // Legacy prefixes, then at most one REX prefix immediately before the opcode.
    let prefixByte = bytes[cursor.pos];
    for (;;) {
      if (prefixByte === 0x66) state.has66 = true;
      else if (prefixByte === 0x67) state.has67 = true;
      else if (prefixByte === 0xf0) state.hasLock = true;
      else if (prefixByte === 0xf2) state.hasF2 = true;
      else if (prefixByte === 0xf3) state.hasF3 = true;
      else if (prefixByte === 0x2e || prefixByte === 0x36 || prefixByte === 0x3e || prefixByte === 0x26 || prefixByte === 0x64 || prefixByte === 0x65) state.hasSegment = true;
      else break;
      cursor.u8();
      prefixByte = bytes[cursor.pos];
      if (cursor.length >= MAX_INSTRUCTION_BYTE) throw new TruncationError("prefix run exceeds instruction bound");
    }
    if (prefixByte >= 0x40 && prefixByte <= 0x4f) {
      state.rexPresent = true;
      state.rexW = (prefixByte & 8) !== 0;
      state.rexR = (prefixByte & 4) !== 0;
      state.rexX = (prefixByte & 2) !== 0;
      state.rexB = (prefixByte & 1) !== 0;
      cursor.u8();
    }

    const opcodeStart = cursor.pos;
    const served = decodeServed(cursor, state);
    if (served && cursor.length <= MAX_INSTRUCTION_BYTE) {
      return { length: cursor.length, mnemonic: served.mnemonic, operand: served.operand, is_served: true };
    }

    // Unserved opcode: advance only the prefix+opcode span (never a guessed
    // operand length), bounded to at least one byte. Honest refusal.
    const rawOpcode = bytes[opcodeStart];
    const opcodeText = rawOpcode === 0x0f ? `0f ${(bytes[opcodeStart + 1] ?? 0).toString(16).padStart(2, "0")}` : rawOpcode.toString(16).padStart(2, "0");
    const consumed = Math.min(Math.max(cursor.length === 0 ? 1 : opcodeStart - offset + (rawOpcode === 0x0f ? 2 : 1), 1), MAX_INSTRUCTION_BYTE, bytes.length - offset);
    return { length: consumed, mnemonic: "(unserved)", operand: opcodeText, is_served: false };
  } catch (error) {
    if (error instanceof TruncationError) {
      const consumed = Math.min(Math.max(cursor.length, 1), bytes.length - offset);
      return { length: consumed, mnemonic: "(truncated)", operand: "", is_served: false };
    }
    throw error;
  }
}
