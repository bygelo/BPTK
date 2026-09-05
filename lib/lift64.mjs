// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The x86-64 lifter spine and interpreter oracle for runtime v2 milestone M2
// (doc/runtime-v2-scope.md §2 "(C) lifter"). It does its OWN structured decode
// of the common integer/branch/call/stack subset — register index, operand
// size, memory {base,index,scale,disp,rip_relative}, immediate as BigInt —
// lifts each instruction to a small typed IR node (singular field: op, dst,
// src, src2, size), splits a run into basic blocks on branch/call/ret, and
// INTERPRETS that IR over a 16-entry 64-bit register file plus a flat guest
// memory to produce architectural state. That interpreter is the correctness
// ORACLE the WASM codegen milestone (M3) is validated against; NO WASM is
// emitted here and nothing outside this file is executed.
//
// lib/x64decode.mjs already decodes this subset, but returns `operand` as a
// RENDERED STRING — good for length and mnemonic class, not for lifting — so
// this file carries an independent structured decode. Anything outside the
// served subset lifts to an `unsupported` node naming the opcode: an honest
// structured refusal, never a wrong lift.
//
// EFLAGS are lazy: an ALU op records only the last flag-defining source (kind +
// masked inputs + result); the six architectural flags are materialized the
// moment a flag is read (a Jcc, a SETcc, a query), never eagerly on every op.

const MAX_INSTRUCTION_BYTE = 15;

const GROUP1_NAME = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"];
const GROUP2_NAME = ["rol", "ror", "rcl", "rcr", "shl", "shr", "shl", "sar"];
const GROUP3_NAME = ["test", "test", "not", "neg", "mul", "imul", "div", "idiv"];
const CONDITION_NAME = ["o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l", "ge", "le", "g"];

const MASK64 = (1n << 64n) - 1n;

class TruncationError extends Error {}

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

function sizeMask(sizeBit) {
  return (1n << BigInt(sizeBit)) - 1n;
}

function signBitOf(sizeBit) {
  return 1n << BigInt(sizeBit - 1);
}

// Sign-extends a BigInt occupying `fromBit` bits to a full signed BigInt.
function toSigned(value, fromBit) {
  const mask = sizeMask(fromBit);
  const v = value & mask;
  return (v & signBitOf(fromBit)) !== 0n ? v - (1n << BigInt(fromBit)) : v;
}

// A register operand. `high8` marks the legacy AH/CH/DH/BH byte lanes, which
// only appear for an 8-bit operand with no REX prefix.
function makeReg(index, sizeBit, rexPresent) {
  if (sizeBit === 8 && !rexPresent && index >= 4 && index <= 7) {
    return { kind: "reg", index: index - 4, size: 8, high8: true };
  }
  return { kind: "reg", index, size: sizeBit, high8: false };
}

// Decodes the ModRM byte plus any SIB and displacement into a structured
// register-field index and a structured r/m operand (a register or a memory
// reference), never a rendered string.
function decodeModRM(cursor, state, rmSizeBit) {
  const { rexR, rexX, rexB, rexPresent } = state;
  const modrm = cursor.u8();
  const mod = modrm >> 6;
  const reg = ((modrm >> 3) & 7) | (rexR ? 8 : 0);
  const rmLow = modrm & 7;

  if (mod === 3) {
    return { mod, reg, rm: makeReg(rmLow | (rexB ? 8 : 0), rmSizeBit, rexPresent) };
  }

  if (mod === 0 && rmLow === 5) {
    const disp = cursor.i32();
    return { mod, reg, rm: { kind: "mem", base: null, index: null, scale: 1, disp, rip_relative: true, size: rmSizeBit } };
  }

  let base = null;
  let index = null;
  let scale = 1;

  if (rmLow === 4) {
    const sib = cursor.u8();
    scale = 1 << (sib >> 6);
    const indexField = ((sib >> 3) & 7) | (rexX ? 8 : 0);
    const baseField = (sib & 7) | (rexB ? 8 : 0);
    if (indexField !== 4) index = indexField; // index=100 → no index register
    if ((sib & 7) === 5 && mod === 0) base = null; // no base; a bare disp32 (plus any index)
    else base = baseField;
  } else {
    base = rmLow | (rexB ? 8 : 0);
  }

  let disp = 0;
  if (mod === 1) disp = cursor.i8();
  else if (mod === 2 || (mod === 0 && base === null)) disp = cursor.i32();

  return { mod, reg, rm: { kind: "mem", base, index, scale, disp, rip_relative: false, size: rmSizeBit } };
}

// Lifts one served instruction to its IR node body. Returns null when the
// opcode is outside the subset, so the caller attaches an honest refusal.
function liftServed(cursor, state) {
  const { rexW, has66, rexB, rexPresent } = state;
  const opBit = rexW ? 64 : has66 ? 16 : 32;
  const stackBit = has66 ? 16 : 64;
  const izByte = opBit === 16 ? 2 : 4;

  const opcode = cursor.u8();

  const regOperand = (index, sizeBit) => makeReg(index, sizeBit, rexPresent);

  const arith = (aluOp, direction, sizeBit) => {
    const info = decodeModRM(cursor, state, sizeBit);
    const regOp = regOperand(info.reg, sizeBit);
    const writeBack = aluOp !== "cmp" && aluOp !== "test";
    if (direction === "eg") return { op: "alu", aluOp, mnemonic: aluOp, size: sizeBit, dst: info.rm, src: regOp, writeBack };
    return { op: "alu", aluOp, mnemonic: aluOp, size: sizeBit, dst: regOp, src: info.rm, writeBack };
  };

  const imm = (widthByte) => {
    if (widthByte === 1) return BigInt(cursor.u8());
    if (widthByte === 2) return BigInt(cursor.u16());
    return BigInt(cursor.u32());
  };

  // 0x00–0x3D arithmetic grid.
  if (opcode <= 0x3d && (opcode & 7) <= 5 && (opcode >> 3) <= 7) {
    const name = GROUP1_NAME[opcode >> 3];
    const column = opcode & 7;
    const writeBack = name !== "cmp";
    if (column === 0) return arith(name, "eg", 8);
    if (column === 1) return arith(name, "eg", opBit);
    if (column === 2) return arith(name, "ge", 8);
    if (column === 3) return arith(name, "ge", opBit);
    if (column === 4) return { op: "alu", aluOp: name, mnemonic: name, size: 8, dst: regOperand(0, 8), src: { kind: "imm", value: imm(1), size: 8 }, writeBack };
    if (column === 5) {
      const value = izByte === 2 ? imm(2) : toSigned(imm(4), 32) & sizeMask(opBit);
      return { op: "alu", aluOp: name, mnemonic: name, size: opBit, dst: regOperand(0, opBit), src: { kind: "imm", value, size: opBit }, writeBack };
    }
  }

  // 0x50–0x57 PUSH / 0x58–0x5F POP.
  if (opcode >= 0x50 && opcode <= 0x5f) {
    const index = (opcode & 7) | (rexB ? 8 : 0);
    if (opcode < 0x58) return { op: "push", mnemonic: "push", size: stackBit, src: regOperand(index, stackBit) };
    return { op: "pop", mnemonic: "pop", size: stackBit, dst: regOperand(index, stackBit) };
  }

  if (opcode === 0x63) {
    // MOVSXD Gv, Ev — sign-extend a 32-bit source into the destination.
    const info = decodeModRM(cursor, state, 32);
    return { op: "movsxd", mnemonic: "movsxd", size: opBit, dst: regOperand(info.reg, opBit), src: info.rm };
  }

  if (opcode === 0x68) {
    const value = izByte === 2 ? imm(2) : toSigned(imm(4), 32) & MASK64;
    return { op: "push", mnemonic: "push", size: stackBit, src: { kind: "imm", value, size: stackBit } };
  }
  if (opcode === 0x6a) return { op: "push", mnemonic: "push", size: stackBit, src: { kind: "imm", value: BigInt(cursor.i8()) & MASK64, size: stackBit } };

  if (opcode === 0x69 || opcode === 0x6b) {
    const info = decodeModRM(cursor, state, opBit);
    const immValue = opcode === 0x6b ? BigInt(cursor.i8()) : izByte === 2 ? BigInt(cursor.u16()) : BigInt(cursor.i32());
    return { op: "imul3", mnemonic: "imul", size: opBit, dst: regOperand(info.reg, opBit), src: info.rm, src2: { kind: "imm", value: immValue & sizeMask(opBit), size: opBit } };
  }

  // 0x70–0x7F Jcc rel8.
  if (opcode >= 0x70 && opcode <= 0x7f) {
    const rel = BigInt(cursor.i8());
    return { op: "jcc", mnemonic: `j${CONDITION_NAME[opcode - 0x70]}`, cc: opcode - 0x70, rel, control: "jcc" };
  }

  // 0x80/0x81/0x83 group 1 immediate arithmetic.
  if (opcode === 0x80 || opcode === 0x81 || opcode === 0x83) {
    const sizeBit = opcode === 0x80 ? 8 : opBit;
    const info = decodeModRM(cursor, state, sizeBit);
    const name = GROUP1_NAME[info.reg & 7];
    let value;
    if (opcode === 0x80) value = imm(1);
    else if (opcode === 0x83) value = toSigned(BigInt(cursor.u8()), 8) & sizeMask(sizeBit);
    else value = (izByte === 2 ? BigInt(cursor.u16()) : toSigned(imm(4), 32)) & sizeMask(sizeBit);
    return { op: "alu", aluOp: name, mnemonic: name, size: sizeBit, dst: info.rm, src: { kind: "imm", value, size: sizeBit }, writeBack: name !== "cmp" };
  }

  // 0x84/0x85 TEST.
  if (opcode === 0x84 || opcode === 0x85) return arith("test", "eg", opcode === 0x84 ? 8 : opBit);

  // 0x88–0x8B MOV.
  if (opcode === 0x88) return movForm(cursor, state, "eg", 8);
  if (opcode === 0x89) return movForm(cursor, state, "eg", opBit);
  if (opcode === 0x8a) return movForm(cursor, state, "ge", 8);
  if (opcode === 0x8b) return movForm(cursor, state, "ge", opBit);

  if (opcode === 0x8d) {
    const info = decodeModRM(cursor, state, opBit);
    if (info.rm.kind !== "mem") return null; // LEA with a register source is illegal
    return { op: "lea", mnemonic: "lea", size: opBit, dst: regOperand(info.reg, opBit), src: info.rm };
  }

  if (opcode === 0x8f) {
    const info = decodeModRM(cursor, state, stackBit);
    if ((info.reg & 7) !== 0) return null;
    return { op: "pop", mnemonic: "pop", size: stackBit, dst: info.rm };
  }

  if (opcode === 0x90) return { op: "nop", mnemonic: state.hasF3 ? "pause" : "nop" };

  if (opcode === 0xa8) return { op: "alu", aluOp: "test", mnemonic: "test", size: 8, dst: regOperand(0, 8), src: { kind: "imm", value: imm(1), size: 8 }, writeBack: false };
  if (opcode === 0xa9) {
    const value = izByte === 2 ? imm(2) : imm(4);
    return { op: "alu", aluOp: "test", mnemonic: "test", size: opBit, dst: regOperand(0, opBit), src: { kind: "imm", value, size: opBit }, writeBack: false };
  }

  // 0xB0–0xB7 MOV r8, Ib.
  if (opcode >= 0xb0 && opcode <= 0xb7) {
    const index = (opcode & 7) | (rexB ? 8 : 0);
    return { op: "mov", mnemonic: "mov", size: 8, dst: regOperand(index, 8), src: { kind: "imm", value: imm(1), size: 8 } };
  }

  // 0xB8–0xBF MOV r16/32/64, Iv (imm64 under REX.W).
  if (opcode >= 0xb8 && opcode <= 0xbf) {
    const index = (opcode & 7) | (rexB ? 8 : 0);
    const value = opBit === 16 ? imm(2) : rexW ? cursor.u64() : imm(4);
    return { op: "mov", mnemonic: "mov", size: opBit, dst: regOperand(index, opBit), src: { kind: "imm", value, size: opBit } };
  }

  // 0xC0/0xC1 shift by Ib; 0xD0/0xD1 by 1; 0xD2/0xD3 by CL.
  if (opcode === 0xc0 || opcode === 0xc1 || (opcode >= 0xd0 && opcode <= 0xd3)) {
    const sizeBit = opcode === 0xc0 || opcode === 0xd0 || opcode === 0xd2 ? 8 : opBit;
    const info = decodeModRM(cursor, state, sizeBit);
    const name = GROUP2_NAME[info.reg & 7];
    let count;
    if (opcode === 0xc0 || opcode === 0xc1) count = { kind: "imm", value: BigInt(cursor.u8()), size: 8 };
    else if (opcode === 0xd0 || opcode === 0xd1) count = { kind: "imm", value: 1n, size: 8 };
    else count = { kind: "reg", index: 1, size: 8, high8: false }; // CL
    return { op: "shift", shiftOp: name, mnemonic: name, size: sizeBit, dst: info.rm, src: count };
  }

  if (opcode === 0xc2) return { op: "ret", mnemonic: "ret", control: "ret", pop: cursor.u16() };
  if (opcode === 0xc3) return { op: "ret", mnemonic: "ret", control: "ret", pop: 0 };

  // 0xC6/0xC7 group 11 MOV E, imm (/0).
  if (opcode === 0xc6 || opcode === 0xc7) {
    const sizeBit = opcode === 0xc6 ? 8 : opBit;
    const info = decodeModRM(cursor, state, sizeBit);
    if ((info.reg & 7) !== 0) return null;
    const value = opcode === 0xc6 ? imm(1) : (izByte === 2 ? BigInt(cursor.u16()) : toSigned(imm(4), 32) & sizeMask(sizeBit));
    return { op: "mov", mnemonic: "mov", size: sizeBit, dst: info.rm, src: { kind: "imm", value, size: sizeBit } };
  }

  if (opcode === 0xc9) return { op: "leave", mnemonic: "leave", control: "leave" };

  if (opcode === 0xe8) return { op: "call", mnemonic: "call", control: "call", rel: BigInt(cursor.i32()) };
  if (opcode === 0xe9) return { op: "jmp", mnemonic: "jmp", control: "jmp", rel: BigInt(cursor.i32()) };
  if (opcode === 0xeb) return { op: "jmp", mnemonic: "jmp", control: "jmp", rel: BigInt(cursor.i8()) };

  // 0xF6/0xF7 group 3.
  if (opcode === 0xf6 || opcode === 0xf7) {
    const sizeBit = opcode === 0xf6 ? 8 : opBit;
    const info = decodeModRM(cursor, state, sizeBit);
    const sub = info.reg & 7;
    const name = GROUP3_NAME[sub];
    if (sub <= 1) {
      const value = opcode === 0xf6 ? imm(1) : (izByte === 2 ? BigInt(cursor.u16()) : toSigned(imm(4), 32) & sizeMask(sizeBit));
      return { op: "alu", aluOp: "test", mnemonic: "test", size: sizeBit, dst: info.rm, src: { kind: "imm", value, size: sizeBit }, writeBack: false };
    }
    if (name === "not" || name === "neg") return { op: name, mnemonic: name, size: sizeBit, dst: info.rm };
    return { op: name, mnemonic: name, size: sizeBit, src: info.rm }; // mul/imul/div/idiv one-operand
  }

  // 0xFE group 4 INC/DEC Eb.
  if (opcode === 0xfe) {
    const info = decodeModRM(cursor, state, 8);
    const sub = info.reg & 7;
    if (sub > 1) return null;
    return { op: sub === 0 ? "inc" : "dec", mnemonic: sub === 0 ? "inc" : "dec", size: 8, dst: info.rm };
  }

  // 0xFF group 5 INC/DEC/CALL/JMP/PUSH.
  if (opcode === 0xff) {
    const sub = ((cursor.bytes[cursor.pos] ?? 0) >> 3) & 7;
    const sizeBit = sub === 0 || sub === 1 ? opBit : stackBit;
    const info = decodeModRM(cursor, state, sizeBit);
    if (sub === 0) return { op: "inc", mnemonic: "inc", size: sizeBit, dst: info.rm };
    if (sub === 1) return { op: "dec", mnemonic: "dec", size: sizeBit, dst: info.rm };
    if (sub === 2) return { op: "callIndirect", mnemonic: "call", control: "callIndirect", size: stackBit, src: info.rm };
    if (sub === 4) return { op: "jmpIndirect", mnemonic: "jmp", control: "jmpIndirect", size: stackBit, src: info.rm };
    if (sub === 6) return { op: "push", mnemonic: "push", size: stackBit, src: info.rm };
    return null;
  }

  if (opcode === 0x0f) return liftTwoByte(cursor, state, opBit);

  return null;
}

function movForm(cursor, state, direction, sizeBit) {
  const info = decodeModRM(cursor, state, sizeBit);
  const regOp = makeReg(info.reg, sizeBit, state.rexPresent);
  if (direction === "eg") return { op: "mov", mnemonic: "mov", size: sizeBit, dst: info.rm, src: regOp };
  return { op: "mov", mnemonic: "mov", size: sizeBit, dst: regOp, src: info.rm };
}

function liftTwoByte(cursor, state, opBit) {
  const op2 = cursor.u8();

  const modrmForm = (op, mnemonic, rmSizeBit, regSizeBit, extra) => {
    const info = decodeModRM(cursor, state, rmSizeBit);
    return { op, mnemonic, size: regSizeBit, srcSize: rmSizeBit, dst: makeReg(info.reg, regSizeBit, state.rexPresent), src: info.rm, ...extra };
  };

  if (op2 === 0x1e) {
    const modrm = cursor.u8();
    if (state.hasF3 && (modrm === 0xfa || modrm === 0xfb)) return { op: "nop", mnemonic: modrm === 0xfa ? "endbr64" : "endbr32" };
    return { op: "nop", mnemonic: "nop" };
  }

  if (op2 === 0x1f) {
    decodeModRM(cursor, state, opBit);
    return { op: "nop", mnemonic: "nop" };
  }

  // 0F 40–4F CMOVcc Gv, Ev.
  if (op2 >= 0x40 && op2 <= 0x4f) {
    const info = decodeModRM(cursor, state, opBit);
    return { op: "cmovcc", mnemonic: `cmov${CONDITION_NAME[op2 - 0x40]}`, cc: op2 - 0x40, size: opBit, dst: makeReg(info.reg, opBit, state.rexPresent), src: info.rm };
  }

  // 0F 80–8F Jcc rel32.
  if (op2 >= 0x80 && op2 <= 0x8f) {
    const rel = BigInt(cursor.i32());
    return { op: "jcc", mnemonic: `j${CONDITION_NAME[op2 - 0x80]}`, cc: op2 - 0x80, rel, control: "jcc" };
  }

  // 0F 90–9F SETcc Eb.
  if (op2 >= 0x90 && op2 <= 0x9f) {
    const info = decodeModRM(cursor, state, 8);
    return { op: "setcc", mnemonic: `set${CONDITION_NAME[op2 - 0x90]}`, cc: op2 - 0x90, size: 8, dst: info.rm };
  }

  if (op2 === 0xaf) return modrmForm("imul2", "imul", opBit, opBit);

  if (op2 === 0xb6) return modrmForm("movzx", "movzx", 8, opBit);
  if (op2 === 0xb7) return modrmForm("movzx", "movzx", 16, opBit);
  if (op2 === 0xbe) return modrmForm("movsx", "movsx", 8, opBit);
  if (op2 === 0xbf) return modrmForm("movsx", "movsx", 16, opBit);

  return null;
}

// Decodes and lifts exactly one instruction beginning at `offset` in `bytes`.
// Returns an IR node: a served node carries op/size/dst/src/…; an unsupported
// node carries { op: "unsupported", opcode, mnemonic }. `length` is always a
// bounded 1..15 byte count safe to advance a linear sweep by. `served` is true
// only when the whole instruction is lifted (decode is correct end to end).
export function decodeStructured(bytes, offset = 0) {
  if (!bytes || typeof bytes.length !== "number") throw new TypeError("decodeStructured requires a byte buffer");
  if (!Number.isInteger(offset) || offset < 0 || offset >= bytes.length) throw new RangeError("decodeStructured offset is outside the buffer");

  const cursor = new Cursor(bytes, offset);
  const state = { has66: false, has67: false, hasF2: false, hasF3: false, hasLock: false, hasSegment: false, rexPresent: false, rexW: false, rexR: false, rexX: false, rexB: false };

  try {
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
    const body = state.hasSegment || state.hasF2 ? null : liftServed(cursor, state);
    if (body && cursor.length <= MAX_INSTRUCTION_BYTE) {
      return { ...body, length: cursor.length, served: true, control: body.control ?? "none" };
    }

    const rawOpcode = bytes[opcodeStart];
    const opcodeText = rawOpcode === 0x0f ? `0f${(bytes[opcodeStart + 1] ?? 0).toString(16).padStart(2, "0")}` : rawOpcode.toString(16).padStart(2, "0");
    const consumed = Math.min(Math.max(cursor.length === 0 ? 1 : opcodeStart - offset + (rawOpcode === 0x0f ? 2 : 1), 1), MAX_INSTRUCTION_BYTE, bytes.length - offset);
    return { op: "unsupported", mnemonic: "(unsupported)", opcode: rawOpcode === 0x0f ? 0x0f00 | (bytes[opcodeStart + 1] ?? 0) : rawOpcode, opcodeText, length: consumed, served: false, control: "none" };
  } catch (error) {
    if (error instanceof TruncationError) {
      const consumed = Math.min(Math.max(cursor.length, 1), bytes.length - offset);
      return { op: "truncated", mnemonic: "(truncated)", length: consumed, served: false, control: "none" };
    }
    throw error;
  }
}

// Lifts a straight-line run starting at `startRva` into one basic block: a node
// list terminated by the first control-transfer node (branch, call, ret, leave)
// or by an unsupported/truncated node. Splitting on control flow is what makes
// the IR a basic-block graph rather than a flat stream.
export function liftBlock(bytes, startRva, budget = 4096) {
  const node = [];
  let offset = startRva;
  for (let guard = 0; guard < budget && offset < bytes.length; guard += 1) {
    const decoded = decodeStructured(bytes, offset);
    const withAddress = { ...decoded, address: offset };
    node.push(withAddress);
    offset += decoded.length;
    if (decoded.control !== "none" || !decoded.served) break;
  }
  return { start_rva: startRva, node, terminator: node.length > 0 ? node[node.length - 1].control : "none" };
}

// -------------------- interpreter oracle --------------------

function parityEven(value) {
  let b = Number(value & 0xffn);
  b ^= b >> 4;
  b ^= b >> 2;
  b ^= b >> 1;
  return (b & 1) === 0;
}

// Materializes the six architectural flags from the recorded flag source. This
// runs only when a flag is actually read — the lazy-EFLAGS contract.
function materializeFlag(flag) {
  if (!flag) return { cf: false, pf: true, af: false, zf: true, sf: false, of: false };
  if (flag.kind === "explicit") return flag.value;
  const size = flag.size;
  const mask = sizeMask(size);
  const sign = signBitOf(size);
  const r = flag.result & mask;
  const zf = r === 0n;
  const sf = (r & sign) !== 0n;
  const pf = parityEven(r);
  const a = flag.a & mask;
  if (flag.kind === "logic") return { cf: false, pf, af: false, zf, sf, of: false };
  if (flag.kind === "add") {
    const b = flag.b & mask;
    const cin = flag.cin ?? 0n;
    const full = a + b + cin;
    return { cf: (full >> BigInt(size)) !== 0n, pf, af: ((a ^ b ^ r) & 0x10n) !== 0n, zf, sf, of: (((a ^ r) & (b ^ r)) & sign) !== 0n };
  }
  if (flag.kind === "sub") {
    const b = flag.b & mask;
    const cin = flag.cin ?? 0n;
    return { cf: a < b + cin, pf, af: ((a ^ b ^ r) & 0x10n) !== 0n, zf, sf, of: (((a ^ b) & (a ^ r)) & sign) !== 0n };
  }
  if (flag.kind === "inc") return { cf: flag.cfKeep, pf, af: ((a ^ 1n ^ r) & 0x10n) !== 0n, zf, sf, of: (((a ^ r) & (1n ^ r)) & sign) !== 0n };
  if (flag.kind === "dec") return { cf: flag.cfKeep, pf, af: ((a ^ 1n ^ r) & 0x10n) !== 0n, zf, sf, of: (((a ^ 1n) & (a ^ r)) & sign) !== 0n };
  return { cf: false, pf, af: false, zf, sf, of: false };
}

function conditionHolds(cc, f) {
  switch (cc) {
    case 0: return f.of;
    case 1: return !f.of;
    case 2: return f.cf;
    case 3: return !f.cf;
    case 4: return f.zf;
    case 5: return !f.zf;
    case 6: return f.cf || f.zf;
    case 7: return !f.cf && !f.zf;
    case 8: return f.sf;
    case 9: return !f.sf;
    case 10: return f.pf;
    case 11: return !f.pf;
    case 12: return f.sf !== f.of;
    case 13: return f.sf === f.of;
    case 14: return f.zf || f.sf !== f.of;
    default: return !f.zf && f.sf === f.of;
  }
}

class Machine {
  constructor(mem, loadBase) {
    this.mem = mem;
    this.loadBase = loadBase;
    this.reg = new Array(16).fill(0n);
    this.rip = 0n;
    this.flagSource = null;
  }

  flags() {
    return materializeFlag(this.flagSource);
  }

  translate(address, sizeByte) {
    const offset = address - this.loadBase;
    if (offset < 0n || offset + BigInt(sizeByte) > BigInt(this.mem.length)) {
      throw new FaultError(`guest address 0x${address.toString(16)} is outside the mapped memory`);
    }
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
    if (operand.size === 64) return raw & MASK64;
    if (operand.size === 32) return raw & 0xffffffffn;
    if (operand.size === 16) return raw & 0xffffn;
    if (operand.high8) return (raw >> 8n) & 0xffn;
    return raw & 0xffn;
  }

  writeReg(operand, value) {
    const index = operand.index;
    if (operand.size === 64) this.reg[index] = value & MASK64;
    else if (operand.size === 32) this.reg[index] = value & 0xffffffffn; // 32-bit writes zero-extend to 64
    else if (operand.size === 16) this.reg[index] = (this.reg[index] & ~0xffffn & MASK64) | (value & 0xffffn);
    else if (operand.high8) this.reg[index] = (this.reg[index] & ~0xff00n & MASK64) | ((value & 0xffn) << 8n);
    else this.reg[index] = (this.reg[index] & ~0xffn & MASK64) | (value & 0xffn);
  }

  effectiveAddress(mem, nextRip) {
    let addr = 0n;
    if (mem.rip_relative) addr = nextRip + BigInt(mem.disp);
    else {
      if (mem.base !== null) addr += this.reg[mem.base];
      if (mem.index !== null) addr += this.reg[mem.index] * BigInt(mem.scale);
      addr += BigInt(mem.disp);
    }
    return addr & MASK64;
  }

  readOperand(operand, nextRip) {
    if (operand.kind === "imm") return operand.value & sizeMask(operand.size);
    if (operand.kind === "reg") return this.readReg(operand);
    return this.readMem(this.effectiveAddress(operand, nextRip), operand.size / 8);
  }

  writeOperand(operand, value, nextRip) {
    if (operand.kind === "reg") this.writeReg(operand, value);
    else this.writeMem(this.effectiveAddress(operand, nextRip), operand.size / 8, value);
  }
}

class FaultError extends Error {}

const NAME64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
const RSP = 4;
const RBP = 5;

// Runs the ALU semantics for one node, recording the lazy flag source.
function executeAlu(machine, node, nextRip) {
  const size = node.size;
  const mask = sizeMask(size);
  const a = machine.readOperand(node.dst, nextRip) & mask;
  const b = machine.readOperand(node.src, nextRip) & mask;
  let result;
  let flag;
  switch (node.aluOp) {
    case "add":
      result = (a + b) & mask;
      flag = { kind: "add", size, a, b, cin: 0n, result };
      break;
    case "adc": {
      const cin = machine.flags().cf ? 1n : 0n;
      result = (a + b + cin) & mask;
      flag = { kind: "add", size, a, b, cin, result };
      break;
    }
    case "sub":
    case "cmp":
      result = (a - b) & mask;
      flag = { kind: "sub", size, a, b, cin: 0n, result };
      break;
    case "sbb": {
      const cin = machine.flags().cf ? 1n : 0n;
      result = (a - b - cin) & mask;
      flag = { kind: "sub", size, a, b, cin, result };
      break;
    }
    case "and":
    case "test":
      result = a & b & mask;
      flag = { kind: "logic", size, a, result };
      break;
    case "or":
      result = (a | b) & mask;
      flag = { kind: "logic", size, a, result };
      break;
    case "xor":
      result = (a ^ b) & mask;
      flag = { kind: "logic", size, a, result };
      break;
    default:
      throw new FaultError(`unhandled alu op ${node.aluOp}`);
  }
  machine.flagSource = flag;
  if (node.writeBack) machine.writeOperand(node.dst, result, nextRip);
}

function executeShift(machine, node, nextRip) {
  const size = node.size;
  const mask = sizeMask(size);
  const value = machine.readOperand(node.dst, nextRip) & mask;
  const countMask = size === 64 ? 0x3fn : 0x1fn;
  const count = machine.readOperand(node.src, nextRip) & countMask;
  if (count === 0n) {
    machine.writeOperand(node.dst, value, nextRip);
    return; // a zero count changes no flag
  }
  const sign = signBitOf(size);
  let result;
  let cf = false;
  let of = false;
  const c = Number(count);
  if (node.shiftOp === "shl") {
    result = (value << count) & mask;
    cf = ((value >> BigInt(size - c)) & 1n) !== 0n;
    of = (((result & sign) !== 0n) !== cf);
  } else if (node.shiftOp === "shr") {
    result = value >> count;
    cf = ((value >> (count - 1n)) & 1n) !== 0n;
    of = (value & sign) !== 0n;
  } else if (node.shiftOp === "sar") {
    const signed = toSigned(value, size);
    result = BigInt.asUintN(size, signed >> count);
    cf = ((value >> (count - 1n)) & 1n) !== 0n;
    of = false;
  } else if (node.shiftOp === "rol") {
    const r = BigInt(c % size);
    result = ((value << r) | (value >> (BigInt(size) - r))) & mask;
    cf = (result & 1n) !== 0n;
    of = (((result & sign) !== 0n) !== cf);
  } else if (node.shiftOp === "ror") {
    const r = BigInt(c % size);
    result = ((value >> r) | (value << (BigInt(size) - r))) & mask;
    cf = (result & sign) !== 0n;
    const secondTop = 1n << BigInt(size - 2);
    of = (((result & sign) !== 0n) !== ((result & secondTop) !== 0n));
  } else {
    throw new FaultError(`unhandled shift op ${node.shiftOp}`);
  }
  const zf = result === 0n;
  const sf = (result & sign) !== 0n;
  const isRotate = node.shiftOp === "rol" || node.shiftOp === "ror";
  machine.writeOperand(node.dst, result, nextRip);
  // Rotates touch only CF/OF; logical/arithmetic shifts define SF/ZF/PF too.
  machine.flagSource = { kind: "explicit", value: isRotate ? { ...machine.flags(), cf, of } : { cf, pf: parityEven(result), af: false, zf, sf, of } };
}

// Interprets a lifted region from the entry RVA over the register file and a
// flat guest memory (image + a bounded stack). Deterministic and budget-bounded.
// Returns the register file, materialized flags, rip, and a stop reason. This is
// the correctness oracle; it executes only the lifted IR.
export function interpret(option) {
  const image = option.image;
  if (!Buffer.isBuffer(image) && !(image instanceof Uint8Array)) throw new TypeError("interpret requires an image buffer");
  const loadBase = BigInt(option.loadBase ?? 0x140000000n);
  const stackSizeByte = option.stackSizeByte ?? 0x10000;
  const budget = option.budget ?? 100000;
  const entryRva = option.entryRva ?? 0;

  const mem = Buffer.alloc(image.length + stackSizeByte);
  Buffer.from(image).copy(mem, 0);
  const machine = new Machine(mem, loadBase);

  const sentinel = 0xdead000000000000n | (loadBase & 0xffffn); // an address never decoded
  const stackTop = loadBase + BigInt(image.length + stackSizeByte - 16);
  machine.reg[RSP] = stackTop;
  // Push the sentinel return address so the entry RET stops the oracle.
  machine.reg[RSP] -= 8n;
  machine.writeMem(machine.reg[RSP], 8, sentinel);
  const balancedRsp = stackTop;

  machine.rip = loadBase + BigInt(entryRva);

  let executedCount = 0;
  let stopReason = "budget_exhausted";
  let fault = null;

  try {
    for (; executedCount < budget; executedCount += 1) {
      const rvaOffset = Number(machine.rip - loadBase);
      if (rvaOffset < 0 || rvaOffset >= mem.length) {
        stopReason = "fault";
        fault = { message: `instruction pointer 0x${machine.rip.toString(16)} is outside the mapped memory`, address: machine.rip };
        break;
      }
      const node = decodeStructured(mem, rvaOffset);
      const nextRip = machine.rip + BigInt(node.length);

      if (!node.served) {
        stopReason = "unsupported_opcode";
        fault = { message: `unsupported opcode 0x${(node.opcode ?? 0).toString(16)}`, opcode: node.opcode ?? null, address: machine.rip };
        break;
      }

      const done = executeNode(machine, node, nextRip, sentinel);
      if (done) {
        stopReason = "entry_return";
        executedCount += 1;
        break;
      }
    }
  } catch (error) {
    if (error instanceof FaultError) {
      stopReason = "fault";
      fault = { message: error.message, address: machine.rip };
    } else {
      throw error;
    }
  }

  const register = {};
  for (let i = 0; i < 16; i += 1) register[NAME64[i]] = machine.reg[i] & MASK64;

  return {
    register,
    flag: machine.flags(),
    rip: machine.rip & MASK64,
    stop_reason: stopReason,
    executed_count: executedCount,
    balanced_rsp: balancedRsp,
    exception: fault,
  };
}

// Executes one node, updating rip. Returns true when the entry has returned.
function executeNode(machine, node, nextRip, sentinel) {
  const size = node.size;
  switch (node.op) {
    case "nop":
      machine.rip = nextRip;
      return false;
    case "mov":
      machine.writeOperand(node.dst, machine.readOperand(node.src, nextRip), nextRip);
      machine.rip = nextRip;
      return false;
    case "movzx": {
      const value = machine.readOperand(node.src, nextRip) & sizeMask(node.srcSize);
      machine.writeReg(node.dst, value);
      machine.rip = nextRip;
      return false;
    }
    case "movsx": {
      const value = toSigned(machine.readOperand(node.src, nextRip), node.srcSize) & sizeMask(node.size);
      machine.writeReg(node.dst, value);
      machine.rip = nextRip;
      return false;
    }
    case "movsxd": {
      const value = toSigned(machine.readOperand(node.src, nextRip), 32) & sizeMask(node.size);
      machine.writeReg(node.dst, value);
      machine.rip = nextRip;
      return false;
    }
    case "lea":
      machine.writeReg(node.dst, machine.effectiveAddress(node.src, nextRip) & sizeMask(node.size));
      machine.rip = nextRip;
      return false;
    case "alu":
      executeAlu(machine, node, nextRip);
      machine.rip = nextRip;
      return false;
    case "shift":
      executeShift(machine, node, nextRip);
      machine.rip = nextRip;
      return false;
    case "inc":
    case "dec": {
      const mask = sizeMask(size);
      const a = machine.readOperand(node.dst, nextRip) & mask;
      const one = 1n;
      const result = node.op === "inc" ? (a + one) & mask : (a - one) & mask;
      const cfKeep = machine.flags().cf;
      machine.flagSource = { kind: node.op, size, a, result, cfKeep };
      machine.writeOperand(node.dst, result, nextRip);
      machine.rip = nextRip;
      return false;
    }
    case "neg": {
      const mask = sizeMask(size);
      const b = machine.readOperand(node.dst, nextRip) & mask;
      const result = (0n - b) & mask;
      machine.flagSource = { kind: "sub", size, a: 0n, b, cin: 0n, result };
      machine.writeOperand(node.dst, result, nextRip);
      machine.rip = nextRip;
      return false;
    }
    case "not": {
      const mask = sizeMask(size);
      const b = machine.readOperand(node.dst, nextRip) & mask;
      machine.writeOperand(node.dst, (~b) & mask, nextRip);
      machine.rip = nextRip;
      return false;
    }
    case "imul2":
    case "imul3": {
      const mask = sizeMask(size);
      const a = toSigned(machine.readOperand(node.src, nextRip), size);
      const b = node.op === "imul3" ? toSigned(machine.readOperand(node.src2, nextRip), size) : toSigned(machine.readOperand(node.dst, nextRip), size);
      const full = a * b;
      const truncated = full & mask;
      const overflow = toSigned(truncated, size) !== full;
      machine.writeReg(node.dst, truncated);
      machine.flagSource = { kind: "explicit", value: { cf: overflow, of: overflow, sf: (truncated & signBitOf(size)) !== 0n, zf: truncated === 0n, pf: parityEven(truncated), af: false } };
      machine.rip = nextRip;
      return false;
    }
    case "imul":
    case "mul": {
      const mask = sizeMask(size);
      const acc = machine.reg[0] & mask;
      const src = machine.readOperand(node.src, nextRip) & mask;
      const product = node.op === "imul" ? toSigned(acc, size) * toSigned(src, size) : acc * src;
      const low = product & mask;
      const high = (product >> BigInt(size)) & mask;
      writeAccumulatorPair(machine, size, low, high);
      const overflow = node.op === "imul" ? toSigned(low, size) !== product : high !== 0n;
      machine.flagSource = { kind: "explicit", value: { cf: overflow, of: overflow, sf: (low & signBitOf(size)) !== 0n, zf: low === 0n, pf: parityEven(low), af: false } };
      machine.rip = nextRip;
      return false;
    }
    case "div":
    case "idiv": {
      const mask = sizeMask(size);
      const low = machine.reg[0] & mask;
      const high = size === 8 ? (machine.reg[0] >> 8n) & 0xffn : machine.reg[2] & mask;
      const dividend = (high << BigInt(size)) | low;
      const divisor = machine.readOperand(node.src, nextRip) & mask;
      if (divisor === 0n) throw new FaultError("integer divide by zero");
      let quotient;
      let remainder;
      if (node.op === "div") {
        quotient = dividend / divisor;
        remainder = dividend % divisor;
      } else {
        const sDividend = (toSigned(high, size) << BigInt(size)) | low;
        const sDivisor = toSigned(divisor, size);
        quotient = sDividend / sDivisor;
        remainder = sDividend % sDivisor;
      }
      writeAccumulatorPair(machine, size, quotient & mask, remainder & mask);
      machine.rip = nextRip;
      return false;
    }
    case "push": {
      const sizeByte = size / 8;
      const value = machine.readOperand(node.src, nextRip) & sizeMask(size);
      machine.reg[RSP] = (machine.reg[RSP] - BigInt(sizeByte)) & MASK64;
      machine.writeMem(machine.reg[RSP], sizeByte, value);
      machine.rip = nextRip;
      return false;
    }
    case "pop": {
      const sizeByte = size / 8;
      const value = machine.readMem(machine.reg[RSP], sizeByte);
      machine.reg[RSP] = (machine.reg[RSP] + BigInt(sizeByte)) & MASK64;
      machine.writeOperand(node.dst, value, nextRip);
      machine.rip = nextRip;
      return false;
    }
    case "jcc":
      machine.rip = conditionHolds(node.cc, machine.flags()) ? nextRip + node.rel : nextRip;
      return false;
    case "jmp":
      machine.rip = nextRip + node.rel;
      return false;
    case "jmpIndirect":
      machine.rip = machine.readOperand(node.src, nextRip) & MASK64;
      return false;
    case "call": {
      machine.reg[RSP] = (machine.reg[RSP] - 8n) & MASK64;
      machine.writeMem(machine.reg[RSP], 8, nextRip);
      machine.rip = nextRip + node.rel;
      return false;
    }
    case "callIndirect": {
      const target = machine.readOperand(node.src, nextRip) & MASK64;
      machine.reg[RSP] = (machine.reg[RSP] - 8n) & MASK64;
      machine.writeMem(machine.reg[RSP], 8, nextRip);
      machine.rip = target;
      return false;
    }
    case "ret": {
      const target = machine.readMem(machine.reg[RSP], 8);
      machine.reg[RSP] = (machine.reg[RSP] + 8n + BigInt(node.pop)) & MASK64;
      if (target === sentinel) {
        machine.rip = target;
        return true;
      }
      machine.rip = target;
      return false;
    }
    case "leave": {
      machine.reg[RSP] = machine.reg[RBP];
      const value = machine.readMem(machine.reg[RSP], 8);
      machine.reg[RSP] = (machine.reg[RSP] + 8n) & MASK64;
      machine.reg[RBP] = value;
      machine.rip = nextRip;
      return false;
    }
    case "setcc":
      machine.writeOperand(node.dst, conditionHolds(node.cc, machine.flags()) ? 1n : 0n, nextRip);
      machine.rip = nextRip;
      return false;
    case "cmovcc":
      if (conditionHolds(node.cc, machine.flags())) machine.writeReg(node.dst, machine.readOperand(node.src, nextRip));
      else if (node.size === 32) machine.writeReg(node.dst, machine.readReg(node.dst)); // a 32-bit CMOV still zero-extends
      machine.rip = nextRip;
      return false;
    default:
      throw new FaultError(`unhandled node op ${node.op}`);
  }
}

// Writes the low/high halves of a one-operand mul/div result to their
// architectural accumulator pair (AX for 8-bit, else eAX:eDX / rAX:rDX).
function writeAccumulatorPair(machine, size, low, high) {
  if (size === 8) {
    machine.reg[0] = (machine.reg[0] & ~0xffffn & MASK64) | (low & 0xffn) | ((high & 0xffn) << 8n);
    return;
  }
  machine.writeReg({ kind: "reg", index: 0, size, high8: false }, low);
  machine.writeReg({ kind: "reg", index: 2, size, high8: false }, high);
}

export { CONDITION_NAME, materializeFlag };
