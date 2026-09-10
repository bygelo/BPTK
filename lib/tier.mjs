// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The TIERED x86-64 runner for runtime v2 milestone M3 (doc/runtime-v2-scope.md
// §2 "(D) recompiler"). It executes a guest program FUNCTION BY FUNCTION, picking
// a tier per function entry and caching the decision by entry RVA:
//
//   • WASM tier  — a function whose whole single-function CFG compiles (lib/wasm64.mjs
//     compileFunction reports complete === true, every other function entry marked
//     external) runs as REAL WebAssembly via runFunction, ~80x faster on hot loops.
//   • interpreter tier — a function that hits a codegen fallback (an indirect jmp,
//     x87, a rotate, a 64-bit IMUL overflow, div/mul-pair, …) runs through the pure
//     lib/lift64.mjs interpreter semantics instead. This module re-declares the same
//     Machine + integer/control executor lib/lift64.mjs uses (that core is not an
//     export) and DELEGATES every complex op (SSE, x87, string, cpuid, cmpxchg, the
//     bit/bswap/xchg family) to lib/lift64.mjs's own EXPORTED executors, so the
//     interpreter tier is bit-exact with the oracle by construction, never a fork.
//
// Both tiers run over ONE consistent guest state — a single linear memory plus the
// sixteen-GPR register file and six flags — so control passes cleanly ACROSS a
// tier boundary. When a WASM-tier function calls a function marked external, the
// wasm64 import boundary fires option.hostCall with a live view of the SHARED
// memory; the dispatcher here runs the callee (interpreter or WASM tier) over that
// same memory and returns, and the WASM caller resumes. When an interpreter-tier
// function calls a WASM-tier function, the interpreter loop runs that callee as a
// nested WASM frame over the same guest memory. Either direction, the tiering must
// NOT change the result: runTiered's final registers/flags/memory are bit-exact to
// running the WHOLE program through lib/lift64.mjs's pure interpreter (interpret).
//
// The whole run is bounded (an instruction budget for the interpreter tier, an
// iteration cap for the WASM dispatch) and deterministic. runTiered returns the
// final architectural state and a tier report: which functions ran on which tier,
// how many interpreter instructions retired, and the wall-time spent per tier.

import {
  decodeStructured,
  materializeFlag,
  executeSse,
  executeX87,
  executeExtra,
  executeString,
  executeCpuid,
  executeCmpxchg,
  createX87State,
} from "./lift64.mjs";
import { compileFunction, runFunction } from "./wasm64.mjs";
import { performance } from "node:perf_hooks";

const MASK64 = (1n << 64n) - 1n;
const MASK128 = (1n << 128n) - 1n;
const NAME64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
const FLAG_ORDER = ["cf", "pf", "af", "zf", "sf", "of"];
const RSP = 4;
const RBP = 5;

function sizeMask(sizeBit) {
  return (1n << BigInt(sizeBit)) - 1n;
}

function signBitOf(sizeBit) {
  return 1n << BigInt(sizeBit - 1);
}

function toSigned(value, fromBit) {
  const mask = sizeMask(fromBit);
  const v = value & mask;
  return (v & signBitOf(fromBit)) !== 0n ? v - (1n << BigInt(fromBit)) : v;
}

function parityEven(value) {
  let b = Number(value & 0xffn);
  b ^= b >> 4;
  b ^= b >> 2;
  b ^= b >> 1;
  return (b & 1) === 0;
}

// The guest condition-code evaluator — identical to lib/lift64.mjs conditionHolds
// (that function is not exported), so setcc/cmovcc/jcc pick the same branch.
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

class FaultError extends Error {}

// A faithful re-declaration of lib/lift64.mjs's internal Machine. Same field
// layout and operand primitives so the EXPORTED lib/lift64.mjs executors
// (executeSse/executeX87/…) drive it exactly as they drive the oracle's machine.
// `mem` is any byte-indexable store with a `.length`: either this module's own
// guest Buffer (an interpreter-tier top frame) or the live WebAssembly memory
// (a Uint8Array over the shared buffer, at a WASM-tier import boundary).
class Machine {
  constructor(mem, loadBase) {
    this.mem = mem;
    this.loadBase = loadBase;
    this.reg = new Array(16).fill(0n);
    this.xmm = new Array(16).fill(0n);
    this.fpu = createX87State();
    this.rip = 0n;
    this.flagSource = null;
    this.df = false;
  }

  flags() {
    // df rides alongside the six arithmetic flags — see lib/lift64.mjs flags().
    return { ...materializeFlag(this.flagSource), df: this.df === true };
  }

  translate(address, sizeByte) {
    const offset = (address & MASK64) - this.loadBase;
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
    else if (operand.size === 32) this.reg[index] = value & 0xffffffffn;
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
    if (operand.kind === "xmm") return this.xmm[operand.index] & MASK128;
    return this.readMem(this.effectiveAddress(operand, nextRip), operand.size / 8);
  }

  writeOperand(operand, value, nextRip) {
    if (operand.kind === "reg") this.writeReg(operand, value);
    else if (operand.kind === "xmm") this.xmm[operand.index] = value & MASK128;
    else this.writeMem(this.effectiveAddress(operand, nextRip), operand.size / 8, value);
  }
}

// ---- integer ALU / shift semantics (ported verbatim from lib/lift64.mjs so the
// recorded lazy flag source matches what the exported materializeFlag reads) ----

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
    return;
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
  machine.flagSource = { kind: "explicit", value: isRotate ? { ...machine.flags(), cf, of } : { cf, pf: parityEven(result), af: false, zf, sf, of } };
}

function executeDoubleShift(machine, node, nextRip) {
  const size = node.size;
  const mask = sizeMask(size);
  const dst = machine.readOperand(node.dst, nextRip) & mask;
  const src = machine.readOperand(node.src, nextRip) & mask;
  const countMask = size === 64 ? 0x3fn : 0x1fn;
  const count = machine.readOperand(node.count, nextRip) & countMask;
  if (count === 0n) {
    machine.writeOperand(node.dst, dst, nextRip);
    return;
  }
  const bigSize = BigInt(size);
  const sign = signBitOf(size);
  let result;
  let cf;
  const shiftIn = (value, amount) => amount >= 0n ? (value << amount) : (value >> -amount);
  if (node.dshiftOp === "shld") {
    result = ((dst << count) | shiftIn(src, count - bigSize)) & mask;
    cf = ((dst >> (bigSize - count)) & 1n) !== 0n;
  } else {
    result = ((dst >> count) | shiftIn(src, bigSize - count)) & mask;
    cf = ((dst >> (count - 1n)) & 1n) !== 0n;
  }
  const zf = result === 0n;
  const sf = (result & sign) !== 0n;
  const of = ((dst & sign) !== 0n) !== sf;
  machine.writeOperand(node.dst, result, nextRip);
  machine.flagSource = { kind: "explicit", value: { cf, pf: parityEven(result), af: false, zf, sf, of } };
}

function writeAccumulatorPair(machine, size, low, high) {
  if (size === 8) {
    machine.reg[0] = (machine.reg[0] & ~0xffffn & MASK64) | (low & 0xffn) | ((high & 0xffn) << 8n);
    return;
  }
  machine.writeReg({ kind: "reg", index: 0, size, high8: false }, low);
  machine.writeReg({ kind: "reg", index: 2, size, high8: false }, high);
}

// Executes one lifted node over the machine, advancing rip. Returns true only
// when the entry frame's RET pops the sentinel (a top-level interpreter frame).
// The integer/control cases mirror lib/lift64.mjs executeNode exactly; the
// complex-op cases delegate to lib/lift64.mjs's EXPORTED executors verbatim.
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
    case "dshift":
      executeDoubleShift(machine, node, nextRip);
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
      else if (node.size === 32) machine.writeReg(node.dst, machine.readReg(node.dst));
      machine.rip = nextRip;
      return false;
    case "sse":
      executeSse(machine, node, nextRip);
      machine.rip = nextRip;
      return false;
    case "x87":
      executeX87(machine, node, nextRip);
      machine.rip = nextRip;
      return false;
    case "cpuid":
      executeCpuid(machine);
      machine.rip = nextRip;
      return false;
    case "cmpxchg":
      executeCmpxchg(machine, node, nextRip);
      machine.rip = nextRip;
      return false;
    case "cbw":
    case "cwd":
    case "bit":
    case "bsf":
    case "bsr":
    case "xadd":
    case "xchg":
    case "bswap":
    case "cld":
    case "std":
      executeExtra(machine, node, nextRip);
      machine.rip = nextRip;
      return false;
    case "string":
      executeString(machine, node, nextRip);
      return false;
    case "int3":
      // The breakpoint trap, on the interpreter tier exactly as the oracle: rip
      // stays AT the instruction and the fault names it.
      throw new FaultError("breakpoint");
    default:
      throw new FaultError(`unhandled node op ${node.op}`);
  }
}

// Normalizes the caller's function-entry list into a sorted, de-duplicated set of
// RVAs that always contains the program entry.
function normalizeEntries(list, entryRva) {
  const set = new Set([entryRva]);
  for (const rva of list ?? []) set.add(Number(rva));
  return [...set].sort((a, b) => a - b);
}

// Reads a live wasm64 host-call context's six flag bytes into a materialized set.
function readCtxFlags(ctx) {
  const flag = {};
  for (const name of FLAG_ORDER) flag[name] = ctx.readFlag(name);
  return flag;
}

// Reads the machine's end-of-frame architectural surfaces the oracle comparison
// inspects (the same shape lib/wasm64.mjs readState returns).
function readMachineState(machine, guestLen) {
  const register = {};
  for (let i = 0; i < 16; i += 1) register[NAME64[i]] = machine.reg[i] & MASK64;
  const flag = machine.flags();
  const xmm = machine.xmm.map((v) => v & MASK128);
  const memory = Buffer.from(machine.mem.subarray(0, guestLen));
  return { register, flag, xmm, memory };
}

// Runs a guest program by function, mixing the WASM fast path and the interpreter
// fallback over ONE shared guest state. Returns the final architectural state
// (registers, flags, xmm, a guest-memory copy) plus a tier report. Bit-exact with
// lib/lift64.mjs interpret over the whole program — the tiering never changes the
// result. `image` is the raw guest bytes; option.functionEntry lists the function
// entry RVAs to tier independently (default: just option.entryRva). An unlisted
// callee is folded into its caller's compilation rather than tiered on its own.
export function runTiered(image, option = {}) {
  if (!Buffer.isBuffer(image) && !(image instanceof Uint8Array)) throw new TypeError("runTiered requires an image buffer");
  const loadBase = BigInt(option.loadBase ?? 0x140000000n);
  const stackSizeByte = option.stackSizeByte ?? 0x10000;
  const entryRva = option.entryRva ?? 0;
  const budget = option.budget ?? 1_000_000;
  const iterationCap = option.iterationCap ?? 1_000_000;
  const imageLen = image.length;
  const guestLen = imageLen + stackSizeByte;
  const sentinel = 0xdead000000000000n | (loadBase & 0xffffn);
  const baseImage = Buffer.from(image);

  const functionEntry = normalizeEntries(option.functionEntry, entryRva);
  const otherEntries = (rva) => functionEntry.filter((e) => e !== rva);

  // ---- per-function tier decision, cached by entry RVA ----
  // Probe each entry's single-function compile with all OTHER entries marked
  // external (a dummy host callback lets those import boundaries count as
  // complete). complete === true ⇒ WASM tier; a codegen fallback ⇒ interpreter.
  const decision = new Map();
  const coverageByRva = new Map();
  for (const rva of functionEntry) {
    const compiled = compileFunction(baseImage, {
      loadBase, stackSizeByte, guestLen, entryRva: rva, decodeStructured,
      hostCall: () => 0, externalRva: otherEntries(rva),
    });
    decision.set(rva, compiled.complete ? "wasm" : "interp");
    coverageByRva.set(rva, compiled.coverage);
  }

  const report = {
    functionEntry: [...functionEntry],
    tier: Object.fromEntries(functionEntry.map((rva) => [rva, decision.get(rva)])),
    wasmFunctionRun: 0,
    interpFunctionRun: 0,
    wasmEntryRun: [],
    interpEntryRun: [],
    interpInstruction: 0,
    wasmResumeRun: 0,
    wasmWallMs: 0,
    interpWallMs: 0,
    coverage: Object.fromEntries(functionEntry.map((rva) => [rva, coverageByRva.get(rva)])),
  };
  const now = () => performance.now();

  // dispatcher is referenced by the interpreter loop and the wasm frames before it
  // is assigned; a forward `let` closes the cycle.
  let dispatcher;

  // Runs a WASM-tier callee as a nested frame over the CURRENT guest memory bytes
  // (either the interpreter's Buffer or a live wasm64 import memory), seeded with
  // the current registers/flags (rsp stays the caller's — the callee gets a fresh,
  // balanced stack). Splices the guest-memory region and the volatile registers/
  // flags/xmm back. Used for the interpreter → WASM call direction.
  // A WASM frame can stop BEFORE its own RET: the return-to-dispatch terminator of
  // an indirect jmp/call, an unhandled boundary, or the iteration cap. lib/wasm64.mjs
  // marks such an exit `resumable`, meaning its registers, flags, xmm and whole guest
  // memory are a state interpretation could hold — so the frame is FINISHED by
  // rebuilding a Machine over exactly those bytes, putting rip at the module's resume
  // rip, and letting the interpreter tier carry it to the frame's own RET. Without
  // this the mid-run state would be handed back as if it were the frame's final state,
  // which is the silent-corruption case the whole tier exists to avoid. A NON-resumable
  // exit (an out-of-region FAULT: a guest store was lost to the trap page) is refused
  // outright — an honest stop beats a wrong result.
  const finishWasmFrame = (res, targetRva) => {
    if (res.statusName === "ok") return res;
    if (!res.resumable) throw new FaultError(`tier: the WASM frame at 0x${targetRva.toString(16)} faulted out of region (${res.statusName}); its state cannot be resumed`);
    const mem = Buffer.alloc(guestLen);
    Buffer.from(res.memory).copy(mem, 0);
    const machine = new Machine(mem, loadBase);
    for (let i = 0; i < 16; i += 1) machine.reg[i] = res.register[NAME64[i]];
    machine.flagSource = { kind: "explicit", value: res.flag };
    // A null xmm means the compiled region contained no SSE op, so it could not have
    // written one: the machine keeps the xmm state it already holds.
    if (res.xmm !== null) for (let i = 0; i < 16; i += 1) machine.xmm[i] = res.xmm[i];
    machine.rip = res.resumeRip & MASK64;
    const t0 = now();
    runInterpFrame(machine, "sentinel", 0n);
    report.interpWallMs += now() - t0;
    report.wasmResumeRun += 1;
    const state = readMachineState(machine, guestLen);
    return { ...state, statusName: "ok" };
  };

  const runWasmNested = (memStore, reg, flag, xmm, targetRva) => {
    const snapshot = Buffer.from(memStore.subarray(0, imageLen));
    const register = {};
    for (let i = 0; i < 16; i += 1) if (i !== RSP) register[NAME64[i]] = reg[i];
    const t0 = now();
    const res = runFunction(snapshot, {
      image: snapshot, loadBase, stackSizeByte, decodeStructured, entryRva: targetRva,
      register, flag, xmm, externalRva: otherEntries(targetRva), hostCall: dispatcher, iterationCap,
    });
    report.wasmWallMs += now() - t0;
    report.wasmFunctionRun += 1;
    report.wasmEntryRun.push(targetRva);
    const done = finishWasmFrame(res, targetRva);
    for (let i = 0; i < imageLen; i += 1) memStore[i] = done.memory[i];
    return done;
  };

  // The interpreter-tier frame runner. Steps lifted nodes over `machine` until the
  // frame returns. Two stop modes: a top-level frame stops when the entry RET pops
  // the sentinel (bit-exact with interpret); an import-boundary sub-frame stops
  // just BEFORE the RET that would pop its caller-pushed return address (rsp back
  // at frameEntryRsp), leaving that address on the stack for the WASM caller to
  // pop. A call to a WASM-tier entry is run as a nested WASM frame.
  const runInterpFrame = (machine, stopMode, frameEntryRsp) => {
    for (let executed = 0; executed < budget; executed += 1) {
      const rvaOff = Number((machine.rip - loadBase) & MASK64);
      if (rvaOff < 0 || rvaOff >= machine.mem.length) throw new FaultError(`tier: rip 0x${machine.rip.toString(16)} outside mapped memory`);
      const node = decodeStructured(machine.mem, rvaOff);
      if (!node.served) throw new FaultError(`tier: unsupported opcode 0x${(node.opcode ?? 0).toString(16)} at 0x${machine.rip.toString(16)}`);
      const nextRip = (machine.rip + BigInt(node.length)) & MASK64;
      report.interpInstruction += 1;

      if (node.op === "ret" && stopMode === "frameRsp" && machine.reg[RSP] === frameEntryRsp) {
        return; // the frame's terminal RET — leave rsp/return-address for the caller
      }
      if (node.op === "call") {
        const target = (nextRip + node.rel) & MASK64;
        const targetRva = Number((target - loadBase) & MASK64);
        if (decision.get(targetRva) === "wasm") {
          // Emulate the call's stack effect (push return address) so guest memory
          // is bit-exact, run the WASM callee as a nested frame, then pop.
          machine.reg[RSP] = (machine.reg[RSP] - 8n) & MASK64;
          machine.writeMem(machine.reg[RSP], 8, nextRip);
          const res = runWasmNested(machine.mem, machine.reg, machine.flags(), machine.xmm, targetRva);
          machine.reg[RSP] = (machine.reg[RSP] + 8n) & MASK64;
          for (let i = 0; i < 16; i += 1) if (i !== RSP) machine.reg[i] = res.register[NAME64[i]];
          machine.flagSource = { kind: "explicit", value: res.flag };
          // A null xmm means the compiled region contained no SSE op, so it could not
          // have written one: the machine keeps the xmm state it already holds.
          if (res.xmm !== null) for (let i = 0; i < 16; i += 1) machine.xmm[i] = res.xmm[i];
          machine.rip = nextRip;
          continue;
        }
      }
      const done = executeNode(machine, node, nextRip, sentinel);
      if (done) return; // sentinel RET — top-level frame complete
    }
    throw new FaultError("tier: interpreter instruction budget exhausted");
  };

  // Runs an interpreter-tier callee at an import boundary over the LIVE wasm64
  // shared memory the context exposes, seeded from the spilled register file/flags.
  const runInterpOnCtx = (rva, ctx) => {
    const machine = new Machine(ctx.mem, loadBase);
    for (let i = 0; i < 16; i += 1) machine.reg[i] = ctx.readReg(NAME64[i]);
    machine.flagSource = { kind: "explicit", value: readCtxFlags(ctx) };
    machine.rip = (loadBase + BigInt(rva)) & MASK64;
    const frameEntryRsp = machine.reg[RSP];
    const t0 = now();
    runInterpFrame(machine, "frameRsp", frameEntryRsp);
    report.interpWallMs += now() - t0;
    report.interpFunctionRun += 1;
    report.interpEntryRun.push(rva);
    for (let i = 0; i < 16; i += 1) ctx.writeReg(NAME64[i], machine.reg[i]);
    const flag = machine.flags();
    for (const name of FLAG_ORDER) ctx.writeFlag(name, flag[name]);
  };

  // The host-call dispatcher bound to every WASM-tier frame's import boundary: it
  // routes a guest call target to the callee's tier over the SHARED memory.
  dispatcher = (targetVA, ctx) => {
    const target = BigInt.asUintN(64, targetVA);
    const rva = Number((target - loadBase) & MASK64);
    const tier = decision.get(rva);
    if (tier === "interp") { runInterpOnCtx(rva, ctx); return 0; }
    if (tier === "wasm") {
      const reg = new Array(16);
      for (let i = 0; i < 16; i += 1) reg[i] = ctx.readReg(NAME64[i]);
      const res = runWasmNested(ctx.mem, reg, readCtxFlags(ctx), new Array(16).fill(0n), rva);
      for (let i = 0; i < 16; i += 1) if (i !== RSP) ctx.writeReg(NAME64[i], res.register[NAME64[i]]);
      for (const name of FLAG_ORDER) ctx.writeFlag(name, res.flag[name]);
      return 0;
    }
    if (typeof option.hostCall === "function") return option.hostCall(targetVA, ctx);
    return 1; // an unknown external boundary — reported as unhandled, never guessed
  };

  // ---- run the entry frame on its chosen tier ----
  let finalState;
  if (decision.get(entryRva) === "wasm") {
    const t0 = now();
    const res = runFunction(baseImage, {
      image: baseImage, loadBase, stackSizeByte, decodeStructured, entryRva,
      externalRva: otherEntries(entryRva), hostCall: dispatcher, iterationCap,
    });
    report.wasmWallMs += now() - t0;
    report.wasmFunctionRun += 1;
    report.wasmEntryRun.push(entryRva);
    const done = finishWasmFrame(res, entryRva);
    finalState = { register: done.register, flag: done.flag, xmm: done.xmm, memory: Buffer.from(done.memory), statusName: done.statusName };
  } else {
    const mem = Buffer.alloc(guestLen);
    baseImage.copy(mem, 0);
    const machine = new Machine(mem, loadBase);
    const stackTop = loadBase + BigInt(imageLen + stackSizeByte - 16);
    machine.reg[RSP] = (stackTop - 8n) & MASK64;
    machine.writeMem(machine.reg[RSP], 8, sentinel);
    machine.rip = (loadBase + BigInt(entryRva)) & MASK64;
    const t0 = now();
    runInterpFrame(machine, "sentinel", 0n);
    report.interpWallMs += now() - t0;
    report.interpFunctionRun += 1;
    report.interpEntryRun.push(entryRva);
    const s = readMachineState(machine, guestLen);
    finalState = { ...s, statusName: "ok" };
  }

  return { ...finalState, report };
}
