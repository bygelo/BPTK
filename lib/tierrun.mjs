// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The TIERED x86-64 runner (runtime v2 milestone: one guest, two engines). A
// mapped PE32+ image is driven function-by-function over the SINGLE shared guest
// state that lib/exec64.mjs buildGuestContext64 constructs — the same
// multi-region Machine, the same Win32 HLE, the same register file. At every
// direct-call site the runner decides, once and cached by the callee's entry
// virtual address, which engine executes that function:
//
//   * WASM tier — the callee compiles COMPLETELY through lib/wasm64.mjs
//     compileFunction (every op and every terminator emittable) AND makes no
//     external/import call. Such a function is run as a real WebAssembly module
//     (lib/wasm64.mjs runFunction) seeded from the live Machine register file, and
//     its mutated registers/flags/xmm are read back into the Machine at the
//     function boundary. No host/HLE call happens inside a WASM-tier function, so
//     no mid-function synchronization is ever needed: the Machine is authoritative
//     at every boundary.
//
//     GUEST MEMORY IS NOT COPIED. Both engines run on ONE memory: buildGuestContext64
//     places the interpreter's region buffers inside a WebAssembly.Memory, and the
//     tier's modules IMPORT that memory rather than defining a private one. A tier
//     transition is a register/rip handoff. The tier used to seed a private copy of
//     the whole mapped map on every invocation and splice it back out afterwards,
//     which made one tier call cost O(total mapped byte) instead of O(instruction
//     executed) — with a real map (~100 MiB for PuTTY x64 under the Win32 HLE) that
//     was a ~33x net slowdown, measured, and it is the reason this shape exists.
//
//     A WASM-tier function may contain an INDIRECT jmp/call. wasm64 compiles that
//     as a return-to-dispatch terminator: everything up to the transfer runs at
//     WASM speed, the module stops immediately BEFORE the transfer, and this
//     runner COMMITS the module's state and continues at the reported resume rip
//     — the transfer instruction itself, which the interpreter then performs. The
//     boundary is therefore no longer the function; it is the next thing the
//     module cannot model. What the runner must never do is commit a run wasm64
//     marks NOT resumable.
//
//     An out-of-region FAULT is not one of those any more, and on a shared memory
//     it cannot be: a run's stores are the guest's own and re-running the callee
//     would apply a non-idempotent instruction (`inc [mem]`) twice. A complete
//     module therefore stops AT the unmapped access having performed none of its
//     effects, so its state is the state interpretation holds there — committed
//     like any other resume, and the interpreter then faults on the same access.
//
//   * Interpreter tier — everything else. The instruction executor here is a
//     BYTE-FOR-BYTE port of lib/exec64.mjs's executeNode / executeAlu /
//     executeShift / executeDoubleShift and its gs/fs segment-aware decode, so
//     an interpreter-tier instruction produces state identical to pure
//     runImage64. Reached imports are served through the SAME Win64 marshal the
//     interpreter loop uses (serveImport64 / serveImportAt64, both exported by
//     lib/exec64.mjs), never re-implemented.
//
// The whole run is bounded by one instruction budget and is deterministic. The
// result is the final Machine state plus a tier report (WASM-tier vs
// interpreter-tier function counts, and instructions/invocations per tier). The
// contract this file exists to prove: runTieredImage's final architectural state
// equals pure interpretation's, BIT-FOR-BIT — a divergence is a real bug in the
// tiering, never something to paper over. The WASM tier genuinely carries the
// guest state forward; it does not secretly re-invoke the interpreter.

import {
  decodeStructured, materializeFlag,
  executeSse, executeCpuid, executeCmpxchg, executeExtra, executeString, executeX87,
} from "./lift64.mjs";
import { buildGuestContext64, serveImport64, serveImportAt64 } from "./exec64.mjs";
import { compileFunction, compileFunctionCached, runFunction } from "./wasm64.mjs";

const MASK64 = (1n << 64n) - 1n;
const MASK128 = (1n << 128n) - 1n;
const RSP = 4;
const RBP = 5;
const NAME64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];

// The harness sentinels lib/exec64.mjs defines. A guest RET onto the entry
// sentinel stops the run; the init/dialog sentinels mark the specialization
// resume points the tiered runner deliberately does NOT drive (see below).
const returnSentinel = 0xdead000000000000n;
const initReturnSentinel = 0xdead000000000010n;
const dialogReturnSentinel = 0xdead000000000020n;

// The import specializations lib/exec64.mjs's loop drives through guest control
// flow (CRT initializer tables, modal/modeless dialogs, the window message
// pump). Each needs a private multi-step resume the exported serve entry points
// do not expose, so the tiered runner refuses them with an honest stop rather
// than mis-serving them as a plain marshal. A real x86-64 startup reaches none of
// these before its first genuinely-unserved import (measured on PuTTY x64), so
// the refusal never fires on the corpus proof; it only guards correctness.
const INITTERM_SYMBOL = new Set(["_initterm", "_initterm_e"]);
const DIALOG_CREATE_SYMBOL = new Set(["CreateDialogParamA", "CreateDialogParamW", "DialogBoxParamA", "DialogBoxParamW"]);
const WINDOW_STRUCT_SYMBOL = new Set([
  "RegisterClassA", "RegisterClassW", "RegisterClassExA", "RegisterClassExW",
  "GetMessageA", "GetMessageW", "PeekMessageA", "PeekMessageW",
  "TranslateMessage", "DispatchMessageA", "DispatchMessageW",
]);
const WINDOW_SCALAR_SYMBOL = new Set([
  "CreateWindowExA", "DefWindowProcA", "DefDlgProcA", "DefDlgProcW", "UnregisterClassA",
  "SetActiveWindow", "SetFocus", "SetForegroundWindow", "BringWindowToTop", "EnableWindow",
  "IsWindowVisible", "IsWindowEnabled", "GetDlgItem", "GetDlgCtrlID",
  "SendDlgItemMessageA", "SendDlgItemMessageW", "EndDialog",
  "SetWindowTextA", "SetWindowTextW", "SetDlgItemTextA", "SetDlgItemTextW",
  "CheckDlgButton", "GetDlgItemTextA", "GetDlgItemTextW",
]);
function isSpecializationSymbol(symbol) {
  return INITTERM_SYMBOL.has(symbol) || DIALOG_CREATE_SYMBOL.has(symbol) || WINDOW_STRUCT_SYMBOL.has(symbol) || WINDOW_SCALAR_SYMBOL.has(symbol);
}

// ===================================================================== //
// The interpreter-tier instruction executor, ported byte-for-byte from    //
// lib/exec64.mjs (the pure runImage64 loop) so a divergence is impossible  //
// by construction and provable by the bit-exact tests. Only the free       //
// functions are copied; they drive the SAME exec64 Machine instance that   //
// buildGuestContext64 returns, through its own methods.                    //
// ===================================================================== //

function sizeMask(sizeBit) { return (1n << BigInt(sizeBit)) - 1n; }
function signBitOf(sizeBit) { return 1n << BigInt(sizeBit - 1); }
function toSigned(value, fromBit) {
  const mask = sizeMask(fromBit);
  const v = value & mask;
  return (v & signBitOf(fromBit)) !== 0n ? v - (1n << BigInt(fromBit)) : v;
}
function parityEven(value) {
  let b = Number(value & 0xffn);
  b ^= b >> 4; b ^= b >> 2; b ^= b >> 1;
  return (b & 1) === 0;
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

class FaultError extends Error {}

const LEGACY_PREFIX = new Set([0x66, 0x67, 0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65]);
function decodeWithoutByte(mem, rva, bytePos) {
  const window = mem.subarray(rva, Math.min(rva + 15, mem.length));
  const stripped = Buffer.alloc(window.length - 1);
  const relative = bytePos - rva;
  window.copy(stripped, 0, 0, relative);
  window.copy(stripped, relative, relative + 1);
  const node = decodeStructured(stripped, 0);
  return { ...node, length: node.length + 1 };
}
const BRANCH_OPCODE = new Set([0xe8, 0xe9, 0xeb, 0xc2, 0xc3, 0xff]);
function isBranchAfterBnd(mem, opcodePos) {
  const opcode = mem[opcodePos];
  if (opcode >= 0x70 && opcode <= 0x7f) return true;
  if (BRANCH_OPCODE.has(opcode)) return true;
  if (opcode === 0x0f) { const second = mem[opcodePos + 1]; return second >= 0x80 && second <= 0x8f; }
  return false;
}
function decodeWithSegment(mem, rva) {
  let scan = rva;
  let segment = null;
  let segmentPos = -1;
  let flatSegmentPos = -1;
  let bndPos = -1;
  for (let guard = 0; guard < 15 && scan < mem.length; guard += 1) {
    const byte = mem[scan];
    if (!LEGACY_PREFIX.has(byte)) break;
    if (byte === 0x64) { segment = "fs"; segmentPos = scan; }
    else if (byte === 0x65) { segment = "gs"; segmentPos = scan; }
    else if (byte === 0x2e || byte === 0x36 || byte === 0x3e || byte === 0x26) { flatSegmentPos = scan; }
    else if (byte === 0xf2) { bndPos = scan; }
    scan += 1;
  }
  if (segment === null && bndPos !== -1 && scan < mem.length && isBranchAfterBnd(mem, scan)) {
    return { node: decodeWithoutByte(mem, rva, bndPos), segment: null };
  }
  if (segment === null && flatSegmentPos !== -1) {
    return { node: decodeWithoutByte(mem, rva, flatSegmentPos), segment: null };
  }
  if (segment === null) return { node: decodeStructured(mem, rva), segment: null };
  return { node: decodeWithoutByte(mem, rva, segmentPos), segment };
}

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
  const shiftIn = (value, amount) => amount >= 0n ? (value << amount) : (value >> -amount);
  let result;
  let cf;
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

// Executes one lifted node, updating rip. Returns null to continue, or a stop
// descriptor { reason, import } when the entry returns or an import is reached.
// Byte-for-byte identical to lib/exec64.mjs executeNode.
function executeNode(machine, node, nextRip, importSet) {
  const size = node.size;
  switch (node.op) {
    case "nop":
      machine.rip = nextRip;
      return null;
    case "mov":
      machine.writeOperand(node.dst, machine.readOperand(node.src, nextRip), nextRip);
      machine.rip = nextRip;
      return null;
    case "movzx": {
      const value = machine.readOperand(node.src, nextRip) & sizeMask(node.srcSize);
      machine.writeReg(node.dst, value);
      machine.rip = nextRip;
      return null;
    }
    case "movsx": {
      const value = toSigned(machine.readOperand(node.src, nextRip), node.srcSize) & sizeMask(node.size);
      machine.writeReg(node.dst, value);
      machine.rip = nextRip;
      return null;
    }
    case "movsxd": {
      const value = toSigned(machine.readOperand(node.src, nextRip), 32) & sizeMask(node.size);
      machine.writeReg(node.dst, value);
      machine.rip = nextRip;
      return null;
    }
    case "lea":
      machine.writeReg(node.dst, (machine.effectiveAddress(node.src, nextRip) - machine.segmentBase) & sizeMask(node.size));
      machine.rip = nextRip;
      return null;
    case "alu":
      executeAlu(machine, node, nextRip);
      machine.rip = nextRip;
      return null;
    case "dshift":
      executeDoubleShift(machine, node, nextRip);
      machine.rip = nextRip;
      return null;
    case "shift":
      executeShift(machine, node, nextRip);
      machine.rip = nextRip;
      return null;
    case "inc":
    case "dec": {
      const mask = sizeMask(size);
      const a = machine.readOperand(node.dst, nextRip) & mask;
      const result = node.op === "inc" ? (a + 1n) & mask : (a - 1n) & mask;
      const cfKeep = machine.flags().cf;
      machine.flagSource = { kind: node.op, size, a, result, cfKeep };
      machine.writeOperand(node.dst, result, nextRip);
      machine.rip = nextRip;
      return null;
    }
    case "neg": {
      const mask = sizeMask(size);
      const b = machine.readOperand(node.dst, nextRip) & mask;
      const result = (0n - b) & mask;
      machine.flagSource = { kind: "sub", size, a: 0n, b, cin: 0n, result };
      machine.writeOperand(node.dst, result, nextRip);
      machine.rip = nextRip;
      return null;
    }
    case "not": {
      const mask = sizeMask(size);
      const b = machine.readOperand(node.dst, nextRip) & mask;
      machine.writeOperand(node.dst, (~b) & mask, nextRip);
      machine.rip = nextRip;
      return null;
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
      return null;
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
      return null;
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
      return null;
    }
    case "push": {
      const sizeByte = size / 8;
      const value = machine.readOperand(node.src, nextRip) & sizeMask(size);
      machine.reg[RSP] = (machine.reg[RSP] - BigInt(sizeByte)) & MASK64;
      machine.writeMem(machine.reg[RSP], sizeByte, value);
      machine.rip = nextRip;
      return null;
    }
    case "pop": {
      const sizeByte = size / 8;
      const value = machine.readMem(machine.reg[RSP], sizeByte);
      machine.reg[RSP] = (machine.reg[RSP] + BigInt(sizeByte)) & MASK64;
      machine.writeOperand(node.dst, value, nextRip);
      machine.rip = nextRip;
      return null;
    }
    case "jcc":
      machine.rip = conditionHolds(node.cc, machine.flags()) ? nextRip + node.rel : nextRip;
      return null;
    case "jmp":
      machine.rip = nextRip + node.rel;
      return null;
    case "jmpIndirect": {
      if (node.src.kind === "mem") {
        const slot = machine.effectiveAddress(node.src, nextRip);
        const reached = importSet.get(slot);
        if (reached) return { reason: "import_present", import: reached, kind: "jmp" };
      }
      machine.rip = machine.readOperand(node.src, nextRip) & MASK64;
      return null;
    }
    case "call": {
      machine.reg[RSP] = (machine.reg[RSP] - 8n) & MASK64;
      machine.writeMem(machine.reg[RSP], 8, nextRip);
      machine.rip = nextRip + node.rel;
      return null;
    }
    case "callIndirect": {
      if (node.src.kind === "mem") {
        const slot = machine.effectiveAddress(node.src, nextRip);
        const reached = importSet.get(slot);
        if (reached) return { reason: "import_present", import: reached, kind: "call" };
      }
      const target = machine.readOperand(node.src, nextRip) & MASK64;
      machine.reg[RSP] = (machine.reg[RSP] - 8n) & MASK64;
      machine.writeMem(machine.reg[RSP], 8, nextRip);
      machine.rip = target;
      return null;
    }
    case "ret": {
      const target = machine.readMem(machine.reg[RSP], 8);
      machine.reg[RSP] = (machine.reg[RSP] + 8n + BigInt(node.pop)) & MASK64;
      machine.rip = target;
      if (target === returnSentinel) return { reason: "entry_return", import: null };
      return null;
    }
    case "leave": {
      machine.reg[RSP] = machine.reg[RBP];
      const value = machine.readMem(machine.reg[RSP], 8);
      machine.reg[RSP] = (machine.reg[RSP] + 8n) & MASK64;
      machine.reg[RBP] = value;
      machine.rip = nextRip;
      return null;
    }
    case "setcc":
      machine.writeOperand(node.dst, conditionHolds(node.cc, machine.flags()) ? 1n : 0n, nextRip);
      machine.rip = nextRip;
      return null;
    case "cmovcc":
      if (conditionHolds(node.cc, machine.flags())) machine.writeReg(node.dst, machine.readOperand(node.src, nextRip));
      else if (node.size === 32) machine.writeReg(node.dst, machine.readReg(node.dst));
      machine.rip = nextRip;
      return null;
    case "sse":
      executeSse(machine, node, nextRip);
      machine.rip = nextRip;
      return null;
    case "x87":
      executeX87(machine, node, nextRip);
      machine.rip = nextRip;
      return null;
    case "cpuid":
      executeCpuid(machine);
      machine.rip = nextRip;
      return null;
    case "cmpxchg":
      executeCmpxchg(machine, node, nextRip);
      machine.rip = nextRip;
      return null;
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
      return null;
    case "string":
      executeString(machine, node, nextRip);
      return null;
    default:
      throw new FaultError(`unhandled node op ${node.op}`);
  }
}

// ===================================================================== //
// The tiered driver.                                                      //
// ===================================================================== //

// Describes the multi-region layout to lib/wasm64.mjs in the shape its
// runFunction expects: image region (seeded from the image bytes), the stack
// region (seeded from a COPY carrying the entry sentinel at the seeded rsp), and
// every other region (TEB, HLE arena/virtual/thunk, the low image alias) seeded
// from its live bytes. Guest addresses map bit-exact to the exec64 layout.
function buildRegionSpec(context, stackCopy) {
  const imageBase = context.loadBase & MASK64;
  const stackBase = context.layout.stack.base & MASK64;
  return context.region.map((r) => {
    const base = r.base & MASK64;
    const size = r.buf.length;
    if (base === imageBase) return { base, size, kind: "image" };
    if (base === stackBase) return { base, size, kind: "stack", init: stackCopy };
    return { base, size, kind: "region", init: r.buf };
  });
}

// Runs the function whose entry is `target` as a real WebAssembly module, seeded
// from the live Machine and read back into it. The module can stop in three ways,
// and this returns which one happened:
//
//   "ok"     — the callee's RET unwound its frame. The Machine is committed past
//              the call, rip at the return address.
//   "resume" — the module handed control back MID-function: it stopped just BEFORE
//              an indirect jmp/call, or an unmatched RET popped an address the
//              compilation does not know. Its registers/flags/xmm/memory are a state
//              interpretation could hold (lib/wasm64.mjs reports `resumable`), so
//              they are committed and rip is set to the module's resume rip. The
//              caller keeps executing from there. Everything before the exit really
//              ran at WASM speed instead of being thrown away.
//
//              For an indirect transfer the resume rip is the TRANSFER INSTRUCTION
//              itself, not its target, and that is load-bearing: `call/jmp [iat]` is
//              an import boundary here, which lib/exec64.mjs executeNode reports
//              BEFORE any stack effect. Only the interpreter can tell an import slot
//              from an ordinary pointer, so it performs every indirect transfer.
//   null     — the run must be DISCARDED and the Machine is left UNTOUCHED, so the
//              interpreter tier runs the call instead. Three causes: an out-of-region
//              FAULT (a guest store was lost to the trap page — never commitable),
//              the module's iteration cap, and any codegen/instantiation surprise.
//
// The iteration cap is deliberately DISCARDED even though wasm64 reports it as
// resumable: this runner's whole bound is one instruction budget, and one unit of it
// buys at most one turn of the loop below. Committing a cap exit would let a single
// unit buy up to iterationCap block dispatches, so a runaway guest loop could outrun
// the bound the run is supposed to have. Interpreting the call instead keeps the
// budget honest, and the guest reaches the identical state either way.
function runWasmTierFunction(context, target, node) {
  const { machine, loadBase } = context;
  const imageBuf = context.imageBuf;
  const stackBase = context.layout.stack.base & MASK64;
  const stackRegion = context.region.find((r) => (r.base & MASK64) === stackBase);
  const stackSize = stackRegion.buf.length;
  const sentinel = returnSentinel | (loadBase & 0xffffn);

  const origRsp = machine.reg[RSP] & MASK64;
  const rspForWasm = (origRsp - 8n) & MASK64;
  const realRet = (machine.rip + BigInt(node.length)) & MASK64;

  const sentinelOff = Number((rspForWasm - stackBase) & MASK64);
  if (sentinelOff < 0 || sentinelOff + 8 > stackSize) return null; // rsp not in the stack region: let the interpreter handle it

  // On the SHARED memory the module writes the entry sentinel straight into the
  // guest's own stack at the seeded rsp — the very slot a `call` pushes its return
  // address into, so nothing live is disturbed and every exit below overwrites it.
  // Without a shared memory the module gets a private stack image instead, and the
  // sentinel is planted in that copy.
  const shared = context.sharedPlan ?? null;
  let stackCopy = null;
  if (shared === null) {
    stackCopy = Buffer.from(stackRegion.buf);
    for (let i = 0; i < 8; i += 1) stackCopy[sentinelOff + i] = Number((sentinel >> (8n * BigInt(i))) & 0xffn);
  }

  const register = {};
  for (let i = 0; i < 16; i += 1) register[NAME64[i]] = machine.reg[i] & MASK64;
  register.rsp = rspForWasm;
  const xmm = [];
  for (let i = 0; i < 16; i += 1) xmm.push(machine.xmm[i] & MASK128);
  const flag = machine.flags();

  const regionSpec = shared === null ? buildRegionSpec(context, stackCopy) : shared.region;
  const entryRva = Number((target - loadBase) & MASK64);

  let jit;
  try {
    jit = runFunction(imageBuf, {
      image: imageBuf, loadBase, decodeStructured, register, xmm, flag, entryRva, rawRegion: true,
      // On the shared memory an iteration-cap exit is COMMITTED, so the cap has to
      // be a bound the whole run can honour rather than lib/wasm64.mjs's very large
      // default: one invocation may then dispatch at most as many blocks as the run
      // has instruction budget. It is a constant for the run, so it does not
      // perturb the compiled-module cache key from call to call.
      ...(shared === null ? { region: regionSpec } : context.tierCompileOption),
    });
  } catch {
    return null; // any codegen/instantiation surprise → interpreter tier, never a wrong result
  }
  // DISCARD. The Machine's registers/flags/xmm are left untouched and rip stays on
  // the call, so the interpreter re-runs the callee from its entry.
  //
  // A discard is only sound while the module ran on a PRIVATE copy of the guest.
  // On the shared memory the run's stores are already in the guest and cannot be
  // un-done, and re-execution is NOT idempotent — a `inc [mem]` the aborted run
  // applied would be applied a second time. So on the shared memory nothing that
  // executed a guest instruction may be discarded:
  //
  //   * FAULT is not a discard any more. lib/wasm64.mjs's complete modules report
  //     `preciseFault`: they leave AT the out-of-region access having performed
  //     none of its effects, so the state is exactly interpretation's state at
  //     that instruction and is committed like any other resume. The interpreter
  //     then executes that access and faults on it honestly.
  //   * The iteration cap is discarded ONLY on a private memory (see below); on
  //     the shared memory it is committed, which is equally honest — the cap exit
  //     is a block boundary with a valid resume rip, and the runner's own
  //     instruction budget still bounds the whole run.
  const discardable = shared === null;
  if (jit.statusName === "fault" && (discardable || jit.preciseFault !== true)) return null;
  if (jit.statusName === "budget_exhausted" && discardable) return null;
  if (jit.statusName !== "ok" && !jit.resumable) return null; // defensive: never commit what wasm64 will not vouch for

  // ---- commit: the module's architectural state becomes the Machine's ----
  for (let i = 0; i < 16; i += 1) machine.reg[i] = jit.register[NAME64[i]] & MASK64;
  machine.flagSource = { kind: "explicit", value: { cf: jit.flag.cf, pf: jit.flag.pf, af: jit.flag.af, zf: jit.flag.zf, sf: jit.flag.sf, of: jit.flag.of } };
  for (let i = 0; i < 16; i += 1) machine.xmm[i] = jit.xmm[i] & MASK128;

  // On the SHARED memory there is nothing to copy: the module ran on the guest's
  // own bytes, so every store it made is already in the Machine's regions. That
  // deletion is the whole point — the copy this replaces was proportional to the
  // TOTAL mapped map (~100 MiB for PuTTY) on every single invocation.
  if (shared === null) {
    // Copy each region's post-run bytes back out of the module's compact memory,
    // deduplicating shared buffers (the image and its low alias are one buffer) so a
    // stale alias read cannot clobber a real image write.
    const done = new Set();
    for (const jr of jit.region) {
      const jbase = jr.base & MASK64;
      const mr = context.region.find((r) => (r.base & MASK64) === jbase);
      if (!mr || done.has(mr.buf)) continue;
      done.add(mr.buf);
      const len = Math.min(jr.size, mr.buf.length);
      mr.buf.set(jit.mem.subarray(jr.wasmOffset, jr.wasmOffset + len), 0);
    }
    // The seedState sentinel at the stack top (stackTop-8) is a WASM-only artifact
    // above the live frame; restore those 8 bytes to their pre-run value so the
    // stack region stays bit-exact with pure interpretation.
    const topOff = stackSize - 24;
    if (topOff >= 0 && topOff + 8 <= stackSize) stackRegion.buf.set(stackCopy.subarray(topOff, topOff + 8), topOff);
  }

  if (jit.statusName === "ok") {
    // The interpreter leaves the pushed return address resident at [origRsp-8]
    // after the callee's RET; reproduce that residual exactly.
    machine.writeMem(rspForWasm, 8, realRet);
    machine.rip = realRet;
    return "ok";
  }

  // A RESUMABLE mid-function exit. The callee's frame is still LIVE, so the return
  // address the interpreter pushed is still on the stack — as the WASM-only
  // sentinel. Rewrite it to the real return address so the frame is exactly the one
  // interpretation would have built. If the guest overwrote that slot itself the
  // committed bytes are already the guest's own, so leave them: interpretation would
  // have computed the same value into the same slot.
  if (machine.readMem(rspForWasm, 8) === sentinel) machine.writeMem(rspForWasm, 8, realRet);
  machine.rip = jit.resumeRip & MASK64;
  return "resume";
}

function snapshotMachine(context) {
  const m = context.machine;
  return { reg: m.reg.slice(), xmm: m.xmm.slice(), flagSource: m.flagSource, df: m.df, rip: m.rip, region: context.region.map((r) => Buffer.from(r.buf)) };
}
function restoreMachine(context, s) {
  const m = context.machine;
  for (let i = 0; i < 16; i += 1) { m.reg[i] = s.reg[i]; m.xmm[i] = s.xmm[i]; }
  m.flagSource = s.flagSource; m.df = s.df; m.rip = s.rip;
  context.region.forEach((r, idx) => s.region[idx].copy(r.buf));
}
function interpretUntilReturn(context, returnRip, cap) {
  const { machine, imageBuf, loadBase, importSet } = context;
  for (let n = 0; n < cap; n += 1) {
    if (machine.rip === returnRip) return true;
    const rvaOffset = machine.rip - loadBase;
    if (rvaOffset < 0n || rvaOffset >= BigInt(imageBuf.length)) return false;
    const { node, segment } = decodeWithSegment(imageBuf, Number(rvaOffset));
    if (node.op === "truncated" || !node.served) return false;
    machine.segmentBase = segment === "gs" ? machine.gsBase : segment === "fs" ? machine.fsBase : 0n;
    if (executeNode(machine, node, machine.rip + BigInt(node.length), importSet)) return false;
  }
  return false;
}
function auditDiff(context, wasmSnap) {
  const m = context.machine;
  const diff = [];
  for (let i = 0; i < 16; i += 1) if ((m.reg[i] & MASK64) !== (wasmSnap.reg[i] & MASK64)) diff.push(`reg ${NAME64[i]} interp=0x${(m.reg[i] & MASK64).toString(16)} wasm=0x${(wasmSnap.reg[i] & MASK64).toString(16)}`);
  const fi = materializeFlag(m.flagSource), fw = materializeFlag(wasmSnap.flagSource);
  for (const f of ["cf", "pf", "af", "zf", "sf", "of"]) if (fi[f] !== fw[f]) diff.push(`flag ${f} interp=${fi[f]} wasm=${fw[f]}`);
  context.region.forEach((r, idx) => {
    const w = wasmSnap.region[idx];
    for (let k = 0; k < r.buf.length; k += 1) if (r.buf[k] !== w[k]) { diff.push(`region#${idx} base=0x${(r.base & MASK64).toString(16)} off=0x${k.toString(16)} interp=0x${r.buf[k].toString(16)} wasm=0x${w[k].toString(16)}`); return; }
  });
  return diff;
}

// Drives a mapped PE image tier-by-tier over ONE shared guest state. `option` is
// the SAME shape lib/exec64.mjs buildGuestContext64 / runImage64 accept. When
// `option.forceInterpreter` is set the WASM tier is disabled — the run is then a
// pure interpretation used to anchor the bit-exact comparison and to expose guest
// memory the interpreter surface does not otherwise return.
export function runTieredImage(option) {
  const forceInterpreter = option.forceInterpreter === true;
  // ONE guest memory for both engines. Asking buildGuestContext64 to place the
  // interpreter's region buffers inside the WebAssembly.Memory the tier's modules
  // import makes a tier transition a register/rip handoff instead of a copy of the
  // whole guest map — which is what turns compile eligibility into throughput.
  // Pure interpretation never asks for it, so it pays nothing; and if the map
  // cannot be placed in a 32-bit WASM memory the context comes back with private
  // buffers and the tier falls back to the copy path unchanged.
  const context = buildGuestContext64({ ...option, sharedGuestMemory: !forceInterpreter });
  const { machine, hleContext, unservedSentinel, loadBase, budget, importSet } = context;
  const imageBuf = context.imageBuf;
  const sharedPlan = forceInterpreter ? null : (context.sharedPlan ?? null);
  // The option every WASM-tier compilation for this run shares (everything but the
  // entry). Held once so the eligibility compile and the invocation compile agree
  // byte-for-byte and hit the same cache entry.
  const tierCompileOption = sharedPlan === null ? null : {
    loadBase, decodeStructured, region: sharedPlan.region, sharedPlan,
    iterationCap: Math.max(1, budget | 0),
  };
  context.tierCompileOption = tierCompileOption;

  const tierDecision = new Map(); // entry VA → "wasm" | "interpreter"
  const wasmEntry = new Set();
  const interpEntry = new Set();
  let wasmInvocation = 0;
  let wasmResume = 0;
  let interpInstruction = 0;

  const decideTier = (target) => {
    if (tierDecision.has(target)) return tierDecision.get(target);
    let decision = "interpreter";
    const entryRva = Number((target - loadBase) & MASK64);
    if (entryRva >= 0 && entryRva < imageBuf.length) {
      try {
        // Compile through the SAME cache and with the SAME option the invocation
        // will use, so deciding eligibility IS the compile the run then reuses.
        // Compiling twice per function was the largest remaining cost once the
        // per-invocation guest copy was gone.
        const compiled = sharedPlan === null
          ? compileFunction(imageBuf, { loadBase, decodeStructured, entryRva, guestLen: imageBuf.length + (context.layout.stack.size_byte ?? 0x10000) })
          : compileFunctionCached(imageBuf, { ...tierCompileOption, entryRva });
        const badReason = new Set((compiled.coverage.unsupported ?? []).map((u) => u.reason));
        const hasUnservedBoundary = badReason.has("control_call_external") || badReason.has("not_served");
        // An indirect jmp/call is NOT a reason to refuse the WASM tier any more. It
        // compiles as a return-to-dispatch terminator, and runWasmTierFunction now
        // COMMITS that exit and continues at the module's resume rip — so everything
        // the function does before the transfer really runs at WASM speed instead of
        // being re-interpreted from the entry. The decision is cached per entry VA,
        // and lib/wasm64.mjs caches the compiled module per entry, so a function that
        // exits at an indirect on every call never re-compiles.
        if (compiled.complete && !hasUnservedBoundary) decision = "wasm";
      } catch { decision = "interpreter"; }
    }
    tierDecision.set(target, decision);
    return decision;
  };

  let stopReason = "instruction_budget_exhausted";
  let fault = null;
  let reachedImport = null;
  let instructionCount = 0;
  const trace = option.trace ? [] : null;

  const mapHleStop = (stop) => {
    stopReason = stop.reason;
    fault = stop.reason === "hle_fault"
      ? { message: stop.message, code: stop.code, address: machine.rip }
      : { message: `The guest ${stop.reason === "process_exit" ? `ended its own process with code 0x${stop.exit_code.toString(16)}` : `raised unhandled exception 0x${stop.exception_code.toString(16)}`}`, address: machine.rip, ...(stop.exit_code !== undefined ? { exit_code: stop.exit_code } : {}), ...(stop.exception_code !== undefined ? { exception_code: stop.exception_code } : {}) };
  };

  try {
    for (; instructionCount < budget; instructionCount += 1) {
      // A guest register-indirect call/jump through an unserved import's IAT slot
      // lands rip on that import's sentinel: the clean import frontier.
      if (unservedSentinel.size > 0 && unservedSentinel.has(machine.rip)) {
        const entry = unservedSentinel.get(machine.rip);
        instructionCount += 1;
        stopReason = "import_present";
        reachedImport = { library: entry.library, symbol: entry.symbol, ordinal: entry.ordinal ?? null, iat_slot_rva: entry.iat_slot_rva ?? null };
        break;
      }
      // The CRT-initializer / dialog resume sentinels: lib/exec64.mjs drives these
      // through private multi-step resumes this runner does not host. Refuse
      // honestly rather than fault or mis-serve (never reached on the corpus proof).
      if (machine.rip === initReturnSentinel || machine.rip === dialogReturnSentinel) {
        stopReason = "tier_unsupported_specialization";
        fault = { message: "the tiered runner does not drive the CRT-initializer / dialog resume path", address: machine.rip };
        break;
      }
      // A guest indirect call/jump through a bound IAT slot lands rip on an HLE
      // thunk. Serve it through the SAME marshal the interpreter loop uses.
      if (hleContext !== null && machine.rip <= 0xffffffffn && hleContext.guest.isThunk(Number(machine.rip))) {
        const entry = hleContext.guest.exportAt(Number(machine.rip));
        if (isSpecializationSymbol(entry.symbol)) {
          stopReason = "tier_unsupported_specialization";
          fault = { message: `the tiered runner does not drive the ${entry.symbol} specialization`, address: machine.rip };
          break;
        }
        const served = serveImportAt64(context, machine.rip);
        if (served.served && served.stop === undefined) continue;
        if (served.served) { instructionCount += 1; mapHleStop(served.stop); break; }
        instructionCount += 1;
        stopReason = "import_present";
        reachedImport = served.import;
        break;
      }

      const rvaOffset = machine.rip - loadBase;
      if (rvaOffset < 0n || rvaOffset >= BigInt(imageBuf.length)) {
        stopReason = "fault";
        fault = { message: `instruction pointer 0x${machine.rip.toString(16)} is outside the mapped image`, address: machine.rip };
        break;
      }
      const { node, segment } = decodeWithSegment(imageBuf, Number(rvaOffset));
      if (node.op === "truncated") {
        stopReason = "fault";
        fault = { message: `instruction at 0x${machine.rip.toString(16)} is truncated at the image edge`, address: machine.rip };
        break;
      }
      if (!node.served) {
        stopReason = "unsupported_opcode";
        fault = { message: `unsupported opcode 0x${(node.opcode ?? 0).toString(16)}`, opcode: node.opcode ?? null, opcode_text: node.opcodeText ?? null, address: machine.rip };
        break;
      }

      // Tier decision at a direct call: a pure-compute callee runs WASM-tier.
      if (node.op === "call") {
        const target = (machine.rip + BigInt(node.length) + BigInt(node.rel)) & MASK64;
        if (!forceInterpreter && decideTier(target) === "wasm") {
          const auditSnap = option.wasmAudit ? snapshotMachine(context) : null;
          const outcome = runWasmTierFunction(context, target, node);
          if (outcome !== null) {
            if (option.wasmAudit) {
              const wasmSnap = snapshotMachine(context);
              restoreMachine(context, auditSnap);
              // wasmSnap.rip is the callee's return address on an "ok" run and the
              // module's resume rip on a "resume" run; either way interpretation
              // from the call must reach it and agree on every surface.
              const ok = interpretUntilReturn(context, wasmSnap.rip, 4_000_000);
              if (!ok) { throw new Error(`wasmAudit: interpreter could not reach return 0x${wasmSnap.rip.toString(16)} for callee 0x${target.toString(16)}`); }
              const diff = auditDiff(context, wasmSnap);
              if (diff.length) { throw new Error(`wasmAudit: WASM tier diverges for callee 0x${target.toString(16)} (invocation ${wasmInvocation + 1}):\n  ${diff.slice(0, 8).join("\n  ")}`); }
              restoreMachine(context, wasmSnap);
            }
            wasmInvocation += 1;
            if (outcome === "resume") {
              wasmResume += 1;
              // NO PROGRESS. The module stopped at the callee's very first
              // instruction — the entry block is nothing but an indirect transfer
              // (an import thunk's `jmp [iat]` is exactly this shape). Running a
              // WASM module to execute zero guest instructions is pure overhead on
              // every future call, so demote the entry to the interpreter for good.
              // Correctness is unaffected either way: this only picks the engine.
              if (machine.rip === target) tierDecision.set(target, "interpreter");
            }
            wasmEntry.add(target);
            continue;
          }
          // The run was discarded: interpret the call instead (state untouched).
          if (!wasmEntry.has(target)) interpEntry.add(target);
        } else {
          interpEntry.add(target);
        }
      }

      machine.segmentBase = segment === "gs" ? machine.gsBase : segment === "fs" ? machine.fsBase : 0n;
      if (trace) trace.push({ i: instructionCount, rip: `0x${machine.rip.toString(16)}`, op: node.op });
      const nextRip = machine.rip + BigInt(node.length);
      const stop = executeNode(machine, node, nextRip, importSet);
      interpInstruction += 1;
      if (stop) {
        if (stop.reason === "import_present" && hleContext !== null) {
          if (isSpecializationSymbol(stop.import.symbol)) {
            stopReason = "tier_unsupported_specialization";
            fault = { message: `the tiered runner does not drive the ${stop.import.symbol} specialization`, address: machine.rip };
            break;
          }
          const dispatch = serveImport64(machine, stop, nextRip, hleContext);
          if (dispatch.served && dispatch.stop === undefined) continue;
          if (dispatch.served) { instructionCount += 1; mapHleStop(dispatch.stop); break; }
          instructionCount += 1;
          stopReason = "import_present";
          reachedImport = stop.import;
          break;
        }
        if (stop.reason === "entry_return") { stopReason = "entry_return"; break; }
        instructionCount += 1;
        stopReason = stop.reason;
        reachedImport = stop.import ?? null;
        break;
      }
    }
  } catch (error) {
    // A guest fault stops the run the way lib/exec64.mjs runImage64 stops it, with
    // stop_reason "fault" — the 1:1 contract this file exists for. The Machine here
    // is exec64's, and exec64 does not export its own FaultError class, so a guest
    // memory fault raised inside the Machine is matched by constructor name; the
    // class above is the one this file's own executor raises.
    if (error instanceof FaultError || error?.constructor?.name === "FaultError") {
      stopReason = "fault";
      fault = { message: error.message, address: machine.rip };
    } else {
      throw error;
    }
  }

  const register = {};
  for (let i = 0; i < 16; i += 1) register[NAME64[i]] = machine.reg[i] & MASK64;
  const regionSnapshot = context.region.map((r) => ({ base: r.base & MASK64, bytes: Buffer.from(r.buf) }));

  return {
    register,
    flag: machine.flags(),
    rip: machine.rip & MASK64,
    stop_reason: stopReason,
    instruction_count: instructionCount,
    exception: fault,
    reached_import: reachedImport,
    region: regionSnapshot,
    machine,
    trace,
    tier_report: {
      wasm_tier_function: wasmEntry.size,
      interpreter_tier_function: interpEntry.size,
      wasm_tier_invocation: wasmInvocation,
      wasm_tier_resume: wasmResume,
      interpreter_tier_instruction: interpInstruction,
      wasm_tier_entry: [...wasmEntry].map((v) => `0x${v.toString(16)}`),
    },
  };
}
