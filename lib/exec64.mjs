// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The x86-64 bounded execution harness for runtime v2 (BPTK-031 /
// doc/runtime-v2-scope.md). Today a PE32+ image only LOADS: lib/pe64.mjs maps
// it and stops. This drives the mapped entry point through the lib/lift64.mjs
// lifter (decodeStructured) and an interpreter that mirrors that file's oracle,
// bounded by an instruction budget — the x86-64 analog of the i386 bounded
// probe. It sets up a bounded guest stack, a 64-bit register file (rsp at the
// stack top, rip at entry), and a minimal gs-based TEB/PEB (x86-64 reads the
// PEB through gs:[0x60] and the TEB self pointer through gs:[0x30], not fs), and
// resolves gs-relative accesses to that region.
//
// It STOPS structured on the first import/IAT indirect call (state
// import_present — no Win64 HLE is invented here, that is milestone M4), an
// unsupported IR node (the opcode is named), a memory/decode fault (named), or
// budget exhaustion. It returns a result shaped like the i386 probe so the run
// surface and corpus read x86-64 and i386 uniformly: state probe_executed the
// moment one instruction runs, probe_blocked otherwise. is_executed and
// instruction_count reflect instructions the interpreter actually ran — an
// import call is an honest structured stop, never a faked return.
//
// The interpreter semantics are ported from lib/lift64.mjs (the M2 oracle) and
// extended with a multi-region address space (image, stack, TEB/PEB), gs/fs
// segment resolution, and IAT-slot detection; lib/lift64.mjs stays read-only.

import { decodeStructured, materializeFlag } from "./lift64.mjs";
import { executionBoundDefault } from "./bound.mjs";

const MASK64 = (1n << 64n) - 1n;
const RSP = 4;
const RBP = 5;
const NAME64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];

// The guest address plan. The image maps at its load base; the stack and the
// TEB/PEB region sit at fixed high addresses that never collide with a mapped
// PE32+ image (image bases live far below), and the return sentinel is outside
// every region so the entry RET is detected, never dereferenced.
const stackRegionBase = 0x00007ff000000000n;
const tebRegionBase = 0x00007ff800000000n;
const stackSizeDefault = 0x00100000; // 1 MiB — enough for a CRT prologue, capped by the execution bound
const tebRegionSizeByte = 0x2000; // TEB in the low page, PEB in the high page
const pebOffsetByte = 0x1000n;
const returnSentinel = 0xdead000000000000n;

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

// The set of legacy prefix bytes, and the two segment-override bytes the
// x86-64 CRT actually uses. lib/lift64.mjs decodeStructured refuses a segment
// prefix (it is not part of the M2 lift subset), so this harness strips the one
// segment byte, decodes the remainder, and resolves the operand through the
// segment base itself — the only way to serve gs:[…] without editing the oracle.
const LEGACY_PREFIX = new Set([0x66, 0x67, 0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65]);

// Decodes one instruction at `rva`, transparently handling a single fs/gs
// segment override. Returns the lifted node plus the segment name (or null).
function decodeWithSegment(mem, rva) {
  let scan = rva;
  let segment = null;
  let segmentPos = -1;
  for (let guard = 0; guard < 15 && scan < mem.length; guard += 1) {
    const byte = mem[scan];
    if (!LEGACY_PREFIX.has(byte)) break;
    if (byte === 0x64) { segment = "fs"; segmentPos = scan; }
    else if (byte === 0x65) { segment = "gs"; segmentPos = scan; }
    scan += 1;
  }
  if (segment === null) return { node: decodeStructured(mem, rva), segment: null };
  // Rebuild the instruction bytes without the single segment-override byte so
  // the oracle decoder lifts the underlying operation; the stripped byte is
  // re-added to the reported length.
  const window = mem.subarray(rva, Math.min(rva + 15, mem.length));
  const stripped = Buffer.alloc(window.length - 1);
  const relative = segmentPos - rva;
  window.copy(stripped, 0, 0, relative);
  window.copy(stripped, relative, relative + 1);
  const node = decodeStructured(stripped, 0);
  return { node: { ...node, length: node.length + 1 }, segment };
}

// A flat multi-region guest address space plus a 16-entry 64-bit register file,
// mirroring the lib/lift64.mjs Machine and extending it with named regions and a
// per-instruction segment base for gs/fs resolution.
class Machine {
  constructor(region) {
    this.region = region; // [{ base, buf }]
    this.reg = new Array(16).fill(0n);
    this.rip = 0n;
    this.flagSource = null;
    this.segmentBase = 0n;
    this.gsBase = 0n;
    this.fsBase = 0n;
  }

  flags() {
    return materializeFlag(this.flagSource);
  }

  locate(address, sizeByte) {
    for (const region of this.region) {
      const end = region.base + BigInt(region.buf.length);
      if (address >= region.base && address + BigInt(sizeByte) <= end) {
        return { buf: region.buf, off: Number(address - region.base) };
      }
    }
    throw new FaultError(`guest address 0x${address.toString(16)} is outside the mapped memory`);
  }

  readMem(address, sizeByte) {
    const { buf, off } = this.locate(address, sizeByte);
    let v = 0n;
    for (let i = 0; i < sizeByte; i += 1) v |= BigInt(buf[off + i]) << (8n * BigInt(i));
    return v;
  }

  writeMem(address, sizeByte, value) {
    const { buf, off } = this.locate(address, sizeByte);
    for (let i = 0; i < sizeByte; i += 1) buf[off + i] = Number((value >> (8n * BigInt(i))) & 0xffn);
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
    return (addr + this.segmentBase) & MASK64;
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
      // LEA computes the address arithmetic only; a segment base never applies.
      machine.writeReg(node.dst, (machine.effectiveAddress(node.src, nextRip) - machine.segmentBase) & sizeMask(node.size));
      machine.rip = nextRip;
      return null;
    case "alu":
      executeAlu(machine, node, nextRip);
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
        if (reached) return { reason: "import_present", import: reached };
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
        if (reached) return { reason: "import_present", import: reached };
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
    default:
      throw new FaultError(`unhandled node op ${node.op}`);
  }
}

// Builds the minimal gs-based TEB/PEB region. x86-64 reads the PEB through
// gs:[0x60] and the TEB self pointer through gs:[0x30]; StackBase/StackLimit
// live at TEB+0x08/+0x10 and the PEB carries the image base at +0x10.
function buildTeb(stackLow, stackHigh, loadBase) {
  const buf = Buffer.alloc(tebRegionSizeByte);
  const pebBase = tebRegionBase + pebOffsetByte;
  const put = (offset, value) => buf.writeBigUInt64LE(value & MASK64, offset);
  put(0x08, stackHigh); // NT_TIB.StackBase
  put(0x10, stackLow); // NT_TIB.StackLimit
  put(0x30, tebRegionBase); // NT_TIB.Self
  put(0x60, pebBase); // TEB.ProcessEnvironmentBlock
  put(Number(pebOffsetByte) + 0x10, loadBase); // PEB.ImageBaseAddress
  return { buf, tebBase: tebRegionBase, pebBase };
}

// Interprets an image buffer from an entry RVA over a fresh register file and a
// three-region address space (image, bounded stack, gs-based TEB/PEB), bounded
// by an instruction budget. `importSet` maps an IAT slot address to its import
// entry; reaching one is a structured import_present stop. This is the core the
// PE32+ probe and the test microprograms share.
export function runImage64(option) {
  const image = option.image;
  if (!Buffer.isBuffer(image) && !(image instanceof Uint8Array)) throw new TypeError("runImage64 requires an image buffer");
  const loadBase = BigInt(option.loadBase ?? 0x140000000n);
  const entryRva = option.entryRva ?? 0;
  const budget = option.budget ?? 100000;
  const stackSizeByte = Math.min(option.stackSizeByte ?? stackSizeDefault, executionBoundDefault.stack_byte);
  const importSet = option.importSet ?? new Map();

  const imageBuf = Buffer.from(image); // a private copy: guest writes never mutate the caller's image
  const stackBuf = Buffer.alloc(stackSizeByte);
  const stackLow = stackRegionBase;
  const stackHigh = stackRegionBase + BigInt(stackSizeByte);
  const teb = buildTeb(stackLow, stackHigh, loadBase);

  const region = [
    { base: loadBase, buf: imageBuf },
    { base: stackRegionBase, buf: stackBuf },
    { base: tebRegionBase, buf: teb.buf },
  ];
  const machine = new Machine(region);
  machine.gsBase = teb.tebBase;
  machine.fsBase = teb.tebBase;

  // rsp at a 16-aligned stack top with the return sentinel pushed, so the entry
  // RET stops the harness rather than running off into unmapped memory.
  const stackTop = (stackHigh - 0x100n) & ~0xfn;
  const balancedRsp = stackTop;
  machine.reg[RSP] = stackTop - 8n;
  machine.writeMem(machine.reg[RSP], 8, returnSentinel);
  machine.rip = loadBase + BigInt(entryRva);

  let instructionCount = 0;
  let stopReason = "instruction_budget_exhausted";
  let fault = null;
  let reachedImport = null;

  try {
    for (; instructionCount < budget; instructionCount += 1) {
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

      machine.segmentBase = segment === "gs" ? machine.gsBase : segment === "fs" ? machine.fsBase : 0n;
      const nextRip = machine.rip + BigInt(node.length);
      const stop = executeNode(machine, node, nextRip, importSet);
      if (stop) {
        instructionCount += 1;
        stopReason = stop.reason;
        reachedImport = stop.import;
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
    instruction_count: instructionCount,
    is_executed: instructionCount > 0,
    balanced_rsp: balancedRsp,
    exception: fault,
    reached_import: reachedImport,
    teb: { teb_base: teb.tebBase, peb_base: teb.pebBase, stack_base: stackHigh, stack_limit: stackLow },
  };
}

// Drives a mapPe64State(...) result through the bounded x86-64 interpreter and
// returns a run-surface-shaped result: probe_executed the moment one x86-64
// instruction runs, probe_blocked otherwise. The stop is always structured —
// an import reached at an IAT slot, an unsupported opcode named, a memory fault
// named, or budget exhaustion. No import is served (that is milestone M4): an
// import is an honest structured stop, never a faked return.
export function executeProbe64(mapped, instructionBudgetCount, option = {}) {
  if (typeof mapped !== "object" || mapped === null || !("image" in mapped)) {
    throw new TypeError("executeProbe64 requires a mapPe64State result");
  }
  const budget = Math.min(instructionBudgetCount, executionBoundDefault.instruction_count);
  const importSet = new Map();
  for (const entry of mapped.import ?? []) {
    importSet.set((mapped.load_base + BigInt(entry.iat_slot_rva)) & MASK64, entry);
  }

  const run = runImage64({
    image: mapped.image,
    loadBase: mapped.load_base,
    entryRva: mapped.entry_rva,
    budget,
    stackSizeByte: option.stackSizeByte,
    importSet,
  });

  const state = run.instruction_count > 0 ? "probe_executed" : "probe_blocked";
  const importReached = run.reached_import
    ? { library: run.reached_import.library, symbol: run.reached_import.symbol, ordinal: run.reached_import.ordinal, iat_slot_rva: run.reached_import.iat_slot_rva }
    : null;
  const runtimeBlocker = [];
  if (run.stop_reason === "import_present" && importReached) {
    runtimeBlocker.push(`Execution reached ${importReached.library}!${importReached.symbol ?? `#${importReached.ordinal}`} through its IAT slot; the Win64 HLE that would serve it is milestone M4 and is not built`);
  } else if (run.stop_reason === "unsupported_opcode") {
    runtimeBlocker.push(`Execution reached an unsupported x86-64 opcode 0x${(run.exception?.opcode ?? 0).toString(16)}; the served lift subset is bounded`);
  } else if (run.stop_reason === "fault") {
    runtimeBlocker.push(`Execution faulted: ${run.exception?.message ?? "unnamed fault"}`);
  } else if (run.stop_reason === "instruction_budget_exhausted") {
    runtimeBlocker.push(`Execution exhausted the ${budget} instruction budget before a structured stop`);
  }

  const register = {};
  for (const name of NAME64) register[name] = `0x${run.register[name].toString(16)}`;

  return {
    state,
    execution_profile: "i386_probe_v1",
    register,
    flag: run.flag,
    rip: `0x${run.rip.toString(16)}`,
    instruction_count: run.instruction_count,
    stop_reason: run.stop_reason,
    is_executed: run.instruction_count > 0,
    import_reached: importReached,
    exception: run.exception,
    thread: { teb_base: `0x${run.teb.teb_base.toString(16)}`, peb_base: `0x${run.teb.peb_base.toString(16)}`, stack_base: `0x${run.teb.stack_base.toString(16)}`, stack_limit: `0x${run.teb.stack_limit.toString(16)}` },
    runtime_blocker: runtimeBlocker,
    blocker: mapped.resolution_blocker ?? [],
  };
}
