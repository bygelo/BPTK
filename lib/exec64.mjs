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

import { decodeStructured, materializeFlag, executeSse, executeCpuid, executeCmpxchg, executeExtra, executeString, executeX87, createX87State } from "./lift64.mjs";
import { executionBoundDefault } from "./bound.mjs";
import { createWin32Hle, createHleLayout, isHleSignal } from "./hle.mjs";
import { createGuestClock } from "./clock.mjs";
import { loadDialogTemplate } from "./rsrc.mjs";
import { windowMessage } from "./user.mjs";
import { createSharedGuestPlan } from "./wasm64.mjs";

const MASK64 = (1n << 64n) - 1n;
const MASK128 = (1n << 128n) - 1n;
// The BigInt form of every access width x86-64 uses, so a bounds test never has to
// allocate one. `locate` runs tens of millions of times on a real binary.
const SIZE_BIG = [0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n, 11n, 12n, 13n, 14n, 15n, 16n];
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
const tebRegionSizeByte = 0x4000; // TEB, PEB, then the TLS array and one TLS block
const pebOffsetByte = 0x1000n;
const tlsArrayOffsetByte = 0x2000n; // the module TLS array (TEB.ThreadLocalStoragePointer target)
const tlsBlockOffsetByte = 0x3000n; // one bounded, zeroed per-module TLS block
const tlsSlotCount = 64;
const returnSentinel = 0xdead000000000000n;
// The return sentinel for a CRT initializer invoked by _initterm/_initterm_e.
// It sits outside every mapped region (like returnSentinel) so an initializer's
// final RET lands here and the harness advances to the next initializer or back
// to the caller, rather than dereferencing it.
const initReturnSentinel = 0xdead000000000010n;
// The return sentinel for a guest window/dialog procedure the harness invokes
// as real guest control flow (WM_INITDIALOG at CreateDialog, and every message
// the loop dispatches). It sits outside every mapped region, like the other
// sentinels, so the guest WndProc's final RET lands here and the harness
// resumes the caller (the CreateDialog site, or the DispatchMessage site).
const dialogReturnSentinel = 0xdead000000000020n;
// The base of the per-import "unserved" sentinel band. Each import the Win32
// core HLE does not serve binds its IAT slot to base+index*8, an address that
// sits below the HLE block (arena/virtual/thunk start at 0xF8000000) and above
// the truncated image alias (loadBase & 0xffffffff), so it collides with no
// mapped region. A register-indirect call through such a slot lands here and the
// loop reports import_present for that exact symbol instead of faulting on the
// raw import-name RVA the slot otherwise held.
const unservedImportSentinelBase = 0x00000000e0000000n;

// The USER32 window/dialog-creation exports the harness serves by instantiating
// the real RT_DIALOG template and re-entering the guest dialog procedure, rather
// than through the JS export marshal (a guest DlgProc pointer cannot be called
// from JS — it is guest code driven by this interpreter). CreateDialogParam is
// modeless (returns the HWND); DialogBoxParam is modal (its own message pump).
const DIALOG_CREATE_SYMBOL = new Set(["CreateDialogParamA", "CreateDialogParamW", "DialogBoxParamA", "DialogBoxParamW"]);
const DIALOG_MODAL_SYMBOL = new Set(["DialogBoxParamA", "DialogBoxParamW"]);
// The message-loop exports the x64 pump intercepts so a message dispatched to a
// window that carries a guest WndProc re-enters guest code (real WndProc
// dispatch), and the MSG struct is marshaled in the 64-bit layout the guest
// reads rather than the 32-bit layout the shared i386 export table writes.
const DISPATCH_SYMBOL = new Set(["DispatchMessageA", "DispatchMessageW"]);
const GETMESSAGE_SYMBOL = new Set(["GetMessageA", "GetMessageW"]);
const PEEKMESSAGE_SYMBOL = new Set(["PeekMessageA", "PeekMessageW"]);

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

// Strip one byte at `bytePos` from the 15-byte window at `rva`, decode the
// remainder through the oracle, and re-add the stripped byte to the length. The
// shared primitive behind both the segment-override strip and the BND-prefix
// strip below.
function decodeWithoutByte(mem, rva, bytePos) {
  const window = mem.subarray(rva, Math.min(rva + 15, mem.length));
  const stripped = Buffer.alloc(window.length - 1);
  const relative = bytePos - rva;
  window.copy(stripped, 0, 0, relative);
  window.copy(stripped, relative, relative + 1);
  const node = decodeStructured(stripped, 0);
  return { ...node, length: node.length + 1 };
}

// The MSVC/CET BND prefix (0xf2) that decorates a control-transfer instruction
// (bnd call/jmp/ret/jcc). It is a no-op for the branch semantics but lib/x64decode
// refuses it, so like the segment strip this harness removes it before the
// oracle decodes — but only when the byte after it is genuinely a branch opcode,
// never when 0xf2 is a REPNZ string prefix or an SSE mandatory prefix.
const BRANCH_OPCODE = new Set([0xe8, 0xe9, 0xeb, 0xc2, 0xc3, 0xff]);
function isBranchAfterBnd(mem, opcodePos) {
  const opcode = mem[opcodePos];
  if (opcode >= 0x70 && opcode <= 0x7f) return true; // short jcc
  if (BRANCH_OPCODE.has(opcode)) return true; // call/jmp/ret (direct or indirect)
  if (opcode === 0x0f) { const second = mem[opcodePos + 1]; return second >= 0x80 && second <= 0x8f; } // near jcc
  return false;
}

// Decodes one instruction at `rva`, transparently handling a single fs/gs
// segment override and a single BND (0xf2) branch prefix. Returns the lifted
// node plus the segment name (or null).
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
    // The CS/SS/DS/ES segment overrides have a flat zero base in 64-bit mode, so
    // they never change an address; the CRT still emits one (0x2e) as the padding
    // byte of a multi-byte NOP, and as a branch hint. decodeStructured refuses a
    // segment prefix, so this harness strips the single flat-segment byte and
    // decodes the remainder with the ordinary base-0 resolution (segment null).
    else if (byte === 0x2e || byte === 0x36 || byte === 0x3e || byte === 0x26) { flatSegmentPos = scan; }
    else if (byte === 0xf2) { bndPos = scan; }
    scan += 1;
  }
  // A BND prefix before a branch: strip it (the branch semantics are unchanged).
  // Only when no segment override is also present — that pairing does not occur
  // in the CRT and keeps the strip to one byte.
  if (segment === null && bndPos !== -1 && scan < mem.length && isBranchAfterBnd(mem, scan)) {
    return { node: decodeWithoutByte(mem, rva, bndPos), segment: null };
  }
  // A flat-base (CS/SS/DS/ES) segment override with no fs/gs override: strip the
  // one byte and decode the remainder at base 0.
  if (segment === null && flatSegmentPos !== -1) {
    return { node: decodeWithoutByte(mem, rva, flatSegmentPos), segment: null };
  }
  if (segment === null) return { node: decodeStructured(mem, rva), segment: null };
  // Rebuild the instruction bytes without the single segment-override byte so
  // the oracle decoder lifts the underlying operation; the stripped byte is
  // re-added to the reported length.
  return { node: decodeWithoutByte(mem, rva, segmentPos), segment };
}

// A flat multi-region guest address space plus a 16-entry 64-bit register file,
// mirroring the lib/lift64.mjs Machine and extending it with named regions and a
// per-instruction segment base for gs/fs resolution.
class Machine {
  constructor(region) {
    this.region = region; // [{ base, buf }]
    this.reg = new Array(16).fill(0n);
    this.xmm = new Array(16).fill(0n); // sixteen 128-bit SSE registers
    this.fpu = createX87State(); // the eight-entry x87 register stack
    this.rip = 0n;
    this.flagSource = null;
    this.df = false; // the direction flag: false = forward (the CRT default)
    this.segmentBase = 0n;
    this.gsBase = 0n;
    this.fsBase = 0n;
    // The stack of in-flight _initterm/_initterm_e invocations. Each frame walks
    // one initializer table, driving the guest initializers through the same
    // interpreter loop (see startInitterm / resumeInitterm).
    this.initStack = [];
    // The stack of in-flight guest window/dialog-procedure invocations. Each
    // frame is one WndProc call the harness drives through this same interpreter
    // loop (WM_INITDIALOG at CreateDialog, or a message the loop dispatches); the
    // procedure's RET lands on dialogReturnSentinel and resumeDialog pops it.
    this.dialogStack = [];
    // locate()'s answer, left in fields rather than returned as a fresh object, plus
    // the region that answered last (guest access is overwhelmingly local).
    this.lastRegion = undefined;
    this.hitBuf = null;
    this.hitOff = 0;
    this.hitWide = false; // the hit region is a Buffer, so the native LE readers exist
  }

  flags() {
    return materializeFlag(this.flagSource);
  }

  // Resolves a guest address to (buffer, offset) in the mapped multi-region map, or
  // faults. Every guest AND host memory access in this runtime funnels through here,
  // and on a real binary that is tens of millions of calls: measured on Chocolate
  // Doom at a 20,000,000-instruction budget it was 24.6% of the whole process, the
  // single largest line in the profile, and identical in both engines.
  //
  // Three things cost that, and none of them is the search:
  //   * the region's end was recomputed as `base + BigInt(buf.length)` on EVERY
  //     region on EVERY call — an allocated BigInt per region per access, for a
  //     value that changes only if a buffer is replaced. It is memoised on the
  //     region and revalidated against `buf.length`, so a resized region still
  //     resolves correctly.
  //   * `BigInt(sizeByte)` allocated a second BigInt per call, for one of five values.
  //   * the result was returned as a fresh `{ buf, off }` object, so a hot loop
  //     allocated one object per byte touched. The answer is left in two instance
  //     fields instead and read by the two callers below.
  // Guest access is overwhelmingly LOCAL, so the region that answered last is tried
  // before the scan. The search order, the bounds test and the fault are unchanged.
  locate(address, sizeByte) {
    const need = SIZE_BIG[sizeByte] ?? BigInt(sizeByte);
    const last = this.lastRegion;
    if (last !== undefined && last.end !== undefined && last.len === last.buf.length
      && address >= last.base && address + need <= last.end) {
      this.hitBuf = last.buf;
      this.hitOff = Number(address - last.base);
      this.hitWide = last.wide;
      return;
    }
    for (const region of this.region) {
      if (region.end === undefined || region.len !== region.buf.length) {
        region.len = region.buf.length;
        region.end = region.base + BigInt(region.len);
        region.wide = Buffer.isBuffer(region.buf);
      }
      if (address >= region.base && address + need <= region.end) {
        this.lastRegion = region;
        this.hitBuf = region.buf;
        this.hitOff = Number(address - region.base);
        this.hitWide = region.wide;
        return;
      }
    }
    throw new FaultError(`guest address 0x${address.toString(16)} is outside the mapped memory`);
  }

  // The byte-at-a-time BigInt shift loop these used to run is 8 BigInt allocations
  // for one qword. Node's Buffer carries native little-endian readers for exactly
  // the four widths x86-64 asks for, and the guest map is little-endian by
  // construction, so each is one native read. The default loop still serves any
  // other width, so nothing is narrowed.
  readMem(address, sizeByte) {
    this.locate(address, sizeByte);
    const buf = this.hitBuf;
    const off = this.hitOff;
    if (sizeByte === 1) return BigInt(buf[off]);
    if (this.hitWide) {
      if (sizeByte === 8) return buf.readBigUInt64LE(off);
      if (sizeByte === 4) return BigInt(buf.readUInt32LE(off));
      if (sizeByte === 2) return BigInt(buf.readUInt16LE(off));
    }
    let v = 0n;
    for (let i = 0; i < sizeByte; i += 1) v |= BigInt(buf[off + i]) << (8n * BigInt(i));
    return v;
  }

  writeMem(address, sizeByte, value) {
    this.locate(address, sizeByte);
    const buf = this.hitBuf;
    const off = this.hitOff;
    if (sizeByte === 1) { buf[off] = Number(value & 0xffn); return; }
    if (this.hitWide) {
      if (sizeByte === 8) { buf.writeBigUInt64LE(value & MASK64, off); return; }
      if (sizeByte === 4) { buf.writeUInt32LE(Number(value & 0xffffffffn), off); return; }
      if (sizeByte === 2) { buf.writeUInt16LE(Number(value & 0xffffn), off); return; }
    }
    for (let i = 0; i < sizeByte; i += 1) buf[off + i] = Number((value >> (8n * BigInt(i))) & 0xffn);
  }

  // A CONTIGUOUS span, resolved once. `null` when the whole span does not fall in a
  // single region — the caller then falls back to the byte-at-a-time path, which
  // keeps the exact partial-effect-then-fault behaviour a straddling or unmapped
  // span has always had.
  span(address, sizeByte) {
    if (sizeByte <= 0) return null;
    try { this.locate(address, sizeByte); } catch { return null; }
    return this.hitBuf;
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
    if (operand.kind === "xmm") return this.xmm[operand.index] & MASK128;
    return this.readMem(this.effectiveAddress(operand, nextRip), operand.size / 8);
  }

  writeOperand(operand, value, nextRip) {
    if (operand.kind === "reg") this.writeReg(operand, value);
    else if (operand.kind === "xmm") this.xmm[operand.index] = value & MASK128;
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

// SHLD/SHRD: a double-precision shift of dst, filling the vacated bits from src
// rather than zero/sign. Mirrors lib/lift64.mjs executeDoubleShift bit for bit —
// count masked to the operand size, a zero count a no-op that leaves flags
// untouched, CF the last bit shifted out, SF/ZF/PF from the result, OF the
// destination sign-bit change.
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
      // The SSE/SSE2 executor is shared with lib/lift64.mjs so the bounded probe
      // and the M2 oracle cannot diverge on a lane result.
      executeSse(machine, node, nextRip);
      machine.rip = nextRip;
      return null;
    case "x87":
      // The x87 FPU executor is shared with lib/lift64.mjs, same as the SSE path.
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
      executeString(machine, node, nextRip); // manages rip itself (repeat vs advance)
      return null;
    default:
      throw new FaultError(`unhandled node op ${node.op}`);
  }
}

// Builds the minimal gs-based TEB/PEB region. x86-64 reads the PEB through
// gs:[0x60] and the TEB self pointer through gs:[0x30]; StackBase/StackLimit
// live at TEB+0x08/+0x10 and the PEB carries the image base at +0x10.
function buildTeb(stackLow, stackHigh, loadBase, target = null) {
  const buf = target ?? Buffer.alloc(tebRegionSizeByte);
  const pebBase = tebRegionBase + pebOffsetByte;
  const tlsArrayBase = tebRegionBase + tlsArrayOffsetByte;
  const tlsBlockBase = tebRegionBase + tlsBlockOffsetByte;
  const put = (offset, value) => buf.writeBigUInt64LE(value & MASK64, offset);
  put(0x08, stackHigh); // NT_TIB.StackBase
  put(0x10, stackLow); // NT_TIB.StackLimit
  put(0x30, tebRegionBase); // NT_TIB.Self
  put(0x58, tlsArrayBase); // TEB.ThreadLocalStoragePointer (x64 offset 0x58)
  put(0x60, pebBase); // TEB.ProcessEnvironmentBlock
  put(Number(pebOffsetByte) + 0x10, loadBase); // PEB.ImageBaseAddress
  // Every module TLS slot points at the single bounded, zero-filled TLS block, so
  // a `mov rax,gs:[0x58]; mov rcx,[rax+idx*8]; mov …,[rcx]` TLS access resolves
  // to real, mapped, zeroed thread-local storage rather than a null dereference.
  for (let slot = 0; slot < tlsSlotCount; slot += 1) put(Number(tlsArrayOffsetByte) + slot * 8, tlsBlockBase);
  return { buf, tebBase: tebRegionBase, pebBase };
}

// The four integer-argument registers of the Win64 calling convention, in
// order: RCX, RDX, R8, R9 (indices into NAME64). Argument five and beyond are
// read from the caller's stack above the 32-byte shadow space.
const WIN64_ARG_REG = [1, 2, 8, 9];
const SHADOW_SPACE_BYTE = 0x20n;

// A guest-memory adapter that presents the exec64 Machine's multi-region
// address space through the four primitives the Win32 core HLE requires
// (readMemory/writeMemory/readBlock/writeBlock). Addresses arrive as JS Number
// (every mapped region sits below 2^48, well inside the safe-integer range) and
// resolve through the same bounds-checked locate() the interpreter uses, so an
// out-of-range HLE access is the same structured fault as a guest access.
function createGuestMemoryAdapter(machine) {
  return {
    readMemory(address, sizeByte) {
      return Number(machine.readMem(BigInt(address), sizeByte));
    },
    writeMemory(address, sizeByte, value) {
      const stored = typeof value === "bigint" ? value : BigInt(value >>> 0);
      machine.writeMem(BigInt(address), sizeByte, stored & MASK64);
    },
    // A BLOCK is where this adapter earns or loses a run. Doom reads its WAD through
    // crt fread and presents every frame through SDL's blit and render-copy, and all
    // of it arrives here: megabytes, one call each. Byte-at-a-time these ran a full
    // multi-region address resolution AND allocated a BigInt PER BYTE — measured on
    // Chocolate Doom at a 20,000,000-instruction budget, that resolution alone was
    // 24.6% of the whole process, in BOTH engines equally.
    //
    // A span that lies inside ONE region resolves once and copies natively. A span
    // that straddles two regions, or runs off the map, falls back to the byte loop
    // so its behaviour — including the bytes already transferred before the faulting
    // one — is exactly what it has always been.
    readBlock(address, sizeByte) {
      const block = Buffer.alloc(sizeByte);
      const buf = machine.span(BigInt(address), sizeByte);
      if (buf !== null) { block.set(buf.subarray(machine.hitOff, machine.hitOff + sizeByte)); return block; }
      for (let index = 0; index < sizeByte; index += 1) block[index] = Number(machine.readMem(BigInt(address + index), 1));
      return block;
    },
    writeBlock(address, buffer) {
      const buf = machine.span(BigInt(address), buffer.length);
      if (buf !== null) { buf.set(buffer, machine.hitOff); return; }
      for (let index = 0; index < buffer.length; index += 1) machine.writeMem(BigInt(address + index), 1, BigInt(buffer[index]));
    },
  };
}

// Serves one reached import through the Win32 core HLE under the Win64 calling
// convention. The integer argument marshal from RCX/RDX/R8/R9 then the stack
// above the 32-byte shadow space; the emulator runs against the shared guest
// memory model; the 32-bit result zero-extends into RAX (Win64 callee-clears
// the high dword of a 32-bit return); and the call returns to the caller
// (caller-cleanup, so RSP is untouched for a call-site intercept, and the
// return address is popped for a jmp-thunk intercept). A capability the core
// does not honestly emulate is not in the table, so the reached import stays an
// unserved structured stop and the frontier stays exact. An HLE exit,
// exception, or fault becomes the structured stop the probe owns.
//
// Exported additively (BPTK tiered-runner boundary): a WASM fast-tier function
// whose guest hits an import thunk calls this against the SAME multi-region
// Machine the interpreter drives, so the register/memory mutation and control
// result are byte-identical to the interpreter's import-thunk dispatch. The
// interpreter loop still calls it exactly as before; the export changes no
// control flow. `stop` is `{ import: { library, symbol, ... }, kind }` where
// kind "jmp" pops the pushed return address (a thunk/register-indirect call)
// and any other kind resumes at nextRip (a decoded call-site).
// lib/hle.mjs resolves a (library, symbol) pair by a LINEAR scan of its whole
// export table, plus a second scan for the ucrt api-set forward. That is fine once
// per import, and it is not once per import: a guest in a frame loop calls the same
// handful of routines hundreds of thousands of times, and the scan is repeated on
// every one. Measured on Chocolate Doom at a 20,000,000-instruction budget it was
// 36% of the WALL TIME of BOTH engines — the single largest cost in the process,
// larger than interpretation and larger than the whole WASM tier, and identical in
// pure interpretation, so it diluted every tier speedup toward 1.0 by construction.
//
// The table is built once and never mutated, and lookupExport is a pure function of
// its two string arguments, so the resolution is memoised per guest. Nothing about
// what is served changes — the SAME entry object comes back, including the `null`
// for an unserved symbol, which is cached too so a repeatedly-reached import
// frontier costs one scan rather than one per arrival.
const exportLookupCache = new WeakMap(); // guest → Map("library!symbol" → entry | null)
function lookupExportCached(guest, library, symbol) {
  let byName = exportLookupCache.get(guest);
  if (byName === undefined) { byName = new Map(); exportLookupCache.set(guest, byName); }
  const key = `${library}!${symbol}`;
  const hit = byName.get(key);
  if (hit !== undefined) return hit;
  const entry = guest.lookupExport(library, symbol) ?? null;
  byName.set(key, entry);
  return entry;
}

export function serveImport64(machine, stop, nextRip, hleContext) {
  const entry = lookupExportCached(hleContext.guest, stop.import.library, stop.import.symbol);
  if (entry === null) return { served: false };

  const stackArgBase = (machine.reg[RSP] + (stop.kind === "jmp" ? 8n : 0n) + SHADOW_SPACE_BYTE) & MASK64;
  const argument = [];
  for (let index = 0; index < entry.argument_count; index += 1) {
    const value = index < 4
      ? machine.reg[WIN64_ARG_REG[index]] & MASK64
      : machine.readMem((stackArgBase + BigInt((index - 4) * 8)) & MASK64, 8);
    argument.push(Number(value));
  }

  let value;
  try {
    value = hleContext.guest.invokeExport(entry, argument);
  } catch (error) {
    if (isHleSignal(error)) {
      if (error.signal === "hle_exit") return { served: true, stop: { reason: "process_exit", exit_code: error.exit_code >>> 0 } };
      if (error.signal === "hle_guest_exception") return { served: true, stop: { reason: "guest_exception", exception_code: error.exception_code >>> 0 } };
      return { served: true, stop: { reason: "hle_fault", message: error.message, code: error.code ?? null } };
    }
    throw error;
  }

  // Win64 return marshal. A 32-bit int return zero-extends into RAX (the callee
  // clears the high dword), so a value that fits in 32 bits — including a
  // negative int, whose `>>> 0` is its 32-bit two's-complement — takes that
  // path. A pointer into memory above 4 GiB (a stack/image address an x64 string
  // routine like strrchr/strstr returns) does NOT fit in 32 bits; truncating it
  // would hand the guest a low address that faults on the next dereference, so a
  // positive integer above 0xffffffff is preserved at full 64-bit width.
  const rax = typeof value === "bigint"
    ? value & MASK64
    : (Number.isInteger(value) && value > 0xffffffff ? BigInt(value) & MASK64 : BigInt(value >>> 0));
  machine.reg[0] = rax; // RAX
  if (stop.kind === "jmp") {
    const ret = machine.readMem(machine.reg[RSP], 8);
    machine.reg[RSP] = (machine.reg[RSP] + 8n) & MASK64;
    machine.rip = ret;
  } else {
    machine.rip = nextRip;
  }
  return { served: true };
}

// The two CRT initializer runners the ucrt startup calls to run the C (_initterm_e)
// and C++ (_initterm) global constructors before main. Each takes a pointer to
// the first and just-past-last slot of a table of function pointers; every
// non-null slot is a guest function to call (void for _initterm, int for
// _initterm_e — a non-zero return aborts the sequence with that error). These are
// pure guest control-flow, so the harness drives them through its own interpreter
// loop rather than the HLE: startInitterm collects the table and enters the first
// initializer, resumeInitterm advances at each initializer's return sentinel.
const INITTERM_SYMBOL = new Set(["_initterm", "_initterm_e"]);

function callInitializer(machine, frame) {
  const target = frame.list[frame.index];
  // Rebuild a fresh Win64 call frame at the initterm entry alignment: 32-byte
  // shadow space then the return sentinel (rsp % 16 == 8 at callee entry).
  let rsp = (frame.rsp0 - SHADOW_SPACE_BYTE) & MASK64;
  rsp = (rsp - 8n) & MASK64;
  machine.writeMem(rsp, 8, initReturnSentinel);
  machine.reg[RSP] = rsp;
  machine.reg[1] = 0n; // rcx
  machine.reg[2] = 0n; // rdx
  machine.reg[8] = 0n; // r8
  machine.reg[9] = 0n; // r9
  machine.rip = target & MASK64;
}

// Begins an _initterm(_e) invocation reached as an import call. Returns a stop
// descriptor only when the guest error path fires; otherwise it either resumes
// the caller directly (empty table) or enters the first initializer.
function startInitterm(machine, stop, nextRip) {
  const isError = stop.import.symbol === "_initterm_e";
  const begin = machine.reg[1] & MASK64; // rcx: first table slot
  const end = machine.reg[2] & MASK64; // rdx: just past the last slot
  const list = [];
  for (let slot = begin; slot + 8n <= end; slot += 8n) {
    const fn = machine.readMem(slot, 8);
    if (fn !== 0n) list.push(fn);
  }
  // Where the _initterm(_e) caller resumes, and the caller's own stack top. A
  // call-site intercept left rsp at the pre-call 16-aligned top and resumes at
  // nextRip; a jmp-thunk intercept has the caller's return address already on the
  // stack, so pop it to find both the resume address and the aligned stack top.
  let returnRip;
  let rsp0;
  if (stop.kind === "jmp") {
    returnRip = machine.readMem(machine.reg[RSP], 8);
    rsp0 = (machine.reg[RSP] + 8n) & MASK64;
  } else {
    returnRip = nextRip;
    rsp0 = machine.reg[RSP] & MASK64;
  }
  const frame = { list, index: 0, returnRip, isError, rsp0 };
  if (list.length === 0) {
    // An empty initializer table resumes the _initterm(_e) caller exactly like a
    // completed table: at returnRip with rsp0 restored. A jmp-thunk intercept
    // has the caller's return address on the stack (returnRip/rsp0 already
    // account for it), so resuming at `nextRip` — the byte after the jmpIndirect
    // inside the import thunk — would fall through the thunk table into the next
    // thunk instead of returning to the CRT startup. That corrupts the startup's
    // _initterm_e result check and it bails before main.
    machine.reg[0] = 0n; // RAX success
    machine.reg[RSP] = rsp0;
    machine.rip = returnRip;
    return;
  }
  machine.initStack.push(frame);
  callInitializer(machine, frame);
}

// Handles the return of one initializer (rip landed on the init sentinel).
function resumeInitterm(machine) {
  const frame = machine.initStack[machine.initStack.length - 1];
  if (frame.isError) {
    const result = machine.reg[0] & 0xffffffffn;
    if (result !== 0n) {
      // A C initializer reported an error: _initterm_e returns it and stops.
      machine.initStack.pop();
      machine.reg[RSP] = frame.rsp0;
      machine.reg[0] = result;
      machine.rip = frame.returnRip;
      return;
    }
  }
  frame.index += 1;
  if (frame.index < frame.list.length) {
    callInitializer(machine, frame);
    return;
  }
  machine.initStack.pop();
  machine.reg[RSP] = frame.rsp0;
  machine.reg[0] = 0n; // _initterm returns void; _initterm_e returns 0 on success
  machine.rip = frame.returnRip;
}

// ---------------------------------------------------------------------------
// The x86-64 window/dialog-creation path (BPTK-031). CreateDialogParam(A/W)
// instantiates the REAL RT_DIALOG template from the mapped image's resource
// directory (lib/rsrc.mjs), creates real window objects for the frame and each
// control (the USER32 subsystem in lib/user.mjs), then dispatches WM_INITDIALOG
// to the guest dialog procedure as real guest control flow — the same
// return-sentinel re-entry the _initterm runner uses. The message loop
// (GetMessage/DispatchMessage) delivers a bounded, deterministic scripted
// sequence and re-enters the guest WndProc for each dispatched message, so the
// probe reaches and pumps the loop without a real display or a blocking wait.
// ---------------------------------------------------------------------------

// Re-enter the guest window/dialog procedure `proc(hwnd, message, wParam,
// lParam)` under the Win64 ABI, on a fresh call frame above `rsp0` (32-byte
// shadow space then the dialog return sentinel), so its RET stops the harness.
function callGuestWndProc(machine, proc, hwnd, message, wParam, lParam, rsp0) {
  let rsp = (rsp0 - SHADOW_SPACE_BYTE) & MASK64;
  rsp = (rsp - 8n) & MASK64;
  machine.writeMem(rsp, 8, dialogReturnSentinel);
  machine.reg[RSP] = rsp;
  machine.reg[1] = BigInt(hwnd) & MASK64; // rcx: HWND
  machine.reg[2] = BigInt(message) & MASK64; // rdx: UINT message
  machine.reg[8] = BigInt(wParam) & MASK64; // r8: WPARAM
  machine.reg[9] = lParam & MASK64; // r9: LPARAM
  machine.rip = proc & MASK64;
}

// Resolve the RT_DIALOG template a CreateDialog/DialogBox call names. The
// template argument (rdx) is a MAKEINTRESOURCE id (its low word) when it is at
// or below 0xffff; a higher value is a pointer to a resource name string, which
// the bounded probe does not resolve (an honest fall-through to import_present).
function resolveDialogTemplate(machine, dialogEnv) {
  const lpTemplate = machine.reg[2] & MASK64;
  if (lpTemplate === 0n || lpTemplate > 0xffffn) return null;
  if (!Number.isInteger(dialogEnv.resourceRva) || dialogEnv.resourceRva <= 0) return null;
  return loadDialogTemplate(dialogEnv.imageBuf, dialogEnv.resourceRva, Number(lpTemplate));
}

// Serve a reached CreateDialogParam/DialogBoxParam: parse the template, create
// the real window objects, and re-enter the guest DlgProc with WM_INITDIALOG.
// Returns true when handled; false when the template cannot be resolved, so the
// caller falls through to the historical import_present frontier. `nextRip` is
// the call-site resume; `stop.kind` distinguishes a call-site from a jmp thunk.
function startDialog(machine, stop, nextRip, hleContext, dialogEnv) {
  const template = resolveDialogTemplate(machine, dialogEnv);
  if (template === null) return false;
  const lpDialogFunc = machine.reg[9] & MASK64; // r9: the guest DlgProc pointer
  if (lpDialogFunc === 0n) return false;
  // The 5th argument (dwInitParam) sits above the 32-byte shadow space; a jmp
  // thunk has the caller's return address on the stack, a call site does not.
  const stackArgBase = (machine.reg[RSP] + (stop.kind === "jmp" ? 8n : 0n) + SHADOW_SPACE_BYTE) & MASK64;
  const dwInitParam = machine.readMem(stackArgBase, 8);

  let returnRip;
  let rsp0;
  if (stop.kind === "jmp") {
    returnRip = machine.readMem(machine.reg[RSP], 8);
    rsp0 = (machine.reg[RSP] + 8n) & MASK64;
  } else {
    returnRip = nextRip;
    rsp0 = machine.reg[RSP] & MASK64;
  }

  const dialog = hleContext.guest.user.instantiateDialog(template, lpDialogFunc, Number(dwInitParam & 0xffffffffn));
  if (dialog.hwnd === 0) {
    // The template was real but the window manager refused it; return NULL to
    // the caller exactly as CreateDialog does, without a guest re-entry.
    machine.reg[0] = 0n;
    machine.rip = returnRip;
    machine.reg[RSP] = rsp0;
    return true;
  }

  const isModal = DIALOG_MODAL_SYMBOL.has(stop.import.symbol);
  machine.dialogStack.push({ result_kind: "handle", hwnd: dialog.hwnd, returnRip, rsp0, is_modal: isModal, dlg_proc: lpDialogFunc });
  callGuestWndProc(machine, lpDialogFunc, dialog.hwnd, windowMessage.WM_INITDIALOG, dialog.focus_control, dwInitParam, rsp0);
  return true;
}

// Handle the return of one guest WndProc (rip landed on the dialog sentinel).
// A "handle" frame is the CreateDialog re-entry: the API result is the dialog
// HWND, not the WM_INITDIALOG return, so RAX is overwritten. A "passthrough"
// frame is a message the loop dispatched: DispatchMessage returns the WndProc
// result, so RAX (whatever the procedure returned) is left in place.
function resumeDialog(machine) {
  const frame = machine.dialogStack.pop();
  machine.reg[RSP] = frame.rsp0;
  if (frame.result_kind === "handle") machine.reg[0] = BigInt(frame.hwnd) & MASK64;
  machine.rip = frame.returnRip;
}

// The USER32 exports whose in-memory struct layout differs between i386 (the
// 4-byte-pointer layout the shared export table marshals) and x86-64 (8-byte
// pointers): the WNDCLASS registration and the MSG message-loop calls. The x64
// dispatch path marshals these itself, in the 64-bit layout the guest reads, so
// the shared table never corrupts an x64 struct. DispatchMessage additionally
// re-enters the guest WndProc as real control flow.
const WINDOW_STRUCT_SYMBOL = new Set([
  "RegisterClassA", "RegisterClassW", "RegisterClassExA", "RegisterClassExW",
  "GetMessageA", "GetMessageW", "PeekMessageA", "PeekMessageW",
  "TranslateMessage", "DispatchMessageA", "DispatchMessageW",
]);
const WM_QUIT = 0x0012;

// The nth integer argument of a reached Win64 call: RCX/RDX/R8/R9 then the
// stack above the 32-byte shadow space (past the return address on a jmp thunk).
function win64Arg(machine, stop, index) {
  if (index < 4) return machine.reg[WIN64_ARG_REG[index]] & MASK64;
  const stackArgBase = (machine.reg[RSP] + (stop.kind === "jmp" ? 8n : 0n) + SHADOW_SPACE_BYTE) & MASK64;
  return machine.readMem((stackArgBase + BigInt((index - 4) * 8)) & MASK64, 8);
}

// Resume the caller of a served window import: RAX carries the result, and the
// return matches the intercept kind (a jmp thunk has the caller's return
// address on the stack; a call site resumes at the fall-through rip).
function resumeWindowCall(machine, stop, resumeRip, result) {
  machine.reg[0] = BigInt(result >>> 0) & MASK64;
  if (stop.kind === "jmp") {
    const ret = machine.readMem(machine.reg[RSP], 8);
    machine.reg[RSP] = (machine.reg[RSP] + 8n) & MASK64;
    machine.rip = ret;
  } else {
    machine.rip = resumeRip;
  }
}

// The x86-64 MSG struct (48 byte): hwnd@0(8), message@8(4), wParam@16(8),
// lParam@24(8), time@32(4), pt@40(8).
function writeMsg64(machine, address, message) {
  if (address === 0n || message === null || message === undefined) return;
  machine.writeMem(address + 0n, 8, BigInt(message.handle >>> 0));
  machine.writeMem(address + 8n, 4, BigInt(message.message >>> 0));
  machine.writeMem(address + 16n, 8, BigInt(message.w_param >>> 0));
  machine.writeMem(address + 24n, 8, BigInt(message.l_param >>> 0));
  machine.writeMem(address + 32n, 4, 0n);
  machine.writeMem(address + 40n, 8, 0n);
}

function readMsg64(machine, address) {
  return {
    handle: Number(machine.readMem(address + 0n, 8) & MASK64),
    message: Number(machine.readMem(address + 8n, 4)),
    w_param: Number(machine.readMem(address + 16n, 8) & 0xffffffffn),
    l_param: Number(machine.readMem(address + 24n, 8) & 0xffffffffn),
  };
}

// Serve one reached window/message import that is struct-layout sensitive, in
// the x86-64 layout. Returns { handled } — handled:false falls through to the
// generic import path. A DispatchMessage to a window carrying a guest WndProc
// re-enters guest code (the loop continues into the procedure); every other
// call marshals its struct and resumes the caller with the documented result.
function serveWindowImport64(machine, stop, resumeRip, hleContext) {
  const symbol = stop.import.symbol;
  const user = hleContext.guest.user;
  const isAnsi = symbol.endsWith("A");

  if (symbol.startsWith("RegisterClass")) {
    const base = win64Arg(machine, stop, 0);
    const isEx = symbol.startsWith("RegisterClassEx");
    const style = Number(machine.readMem(base + (isEx ? 4n : 0n), 4));
    const wndProc = machine.readMem(base + 8n, 8); // 8-byte WNDPROC on x64
    const namePointer = machine.readMem(base + 64n, 8); // lpszClassName at +64 (both layouts)
    const name = isAnsi ? hleContext.guest.readAnsiString(Number(namePointer)) : hleContext.guest.readWideString(Number(namePointer));
    const atom = typeof name === "string" && name.length > 0 ? user.registerClassGuest(name, wndProc, style) : 0;
    resumeWindowCall(machine, stop, resumeRip, atom);
    return { handled: true };
  }

  if (symbol.startsWith("GetMessage")) {
    const lpMsg = win64Arg(machine, stop, 0);
    const sink = {};
    const code = user.getMessage(sink);
    if (code === -1) {
      // A bounded, deterministic empty input trace: with no real user and an
      // empty queue, the loop is handed WM_QUIT so it terminates cleanly rather
      // than blocking. GetMessage returns 0 on WM_QUIT.
      writeMsg64(machine, lpMsg, { handle: 0, message: WM_QUIT, w_param: 0, l_param: 0 });
      resumeWindowCall(machine, stop, resumeRip, 0);
      return { handled: true };
    }
    writeMsg64(machine, lpMsg, sink.message);
    resumeWindowCall(machine, stop, resumeRip, code >>> 0);
    return { handled: true };
  }

  if (symbol.startsWith("PeekMessage")) {
    const lpMsg = win64Arg(machine, stop, 0);
    const remove = (Number(win64Arg(machine, stop, 4)) & 1) === 1;
    const sink = {};
    const available = user.peekMessage(sink, remove);
    if (available === 1) writeMsg64(machine, lpMsg, sink.message);
    resumeWindowCall(machine, stop, resumeRip, available);
    return { handled: true };
  }

  if (symbol === "TranslateMessage") {
    const lpMsg = win64Arg(machine, stop, 0);
    const result = user.translateMessage(readMsg64(machine, lpMsg));
    resumeWindowCall(machine, stop, resumeRip, result);
    return { handled: true };
  }

  // DispatchMessage: route to the guest WndProc as real control flow when the
  // target window carries one; otherwise dispatch host-side (DefWindowProc).
  const lpMsg = win64Arg(machine, stop, 0);
  const message = readMsg64(machine, lpMsg);
  const guestProc = message.handle === 0 ? 0n : user.getGuestWndProc(message.handle);
  if (guestProc !== 0 && guestProc !== 0n) {
    let returnRip;
    let rsp0;
    if (stop.kind === "jmp") {
      returnRip = machine.readMem(machine.reg[RSP], 8);
      rsp0 = (machine.reg[RSP] + 8n) & MASK64;
    } else {
      returnRip = resumeRip;
      rsp0 = machine.reg[RSP] & MASK64;
    }
    machine.dialogStack.push({ result_kind: "passthrough", hwnd: message.handle, returnRip, rsp0 });
    callGuestWndProc(machine, BigInt(guestProc), message.handle, message.message, message.w_param, BigInt(message.l_param), rsp0);
    return { handled: true };
  }
  const result = user.dispatchMessage(message);
  resumeWindowCall(machine, stop, resumeRip, result);
  return { handled: true };
}

// The scalar USER32 window/dialog exports the x86-64 GUI path reaches after
// CreateDialog — window focus/enable, the dialog-item accessors, and the ANSI
// class/window defaults. These carry only scalar and pointer arguments (no
// struct whose layout differs by pointer width), so the x64 path serves them
// directly over the shared window manager rather than through the i386 export
// table (which the forbidden HLE owns and whose conformance ledger it fixes).
const WINDOW_SCALAR_SYMBOL = new Set([
  "CreateWindowExA", "DefWindowProcA", "DefDlgProcA", "DefDlgProcW", "UnregisterClassA",
  "SetActiveWindow", "SetFocus", "SetForegroundWindow", "BringWindowToTop", "EnableWindow",
  "IsWindowVisible", "IsWindowEnabled", "GetDlgItem", "GetDlgCtrlID",
  "SendDlgItemMessageA", "SendDlgItemMessageW", "EndDialog",
  "SetWindowTextA", "SetWindowTextW", "SetDlgItemTextA", "SetDlgItemTextW",
  "CheckDlgButton", "GetDlgItemTextA", "GetDlgItemTextW",
]);

function serveWindowScalar64(machine, stop, resumeRip, hleContext) {
  const symbol = stop.import.symbol;
  const user = hleContext.guest.user;
  const arg = (index) => Number(win64Arg(machine, stop, index) & 0xffffffffn);
  const argFull = (index) => Number(win64Arg(machine, stop, index));
  let result;
  switch (symbol) {
    case "CreateWindowExA":
      result = user.createWindowEx({
        class_name: hleContext.guest.readAnsiString(argFull(1)),
        style: arg(3), x: arg(4) | 0, y: arg(5) | 0, width: arg(6) | 0, height: arg(7) | 0,
        create_param: argFull(11),
      });
      break;
    case "DefWindowProcA":
    case "DefDlgProcA":
    case "DefDlgProcW":
      result = user.defWindowProc(arg(0), arg(1), argFull(2), argFull(3));
      break;
    case "UnregisterClassA":
      result = user.unregisterClass(hleContext.guest.readAnsiString(argFull(0)));
      break;
    case "SetActiveWindow":
      result = user.setActiveWindow(arg(0));
      break;
    case "SetFocus":
      result = user.setFocusWindow(arg(0));
      break;
    case "SetForegroundWindow":
      user.setActiveWindow(arg(0));
      result = 1;
      break;
    case "BringWindowToTop":
      result = 1;
      break;
    case "EnableWindow":
      result = 0; // the previous state was enabled
      break;
    case "IsWindowVisible":
    case "IsWindowEnabled":
      result = user.isWindow(arg(0)) ? 1 : 0;
      break;
    case "GetDlgItem":
      result = user.getDlgItem(arg(0), arg(1));
      break;
    case "GetDlgCtrlID":
      result = 0;
      break;
    case "SendDlgItemMessageA":
    case "SendDlgItemMessageW": {
      const control = user.getDlgItem(arg(0), arg(1));
      result = control === 0 ? 0 : user.sendMessage(control, arg(2), argFull(3), argFull(4));
      break;
    }
    case "EndDialog":
    case "SetWindowTextA":
    case "SetWindowTextW":
    case "SetDlgItemTextA":
    case "SetDlgItemTextW":
    case "CheckDlgButton":
      result = 1;
      break;
    default: // GetDlgItemTextA / GetDlgItemTextW: no text from an unlabeled control
      result = 0;
      break;
  }
  resumeWindowCall(machine, stop, resumeRip, result);
  return { handled: true };
}

// Interprets an image buffer from an entry RVA over a fresh register file and a
// three-region address space (image, bounded stack, gs-based TEB/PEB), bounded
// by an instruction budget. `importSet` maps an IAT slot address to its import
// entry; reaching one is a structured import_present stop unless option.hle
// wires the Win32 core HLE, in which case a served import returns and execution
// continues. This is the core the PE32+ probe and the test microprograms share.
// Builds the multi-region guest execution context the interpreter drives — the
// Machine (register file + image/stack/TEB memory, plus the HLE arena/virtual/
// thunk regions and the low-address image alias when an HLE layout is
// declared), the live Win32 core HLE guest with its IAT slots bound, the
// unserved-import sentinel map, the window/dialog environment, and the region
// layout (bases/sizes) another module needs to build a matching compact memory.
//
// EXTRACTED from runImage64 so the interpreter and a future tiered runner share
// exactly one setup path: runImage64 calls this and drives the returned Machine,
// so the existing tests prove the extraction changed no behavior. The returned
// context bundles every value the run loop reads after setup (machine,
// hleContext, unservedSentinel, dialogEnv, imageBuf, loadBase, budget,
// importSet, balancedRsp, teb, stackHigh, stackLow) plus `layout`, the region
// bases/sizes (BPTK tiered-runner boundary).
export function buildGuestContext64(option) {
  const image = option.image;
  if (!Buffer.isBuffer(image) && !(image instanceof Uint8Array)) throw new TypeError("runImage64 requires an image buffer");
  const loadBase = BigInt(option.loadBase ?? 0x140000000n);
  const entryRva = option.entryRva ?? 0;
  const budget = option.budget ?? 100000;
  const stackSizeByte = Math.min(option.stackSizeByte ?? stackSizeDefault, executionBoundDefault.stack_byte);
  const importSet = option.importSet ?? new Map();

  // ---- the guest address space ----
  //
  // When `option.sharedGuestMemory` is set (the TIERED runner sets it; pure
  // interpretation does not), every region is allocated as a VIEW into one
  // WebAssembly.Memory laid out by lib/wasm64.mjs's compact region plan, so the
  // WASM tier can import that memory and address the interpreter's own bytes.
  //
  // The regions are placed here, at construction, rather than copied into a shared
  // memory afterwards: the map is ~100 MiB on a real binary under the Win32 HLE,
  // and a one-off 100 MiB memcpy is itself ~25 ms — visible against a whole PuTTY
  // startup. Allocating in place costs nothing (a WebAssembly.Memory arrives
  // zero-filled, exactly like Buffer.alloc).
  //
  // OWNERSHIP AND LIFETIME: the plan owns the memory, the context holds the plan,
  // and every region buffer is a view into it for the life of the run.
  //
  // GROWTH: none, deliberately. Growing a WebAssembly.Memory detaches its
  // ArrayBuffer and would silently invalidate every region view and every
  // Uint8Array/DataView the tier derives from it — a stale view is a wrong answer
  // with no symptom. The whole map is therefore sized here, up front, and the
  // memory is created with `maximum === initial` so it CANNOT grow. Nothing may
  // append a region after this function returns.
  const hleLayout = option.hle?.layout ?? null;
  const imageAlias = loadBase & 0xffffffffn;
  const hasImageAlias = hleLayout !== null && imageAlias !== loadBase;
  let sharedPlan = null;
  if (option.sharedGuestMemory === true) {
    const spec = [
      { base: loadBase, size: image.length, kind: "image" },
      { base: stackRegionBase, size: stackSizeByte, kind: "stack" },
      { base: tebRegionBase, size: tebRegionSizeByte, kind: "region" },
    ];
    if (hleLayout !== null) {
      spec.push({ base: BigInt(hleLayout.arena_base), size: hleLayout.arena_size_byte, kind: "region" });
      spec.push({ base: BigInt(hleLayout.virtual_base), size: hleLayout.virtual_size_byte, kind: "region" });
      spec.push({ base: BigInt(hleLayout.thunk_base), size: hleLayout.thunk_page_byte, kind: "region" });
      // The low-32-bit image alias is the SAME bytes at a second guest address, so
      // it takes the image's compact offset and stays one buffer in both engines.
      if (hasImageAlias) spec.push({ base: imageAlias, size: image.length, kind: "region", aliasOf: 0 });
    }
    try {
      sharedPlan = createSharedGuestPlan(spec, loadBase);
    } catch {
      sharedPlan = null; // a map too wide for a 32-bit WASM memory: private buffers, no WASM tier
    }
  }
  // Region `index` in the plan's order, as a private Buffer or a view into the
  // shared memory. A view arrives zero-filled, like Buffer.alloc.
  const allocRegion = (index, sizeByte) => (sharedPlan === null
    ? Buffer.alloc(sizeByte)
    : Buffer.from(sharedPlan.memory.buffer, sharedPlan.region[index].wasmOffset, sizeByte));

  const imageBuf = allocRegion(0, image.length); // a private copy: guest writes never mutate the caller's image
  imageBuf.set(image);
  const stackBuf = allocRegion(1, stackSizeByte);
  const stackLow = stackRegionBase;
  const stackHigh = stackRegionBase + BigInt(stackSizeByte);
  const teb = buildTeb(stackLow, stackHigh, loadBase, allocRegion(2, tebRegionSizeByte));

  const region = [
    { base: loadBase, buf: imageBuf },
    { base: stackRegionBase, buf: stackBuf },
    { base: tebRegionBase, buf: teb.buf },
  ];
  const machine = new Machine(region);
  machine.gsBase = teb.tebBase;
  machine.fsBase = teb.tebBase;

  // The region layout (bases/sizes) a matching compact memory is built from. The
  // image/stack/TEB regions are always present; the HLE arena/virtual/thunk and
  // the low-address image alias are appended below when an HLE layout is
  // declared. Sizes come from the live region buffers, so the layout always
  // describes the memory the Machine actually maps.
  const layout = {
    image: { base: loadBase, size_byte: imageBuf.length },
    stack: { base: stackRegionBase, size_byte: stackSizeByte },
    teb: { base: tebRegionBase, size_byte: teb.buf.length, teb_base: teb.tebBase, peb_base: teb.pebBase },
  };

  // The Win32 core HLE (milestone M4). When option.hle declares a layout, the
  // HLE arena/virtual/thunk pages join the guest address space (so the pointers
  // the HLE hands back resolve) and a per-run guest is constructed over the
  // shared memory model. A reached import then dispatches through the Win64 ABI
  // marshal instead of stopping. No layout means the historical import_present
  // stop, so the test microprograms and the bare probe are unaffected.
  let hleContext = null;
  // Maps a per-import unserved sentinel address to its import entry (see
  // unservedImportSentinelBase). Populated when the HLE binds the IAT.
  const unservedSentinel = new Map();
  if (hleLayout !== null) {
    region.push({ base: BigInt(hleLayout.arena_base), buf: allocRegion(3, hleLayout.arena_size_byte) });
    region.push({ base: BigInt(hleLayout.virtual_base), buf: allocRegion(4, hleLayout.virtual_size_byte) });
    region.push({ base: BigInt(hleLayout.thunk_base), buf: allocRegion(5, hleLayout.thunk_page_byte) });
    layout.arena = { base: BigInt(hleLayout.arena_base), size_byte: hleLayout.arena_size_byte };
    layout.virtual = { base: BigInt(hleLayout.virtual_base), size_byte: hleLayout.virtual_size_byte };
    layout.thunk = { base: BigInt(hleLayout.thunk_base), size_byte: hleLayout.thunk_page_byte };
    // The Win32 core HLE addresses guest memory as an unsigned 32-bit value
    // (lib/hle.mjs). Its own arena/virtual/thunk/TEB regions sit below 4 GiB, but
    // a PE32+ image maps at its preferred base above 4 GiB (typically
    // 0x140000000), so a guest pointer INTO the image passed to an HLE routine
    // (memset/memcpy of a global, for one) is truncated to its low 32 bits. An
    // alias region at that truncated image base — the same imageBuf, so a write
    // through either address is the same byte — makes such a pointer resolve to
    // the real image bytes instead of faulting on an unmapped low address.
    if (hasImageAlias) {
      region.push({ base: imageAlias, buf: imageBuf });
      layout.image_alias = { base: imageAlias, size_byte: imageBuf.length };
    }
    const guest = createWin32Hle(createGuestMemoryAdapter(machine), hleLayout, {
      clock: option.hle.clock,
      executable_name: option.hle.executableName,
      image_base: Number(loadBase & MASK64),
      image_size_byte: imageBuf.length,
      host_file: option.hle.hostFile,
      environment: option.hle.environment,
      command_line: option.hle.commandLine,
    });
    hleContext = { guest };
    // Install the scripted SDL input trace (lib/sdl.mjs) when the caller supplies
    // one. The SDL subsystem is created inside the Win32 core HLE with a fixed
    // dependency set, so the trace is configured here, on the live guest, right
    // after construction; an absent trace leaves the honest empty input queue.
    if (option.hle.inputTrace !== undefined && guest.sdl !== undefined) {
      guest.sdl.loadInputTrace(option.hle.inputTrace);
    }
    // Bind every import's IAT slot to a recognizable address, so a guest that
    // loads the slot into a register and calls/jumps through it (`mov reg,[slot];
    // call reg`) transfers control somewhere this harness recognizes — the same
    // import service the direct `call [slot]` path already provides. A served
    // import (including one resolved through the ucrt api-set forward to msvcrt)
    // binds to its HLE thunk, which the loop dispatches. A genuinely unserved
    // import binds to a per-import sentinel outside every mapped region, so a
    // register-indirect call to it is a clean import_present stop naming the
    // symbol, not a wild jump to the raw import-name-table RVA the slot still
    // held (which faults on an address that is data, not code).
    let unservedIndex = 0;
    for (const [slot, entry] of importSet) {
      const resolved = guest.lookupExport(entry.library, entry.symbol);
      const thunk = resolved ? guest.thunkOf(resolved.library, resolved.symbol) : null;
      if (thunk !== null) {
        machine.writeMem(slot, 8, BigInt(thunk >>> 0));
        continue;
      }
      const sentinel = unservedImportSentinelBase + BigInt(unservedIndex) * 8n;
      unservedIndex += 1;
      unservedSentinel.set(sentinel, entry);
      machine.writeMem(slot, 8, sentinel);
    }
  }

  // The window/dialog-creation environment: the mapped image bytes (for the
  // RT_DIALOG resource parse) and the resource directory RVA. When no resource
  // directory is declared the dialog path stays inert and CreateDialog keeps the
  // historical import_present frontier.
  const dialogEnv = { imageBuf, resourceRva: option.resourceRva ?? 0, loadBase };

  // rsp at a 16-aligned stack top with the return sentinel pushed, so the entry
  // RET stops the harness rather than running off into unmapped memory.
  const stackTop = (stackHigh - 0x100n) & ~0xfn;
  const balancedRsp = stackTop;
  machine.reg[RSP] = stackTop - 8n;
  machine.writeMem(machine.reg[RSP], 8, returnSentinel);
  machine.rip = loadBase + BigInt(entryRva);

  return {
    machine, hleContext, unservedSentinel, dialogEnv, region, layout,
    imageBuf, loadBase, entryRva, budget, importSet,
    balancedRsp, teb, stackHigh, stackLow,
    // The ONE guest memory both engines address, or null when this context runs
    // on private buffers (pure interpretation, or a map too wide to place).
    sharedPlan,
  };
}

// A fresh per-run interpreter state: the loop-local bookkeeping runImage64 used
// to keep in closure locals, hoisted into an object so a resumable session can
// carry it across stepContext calls. The guest state proper (registers, memory,
// rip, initStack, dialogStack) lives in context.machine and is untouched here.
function createRunState(trace = null) {
  return { instructionCount: 0, stopReason: "instruction_budget_exhausted", fault: null, reachedImport: null, trace, done: false };
}

// The interpreter loop body, extracted from runImage64 so the monolithic run and
// a resumable session (lib/live.mjs) share exactly one implementation. It
// advances `context` (a buildGuestContext64 result) FROM ITS CURRENT machine
// state for up to `stepBudget` more instructions, mutating `runState` in place.
// A structured stop sets runState.done = true plus the terminal fields; reaching
// the step budget without a stop leaves runState.done false so a later call
// resumes exactly where this one stopped. Because every byte of guest state is
// in context.machine and nothing here resets between calls, N calls of stepBudget
// B reproduce one call of budget N*B bit-for-bit — this is what makes
// stepContext == runImage64. The instruction-count and stop bookkeeping is
// identical to the original loop: each break pre-increments the count exactly as
// before, and budget exhaustion leaves stopReason at instruction_budget_exhausted.
function runInterpreterStep(context, runState, stepBudget) {
  const { machine, hleContext, unservedSentinel, dialogEnv, imageBuf, loadBase, importSet } = context;
  const trace = runState.trace;
  const traceImport = (symbol, served) => { if (trace) trace.push({ i: runState.instructionCount, kind: "import", symbol, served }); };
  const limit = runState.instructionCount + stepBudget;

  try {
    for (; runState.instructionCount < limit; runState.instructionCount += 1) {
      // A CRT initializer just returned to the init sentinel (advance to the next
      // initializer, or resume the _initterm(_e) caller), or a guest
      // window/dialog procedure just returned to the dialog sentinel (resume the
      // CreateDialog site with the HWND result, or the DispatchMessage site with
      // the WndProc result). Checked before the image-bounds test because both
      // sentinels deliberately lie outside every mapped region. This is the
      // exported resumeSpecialization64 step, so this loop and any other host
      // loop advance a specialization walk through ONE code path.
      if (resumeSpecialization64(context).resumed) continue;
      // A guest register-indirect call/jump through an unserved import's IAT
      // slot lands rip on that import's sentinel. Report import_present naming
      // the exact symbol — the clean frontier, not a fault on a data RVA.
      if (unservedSentinel.size > 0 && unservedSentinel.has(machine.rip)) {
        const entry = unservedSentinel.get(machine.rip);
        runState.instructionCount += 1;
        runState.stopReason = "import_present";
        runState.reachedImport = { library: entry.library, symbol: entry.symbol, ordinal: entry.ordinal ?? null, iat_slot_rva: entry.iat_slot_rva ?? null };
        runState.done = true;
        break;
      }
      // A guest indirect call/jump through a bound IAT slot lands rip on an HLE
      // thunk address. Dispatch it exactly like the direct call-site path: the
      // return address the call pushed is on the stack (kind "jmp"), so serving
      // the import pops it and resumes the caller.
      if (hleContext !== null && machine.rip <= 0xffffffffn && hleContext.guest.isThunk(Number(machine.rip))) {
        const entry = hleContext.guest.exportAt(Number(machine.rip));
        const thunkStop = { import: { library: entry.library, symbol: entry.symbol, ordinal: null, iat_slot_rva: null }, kind: "jmp" };
        if (INITTERM_SYMBOL.has(entry.symbol)) { startInitterm(machine, thunkStop, machine.rip); continue; }
        if (DIALOG_CREATE_SYMBOL.has(entry.symbol) && startDialog(machine, thunkStop, machine.rip, hleContext, dialogEnv)) continue;
        if (WINDOW_STRUCT_SYMBOL.has(entry.symbol)) { serveWindowImport64(machine, thunkStop, machine.rip, hleContext); continue; }
        if (WINDOW_SCALAR_SYMBOL.has(entry.symbol)) { serveWindowScalar64(machine, thunkStop, machine.rip, hleContext); continue; }
        const dispatch = serveImport64(machine, thunkStop, machine.rip, hleContext);
        if (dispatch.served && dispatch.stop === undefined) continue;
        if (dispatch.served) {
          runState.instructionCount += 1;
          runState.stopReason = dispatch.stop.reason;
          runState.fault = dispatch.stop.reason === "hle_fault"
            ? { message: dispatch.stop.message, code: dispatch.stop.code, address: machine.rip }
            : { message: `The guest ${dispatch.stop.reason === "process_exit" ? `ended its own process with code 0x${dispatch.stop.exit_code.toString(16)}` : `raised unhandled exception 0x${dispatch.stop.exception_code.toString(16)}`}`, address: machine.rip, ...(dispatch.stop.exit_code !== undefined ? { exit_code: dispatch.stop.exit_code } : {}), ...(dispatch.stop.exception_code !== undefined ? { exception_code: dispatch.stop.exception_code } : {}) };
          runState.done = true;
          break;
        }
        // A thunk with no served row is an honest import frontier.
        runState.instructionCount += 1;
        runState.stopReason = "import_present";
        runState.reachedImport = thunkStop.import;
        runState.done = true;
        break;
      }
      const rvaOffset = machine.rip - loadBase;
      if (rvaOffset < 0n || rvaOffset >= BigInt(imageBuf.length)) {
        runState.stopReason = "fault";
        runState.fault = { message: `instruction pointer 0x${machine.rip.toString(16)} is outside the mapped image`, address: machine.rip };
        runState.done = true;
        break;
      }
      const { node, segment } = decodeWithSegment(imageBuf, Number(rvaOffset));

      if (node.op === "truncated") {
        runState.stopReason = "fault";
        runState.fault = { message: `instruction at 0x${machine.rip.toString(16)} is truncated at the image edge`, address: machine.rip };
        runState.done = true;
        break;
      }
      if (!node.served) {
        runState.stopReason = "unsupported_opcode";
        runState.fault = { message: `unsupported opcode 0x${(node.opcode ?? 0).toString(16)}`, opcode: node.opcode ?? null, opcode_text: node.opcodeText ?? null, address: machine.rip };
        runState.done = true;
        break;
      }

      machine.segmentBase = segment === "gs" ? machine.gsBase : segment === "fs" ? machine.fsBase : 0n;
      if (trace) trace.push({ i: runState.instructionCount, rip: `0x${machine.rip.toString(16)}`, op: node.op, text: node.opcodeText ?? null });
      const nextRip = machine.rip + BigInt(node.length);
      const stop = executeNode(machine, node, nextRip, importSet);
      if (stop) {
        if (stop.import) traceImport(stop.import.symbol, true);
        if (stop.reason === "import_present" && hleContext !== null && INITTERM_SYMBOL.has(stop.import.symbol)) {
          // _initterm / _initterm_e transfer control into the guest initializer
          // table; the harness drives them through this same loop rather than the
          // HLE, so the C/C++ global constructors actually run before main.
          startInitterm(machine, stop, nextRip);
          continue;
        }
        if (stop.reason === "import_present" && hleContext !== null && DIALOG_CREATE_SYMBOL.has(stop.import.symbol) && startDialog(machine, stop, nextRip, hleContext, dialogEnv)) {
          continue;
        }
        if (stop.reason === "import_present" && hleContext !== null && WINDOW_STRUCT_SYMBOL.has(stop.import.symbol)) {
          serveWindowImport64(machine, stop, nextRip, hleContext);
          continue;
        }
        if (stop.reason === "import_present" && hleContext !== null && WINDOW_SCALAR_SYMBOL.has(stop.import.symbol)) {
          serveWindowScalar64(machine, stop, nextRip, hleContext);
          continue;
        }
        if (stop.reason === "import_present" && hleContext !== null) {
          const dispatch = serveImport64(machine, stop, nextRip, hleContext);
          if (dispatch.served && dispatch.stop === undefined) continue; // served; the loop increment counts the call
          if (dispatch.served) {
            runState.instructionCount += 1;
            runState.stopReason = dispatch.stop.reason;
            runState.fault = dispatch.stop.reason === "hle_fault"
              ? { message: dispatch.stop.message, code: dispatch.stop.code, address: machine.rip }
              : { message: `The guest ${dispatch.stop.reason === "process_exit" ? `ended its own process with code 0x${dispatch.stop.exit_code.toString(16)}` : `raised unhandled exception 0x${dispatch.stop.exception_code.toString(16)}`}`, address: machine.rip, ...(dispatch.stop.exit_code !== undefined ? { exit_code: dispatch.stop.exit_code } : {}), ...(dispatch.stop.exception_code !== undefined ? { exception_code: dispatch.stop.exception_code } : {}) };
            runState.done = true;
            break;
          }
        }
        runState.instructionCount += 1;
        runState.stopReason = stop.reason;
        runState.reachedImport = stop.import;
        runState.done = true;
        break;
      }
    }
  } catch (error) {
    if (error instanceof FaultError) {
      runState.stopReason = "fault";
      runState.fault = { message: error.message, address: machine.rip };
      runState.done = true;
    } else {
      throw error;
    }
  }
}

// Interprets an image to a bounded budget and returns the run surface. Now a thin
// driver over buildGuestContext64 + runInterpreterStep: it builds the context,
// runs one step of the whole budget, and reads the terminal bookkeeping off the
// run state. Byte-identical to the prior monolithic loop (the loop body moved
// verbatim into runInterpreterStep), so the existing exec64/corpus tests hold.
export function runImage64(option) {
  const context = buildGuestContext64(option);
  const { machine, hleContext, budget, balancedRsp, teb, stackHigh, stackLow } = context;
  const trace = option.trace ? [] : null;
  const runState = createRunState(trace);
  runInterpreterStep(context, runState, budget);
  const instructionCount = runState.instructionCount;
  const stopReason = runState.stopReason;
  const fault = runState.fault;
  const reachedImport = runState.reachedImport;

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
    // The live HLE guest (null when no import service was wired). The present
    // path reads guest.gdi / guest.user to composite the windows this run
    // created into the display surface; it is not serialized into any report.
    guest: hleContext === null ? null : hleContext.guest,
    trace,
  };
}

// Resumably advance a persistent buildGuestContext64 context by up to
// `instructionBudget` more instructions, RESUMING where the previous call left
// off rather than rebuilding — the foundation for an interactive, chunked live
// session (lib/live.mjs). The per-run interpreter bookkeeping is kept on
// `context.runState` (created on the first call), so successive stepContext calls
// thread one continuous run over one Machine: K calls of budget B are
// bit-for-bit identical to a single runImage64 at budget K*B, because both drive
// the SAME runInterpreterStep loop over the same guest state (proven in
// test/live.test.mjs). Returns the reason the last step stopped (or
// instruction_budget_exhausted when it merely ran out this chunk), the CUMULATIVE
// instruction and present counts, and the per-step deltas; `done` is true once a
// structured stop (entry return, process exit, fault, unsupported opcode,
// unserved import) has been reached, after which further calls are no-ops.
export function stepContext(context, instructionBudget) {
  if (context.runState === undefined) context.runState = createRunState(context.trace ?? null);
  const runState = context.runState;
  const sdl = context.hleContext?.guest?.sdl ?? null;
  const startInstruction = runState.instructionCount;
  const startPresent = sdl === null ? 0 : sdl.present_count;
  const budget = Number.isInteger(instructionBudget) && instructionBudget > 0 ? instructionBudget : 0;
  if (!runState.done && budget > 0) runInterpreterStep(context, runState, budget);
  const presentCount = sdl === null ? 0 : sdl.present_count;
  return {
    stopReason: runState.stopReason,
    done: runState.done,
    instructionCount: runState.instructionCount,
    presentCount,
    stepInstructionCount: runState.instructionCount - startInstruction,
    stepPresentCount: presentCount - startPresent,
    reachedImport: runState.reachedImport,
    fault: runState.fault,
  };
}

// Serves the import bound at guest address `targetVA` against the context's live
// Machine, exactly as the interpreter loop does when execution lands on an HLE
// thunk (the register-indirect / bound-IAT-slot path). A WASM fast-tier
// function whose guest calls through an import thunk invokes this as its
// `hostCall(targetVA)`: the specialization order (initterm, dialog-create,
// window struct/scalar, then the general Win64 ABI marshal) and the resulting
// register/memory mutation + control transfer are byte-identical to the loop's
// thunk branch, because both call the same private dispatchers over the same
// Machine. This is a NEW export the interpreter loop never calls, so it changes
// no existing behavior.
//
// `context` is a buildGuestContext64(...) result (needs `machine`, `hleContext`,
// `dialogEnv`). The return names the outcome the loop would have taken:
//   { served:true, kind:"call" }             — general import served; rip resumed
//   { served:true, kind:"initterm"|"dialog"|"window_struct"|"window_scalar" }
//                                             — a specialization drove the guest
//   { served:true, kind:"hle_stop", stop }   — the HLE exited/faulted (structured)
//   { served:false, kind:"import_present" }  — a thunk with no served row (frontier)
//   { served:false, reason:"no_hle"|"not_a_thunk" } — targetVA is not a served thunk
// Every served/frontier result also carries `import` ({ library, symbol, ... }).
export function serveImportAt64(context, targetVA) {
  const { hleContext } = context;
  if (hleContext === null) return { served: false, reason: "no_hle" };
  const rip = BigInt(targetVA);
  if (rip > 0xffffffffn || !hleContext.guest.isThunk(Number(rip))) return { served: false, reason: "not_a_thunk" };
  const entry = hleContext.guest.exportAt(Number(rip));
  const thunkStop = { import: { library: entry.library, symbol: entry.symbol, ordinal: null, iat_slot_rva: null }, kind: "jmp" };
  return serveImportStop64(context, thunkStop, rip);
}

// The same dispatch for an import reached at a DECODED CALL SITE — the shape
// executeNode reports as `{ reason:"import_present", import, kind }` when a
// direct call/jmp lands on a bound IAT slot. serveImportAt64 above is this
// function with the thunk stop built for it, so the specialization order
// (initterm, dialog-create, window struct/scalar, then the general Win64 ABI
// marshal) has exactly one implementation and a host loop cannot pick a
// different one than the interpreter's.
//
// Exported additively (BPTK tiered-runner boundary). The `kind` field of the
// result names the outcome, as documented on serveImportAt64; a specialization
// outcome ("initterm" / "dialog") means guest control flow was ENTERED and the
// caller's loop must now step the guest until rip reaches the matching
// specialization sentinel, where resumeSpecialization64 advances the walk.
export function serveImportStop64(context, stop, nextRip) {
  const { machine, hleContext, dialogEnv } = context;
  if (hleContext === null) return { served: false, reason: "no_hle" };
  const symbol = stop.import.symbol;
  if (INITTERM_SYMBOL.has(symbol)) { startInitterm(machine, stop, nextRip); return { served: true, kind: "initterm", import: stop.import }; }
  if (DIALOG_CREATE_SYMBOL.has(symbol) && startDialog(machine, stop, nextRip, hleContext, dialogEnv)) return { served: true, kind: "dialog", import: stop.import };
  if (WINDOW_STRUCT_SYMBOL.has(symbol)) { serveWindowImport64(machine, stop, nextRip, hleContext); return { served: true, kind: "window_struct", import: stop.import }; }
  if (WINDOW_SCALAR_SYMBOL.has(symbol)) { serveWindowScalar64(machine, stop, nextRip, hleContext); return { served: true, kind: "window_scalar", import: stop.import }; }
  const dispatch = serveImport64(machine, stop, nextRip, hleContext);
  if (dispatch.served && dispatch.stop === undefined) return { served: true, kind: "call", import: stop.import };
  if (dispatch.served) return { served: true, kind: "hle_stop", stop: dispatch.stop, import: stop.import };
  return { served: false, kind: "import_present", import: stop.import };
}

// The specialization RESUME step. The initterm and dialog specializations are
// driven through GUEST control flow: startInitterm / startDialog / a
// DispatchMessage re-entry each enter a guest function on a fresh Win64 frame
// whose return address is a harness sentinel outside every mapped region, and
// the walk advances when the guest's RET lands rip back on that sentinel. A host
// that runs its own instruction loop (lib/tierrun.mjs) therefore cannot drive a
// specialization without this step — which is why it used to refuse them.
//
// Exported additively (BPTK tiered-runner boundary): runInterpreterStep calls
// this at the top of its own loop, so both loops advance a walk identically by
// construction. Returns { resumed:false } when rip is not on a LIVE
// specialization sentinel (no matching frame in flight), so a host may call it
// unconditionally once per instruction step, exactly as the interpreter does.
export function resumeSpecialization64(context) {
  const { machine } = context;
  if (machine.initStack.length > 0 && machine.rip === initReturnSentinel) { resumeInitterm(machine); return { resumed: true, kind: "initterm" }; }
  if (machine.dialogStack.length > 0 && machine.rip === dialogReturnSentinel) { resumeDialog(machine); return { resumed: true, kind: "dialog" }; }
  return { resumed: false };
}

// The harness sentinel a specialization's guest re-entry uses as its return
// address, exported so a host loop tests rip against the SAME constants the
// specializations write rather than a private copy that can drift out of step.
export const specializationSentinel64 = Object.freeze({
  init: initReturnSentinel,
  dialog: dialogReturnSentinel,
});

// Drives a mapPe64State(...) result through the bounded x86-64 interpreter and
// returns a run-surface-shaped result: probe_executed the moment one x86-64
// instruction runs, probe_blocked otherwise. The stop is always structured —
// an import reached at an IAT slot with no Win64 HLE row, an unsupported
// opcode named, a memory fault named, a guest exit/exception, or budget
// exhaustion. A reached import that the Win32 core HLE serves is dispatched
// through the Win64 ABI marshal (milestone M4) so execution continues, never a
// faked return.
export function executeProbe64(mapped, instructionBudgetCount, option = {}) {
  if (typeof mapped !== "object" || mapped === null || !("image" in mapped)) {
    throw new TypeError("executeProbe64 requires a mapPe64State result");
  }
  const budget = Math.min(instructionBudgetCount, executionBoundDefault.instruction_count);
  const importSet = new Map();
  for (const entry of mapped.import ?? []) {
    importSet.set((mapped.load_base + BigInt(entry.iat_slot_rva)) & MASK64, entry);
  }

  // The Win32 core HLE layout for this image (milestone M4). The arena, virtual
  // arena, and thunk page sit in the 32-bit range, disjoint from the PE32+
  // image (mapped far above 4 GiB) and the high-address guest stack/TEB, so the
  // scan always finds a block. A failed layout leaves the HLE unwired and the
  // probe keeps the historical import_present stop.
  const stackSizeByte = Math.min(option.stackSizeByte ?? stackSizeDefault, executionBoundDefault.stack_byte);
  const stackLowNum = Number(stackRegionBase);
  const layout = createHleLayout({
    load_base: Number(mapped.load_base & MASK64),
    image_size_byte: mapped.image_size_byte ?? mapped.image.length,
    stack_base: stackLowNum,
    stack_end: stackLowNum + stackSizeByte,
  });
  const hle = layout === null ? null : {
    layout,
    clock: createGuestClock({ mode: "virtual_monotonic" }),
    executableName: option.executable_name ?? "game.exe",
    hostFile: option.host_file instanceof Map ? option.host_file : undefined,
    environment: option.environment && typeof option.environment === "object" ? option.environment : undefined,
    commandLine: Array.isArray(option.command_line) ? option.command_line : undefined,
    inputTrace: Array.isArray(option.input_trace) ? option.input_trace : undefined,
  };

  // The resource directory RVA (IMAGE_DIRECTORY_ENTRY_RESOURCE = index 2) feeds
  // the window/dialog-creation path so CreateDialog instantiates the real
  // RT_DIALOG template rather than stopping at the import.
  const resourceRva = mapped.directory?.[2]?.rva ?? 0;

  const run = runImage64({
    image: mapped.image,
    loadBase: mapped.load_base,
    entryRva: mapped.entry_rva,
    budget,
    stackSizeByte: option.stackSizeByte,
    importSet,
    hle,
    resourceRva,
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
  } else if (run.stop_reason === "process_exit") {
    runtimeBlocker.push(`The guest ended its own process with code 0x${(run.exception?.exit_code ?? 0).toString(16)} through a served import`);
  } else if (run.stop_reason === "guest_exception") {
    runtimeBlocker.push(`The guest raised an unhandled exception 0x${(run.exception?.exception_code ?? 0).toString(16)} through a served import`);
  } else if (run.stop_reason === "hle_fault") {
    runtimeBlocker.push(`The Win32 core HLE refused a served import: ${run.exception?.message ?? "unnamed HLE fault"}`);
  } else if (run.stop_reason === "fault") {
    runtimeBlocker.push(`Execution faulted: ${run.exception?.message ?? "unnamed fault"}`);
  } else if (run.stop_reason === "instruction_budget_exhausted") {
    runtimeBlocker.push(`Execution exhausted the ${budget} instruction budget before a structured stop`);
  }

  const register = {};
  for (const name of NAME64) register[name] = `0x${run.register[name].toString(16)}`;

  // The live HLE guest, exposed only when the caller asks (the present path).
  // The corpus/run result is a serialized record, so guest — an object of live
  // functions — is attached only under option.capture_guest and never leaks
  // into a JSON surface.
  const guest = option.capture_guest ? run.guest : undefined;

  return {
    state,
    ...(guest === undefined ? {} : { guest }),
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
