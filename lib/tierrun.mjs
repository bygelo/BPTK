// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The TIERED x86-64 runner (runtime v2 milestone: one guest, two engines). A
// mapped PE32+ image is driven function-by-function over the SINGLE shared guest
// state that lib/exec64.mjs buildGuestContext64 constructs — the same
// multi-region Machine, the same Win32 HLE, the same register file. At every
// tier BOUNDARY the runner decides, once and cached by the entry virtual
// address, which engine executes from there:
//
//   * WASM tier — the region compiles through lib/wasm64.mjs compileFunction and
//     is run as a real WebAssembly module
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
//     WHAT THIS TIER IS FOR is WALL CLOCK: a tiered run must finish a guest in
//     less time than pure interpretation finishes the same guest. Residency —
//     the share of executed instruction the compiled engine carries — is the
//     MEANS, not the goal, and the two come apart. A change can raise residency
//     and lose wall time, and one here did: pushing residency to 12% interpreter
//     on Chocolate Doom while compiling 512-instruction regions was measurably
//     SLOWER than interpreting, because a tier invocation costs more the larger
//     its module is and the guest was only carried ~20 instruction per
//     invocation. The tuning below is therefore chosen against the clock.
//
//     Four things make the tier win, and none touches the import rule above:
//
//       1. RESIDENT ENTRY. The tier is entered where the guest ALREADY STANDS,
//          on the frame it already has, not only at a direct call. After the
//          interpreter performs the one indirect jmp/call (or the RET) the
//          module handed back for, the tier picks the guest straight back up at
//          whatever that landed on. A tier exit becomes a HOP rather than a
//          return to pure interpretation.
//       2. PARTIAL REGIONS. lib/wasm64.mjs no longer refuses a whole region
//          because one instruction somewhere in it is un-emittable; the region
//          runs up to that instruction and hands back AT it. Refusing whole
//          regions is what kept a hot loop out of the tier on account of an
//          unserved opcode on a cold path it never executed.
//       3. THE PROBE BACKSTOP (below): the interpreter may not run more than a
//          fixed number of instruction without offering the tier the current
//          address, so an intra-function loop cannot be interpreted forever.
//       4. BOUNDED REGIONS. A tier invocation's cost grows with the size of the
//          module it enters, so `regionInstructionCap` is tuned to the CLOCK
//          rather than to how much of the guest compiles. Its optimum is not a
//          constant of the design: it moved from 32 to 64 the moment the region
//          frontier stopped being depth-first (lib/wasm64.mjs buildCfg), because a
//          cap only buys coverage if the decode budget is spent near the entry.
//
//     Measured on Chocolate Doom at a 20,000,000-instruction budget, each engine
//     run in its own fresh process and alternated in BOTH orderings, three pairs
//     each (see the instruction accounting below, which is what makes the two
//     comparable at all): interpreter residency 99% → 25.8% → 1.99%, instruction
//     per invocation 13.9 → 37.6, and tiered wall time 0.97x → 1.13x → 3.5x pure
//     interpretation's. Pure interpretation itself got 1.4x faster over the same
//     window, because most of what the profile called "the tier" was neither
//     engine: an export-table scan, an address resolution and a register marshal
//     that both engines paid equally and that therefore diluted the ratio.
//
//     WHERE THE REMAINING TIME GOES, measured at that budget: the compiled code
//     performs 19.46 M guest instruction in 1.4 s — 14 M instruction/second, which
//     is the rate real-time playability asks for. Everything else in the ~12 s a
//     tiered run takes is HOST side: the js-to-wasm boundary on 517,388
//     invocations, compiling ~2,000 regions, the Win32 HLE serving 237,186
//     imports, and this file's own dispatch loop. The compiled tier is no longer
//     what is slow.
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
//     interpreter loop uses (serveImportAt64 / serveImportStop64, both exported
//     by lib/exec64.mjs), never re-implemented — including the CRT-initializer
//     specialization, which is a multi-step walk through guest control flow and
//     is advanced by exec64's exported resumeSpecialization64 step.
//
// INSTRUCTION ACCOUNTING. The whole run is bounded by one instruction budget and
// is deterministic, and that budget counts GUEST INSTRUCTION in both engines: a
// WASM-tier invocation is charged the instruction its module actually performed
// (lib/wasm64.mjs reports it), never one per invocation. Charging one per
// invocation made a tiered run and a pure interpretation measure their budgets in
// different units, so neither their progress nor the tier's residency could be
// compared — the number this file exists to move would have been unmeasurable.
//
// The
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
import {
  buildGuestContext64, serveImportAt64,
  serveImportStop64, resumeSpecialization64, specializationSentinel64,
} from "./exec64.mjs";
import { compileFunction, compileFunctionCached, runFunction, createCallSlotAllocator } from "./wasm64.mjs";

const MASK64 = (1n << 64n) - 1n;
const MASK128 = (1n << 128n) - 1n;
const RSP = 4;
const RBP = 5;
const NAME64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];

// The harness sentinels lib/exec64.mjs defines. A guest RET onto the entry
// sentinel stops the run; the init/dialog sentinels are the specialization
// resume points, taken from exec64's own exported constants so this loop can
// never test rip against a stale private copy.
const returnSentinel = 0xdead000000000000n;
const initReturnSentinel = specializationSentinel64.init;
const dialogReturnSentinel = specializationSentinel64.dialog;

// The import specializations lib/exec64.mjs drives through GUEST control flow
// rather than as a plain ABI marshal: the CRT initializer tables
// (_initterm/_initterm_e), the modal/modeless dialog creation that re-enters the
// guest DlgProc with WM_INITDIALOG, and the window message pump whose
// DispatchMessage re-enters the guest WndProc. Each enters a guest function on a
// fresh Win64 frame whose return address is a harness sentinel and advances when
// the guest RETs onto it — a multi-step walk, not a single call.
//
// This runner DRIVES all of them. exec64 exports the two halves the walk needs,
// and BOTH loops go through that one implementation, so tiering cannot change
// what an initializer table or a dialog procedure does:
//
//   * serveImportStop64 / serveImportAt64 ENTER the walk (call site and import
//     thunk respectively), in exec64's own specialization order.
//   * resumeSpecialization64 ADVANCES it wherever rip lands on a sentinel with a
//     live frame behind it — called once per instruction step, exactly as
//     exec64's runInterpreterStep calls it.
//
// This runner used to refuse the whole class by symbol name, and that refusal was
// never hypothetical: measured on this corpus it stopped a tiered Chocolate Doom
// x64 run after 164 instruction (_initterm_e) and a tiered PuTTY x64 run after
// 26416 (CreateDialogParamA), so the tier reached no hot loop on either. Driven,
// both now run to the SAME frontier pure interpretation reaches — Doom to its own
// process_exit, PuTTY to ole32!CoInitialize — bit-for-bit.
//
// One refusal remains, and it is a real one: rip on a specialization sentinel
// with NO live frame behind it. That cannot happen through the paths above, so it
// means the guest jumped to a harness address on its own. Stopping there is
// honest; guessing which walk it belonged to would not be.

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

// The decoder the WASM TIER compiles through. It is decodeWithSegment's served half:
// exactly the instruction the INTERPRETER above would execute, whenever that
// instruction needs no segment base — which is every case decodeWithSegment resolves
// with `segment: null`, i.e. a flat CS/SS/DS/ES override (zero base in 64-bit mode)
// and a BND branch prefix, both of which it strips and neither of which changes what
// the instruction computes.
//
// Passing lib/lift64.mjs's raw decodeStructured here instead was worth 73,146 guest
// hand-backs across 43 sites over the Chocolate Doom 80,000,000–120,000,000 window —
// 7.7% of every hand-back — and ALL of them were one shape: the CRT's own alignment
// padding, `66 66 2e 0f 1f 84 00 …`, the multi-byte NOP whose 0x2e is a padding byte.
// decodeStructured refuses ANY segment prefix (it is outside the M2 lift subset), so
// the tier read a NOP as unserved and left the module at it — including at
// 0x1400464d4, the single hottest hand-back site in the whole window and the address
// a 120,000,000-instruction run terminated on. This is a decode-parity fix, not a new
// opcode: the tier now sees the SAME node the interpreter sees, which is the only
// thing that keeps the two engines bit-exact anyway.
//
// An fs/gs override is deliberately NOT served: those DO carry a segment base, the
// tier does not model one, and decodeStructured's honest `unsupported` node is what
// makes the module hand back at that instruction instead of computing a wrong
// address. A correct exit beats a wrong dispatch.
function decodeStructuredTier(mem, rva) {
  const resolved = decodeWithSegment(mem, rva);
  return resolved.segment === null ? resolved.node : decodeStructured(mem, rva);
}

// Decoding is PURE in the guest code bytes at `rva`, and the interpreter tier
// re-decodes the same few thousand addresses over and over: measured on Chocolate
// Doom at a 120,000,000-instruction budget, decodeWithSegment was 10.7% of the whole
// tiered run for 1.8% of the executed instruction — ~825 ns per interpreted
// instruction, against ~30 ns to prove a memo entry still applies. The probe backstop
// is what makes that ratio so lopsided: the interpreter runs SHORT stretches at the
// same handful of hand-back sites, so almost every decode is a repeat.
//
// The memo is REVALIDATED, not trusted. Both engines run on one shared guest memory
// and the image is part of it, so guest code can rewrite itself; the entry therefore
// carries the exact bytes the decode consumed and a reuse compares them. That
// comparison is complete: `node.length` IS the number of bytes decodeWithSegment
// read at `rva` (including a stripped prefix byte), so identical bytes decode
// identically — a memo hit cannot differ from a fresh decode, and a rewritten
// instruction misses and re-decodes.
//
// Bounded so a guest that walks a large code span cannot grow it without limit; past
// the ceiling the memo is emptied and refills with what the guest is executing now.
const DECODE_MEMO_LIMIT = 200000;
function decodeMemoized(memo, mem, rva) {
  const hit = memo.get(rva);
  if (hit !== undefined) {
    const byte = hit.byte;
    let same = true;
    for (let i = 0; i < byte.length; i += 1) if (mem[rva + i] !== byte[i]) { same = false; break; }
    if (same) return hit;
  }
  const made = decodeWithSegment(mem, rva);
  const len = made.node.length | 0;
  // A truncated decode has no honest length to remember, so it is never memoized:
  // it stops the run on the very next check anyway.
  if (len <= 0 || rva + len > mem.length) return made;
  const byte = new Uint8Array(len);
  for (let i = 0; i < len; i += 1) byte[i] = mem[rva + i];
  if (memo.size >= DECODE_MEMO_LIMIT) memo.clear();
  const entry = { node: made.node, segment: made.segment, byte };
  memo.set(rva, entry);
  return entry;
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
//
// `node` is the direct CALL instruction being tiered, and then this invocation
// BUILDS the callee's frame (rsp-8, sentinel return address) exactly as the guest
// call would. It is null for a RESIDENT entry: the module picks the guest up at the
// address it already stands on, on the frame it already has, creating no frame and
// planting no sentinel. A resident entry is what keeps the guest IN the tier across
// a transfer the module cannot model — the interpreter performs the one indirect
// jmp/call (or the RET) and the tier is re-entered at wherever that landed, instead
// of interpreting onward until the next direct call happens by.
function runWasmTierFunction(context, target, node) {
  const { machine, loadBase } = context;
  const imageBuf = context.imageBuf;
  // The stack region, its base and the entry sentinel are properties of the RUN, not
  // of the invocation. Re-deriving them meant a masked BigInt and a linear scan of
  // the region list — with a BigInt mask per region — on every one of half a million
  // invocations, for three values that never change. Held on the context instead.
  let fixed = context.tierFixed;
  if (fixed === undefined) {
    const base = context.layout.stack.base & MASK64;
    const region = context.region.find((r) => (r.base & MASK64) === base);
    fixed = { stackBase: base, stackRegion: region, stackSize: region.buf.length, sentinel: returnSentinel | (loadBase & 0xffffn) };
    context.tierFixed = fixed;
  }
  const { stackBase, stackRegion, stackSize, sentinel } = fixed;

  const entering = node !== null;
  const origRsp = machine.reg[RSP] & MASK64;
  const rspForWasm = entering ? (origRsp - 8n) & MASK64 : origRsp;
  const realRet = entering ? (machine.rip + BigInt(node.length)) & MASK64 : 0n;

  const sentinelOff = Number((rspForWasm - stackBase) & MASK64);
  if (sentinelOff < 0 || sentinelOff + 8 > stackSize) return null; // rsp not in the stack region: let the interpreter handle it

  // On the SHARED memory the module writes the entry sentinel straight into the
  // guest's own stack at the seeded rsp — the very slot a `call` pushes its return
  // address into, so nothing live is disturbed and every exit below overwrites it.
  // Without a shared memory the module gets a private stack image instead, and the
  // sentinel is planted in that copy.
  const shared = context.sharedPlan ?? null;
  // A resident entry only makes sense on the SHARED memory: on a private copy the
  // module's stack is a seeded duplicate whose sentinel lives at the copy's top, and
  // picking the guest up mid-frame there would resume against bytes that are not the
  // guest's own.
  if (!entering && shared === null) return null;
  let stackCopy = null;
  if (shared === null) {
    stackCopy = Buffer.from(stackRegion.buf);
    for (let i = 0; i < 8; i += 1) stackCopy[sentinelOff + i] = Number((sentinel >> (8n * BigInt(i))) & 0xffn);
  }

  // The Machine's OWN register array, handed over without a copy and without the
  // named-property object it used to be re-packed into. lib/wasm64.mjs seedStatePlan
  // masks each value itself and never mutates the array, and its `registerFile`
  // protocol is this exact NAME64 index order — so the marshal is sixteen reads
  // rather than a sixteen-key object built here and taken apart with
  // `Object.entries` + `NAME64.indexOf` there, on every one of a million invocations.
  const registerFile = machine.reg;
  // The Machine's own xmm file, handed over WITHOUT a masked copy: seedStatePlan
  // masks each value itself and never mutates the array, and building a sixteen-entry
  // BigInt copy per invocation is pure cost. When the region contains no SSE op the
  // seed skips it entirely (lib/wasm64.mjs `usesXmm`).
  const xmm = machine.xmm;
  const flag = machine.flags();

  const regionSpec = shared === null ? buildRegionSpec(context, stackCopy) : shared.region;
  const entryRva = Number((target - loadBase) & MASK64);

  // The invocation option. Everything in it but five fields is a constant of the
  // RUN, and lib/wasm64.mjs reads it synchronously and never retains it, so on the
  // shared-memory path it is built ONCE and the five varying fields are assigned.
  // Building it per invocation meant one ~17-key object literal plus a spread of the
  // compile option, half a million times, and the spread of the SAME constant keys
  // is what made it worth hoisting rather than the literal itself. The private-memory
  // path keeps the literal: its `region` list is rebuilt per invocation anyway.
  let invocationOption;
  if (shared === null) {
    invocationOption = {
      image: imageBuf, loadBase, decodeStructured: decodeStructuredTier, registerFile, rspOverride: rspForWasm, xmm, flag, entryRva,
      rawRegion: true, rawRegister: true, region: regionSpec, entrySentinel: entering,
    };
  } else {
    invocationOption = context.tierInvokeOption;
    if (invocationOption === undefined) {
      // On the shared memory an iteration-cap exit is COMMITTED, so the cap has to
      // be a bound the whole run can honour rather than lib/wasm64.mjs's very large
      // default: one invocation may then dispatch at most as many blocks as the run
      // has instruction budget. It is a constant for the run, so it does not
      // perturb the compiled-module cache key from call to call.
      invocationOption = { image: imageBuf, loadBase, decodeStructured: decodeStructuredTier, xmm, rawRegion: true, rawRegister: true, ...context.tierCompileOption };
      context.tierInvokeOption = invocationOption;
    }
    invocationOption.registerFile = registerFile;
    invocationOption.rspOverride = rspForWasm;
    invocationOption.flag = flag;
    invocationOption.entryRva = entryRva;
    // A resident entry owns no frame, so it plants no entry sentinel: the qword at
    // its rsp is a live guest byte. See lib/wasm64.mjs seedStatePlan.
    invocationOption.entrySentinel = entering;
  }

  // Per-invocation counters the in-module import boundary writes (see
  // runTieredImage): how many imports this module served without leaving, and the
  // HLE stop one of them raised, if any.
  context.tierImport = 0;
  context.tierHleStop = null;

  let jit;
  try {
    jit = runFunction(imageBuf, invocationOption);
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
  // The guest instruction this invocation actually performed. The run's budget is
  // charged this rather than one per invocation, so a tiered run and a pure
  // interpretation measure their budgets in the SAME unit and their progress — and
  // therefore the tier's residency — is comparable.
  context.tierStep = jit.instructionCount | 0;
  // `rawRegister`: jit.register is the sixteen-element array in NAME64 index order,
  // the same shape the Machine's own file has, so the read-back is sixteen indexed
  // loads instead of sixteen named-property lookups off a freshly allocated object.
  for (let i = 0; i < 16; i += 1) machine.reg[i] = jit.register[i] & MASK64;
  machine.flagSource = { kind: "explicit", value: { cf: jit.flag.cf, pf: jit.flag.pf, af: jit.flag.af, zf: jit.flag.zf, sf: jit.flag.sf, of: jit.flag.of } };
  // A null xmm means the region contained no SSE op at all, so it could not have
  // written one — the Machine's own xmm file is already this run's state, and the
  // marshal it would have cost (32 BigInt loads plus 16 masked stores, the largest
  // fixed cost of an invocation) is skipped in both directions.
  if (jit.xmm !== null) for (let i = 0; i < 16; i += 1) machine.xmm[i] = jit.xmm[i] & MASK128;

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

  // The HAND-BACK histogram, off unless a caller asks for it. Every invocation that
  // does not run its region to completion resumes somewhere, and WHY it resumed is
  // the number that decides which shape is worth compiling next. The module reports
  // no reason at run time; it does not have to, because every mid-run exit resumes ON
  // the instruction that produced it, so the compilation's own exit map names it.
  const handback = context.tierHandback;
  if (handback !== undefined && jit.statusName !== "ok") {
    const rip = jit.resumeRip & MASK64;
    const reason = jit.exitReason?.get(rip)
      ?? context.tierReason?.get(rip)
      ?? (jit.statusName === "budget_exhausted" ? "iteration_cap" : jit.statusName === "fault" ? "precise_fault" : "ret_out_of_region");
    const key = `${reason}@0x${rip.toString(16)}`;
    const row = handback.get(key);
    if (row === undefined) handback.set(key, { reason, address: `0x${rip.toString(16)}`, count: 1, step: jit.instructionCount | 0 });
    else { row.count += 1; row.step += jit.instructionCount | 0; }
  }

  if (jit.statusName === "ok") {
    if (!entering) {
      // A RESIDENT entry plants no sentinel, so the only value a RET can pop that
      // wasm64 reads as the entry frame is the one the HOST put there — exec64's
      // guest entry-frame return address. The guest has returned out of its own
      // entry: rip is that address, exactly as the interpreter's `ret` assigns it,
      // and the run's stop is entry_return. jit.resumeRip carries the popped value,
      // so no assumption about which sentinel it was is made here.
      machine.rip = jit.resumeRip & MASK64;
      return "resume";
    }
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
  if (entering && machine.readMem(rspForWasm, 8) === sentinel) machine.writeMem(rspForWasm, 8, realRet);
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
    // A stop is only a failure to reach `returnRip` if rip is not already THERE. A
    // WASM-tier run that ends by RETurning out of the guest's own entry frame resumes
    // on exec64's entry sentinel, and interpretation reaches that same address by
    // executing the same `ret` — which reports entry_return as it assigns rip.
    if (executeNode(machine, node, machine.rip + BigInt(node.length), importSet)) return machine.rip === returnRip;
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

  // ---- the in-module import boundary ----
  //
  // A WASM-tier region that reached a Win32/CRT import used to END the invocation:
  // the module handed back at the call and the interpreter performed the transfer,
  // the loop below served the import, and the tier was re-entered afterwards.
  // Measured on Chocolate Doom at a 20,000,000-instruction budget that was ~312,000
  // of 517,388 invocations — the single largest remaining HOST-side cost, and not one
  // instruction of it is guest work. This callback is what lets a module stay
  // resident across one: lib/wasm64.mjs spills the guest register file, calls in
  // here with the target virtual address, and continues at the call's return address
  // when the import came back to it.
  //
  // The import is SERVED BY THE HLE, never emulated or guessed in the tier. This is
  // the SAME serveImportAt64 the interpreter loop calls, on the same Machine, over
  // the same shared guest memory, so a served import is byte-for-byte the one pure
  // interpretation performs — including its Win64 return marshal and its POP of the
  // return address, which is why lib/wasm64.mjs hands the return to the host here
  // rather than popping itself.
  //
  // Classification REFUSES by default. A target the HLE does not know as one of its
  // own thunks is handed straight back (status 1) having touched nothing, and the
  // module undoes its return-address push and resumes at the call — a correct exit
  // beats a wrong dispatch. So is an import with no served row: that is the honest
  // import_present frontier, and only the loop below may report it.
  const thunkRegion = context.layout?.thunk ?? null;
  const savedReg = new Array(16);
  const serveImportInModule = (hleContext === null || thunkRegion === null || sharedPlan === null) ? null : (targetVA, ctx) => {
    const target = BigInt.asUintN(64, targetVA);
    if (target > 0xffffffffn || !hleContext.guest.isThunk(Number(target))) return 1;
    for (let i = 0; i < 16; i += 1) { savedReg[i] = machine.reg[i]; machine.reg[i] = ctx.readReg(NAME64[i]); }
    const savedFlagSource = machine.flagSource;
    const savedRip = machine.rip;
    machine.flagSource = { kind: "explicit", value: { cf: ctx.readFlag("cf"), pf: ctx.readFlag("pf"), af: ctx.readFlag("af"), zf: ctx.readFlag("zf"), sf: ctx.readFlag("sf"), of: ctx.readFlag("of") } };
    machine.rip = target;
    const served = serveImportAt64(context, target);
    if (!served.served) {
      // An unserved import row: serveImport64 refuses BEFORE it reads an argument or
      // writes a register, so nothing happened and the Machine goes back exactly as
      // it was — the runner may still discard this whole invocation.
      for (let i = 0; i < 16; i += 1) machine.reg[i] = savedReg[i];
      machine.flagSource = savedFlagSource;
      machine.rip = savedRip;
      return 1;
    }
    // The interpreter loop charges its own budget ONE instruction for serving an
    // import (the turn of the loop that does it), on top of the transfer that
    // reached the thunk. Counting them here and charging them to the run keeps a
    // tiered run and a pure interpretation consuming the budget in the SAME unit —
    // without which the two do not reach the same place and the whole comparison is
    // worthless. It is charged to the RUN, not to either engine's instruction count:
    // serving an import is guest work in neither.
    context.tierImport += 1;
    // The HLE ended the run (process exit, guest exception, HLE fault). The effect is
    // already applied and cannot be undone, so it is REPORTED rather than refused:
    // the loop below maps it the moment this invocation returns. rip is still the
    // thunk, so the module hands back rather than resuming at the return address.
    if (served.stop !== undefined) context.tierHleStop = served.stop;
    for (let i = 0; i < 16; i += 1) ctx.writeReg(NAME64[i], machine.reg[i]);
    const flag = machine.flags();
    ctx.writeFlag("cf", flag.cf); ctx.writeFlag("pf", flag.pf); ctx.writeFlag("af", flag.af);
    ctx.writeFlag("zf", flag.zf); ctx.writeFlag("sf", flag.sf); ctx.writeFlag("of", flag.of);
    // Where the guest now stands. The general marshal pops the return address and
    // leaves rip ON it, so the module carries on in the same region; a specialization
    // (a CRT-initializer walk, a dialog re-entry) leaves rip inside GUEST code on a
    // fresh frame, and the module hands back there exactly as this loop would.
    ctx.writeRip(machine.rip);
    return 0;
  };

  // The option every WASM-tier compilation for this run shares (everything but the
  // entry). Held once so the eligibility compile and the invocation compile agree
  // byte-for-byte and hit the same cache entry.
  const tierCompileOption = sharedPlan === null ? null : {
    loadBase, decodeStructured: decodeStructuredTier, region: sharedPlan.region, sharedPlan,
    iterationCap: Math.max(1, budget | 0),
    // Compile a PARTIAL region: a shape lib/wasm64.mjs will not model stops being a
    // refusal of the whole region and becomes a named mid-run exit at that
    // instruction's own address. Refusing whole regions is what kept residency at
    // 1.7% on Chocolate Doom — one unserved opcode on a cold path made the hot loop
    // around it ineligible.
    partialRegion: true,
    // How much guest a single region may cover, TUNED TO THE CLOCK. It is tempting to
    // make this large — a bigger region compiles more of the guest and needs fewer
    // invocations to cover it — and that is exactly the trade that loses. The emitted
    // module grows superlinearly in the instruction a region covers (one br_table arm
    // per block, one address comparison per followed call in every RET block), and a
    // tier invocation costs more the larger the module it enters is: a run rotates
    // through thousands of them, so each entry lands in cold code. Measured on
    // Chocolate Doom at a 20,000,000-instruction budget, tiered wall time against pure
    // interpretation by cap — 256: 1.04x, 128: 1.16x, 64: 1.38x, 32: 1.60x, 16: 1.14x.
    // Residency barely moves across that range (23%–29% interpreter) because the probe
    // backstop re-enters regardless; what moves is the clock. Left large, this cap
    // also exhausts the WASM compiler's own memory on a real binary.
    // How much guest a single region may cover, TUNED TO THE CLOCK. It is tempting to
    // make this large — a bigger region compiles more of the guest and needs fewer
    // invocations to cover it — and past a point that is the trade that loses: the
    // emitted module grows superlinearly in the instruction a region covers (one
    // br_table arm per block, one address comparison per followed call in every RET
    // block), and a tier invocation costs more the larger the module it enters is.
    //
    // The optimum MOVED when the region frontier stopped being depth-first
    // (lib/wasm64.mjs buildCfg): a cap only buys coverage if the budget is spent
    // near the entry, and until it was, every cap from 32 to 256 exited on the
    // entry block's own first `jcc`. Measured on Chocolate Doom at a
    // 20,000,000-instruction budget, three interleaved rounds (interleaved because
    // this machine drifts up to 40% across a few minutes, which is larger than the
    // effect) — median wall time by cap: 32: 26.7 s, 48: 19.6 s, 64: 18.0 s,
    // 96: 19.5 s, and 64 was the fastest in all three rounds. Left large, this cap
    // also exhausts the WASM compiler's own memory on a real binary.
    regionInstructionCap: 64,
    // THE CROSS-MODULE CALL. A direct `call` to image code the region's own decode
    // budget did not reach used to END the invocation, and the callee's RET ended a
    // second one — so one guest call round trip cost THREE host invocations. With an
    // allocator bound, lib/wasm64.mjs reserves a slot in this run's shared function
    // table for that target and calls the callee's own compiled region in-place, so
    // the call and its return never leave WASM. Measured on Chocolate Doom x64 at a
    // 120,000,000-instruction budget those two shapes were 507,430 of 853,042
    // hand-back (59.5%), against ~102 ns of guest work per ~2,672 ns invocation:
    // the round trip, not the compiled code, is what the tier was spending its time
    // on. The table lives on the shared plan, so it is per-RUN and can never be
    // reached by another guest.
    ...(sharedPlan === null ? {} : { callSlot: createCallSlotAllocator(sharedPlan) ?? undefined }),
    // The in-module import boundary (above). Both halves are supplied together and
    // mean one thing: the host serves an import at a target inside the HLE's own
    // thunk region, and performs the guest's return as part of serving it. A target
    // anywhere else is never offered — the module hands back instead.
    ...(serveImportInModule === null ? {} : {
      hostCall: serveImportInModule,
      importThunkRange: { lo: BigInt(thunkRegion.base) & MASK64, hi: (BigInt(thunkRegion.base) + BigInt(thunkRegion.size_byte)) & MASK64 },
    }),
  };
  context.tierCompileOption = tierCompileOption;

  // Opt-in hand-back accounting (see runWasmTierFunction). `undefined` unless the
  // caller supplies a Map, so a normal run pays one property read per invocation.
  context.tierHandback = option.handbackHistogram instanceof Map ? option.handbackHistogram : undefined;
  // Every compiled region's exit map, merged. An invocation may now end INSIDE a
  // region the host never entered — a cross-module call or continuation carries the
  // guest across module boundaries without leaving WASM, so the address handed back
  // at is frequently a callee's, and the module the host entered has no idea why it
  // stopped. Attributing that to the entered module's own map alone reports every one
  // of them as the default. Diagnostic only, and built only when a caller asks for
  // the histogram.
  context.tierReason = context.tierHandback === undefined ? undefined : new Map();

  const tierDecision = new Map(); // entry VA → "wasm" | "interpreter"
  const wasmEntry = new Set();
  const interpEntry = new Set();
  let wasmInvocation = 0;
  let wasmResume = 0;
  let interpInstruction = 0;
  let wasmInstruction = 0;
  // Imports served from INSIDE a WASM-tier module, without ending the invocation.
  let wasmImport = 0;

  // HOTNESS was evaluated here and REFUSED. Compiling a region is the most expensive
  // thing a tier invocation can do (~20% of a Chocolate Doom run's wall clock across
  // ~2,000 regions), and requiring an address to be offered twice before compiling it
  // is worth a measured 15-20% of that run — but it buys the time by not tiering code
  // the guest visits once, and "visits once" includes the whole of a SHORT run. It
  // cost the PuTTY 1:1 corpus case every one of its in-module import boundaries and
  // pushed real work back into the interpreter on every mechanism case in
  // test/tierrun.test.mjs. Residency is the mechanism this tier is; trading it for
  // clock at the boundary where a run is short is the wrong side of the trade, so the
  // compile cost is attacked in the codegen (lib/wasm64.mjs memoizes the instruction
  // bytes it emits) rather than by tiering less.
  const decideTier = (target) => {
    if (tierDecision.has(target)) return tierDecision.get(target);
    let decision = "interpreter";
    const entryRva = Number((target - loadBase) & MASK64);
    if (entryRva >= 0 && entryRva < imageBuf.length && tierCompile < tierCompileCeiling) {
      tierCompile += 1;
      try {
        // Compile through the SAME cache and with the SAME option the invocation
        // will use, so deciding eligibility IS the compile the run then reuses.
        // Compiling twice per function was the largest remaining cost once the
        // per-invocation guest copy was gone.
        const compiled = sharedPlan === null
          ? compileFunction(imageBuf, { loadBase, decodeStructured: decodeStructuredTier, entryRva, guestLen: imageBuf.length + (context.layout.stack.size_byte ?? 0x10000) })
          : compileFunctionCached(imageBuf, { ...tierCompileOption, entryRva });
        const badReason = new Set((compiled.coverage.unsupported ?? []).map((u) => u.reason));
        // A PARTIAL region has already resolved every refused shape — including an
        // external call boundary and an unserved opcode — to a named mid-run exit at
        // that instruction's own address, so there is no unserved boundary left to
        // guard against. Only a compilation that could NOT do that is refused here.
        const hasUnservedBoundary = compiled.partial !== true
          && (badReason.has("control_call_external") || badReason.has("not_served"));
        // An indirect jmp/call is NOT a reason to refuse the WASM tier any more. It
        // compiles as a return-to-dispatch terminator, and runWasmTierFunction now
        // COMMITS that exit and continues at the module's resume rip — so everything
        // the function does before the transfer really runs at WASM speed instead of
        // being re-interpreted from the entry. The decision is cached per entry VA,
        // and lib/wasm64.mjs caches the compiled module per entry, so a function that
        // exits at an indirect on every call never re-compiles.
        if ((compiled.complete || compiled.partial === true) && !hasUnservedBoundary) decision = "wasm";
        if (context.tierReason !== undefined && compiled.exitReason !== undefined) {
          for (const [va, reason] of compiled.exitReason) context.tierReason.set(va, reason);
        }
      } catch { decision = "interpreter"; }
    }
    tierDecision.set(target, decision);
    return decision;
  };

  // The RESIDENCY probe. The tier used to be reachable at exactly one kind of site —
  // a direct `call` — so every exit the module could not model (an indirect jmp/call,
  // an unmatched RET) dropped the guest back into the interpreter until the next
  // direct call happened by. Measured on Chocolate Doom that left 98.3% of executed
  // instruction in the interpreter: 1208 invocations carrying ~28 instruction each.
  //
  // `probeArmed` marks a boundary at which the tier may be RE-ENTERED where the guest
  // already stands, on the frame it already has. It is armed at the guest entry, after
  // any WASM-tier invocation that made progress, and after the interpreter executes
  // one of the three transfers the module hands back for — callIndirect, jmpIndirect,
  // ret. Those are precisely the addresses a compiled region can begin at, and they
  // are a small, converging set: a probe that turns out to buy nothing demotes its
  // address permanently (below), so a hot site costs one compile ever and a dead one
  // costs one compile ever.
  // The three transfers the module hands back for. A direct `jcc`/`jmp` is
  // deliberately NOT here, and that is a measured choice against the clock rather than
  // an oversight: arming the probe on every direct branch as well drove interpreter
  // residency on Chocolate Doom from 26% down to 8% — and was SLOWER, 49.2 s against
  // 46.1 s at a 20,000,000-instruction budget (best of three, alternated in one
  // thermal window). It bought that residency with 1.77 M invocations instead of
  // 1.06 M, and an invocation costs more than the handful of instruction it saves.
  // Residency is the means; the clock is the goal, and here they point opposite ways.
  const TRANSFER_OP = new Set(["callIndirect", "jmpIndirect", "ret"]);
  // The BACKSTOP. Arming the probe only at a transfer leaves a hole with teeth: once
  // the interpreter is running a stretch that began at an address the tier refused,
  // nothing re-offers the work, and an intra-function loop — whose back edge is a
  // `jcc`, not a transfer — is interpreted forever even when the region around it
  // compiles perfectly. Measured on Chocolate Doom that is not hypothetical: a
  // SIX-instruction loop at one address that compiles COMPLETELY ran 697,349 times in
  // the interpreter, 4.2 M of the run's 14.5 M interpreted instruction, because the
  // probe was never armed inside it. So the interpreter may not run more than
  // `probeInterval` instruction without offering the tier the current address. The
  // offer is a cached decision lookup, and an address that buys nothing is cached as
  // the interpreter's for good, so the backstop costs a Map lookup per interval.
  const probeInterval = 8;
  let sinceProbe = 0;
  let probeArmed = !forceInterpreter && sharedPlan !== null;
  let residentInvocation = 0;
  // Compiling a region is by far the most expensive thing a tier invocation can do,
  // and a resident entry can be attempted at any boundary — so a run that compiled
  // every boundary it ever reached would spend its whole budget compiling regions it
  // enters once, and hold every one of those modules alive. A CEILING on distinct
  // compilations bounds that for the whole run without keying on anything about a
  // particular guest: past it the tier keeps using every region it already has and
  // stops adding new ones. It does not change what the guest computes — it only picks
  // the engine — and an address that turns out to buy nothing is demoted for good
  // (below), so the ceiling is reached by breadth of real code, never by churn.
  const tierCompileCeiling = 20000;
  let tierCompile = 0;

  // The interpreter tier's decode memo (see decodeMemoized). One per run, so nothing
  // survives a run and a fresh guest can never see another guest's decode.
  const decodeMemo = new Map();

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
      // The guest RETurned out of its own entry frame INSIDE a WASM-tier module: the
      // module popped exec64's entry-frame return address and committed rip onto it.
      // Pure interpretation reports that at the `ret` itself; reaching it here is the
      // same stop with the same rip, and it is the only way a harness address becomes
      // rip without an interpreted instruction having assigned it.
      if (machine.rip === returnSentinel) { stopReason = "entry_return"; break; }
      // A guest register-indirect call/jump through an unserved import's IAT slot
      // lands rip on that import's sentinel: the clean import frontier.
      if (unservedSentinel.size > 0 && unservedSentinel.has(machine.rip)) {
        const entry = unservedSentinel.get(machine.rip);
        instructionCount += 1;
        stopReason = "import_present";
        reachedImport = { library: entry.library, symbol: entry.symbol, ordinal: entry.ordinal ?? null, iat_slot_rva: entry.iat_slot_rva ?? null };
        break;
      }
      // A specialization's guest re-entry just RETurned onto its harness
      // sentinel. exec64's exported step advances the walk — the next CRT
      // initializer, or the _initterm(_e) caller once the table is done — over
      // the same shared Machine, through the SAME code the interpreter loop
      // runs, so a tiered walk and an interpreted walk are the same walk. The
      // enclosing `for` increment charges this step one instruction, exactly as
      // the interpreter's `continue` does.
      if (resumeSpecialization64(context).resumed) continue;
      // rip is on a sentinel with no live frame behind it: a specialization this
      // runner entered but does not host. Refuse honestly rather than fault.
      if (machine.rip === initReturnSentinel || machine.rip === dialogReturnSentinel) {
        stopReason = "tier_unsupported_specialization";
        fault = { message: "the tiered runner does not drive this specialization resume path", address: machine.rip };
        break;
      }
      // A guest indirect call/jump through a bound IAT slot lands rip on an HLE
      // thunk. Serve it through the SAME marshal the interpreter loop uses.
      if (hleContext !== null && machine.rip <= 0xffffffffn && hleContext.guest.isThunk(Number(machine.rip))) {
        // serveImportAt64 applies exec64's own specialization order before the
        // general marshal. A specialization serves by ENTERING guest control flow
        // (kind "initterm" / "dialog" / "window_struct") — a served result with no
        // stop, so this loop simply continues into the guest, and the sentinel
        // branch above advances the walk when the guest returns.
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
      // RESIDENT ENTRY. rip stands at a boundary the tier may pick the guest up at.
      // Nothing about the guest changes: no frame is built, no sentinel is planted,
      // the module simply continues the current function on the current stack until
      // it reaches something it cannot model — and every one of those exits is the
      // same committed, resumable exit a direct-call invocation makes.
      if (probeArmed) {
        probeArmed = false;
        const here = machine.rip & MASK64;
        if (decideTier(here) === "wasm") {
          const auditSnap = option.wasmAudit ? snapshotMachine(context) : null;
          const outcome = runWasmTierFunction(context, here, null);
          if (outcome !== null) {
            if (option.wasmAudit) {
              const wasmSnap = snapshotMachine(context);
              restoreMachine(context, auditSnap);
              const ok = interpretUntilReturn(context, wasmSnap.rip, 4_000_000);
              if (!ok) throw new Error(`wasmAudit: interpreter could not reach resume 0x${wasmSnap.rip.toString(16)} for resident entry 0x${here.toString(16)}`);
              const diff = auditDiff(context, wasmSnap);
              if (diff.length) throw new Error(`wasmAudit: WASM tier diverges for resident entry 0x${here.toString(16)}:\n  ${diff.slice(0, 8).join("\n  ")}`);
              restoreMachine(context, wasmSnap);
            }
            wasmInvocation += 1;
            residentInvocation += 1;
            // Charge the budget EXACTLY what the module executed — the enclosing `for`
            // adds the last one, so this adds the rest. A zero-progress invocation
            // subtracts one and the `for` adds it back, charging nothing: the module
            // performed no guest instruction, and charging one for it would make the
            // tiered run's instruction count mean something different from pure
            // interpretation's, which is the one thing that must not drift.
            wasmInstruction += context.tierStep;
            instructionCount += context.tierStep - 1;
            // Imports this module served WITHOUT leaving. The interpreter loop charges
            // its budget one turn for each, so this run charges the same.
            instructionCount += context.tierImport;
            wasmImport += context.tierImport;
            if (context.tierHleStop !== null) { mapHleStop(context.tierHleStop); break; }
            wasmEntry.add(here);
            if (outcome === "resume") {
              wasmResume += 1;
              // NO PROGRESS: the module stopped on the very instruction it started
              // on, so the whole invocation bought nothing and never will. Demote the
              // address for good — this is what keeps the probe's compile count
              // bounded by the number of DISTINCT boundaries rather than growing with
              // the number of times each is reached. Correctness is unaffected either
              // way: the demotion only picks the engine.
              if (machine.rip === here) tierDecision.set(here, "interpreter");
              else probeArmed = true;
            }
            continue;
          }
        }
      }

      const { node, segment } = decodeMemoized(decodeMemo, imageBuf, Number(rvaOffset));
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
            // The module executed the callee's body, and this invocation performed the
            // `call` itself as the frame it built — so the WASM tier is credited both,
            // and the enclosing `for` charges the budget the one the module did not
            // count for itself.
            wasmInstruction += context.tierStep + 1;
            instructionCount += context.tierStep;
            // Imports this module served WITHOUT leaving (see the resident-entry site).
            instructionCount += context.tierImport;
            wasmImport += context.tierImport;
            if (context.tierHleStop !== null) { mapHleStop(context.tierHleStop); break; }
            // An "ok" run leaves rip at the call's return address — a resident-entry
            // boundary inside the CALLER, so the tier can carry straight on there
            // instead of dropping back to the interpreter until the next direct call.
            if (outcome === "ok") probeArmed = true;
            if (outcome === "resume") {
              wasmResume += 1;
              // NO PROGRESS. The module stopped at the callee's very first
              // instruction — the entry block is nothing but an indirect transfer
              // (an import thunk's `jmp [iat]` is exactly this shape). Running a
              // WASM module to execute zero guest instructions is pure overhead on
              // every future call, so demote the entry to the interpreter for good.
              // Correctness is unaffected either way: this only picks the engine.
              if (machine.rip === target) tierDecision.set(target, "interpreter");
              else probeArmed = true;
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
      // The interpreter has just performed one of the three transfers the WASM tier
      // hands back for. rip now names a fresh region the tier may resume in, so arm
      // the probe: this is the step that turns a tier EXIT into a tier hop instead of
      // a return to pure interpretation.
      if (!forceInterpreter && sharedPlan !== null) {
        sinceProbe += 1;
        if (TRANSFER_OP.has(node.op) || sinceProbe >= probeInterval) { probeArmed = true; sinceProbe = 0; }
      }
      if (stop) {
        if (stop.reason === "import_present" && hleContext !== null) {
          // serveImportStop64 is serveImportAt64's call-site twin: ONE
          // implementation of the specialization-then-marshal order, so a
          // specialization reached at a decoded call site enters the guest walk
          // exactly as the interpreter's own loop enters it.
          const dispatch = serveImportStop64(context, stop, nextRip);
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
      // An ENTRY, not strictly a function: the tier is entered where the guest stands
      // as well as at a direct call, so an entry address may be mid-function, and a
      // function reached by a direct call from inside a compiled region never appears
      // as one at all — it is compiled into its caller's region.
      wasm_tier_function: wasmEntry.size,
      interpreter_tier_function: interpEntry.size,
      wasm_tier_invocation: wasmInvocation,
      // Of those invocations, the ones entered where the guest already stood rather
      // than at a direct call — the residency probe's own contribution.
      wasm_tier_resident_invocation: residentInvocation,
      wasm_tier_resume: wasmResume,
      // Imports the WASM tier served WITHOUT leaving the module. Each one is an
      // invocation that used to end at the call and no longer does.
      wasm_tier_import: wasmImport,
      // The guest instruction each engine actually performed, in the SAME unit. Their
      // ratio is the tier's RESIDENCY, which is the number that decides whether
      // compiling anything is worth doing at all.
      wasm_tier_instruction: wasmInstruction,
      interpreter_tier_instruction: interpInstruction,
      // How much of the run's clock went into COMPILING rather than executing, in the
      // only unit that can be checked against the ceiling: distinct compilations, and
      // the distinct boundary addresses a decision was ever taken at. Compiling a
      // region is the most expensive single thing an invocation does, so a run whose
      // compile count runs far ahead of its `wasm_tier_function` count is paying for
      // regions it never re-enters — measured on Chocolate Doom at a 120,000,000
      // budget these are 3066 / 3066 / 3066, so none of that compilation is waste and
      // the ceiling is never the thing binding.
      tier_compile: tierCompile,
      tier_decision: tierDecision.size,
      wasm_tier_entry: [...wasmEntry].map((v) => `0x${v.toString(16)}`),
    },
  };
}
