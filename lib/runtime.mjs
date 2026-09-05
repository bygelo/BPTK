// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { createGuestClock } from "./clock.mjs";
import { createWin32Hle, isHleSignal, listWin32HleExport, hleProfile } from "./hle.mjs";
import { buildTebImage } from "./thread.mjs";
import { mapFaultToException } from "./seh.mjs";

const registerName = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];
const registerIndex = Object.freeze({ eax: 0, ecx: 1, edx: 2, ebx: 3, esp: 4, ebp: 5, esi: 6, edi: 7 });
const maxStackSizeByte = 16 * 1024 * 1024;
const stackPageSizeByte = 0x1000;
const returnSentinelCandidate = [0xfffff000, 0x20000000, 0x10000000, 0x80000000, 0x90000000];
const flagMask = Object.freeze({ carry: 1, parity: 4, adjust: 0x10, zero: 0x40, sign: 0x80, direction: 0x400, overflow: 0x800 });
const aluKindName = Object.freeze(["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"]);
// The repeat loop is one instruction to the budget, so its iteration count is
// bounded by this declared amount; exceeding it is a structured stop, never a
// silent stall (BPTK-044 declared bound).
const repIterationBound = 1 << 20;

class RuntimeFault extends Error {
  constructor(code, message, detail = {}) {
    super(message);
    this.name = "RuntimeFault";
    this.code = code;
    Object.assign(this, detail);
  }
}

function unsigned(value) {
  return value >>> 0;
}

function signed(value) {
  return value | 0;
}

function signExtend(value, bitCount) {
  const shiftCount = 32 - bitCount;
  return (value << shiftCount) >> shiftCount;
}

function maskValue(value, sizeByte) {
  if (sizeByte === 1) return value & 0xff;
  if (sizeByte === 2) return value & 0xffff;
  return value >>> 0;
}

function parity(value) {
  let bit = value & 0xff;
  bit ^= bit >>> 4;
  bit ^= bit >>> 2;
  bit ^= bit >>> 1;
  return (bit & 1) === 0;
}

function chooseStackBase(imageStart, imageEnd, stackSizeByte) {
  const stackBaseValue = [0x70000000, 0x60000000, 0x50000000, 0x40000000, 0x30000000];
  for (const currentBase of stackBaseValue) {
    const currentEnd = currentBase + stackSizeByte;
    if (currentEnd <= 0x100000000 && (currentEnd <= imageStart || currentBase >= imageEnd)) return currentBase;
  }
  throw new RuntimeFault("memory_fault", "No bounded stack range is available", { address: null });
}function chooseReturnSentinel(imageStart, imageEnd, stackBase, stackEnd) {
  for (const candidate of returnSentinelCandidate) {
    const isImageAddress = candidate >= imageStart && candidate < imageEnd;
    const isStackAddress = candidate >= stackBase && candidate < stackEnd;
    if (!isImageAddress && !isStackAddress) return candidate;
  }
  throw new RuntimeFault("memory_fault", "No reserved return sentinel is available", { address: null });
}

function normalizeStackSize(value) {
  const reserveByte = Number.isSafeInteger(value) && value > 0 ? value : 0x10000;
  return Math.max(stackPageSizeByte, Math.min(maxStackSizeByte, Math.ceil(reserveByte / stackPageSizeByte) * stackPageSizeByte));
}

function flagValue(flag) {
  let value = 0x2;
  for (const [name, mask] of Object.entries(flagMask)) if (flag[name]) value |= mask;
  return value >>> 0;
}

// Bounded x87 state: eight 64-bit register stack with a top pointer, a
// status word for the comparison flag, and a control word declaring the
// 64-bit precision mode this subset implements.
function createFpuState() {
  return {
    stack: new Float64Array(8),
    valid: new Uint8Array(8),
    top: 0,
    status_word: 0,
    control_word: 0x027f,
  };
}

function fpuStatusWord(fpu) {
  return ((fpu.top & 7) << 11) | (fpu.status_word & 0x4700) | (fpu.control_word & 0x003f);
}

function fpuPush(fpu, value) {
  fpu.top = (fpu.top + 7) & 7;
  fpu.stack[fpu.top] = value;
  fpu.valid[fpu.top] = 1;
}

function fpuPop(fpu) {
  if (!fpu.valid[fpu.top]) throw new RuntimeFault("x87_stack_fault", "FPU stack underflow", {});
  const value = fpu.stack[fpu.top];
  fpu.valid[fpu.top] = 0;
  fpu.top = (fpu.top + 1) & 7;
  return value;
}

function fpuTop(fpu) {
  if (!fpu.valid[fpu.top]) throw new RuntimeFault("x87_stack_fault", "FPU stack underflow", {});
  return fpu.stack[fpu.top];
}

function fpuSetCompareFlag(fpu, value) {
  fpu.status_word &= ~0x4500;
  if (Number.isNaN(value)) fpu.status_word |= 0x4500;
  else if (value === 0) fpu.status_word |= 0x4000;
  else if (value < 0) fpu.status_word |= 0x0100;
}

function createRegisterReport(registerValue, instructionPointer) {
  const register = {};
  for (let index = 0; index < registerName.length; index += 1) register[registerName[index]] = registerValue[index] >>> 0;
  register.eip = instructionPointer >>> 0;
  return register;
}

function createFlagReport(flag, eflagsValue) {
  return {
    carry: Boolean(flag.carry),
    parity: Boolean(flag.parity),
    adjust: Boolean(flag.adjust),
    zero: Boolean(flag.zero),
    sign: Boolean(flag.sign),
    overflow: Boolean(flag.overflow),
    eflags: eflagsValue >>> 0,
  };
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function faultValue(fault) {
  const exception = { code: fault.code, type: fault.code, message: fault.message };
  for (const name of ["address", "opcode", "size_byte", "target", "exit_code", "exception_code"]) {
    if (fault[name] !== undefined) exception[name] = fault[name];
  }
  // Surface the guest structured-exception view (BPTK-053): a CPU fault that a
  // guest __except would see carries its Win32 status code, and an access
  // violation carries the access type (0 read, 1 write, 8 execute) and the
  // faulting address. A probe refusal (budget or block bound) maps to null and
  // adds nothing, so it never masquerades as a guest exception.
  const record = mapFaultToException(fault, { instruction_address: fault.address });
  if (record !== null) {
    exception.guest_exception_code = record.exception_code;
    if (record.exception_information.length === 2) {
      exception.access_type = record.exception_information[0];
      exception.fault_address = record.exception_information[1];
    }
  }
  return exception;
}

function conditionValue(condition, flag) {
  switch (condition & 0x0f) {
    case 0x0: return flag.overflow;
    case 0x1: return !flag.overflow;
    case 0x2: return flag.carry;
    case 0x3: return !flag.carry;
    case 0x4: return flag.zero;
    case 0x5: return !flag.zero;
    case 0x6: return flag.carry || flag.zero;
    case 0x7: return !flag.carry && !flag.zero;
    case 0x8: return flag.sign;
    case 0x9: return !flag.sign;
    case 0xa: return flag.parity;
    case 0xb: return !flag.parity;
    case 0xc: return flag.sign !== flag.overflow;
    case 0xd: return flag.sign === flag.overflow;
    case 0xe: return flag.zero || flag.sign !== flag.overflow;
    case 0xf: return !flag.zero && flag.sign === flag.overflow;
    default: return false;
  }
}

// The 0x0f extension bytes the bounded MMX integer subset serves: data
// movement (movd/movq), packed logical, packed byte/word/dword add and sub,
// packed equality compare, the word/dword/qword shifts (immediate group and
// register form), the four-word shuffle, and EMMS. The 0x66/0xf2/0xf3
// prefixed forms are SSE/SSE2 and stay structured refusals.
const mmxOpcode = new Set([
  0x6e, 0x6f, 0x7e, 0x7f, 0x77, 0x70, 0x71, 0x72, 0x73,
  0xdb, 0xdf, 0xeb, 0xef, 0x74, 0x75, 0x76,
  0xfc, 0xfd, 0xfe, 0xf8, 0xf9, 0xfa,
  0xd1, 0xd2, 0xd3, 0xe1, 0xe2, 0xf1, 0xf2, 0xf3,
]);

// The 0x0f extension bytes the bounded SSE/SSE2 subset serves. The mandatory
// prefix (none/0x66/0xf3/0xf2) selects the packed-single, packed-double,
// scalar-single, or scalar-double form at execution. The 6e/6f/7e/7f bytes
// are MMX in the no-prefix form and route to SSE only under a prefix.
const sseOpcode = new Set([
  0x10, 0x11, 0x28, 0x29, 0x51, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,
  0x5c, 0x5d, 0x5e, 0x5f, 0x2e, 0x2f, 0x2a, 0x2c, 0x2d,
  0x6e, 0x6f, 0x7e, 0x7f,
]);

// One packed lane operation over a 64-bit MMX value: split into equal lanes
// of laneByte width, apply fn per lane with the lane mask (BigInt bitwise
// wraps two's-complement, so subtraction and compare are exact), recombine.
function mmxPackedLane(left, right, laneByte, fn) {
  const laneBit = BigInt(laneByte * 8);
  const mask = (1n << laneBit) - 1n;
  let result = 0n;
  for (let lane = 0; lane < 8 / laneByte; lane += 1) {
    const shift = BigInt(lane) * laneBit;
    const value = fn((left >> shift) & mask, (right >> shift) & mask) & mask;
    result |= value << shift;
  }
  return result;
}

// One packed shift over a 64-bit MMX value: every lane shifts by the same
// scalar count, saturating to zero (logical/left) or the sign fill
// (arithmetic) once the count reaches the lane width, exactly like the
// hardware's over-shift behavior.
function mmxPackedShift(value, count, laneByte, kind) {
  const laneBit = laneByte * 8;
  const mask = (1n << BigInt(laneBit)) - 1n;
  const signBit = 1n << BigInt(laneBit - 1);
  let result = 0n;
  for (let lane = 0; lane < 8 / laneByte; lane += 1) {
    const shift = BigInt(lane * laneBit);
    const laneValue = (value >> shift) & mask;
    let out;
    if (count >= laneBit) {
      out = kind === "sra" && (laneValue & signBit) !== 0n ? mask : 0n;
    } else if (kind === "sll") {
      out = (laneValue << BigInt(count)) & mask;
    } else if (kind === "srl") {
      out = laneValue >> BigInt(count);
    } else {
      out = laneValue >> BigInt(count);
      if ((laneValue & signBit) !== 0n) out |= (mask << BigInt(laneBit - count)) & mask;
    }
    result |= (out & mask) << shift;
  }
  return result;
}

// The 0x66-prefixed 0x0f extension bytes the bounded SSE2 128-bit packed
// integer subset serves (plus the 0xf2/0xf3 pshuf variants of 0x70). The
// no-prefix form of each stays the MMX 64-bit form or a structured refusal —
// this set only ever intercepts the 0x66 (and 0x70 prefixed) encoding.
const sse2PackedOpcode = new Set([
  0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
  0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
  0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xdb, 0xdf,
  0xe1, 0xe2, 0xeb, 0xef,
  0xf1, 0xf2, 0xf3, 0xf4, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe,
]);

// A 128-bit xmm register read as a single unsigned BigInt (little-endian) and
// the inverse. BigInt bitwise wraps two's-complement, so packed add, subtract,
// logical, and shift are bit-exact through it.
function xmmBig(buffer) {
  return buffer.readBigUInt64LE(0) | (buffer.readBigUInt64LE(8) << 64n);
}
function bigToBuffer(value) {
  const buffer = Buffer.alloc(16);
  buffer.writeBigUInt64LE(value & 0xffffffffffffffffn, 0);
  buffer.writeBigUInt64LE((value >> 64n) & 0xffffffffffffffffn, 8);
  return buffer;
}

// One packed lane operation over a 128-bit value: equal lanes of laneByte
// width, fn per lane with the lane mask, recombined.
function packedLane128(left, right, laneByte, fn) {
  const laneBit = BigInt(laneByte * 8);
  const mask = (1n << laneBit) - 1n;
  let result = 0n;
  for (let lane = 0; lane < 16 / laneByte; lane += 1) {
    const shift = BigInt(lane) * laneBit;
    result |= (fn((left >> shift) & mask, (right >> shift) & mask) & mask) << shift;
  }
  return result;
}

// One packed shift over a 128-bit value: every lane shifts by the same scalar
// count, saturating to zero (logical) or the sign fill (arithmetic) once the
// count reaches the lane width, exactly like the hardware over-shift.
function packedShift128(value, count, laneByte, kind) {
  const laneBit = laneByte * 8;
  const mask = (1n << BigInt(laneBit)) - 1n;
  const signBit = 1n << BigInt(laneBit - 1);
  let result = 0n;
  for (let lane = 0; lane < 16 / laneByte; lane += 1) {
    const shift = BigInt(lane * laneBit);
    const laneValue = (value >> shift) & mask;
    let out;
    if (count >= laneBit) {
      out = kind === "sra" && (laneValue & signBit) !== 0n ? mask : 0n;
    } else if (kind === "sll") {
      out = (laneValue << BigInt(count)) & mask;
    } else if (kind === "srl") {
      out = laneValue >> BigInt(count);
    } else {
      out = laneValue >> BigInt(count);
      if ((laneValue & signBit) !== 0n) out |= (mask << BigInt(laneBit - count)) & mask;
    }
    result |= (out & mask) << shift;
  }
  return result;
}

// The packed unpack/interleave: the low (or high) half of each operand splits
// into laneByte lanes and interleaves dest,src,dest,src into the 128-bit result.
function unpack128(destBuf, srcBuf, laneByte, high) {
  const out = Buffer.alloc(16);
  const start = high ? 8 : 0;
  let pos = 0;
  for (let i = 0; i < 8; i += laneByte) {
    destBuf.copy(out, pos, start + i, start + i + laneByte);
    pos += laneByte;
    srcBuf.copy(out, pos, start + i, start + i + laneByte);
    pos += laneByte;
  }
  return out;
}

// The packed saturating pack: each source lane (word or dword) saturates into
// a half-width destination lane, dest lanes first then src lanes.
function pack128(destBuf, srcBuf, srcLaneByte, unsignedResult) {
  const out = Buffer.alloc(16);
  const dstLaneByte = srcLaneByte / 2;
  const lanesPer = 16 / srcLaneByte;
  const readSrc = (buf, index) => srcLaneByte === 2 ? buf.readInt16LE(index * srcLaneByte) : buf.readInt32LE(index * srcLaneByte);
  const lo = unsignedResult ? 0 : -(1 << (dstLaneByte * 8 - 1));
  const hi = unsignedResult ? (1 << (dstLaneByte * 8)) - 1 : (1 << (dstLaneByte * 8 - 1)) - 1;
  let pos = 0;
  const writeLane = (value) => {
    const clamped = Math.max(lo, Math.min(hi, value));
    if (dstLaneByte === 1) out.writeUInt8(clamped & 0xff, pos);
    else out.writeUInt16LE(clamped & 0xffff, pos);
    pos += dstLaneByte;
  };
  for (let index = 0; index < lanesPer; index += 1) writeLane(readSrc(destBuf, index));
  for (let index = 0; index < lanesPer; index += 1) writeLane(readSrc(srcBuf, index));
  return out;
}

// The packed signed greater-than compare: a lane becomes all-ones where the
// signed dest lane exceeds the signed src lane, otherwise zero.
function pcmpgt128(destBuf, srcBuf, laneByte) {
  const out = Buffer.alloc(16);
  const read = (buf, off) => laneByte === 1 ? buf.readInt8(off) : laneByte === 2 ? buf.readInt16LE(off) : buf.readInt32LE(off);
  for (let off = 0; off < 16; off += laneByte) {
    const greater = read(destBuf, off) > read(srcBuf, off);
    for (let b = 0; b < laneByte; b += 1) out[off + b] = greater ? 0xff : 0;
  }
  return out;
}

// The packed equality compare: a lane becomes all-ones on a byte-exact match,
// otherwise zero.
function pcmpeq128(destBuf, srcBuf, laneByte) {
  const out = Buffer.alloc(16);
  for (let off = 0; off < 16; off += laneByte) {
    let equal = true;
    for (let b = 0; b < laneByte; b += 1) if (destBuf[off + b] !== srcBuf[off + b]) { equal = false; break; }
    for (let b = 0; b < laneByte; b += 1) out[off + b] = equal ? 0xff : 0;
  }
  return out;
}

// Round-to-nearest, ties-to-even — the default SSE rounding mode the bounded
// probe declares (the MXCSR rounding field is fixed at round-nearest).
function roundHalfEven(value) {
  const floorValue = Math.floor(value);
  const fraction = value - floorValue;
  if (fraction < 0.5) return floorValue;
  if (fraction > 0.5) return floorValue + 1;
  return floorValue % 2 === 0 ? floorValue : floorValue + 1;
}

// The float-to-int32 conversion of the cvt*2si family: an out-of-range or
// non-finite source yields the 0x80000000 integer-indefinite, exactly like
// the hardware.
function convertToInt32(value, truncate) {
  if (!Number.isFinite(value)) return 0x80000000;
  const rounded = truncate ? Math.trunc(value) : roundHalfEven(value);
  if (rounded < -2147483648 || rounded > 2147483647) return 0x80000000;
  return rounded >>> 0;
}

function executeProbe(mapped, instructionBudgetCount, option = {}) {
  const { report, image, section } = mapped;
  const clock = createGuestClock({ mode: "virtual_monotonic" });
  const hleLayout = option.hle_layout ?? null;
  const hleArena = hleLayout === null ? null : Buffer.alloc(hleLayout.arena_size_byte);
  const hleVirtual = hleLayout === null ? null : Buffer.alloc(hleLayout.virtual_size_byte);
  const imageStart = report.load_base;
  const imageEnd = imageStart + image.length;
  const stackSizeByte = normalizeStackSize(report.stack_reserve_byte);
  const stackBase = chooseStackBase(imageStart, imageEnd, stackSizeByte);
  const stackEnd = stackBase + stackSizeByte;
  const returnSentinel = chooseReturnSentinel(imageStart, imageEnd, stackBase, stackEnd);
  const stack = Buffer.alloc(stackSizeByte);
  // The thread-environment block (BPTK-025). A real process reaches its entry
  // with the TEB mapped and fs pointing at it, so a declared layout builds the
  // block over the stack the guest actually runs on and fs:[disp] resolves
  // against it. The bare CPU-conformance probe declares no layout and keeps
  // refusing the fs override, because there is no thread to describe.
  const teb = hleLayout !== null && hleLayout.teb_base !== undefined
    ? buildTebImage({
        tebBase: hleLayout.teb_base,
        pebBase: hleLayout.peb_base,
        stackHighAddress: stackEnd,
        stackLowAddress: stackBase,
        imageBase: imageStart,
      })
    : null;
  const tebImage = teb === null ? null : teb.teb;
  const pebImage = teb === null ? null : teb.peb;
  const fsBase = teb === null ? 0 : teb.fs_base;
  const gsBase = teb === null ? 0 : teb.gs_base;
  // The active segment base for the current instruction's memory operand: zero
  // for every flat-model segment (cs/ds/es/ss), the TEB linear address under
  // an fs override, zero under gs. Reset before each instruction decode.
  let segmentBaseValue = 0;
  const registerValue = new Uint32Array(8);
  const flag = { carry: false, parity: false, adjust: false, zero: false, sign: false, direction: false, overflow: false };
  const fpu = createFpuState();
  // Bounded MMX state (BPTK-009): eight 64-bit integer lanes modeled directly
  // as unsigned 64-bit registers. The physical mm/st aliasing is not modeled
  // beyond EMMS resetting the x87 tag word — a declared bound, since real MMX
  // is integer SIMD bracketed by EMMS and never reads st between mm writes.
  const mm = new BigUint64Array(8);
  // Bounded SSE/SSE2 state (BPTK-009): eight 128-bit xmm registers held as raw
  // little-endian byte, so the FP lanes read back bit-exact through the
  // Float32/Float64 view and the integer moves stay byte-for-byte.
  const xmm = Array.from({ length: 8 }, () => Buffer.alloc(16));
  const traceHash = createHash("sha256");
  const initialStackPointer = stackEnd - 4;
  let instructionPointer = report.entry_address >>> 0;
  let instructionCount = 0;
  let stopReason = null;
  let exception = null;
  let instructionByte = null;
  let memoryUndo = null;

  registerValue[registerIndex.esp] = initialStackPointer >>> 0;

  function checkRange(address, sizeByte, code, mode) {
    const addressValue = unsigned(address);
    if (!Number.isInteger(sizeByte) || sizeByte <= 0 || addressValue + sizeByte > 0x100000000) {
      throw new RuntimeFault(code, `${mode} address is outside the 32-bit address space`, { address: addressValue, size_byte: sizeByte });
    }
    if (addressValue >= imageStart && addressValue + sizeByte <= imageEnd) {
      let offset = addressValue - imageStart;
      const end = offset + sizeByte;
      while (offset < end) {
        const currentSection = section.find((entry) => offset >= entry.virtual_address && offset < entry.virtual_address + entry.mapped_size_byte);
        if (!currentSection) {
          if (mode !== "read") throw new RuntimeFault(`${mode}_fault`, `${mode} touches unmapped image bytes`, { address: addressValue, size_byte: sizeByte });
          offset += 1;
          continue;
        }
        const sectionEnd = Math.min(end, currentSection.virtual_address + currentSection.mapped_size_byte);
        const isReadable = (currentSection.characteristic & 0x40000000) !== 0 || (currentSection.characteristic & 0x20000000) !== 0;
        const isWritable = (currentSection.characteristic & 0x80000000) !== 0;
        const isExecutable = (currentSection.characteristic & 0x20000000) !== 0;
        if (mode === "fetch" && !isExecutable) throw new RuntimeFault("fetch_fault", "Instruction fetch is not executable", { address: addressValue, size_byte: sizeByte });
        if (mode === "read" && !isReadable) throw new RuntimeFault("read_fault", "Image bytes are not readable", { address: addressValue, size_byte: sizeByte });
        if (mode === "write" && !isWritable) throw new RuntimeFault("write_fault", "Image bytes are not writable", { address: addressValue, size_byte: sizeByte });
        offset = sectionEnd;
      }
      return { kind: "image", offset: addressValue - imageStart };
    }
    if (addressValue >= stackBase && addressValue + sizeByte <= stackEnd) {
      if (mode === "fetch") throw new RuntimeFault("fetch_fault", "Stack memory is not executable", { address: addressValue, size_byte: sizeByte });
      return { kind: "stack", offset: addressValue - stackBase };
    }
    if (hleLayout !== null) {
      if (addressValue >= hleLayout.arena_base && addressValue + sizeByte <= hleLayout.arena_base + hleLayout.arena_size_byte) {
        if (mode === "fetch") throw new RuntimeFault("fetch_fault", "HLE arena memory is not executable", { address: addressValue, size_byte: sizeByte });
        return { kind: "hle_arena", offset: addressValue - hleLayout.arena_base };
      }
      if (addressValue >= hleLayout.virtual_base && addressValue + sizeByte <= hleLayout.virtual_base + hleLayout.virtual_size_byte) {
        if (mode === "fetch") throw new RuntimeFault("fetch_fault", "HLE virtual memory is not executable", { address: addressValue, size_byte: sizeByte });
        return { kind: "hle_virtual", offset: addressValue - hleLayout.virtual_base };
      }
      if (addressValue >= hleLayout.thunk_base && addressValue + sizeByte <= hleLayout.thunk_base + hleLayout.thunk_page_byte) {
        if (mode !== "read") throw new RuntimeFault(`${mode}_fault`, `Thunk-page memory is read-only`, { address: addressValue, size_byte: sizeByte });
        return { kind: "hle_thunk", offset: addressValue - hleLayout.thunk_base };
      }
      if (teb !== null && addressValue >= hleLayout.teb_base && addressValue + sizeByte <= hleLayout.teb_base + hleLayout.teb_size_byte) {
        if (mode === "fetch") throw new RuntimeFault("fetch_fault", "TEB memory is not executable", { address: addressValue, size_byte: sizeByte });
        return { kind: "teb", offset: addressValue - hleLayout.teb_base };
      }
      if (teb !== null && addressValue >= hleLayout.peb_base && addressValue + sizeByte <= hleLayout.peb_base + hleLayout.peb_size_byte) {
        if (mode === "fetch") throw new RuntimeFault("fetch_fault", "PEB memory is not executable", { address: addressValue, size_byte: sizeByte });
        return { kind: "peb", offset: addressValue - hleLayout.peb_base };
      }
    }
    throw new RuntimeFault(`${mode}_fault`, `${mode} address is outside mapped image and bounded stack`, { address: addressValue, size_byte: sizeByte });
  }

  function readMemory(address, sizeByte, mode = "read") {
    const location = checkRange(address, sizeByte, `${mode}_fault`, mode);
    if (location.kind === "hle_thunk") return 0;
    const value = memoryTarget(location.kind);
    if (sizeByte === 1) return value[location.offset];
    if (sizeByte === 2) return value.readUInt16LE(location.offset);
    if (sizeByte === 4) return value.readUInt32LE(location.offset);
    throw new RuntimeFault("read_fault", "Only byte, word, and dword accesses are supported", { address: unsigned(address), size_byte: sizeByte });
  }

  function writeMemory(address, sizeByte, value) {
    const location = checkRange(address, sizeByte, "write_fault", "write");
    const target = memoryTarget(location.kind);
    if (memoryUndo !== null) {
      memoryUndo.push({ target, offset: location.offset, value: Buffer.from(target.subarray(location.offset, location.offset + sizeByte)) });
    }
    if (sizeByte === 1) target[location.offset] = value & 0xff;
    else if (sizeByte === 2) target.writeUInt16LE(value & 0xffff, location.offset);
    else if (sizeByte === 4) target.writeUInt32LE(value >>> 0, location.offset);
    else throw new RuntimeFault("write_fault", "Only byte, word, and dword accesses are supported", { address: unsigned(address), size_byte: sizeByte });
  }

  // Bounded block primitives for the HLE core: byte-granular through the
  // checked access so bounds, section permission, and the instruction undo
  // log stay in force.
  function readBlock(address, sizeByte) {
    if (!Number.isSafeInteger(sizeByte) || sizeByte < 0 || sizeByte > 1024 * 1024) {
      throw new RuntimeFault("hle_block_bound", `The block read of ${sizeByte} byte exceeds the bounded block size`);
    }
    const block = Buffer.alloc(sizeByte);
    for (let index = 0; index < sizeByte; index += 1) block[index] = readMemory(unsigned(address + index), 1, "read");
    return block;
  }

  function writeBlock(address, buffer) {
    if (!Buffer.isBuffer(buffer) || buffer.length > 1024 * 1024) {
      throw new RuntimeFault("hle_block_bound", `The block write exceeds the bounded block size`);
    }
    for (let index = 0; index < buffer.length; index += 1) writeMemory(unsigned(address + index), 1, buffer[index]);
  }

  // The Win32 core HLE (BPTK-010). When a layout is declared, the guest
  // import call dispatches here: one stdcall frame is read off the guest
  // stack, the emulator runs against the checked memory model, and EAX
  // carries the result. A guest exit or exception becomes the structured
  // stop the probe owns; an emulator fault rolls back like any other fault.
  const hleGuest = hleLayout === null ? null : createWin32Hle(
    { readMemory, writeMemory, readBlock, writeBlock },
    hleLayout,
    { executable_name: option.executable_name, clock, image_base: imageStart, image_size_byte: image.length },
  );

  function dispatchHle(entry, isJump) {
    const argument = [];
    let returnAddress;
    if (isJump) {
      returnAddress = readMemory(registerValue[registerIndex.esp], 4);
      for (let index = 0; index < entry.argument_count; index += 1) {
        argument.push(readMemory(unsigned(registerValue[registerIndex.esp] + 4 + index * 4), 4));
      }
      registerValue[registerIndex.esp] = unsigned(registerValue[registerIndex.esp] + 4 + entry.argument_count * 4);
    } else {
      returnAddress = instructionPointer;
      for (let index = 0; index < entry.argument_count; index += 1) {
        argument.push(readMemory(unsigned(registerValue[registerIndex.esp] + index * 4), 4));
      }
      registerValue[registerIndex.esp] = unsigned(registerValue[registerIndex.esp] + entry.argument_count * 4);
    }
    let value;
    try {
      value = hleGuest.invokeExport(entry, argument);
    } catch (error) {
      if (isHleSignal(error)) {
        if (error.signal === "hle_exit") throw new RuntimeFault("process_exit", `The guest ended its own process with code 0x${(error.exit_code >>> 0).toString(16)}`, { exit_code: error.exit_code >>> 0 });
        if (error.signal === "hle_guest_exception") throw new RuntimeFault("guest_exception", `The guest raised unhandled exception 0x${(error.exception_code >>> 0).toString(16)}`, { exception_code: error.exception_code >>> 0 });
        throw new RuntimeFault(error.code, error.message, { address: error.address });
      }
      throw error;
    }
    setRegister(registerIndex.eax, value, 4);
    instructionPointer = returnAddress >>> 0;
  }

  function memoryTarget(kind) {
    if (kind === "image") return image;
    if (kind === "stack") return stack;
    if (kind === "hle_arena") return hleArena;
    if (kind === "teb") return tebImage;
    if (kind === "peb") return pebImage;
    return hleVirtual;
  }

  function readFloatMemory(address) {
    const location = checkRange(address, 4, "read_fault", "read");
    if (location.kind === "hle_thunk") return 0;
    return memoryTarget(location.kind).readFloatLE(location.offset);
  }

  function writeFloatMemory(address, value) {
    const location = checkRange(address, 4, "write_fault", "write");
    const target = memoryTarget(location.kind);
    if (memoryUndo !== null) memoryUndo.push({ target, offset: location.offset, value: Buffer.from(target.subarray(location.offset, location.offset + 4)) });
    target.writeFloatLE(value, location.offset);
  }

  function readDoubleMemory(address) {
    const location = checkRange(address, 8, "read_fault", "read");
    if (location.kind === "hle_thunk") return 0;
    return memoryTarget(location.kind).readDoubleLE(location.offset);
  }

  function writeDoubleMemory(address, value) {
    const location = checkRange(address, 8, "write_fault", "write");
    const target = memoryTarget(location.kind);
    if (memoryUndo !== null) memoryUndo.push({ target, offset: location.offset, value: Buffer.from(target.subarray(location.offset, location.offset + 8)) });
    target.writeDoubleLE(value, location.offset);
  }

  function readInt64Memory(address) {
    const location = checkRange(address, 8, "read_fault", "read");
    if (location.kind === "hle_thunk") return 0n;
    return memoryTarget(location.kind).readBigInt64LE(location.offset);
  }

  function writeInt64Memory(address, value) {
    const location = checkRange(address, 8, "write_fault", "write");
    const target = memoryTarget(location.kind);
    if (memoryUndo !== null) memoryUndo.push({ target, offset: location.offset, value: Buffer.from(target.subarray(location.offset, location.offset + 8)) });
    target.writeBigInt64LE(BigInt.asIntN(64, value), location.offset);
  }

  function peekModrm() {
    return readMemory(instructionPointer, 1, "fetch");
  }

  function push(value) {
    const nextStackPointer = unsigned(registerValue[registerIndex.esp] - 4);
    writeMemory(nextStackPointer, 4, value);
    registerValue[registerIndex.esp] = nextStackPointer;
  }

  function pushSized(value, sizeByte) {
    if (sizeByte === 4) return push(value);
    const nextStackPointer = unsigned(registerValue[registerIndex.esp] - 2);
    writeMemory(nextStackPointer, 2, value & 0xffff);
    registerValue[registerIndex.esp] = nextStackPointer;
  }

  function pop() {
    const stackPointer = registerValue[registerIndex.esp] >>> 0;
    const value = readMemory(stackPointer, 4);
    registerValue[registerIndex.esp] = unsigned(stackPointer + 4);
    return value >>> 0;
  }

  function popSized(sizeByte) {
    if (sizeByte === 4) return pop();
    const stackPointer = registerValue[registerIndex.esp] >>> 0;
    const value = readMemory(stackPointer, 2);
    registerValue[registerIndex.esp] = unsigned(stackPointer + 2);
    return value;
  }

  // Flat-model string primitive: ESI and EDI address the mapped image or the
  // bounded stack, and the direction flag selects the step.
  const repIterationBoundValue = repIterationBound;
  function stringStep(kind, sizeByte, repeatPrefix) {
    const esiIndex = registerIndex.esi;
    const ediIndex = registerIndex.edi;
    const ecxIndex = registerIndex.ecx;
    const step = flag.direction ? unsigned(-sizeByte) : sizeByte;
    const readSource = () => readMemory(registerValue[esiIndex], sizeByte);
    const writeTarget = (value) => writeMemory(registerValue[ediIndex], sizeByte, value);
    const advance = () => {
      registerValue[esiIndex] = unsigned(registerValue[esiIndex] + step);
      registerValue[ediIndex] = unsigned(registerValue[ediIndex] + step);
    };
    const oneIteration = () => {
      let compareFlag = null;
      if (kind === "movs") {
        writeTarget(readSource());
        advance();
      } else if (kind === "stos") {
        writeTarget(getRegister(registerIndex.eax, sizeByte));
        registerValue[ediIndex] = unsigned(registerValue[ediIndex] + step);
      } else if (kind === "lods") {
        setRegister(registerIndex.eax, readSource(), sizeByte);
        registerValue[esiIndex] = unsigned(registerValue[esiIndex] + step);
      } else if (kind === "cmps") {
        // CMPS compares [esi] with [edi] — the two string operands, never EAX.
        compareFlag = arithmetic("cmp", readSource(), readMemory(registerValue[ediIndex], sizeByte), sizeByte, false);
        advance();
      } else if (kind === "scas") {
        compareFlag = arithmetic("cmp", getRegister(registerIndex.eax, sizeByte), readMemory(registerValue[ediIndex], sizeByte), sizeByte, false);
        registerValue[ediIndex] = unsigned(registerValue[ediIndex] + step);
      }
      return compareFlag;
    };
    if (repeatPrefix === null) {
      oneIteration();
      return;
    }
    let iteration = 0;
    while (registerValue[ecxIndex] > 0) {
      iteration += 1;
      if (iteration > repIterationBoundValue) {
        throw new RuntimeFault("rep_iteration_bound", `The repeat count exceeds the declared bound of ${repIterationBoundValue} iteration`, { bound: repIterationBoundValue });
      }
      const compareFlag = oneIteration();
      registerValue[ecxIndex] = unsigned(registerValue[ecxIndex] - 1);
      if (repeatPrefix === 0xf2 && (kind === "cmps" || kind === "scas") && compareFlag !== null && flag.zero) break;
      if (repeatPrefix === 0xf3 && (kind === "cmps" || kind === "scas") && compareFlag !== null && !flag.zero) break;
    }
  }

  // Bounded shift and rotate group shared by C0/C1/D0/D1/D2/D3. Shifts
  // update carry, overflow (one-bit shift), adjust, zero, sign, and parity;
  // rotates update only carry and overflow. Wide intermediates use BigInt.
  function shiftOperation(kind, value, count, sizeByte) {
    const bitCount = sizeByte * 8;
    const mask = sizeByte === 1 ? 0xff : sizeByte === 2 ? 0xffff : 0xffffffff;
    count &= 0x1f;
    let result = maskValue(value, sizeByte);
    if (count === 0) return result;
    if (kind === "shl" || kind === "shr" || kind === "sar") {
      const wide = BigInt(result);
      const bigCount = BigInt(count);
      const bigBits = BigInt(bitCount);
      const wideMask = (1n << bigBits) - 1n;
      if (kind === "shl") {
        const shifted = wide << bigCount;
        flag.carry = ((shifted >> bigBits) & 1n) === 1n;
        result = Number(shifted & wideMask);
      } else if (kind === "shr") {
        flag.carry = count <= bitCount ? ((wide >> BigInt(count - 1)) & 1n) === 1n : false;
        result = count >= bitCount ? 0 : Number(wide >> bigCount);
      } else {
        const signedWide = BigInt.asIntN(bitCount, wide);
        flag.carry = count <= bitCount ? ((signedWide >> BigInt(Math.min(count, bitCount) - 1)) & 1n) === 1n : (signedWide < 0n);
        const fill = signedWide < 0n ? mask : 0;
        result = count >= bitCount ? fill : Number(BigInt.asUintN(bitCount, signedWide >> bigCount));
      }
      if (count === 1 && kind === "shl") {
        flag.overflow = ((result >>> (bitCount - 1)) & 1) !== flag.carry;
      }
      flag.adjust = false;
      flag.zero = result === 0;
      flag.sign = (result & (1 << (bitCount - 1))) !== 0;
      flag.parity = parity(result);
      return result >>> 0;
    }
    const width = BigInt(bitCount + 1);
    const widthMask = (1n << width) - 1n;
    let combined = BigInt(result) | (flag.carry ? 1n << BigInt(bitCount) : 0n);
    const effective = BigInt(count % (bitCount + 1));
    if (kind === "rol") {
      if (count % bitCount > 0) {
        const shift = BigInt(count % bitCount);
        result = Number(((BigInt(result) << shift) | (BigInt(result) >> (BigInt(bitCount) - shift))) & BigInt(mask));
        flag.carry = (result & 1) !== 0;
        if (count === 1) flag.overflow = ((result >>> (bitCount - 1)) & 1) !== flag.carry;
      }
      return result >>> 0;
    }
    if (kind === "ror") {
      if (count % bitCount > 0) {
        const shift = BigInt(count % bitCount);
        result = Number(((BigInt(result) >> shift) | (BigInt(result) << (BigInt(bitCount) - shift))) & BigInt(mask));
        flag.carry = ((result >>> (bitCount - 1)) & 1) !== 0;
        if (count === 1) flag.overflow = ((result >>> (bitCount - 1)) & 1) !== ((result >>> (bitCount - 2)) & 1);
      }
      return result >>> 0;
    }
    if (effective > 0n) {
      if (kind === "rcl") combined = ((combined << effective) | (combined >> (width - effective))) & widthMask;
      else combined = ((combined >> effective) | (combined << (width - effective))) & widthMask;
      result = Number(combined & BigInt(mask));
      flag.carry = ((combined >> BigInt(bitCount)) & 1n) === 1n;
    }
    return result >>> 0;
  }

  // Bounded multiply and divide group. Division by zero and quotient
  // overflow are structured divide_error fault; wide products use BigInt so
  // the 64-bit intermediate stays exact and deterministic.
  function multiplyDivide(operation, decoded, sizeByte, opcode) {
    const isByte = sizeByte === 1;
    const mask = isByte ? 0xff : sizeByte === 2 ? 0xffff : 0xffffffff;
    const bits = sizeByte * 8;
    const divisor = operandRead(decoded, sizeByte);

    if (operation === "mul" || operation === "imul") {
      const isSigned = operation === "imul";
      const left = getRegister(registerIndex.eax, isByte ? 2 : sizeByte);
      const toSigned = (value) => {
        const wide = BigInt(value >>> 0);
        return isSigned ? BigInt.asIntN(bits, wide) : wide;
      };
      const product = toSigned(isByte ? left & 0xffff : left) * toSigned(divisor);
      if (isByte) {
        setRegister(registerIndex.eax, Number(product & 0xffffn), 2);
        const high = Number((product >> 8n) & 0xffn);
        const negative = isSigned && (product & 0x80n) !== 0n;
        flag.carry = flag.overflow = negative ? high !== 0xff : high !== 0;
      } else {
        const half = BigInt(bits);
        setRegister(registerIndex.eax, Number(product & ((1n << half) - 1n)), sizeByte);
        const high = Number((product >> half) & ((1n << half) - 1n));
        setRegister(registerIndex.edx, high, sizeByte);
        const negative = isSigned && (product >> BigInt(bits * 2 - 1) & 1n) === 1n;
        flag.carry = flag.overflow = negative ? high !== mask : high !== 0;
      }
      return;
    }

    if (divisor === 0) {
      throw new RuntimeFault("divide_error", "Division by zero", { opcode });
    }
    const isSigned = operation === "idiv";
    const dividendSize = isByte ? 2 : sizeByte;
    const low = BigInt(getRegister(registerIndex.eax, dividendSize));
    const high = isByte ? 0n : BigInt(getRegister(registerIndex.edx, sizeByte));
    let combined = (high << BigInt(dividendSize * 8)) | low;
    const divisorBig = isSigned ? BigInt.asIntN(bits, BigInt(divisor >>> 0)) : BigInt(divisor >>> 0);
    if (isSigned) combined = BigInt.asIntN(dividendSize * 8, combined);
    const quotient = combined / divisorBig;
    const remainder = combined % divisorBig;
    if (isSigned) {
      const limit = 1n << BigInt(dividendSize * 8 - 1);
      if (quotient >= limit || quotient < -limit) throw new RuntimeFault("divide_error", "Signed division quotient overflow", { opcode });
    } else if (quotient > BigInt(mask)) {
      throw new RuntimeFault("divide_error", "Division quotient overflow", { opcode });
    }
    if (isByte) {
      setRegister(registerIndex.eax, ((Number(remainder) & 0xff) << 8) | (Number(quotient) & 0xff), 2);
      return;
    }
    setRegister(registerIndex.eax, Number(quotient) & mask, sizeByte);
    setRegister(registerIndex.edx, Number(remainder) & mask, sizeByte);
  }

  // The BT family (BTS/BTR/BTC share the read): the register form picks the
  // bit modulo the operand size, the memory form adds the signed bit offset
  // in byte to the effective address and picks the bit within that byte. Only
  // carry is architecturally defined, so the other flag keep their value.
  function bitOperation(operation, decoded, bitOffsetValue, sizeByte) {
    const bitCount = sizeByte * 8;
    flag.carry = false;
    if (decoded.is_register) {
      const bitIndex = (bitOffsetValue >>> 0) % bitCount;
      const value = getRegister(decoded.rm, sizeByte);
      const bit = (value >>> bitIndex) & 1;
      if (operation === "bts") operandWrite(decoded, value | (1 << bitIndex), sizeByte);
      else if (operation === "btr") operandWrite(decoded, value & ~(1 << bitIndex), sizeByte);
      else if (operation === "btc") operandWrite(decoded, value ^ (1 << bitIndex), sizeByte);
      flag.carry = bit === 1;
      return;
    }
    const byteAddress = unsigned(decoded.address + (signed(bitOffsetValue) >> 3));
    const bitIndex = (bitOffsetValue >>> 0) & 7;
    const byte = readMemory(byteAddress, 1);
    if (operation === "bts") writeMemory(byteAddress, 1, byte | (1 << bitIndex));
    else if (operation === "btr") writeMemory(byteAddress, 1, byte & ~(1 << bitIndex));
    else if (operation === "btc") writeMemory(byteAddress, 1, byte ^ (1 << bitIndex));
    flag.carry = ((byte >>> bitIndex) & 1) === 1;
  }

  // Two-operand IMUL (0F AF r, rm and 69/6B r, rm, imm): the signed product
  // wraps into the destination register and carry and overflow flag the
  // truncation.
  function imulTwoOperand(target, left, right, sizeByte) {
    const bits = sizeByte * 8;
    const mask = sizeByte === 1 ? 0xff : sizeByte === 2 ? 0xffff : 0xffffffff;
    const product = BigInt.asIntN(bits, BigInt(left >>> 0)) * BigInt.asIntN(bits, BigInt(right >>> 0));
    const truncated = Number(BigInt.asIntN(bits, product));
    setRegister(target, truncated & mask, sizeByte);
    flag.carry = flag.overflow = product !== BigInt.asIntN(bits, BigInt(truncated & mask));
  }

  function getRegister(index, sizeByte = 4) {
    const register = index & 7;
    const value = registerValue[register] >>> 0;
    if (sizeByte === 1) {
      if (register < 4) return value & 0xff;
      return (registerValue[register - 4] >>> 8) & 0xff;
    }
    if (sizeByte === 2) return value & 0xffff;
    return value;
  }

  function setRegister(index, value, sizeByte = 4) {
    const register = index & 7;
    if (sizeByte === 1) {
      if (register < 4) registerValue[register] = (registerValue[register] & 0xffffff00) | (value & 0xff);
      else {
        const target = register - 4;
        registerValue[target] = (registerValue[target] & 0xffff00ff) | ((value & 0xff) << 8);
      }
    } else if (sizeByte === 2) registerValue[register] = (registerValue[register] & 0xffff0000) | (value & 0xffff);
    else registerValue[register] = value >>> 0;
  }

  function fetchByte() {
    const value = readMemory(instructionPointer, 1, "fetch");
    instructionPointer = unsigned(instructionPointer + 1);
    if (instructionByte !== null) instructionByte.push(value);
    return value;
  }

  function fetchWord() {
    const low = fetchByte();
    return low | (fetchByte() << 8);
  }

  function fetchDword() {
    return (fetchByte() | (fetchByte() << 8) | (fetchByte() << 16) | (fetchByte() << 24)) >>> 0;
  }

  function decodeModrm(operandSizeByte) {
    const value = fetchByte();
    const mode = value >>> 6;
    const reg = (value >>> 3) & 7;
    const rm = value & 7;
    if (mode === 3) return { mode, reg, rm, is_register: true, address: null, size_byte: operandSizeByte };
    let address = 0;
    if (rm === 4) {
      const sib = fetchByte();
      const scale = 1 << (sib >>> 6);
      const index = (sib >>> 3) & 7;
      const base = sib & 7;
      if (index !== 4) address += getRegister(index) * scale;
      if (mode === 0 && base === 5) address += fetchDword();
      else address += getRegister(base);
    } else if (mode === 0 && rm === 5) address = fetchDword();
    else address = getRegister(rm);
    if (mode === 1) address += signExtend(fetchByte(), 8);
    else if (mode === 2) address += fetchDword();
    // The effective offset is the pure ModRM address (what LEA computes); the
    // memory address adds the active segment base, which is zero except under
    // an fs override that resolves against the TEB.
    const effectiveOffset = unsigned(address);
    return { mode, reg, rm, is_register: false, address: unsigned(effectiveOffset + segmentBaseValue), effective_offset: effectiveOffset, size_byte: operandSizeByte };
  }

  function operandRead(decoded, sizeByte = decoded.size_byte) {
    return decoded.is_register ? getRegister(decoded.rm, sizeByte) : readMemory(decoded.address, sizeByte);
  }

  function operandWrite(decoded, value, sizeByte = decoded.size_byte) {
    if (decoded.is_register) setRegister(decoded.rm, value, sizeByte);
    else writeMemory(decoded.address, sizeByte, value);
  }

  function setLogicFlag(value, sizeByte) {
    const mask = sizeByte === 1 ? 0xff : sizeByte === 2 ? 0xffff : 0xffffffff;
    const result = maskValue(value, sizeByte);
    flag.carry = false;
    flag.overflow = false;
    flag.adjust = false;
    flag.zero = result === 0;
    flag.sign = (result & (sizeByte === 1 ? 0x80 : sizeByte === 2 ? 0x8000 : 0x80000000)) !== 0;
    flag.parity = parity(result);
  }

  function setAddFlag(left, right, carryValue, result, sizeByte) {
    const bitCount = sizeByte * 8;
    const mask = sizeByte === 1 ? 0xff : sizeByte === 2 ? 0xffff : 0xffffffff;
    const leftValue = maskValue(left, sizeByte);
    const rightValue = maskValue(right, sizeByte);
    const resultValue = maskValue(result, sizeByte);
    const sum = leftValue + rightValue + carryValue;
    flag.carry = sum > mask;
    flag.adjust = ((leftValue ^ rightValue ^ resultValue) & 0x10) !== 0;
    flag.zero = resultValue === 0;
    flag.sign = (resultValue & (1 << (bitCount - 1))) !== 0;
    flag.overflow = ((~(leftValue ^ rightValue) & (leftValue ^ resultValue) & (1 << (bitCount - 1))) !== 0);
    flag.parity = parity(resultValue);
  }

  function setSubFlag(left, right, borrowValue, result, sizeByte) {
    const bitCount = sizeByte * 8;
    const mask = sizeByte === 1 ? 0xff : sizeByte === 2 ? 0xffff : 0xffffffff;
    const leftValue = maskValue(left, sizeByte);
    const rightValue = maskValue(right, sizeByte);
    const resultValue = maskValue(result, sizeByte);
    flag.carry = leftValue < rightValue + borrowValue;
    flag.adjust = ((leftValue ^ rightValue ^ resultValue) & 0x10) !== 0;
    flag.zero = resultValue === 0;
    flag.sign = (resultValue & (1 << (bitCount - 1))) !== 0;
    flag.overflow = (((leftValue ^ rightValue) & (leftValue ^ resultValue) & (1 << (bitCount - 1))) !== 0);
    flag.parity = parity(resultValue);
  }

  function arithmetic(kind, left, right, sizeByte, writeValue = true) {
    const mask = sizeByte === 1 ? 0xff : sizeByte === 2 ? 0xffff : 0xffffffff;
    const leftValue = maskValue(left, sizeByte);
    const rightValue = maskValue(right, sizeByte);
    let result;
    if (kind === "add" || kind === "adc") {
      const carryValue = kind === "adc" && flag.carry ? 1 : 0;
      result = unsigned(leftValue + rightValue + carryValue) & mask;
      setAddFlag(leftValue, rightValue, carryValue, result, sizeByte);
    } else if (kind === "sub" || kind === "cmp" || kind === "sbb") {
      const borrowValue = kind === "sbb" && flag.carry ? 1 : 0;
      result = unsigned(leftValue - rightValue - borrowValue) & mask;
      setSubFlag(leftValue, rightValue, borrowValue, result, sizeByte);
    } else if (kind === "and" || kind === "test") {
      result = leftValue & rightValue;
      setLogicFlag(result, sizeByte);
    } else if (kind === "or") {
      result = leftValue | rightValue;
      setLogicFlag(result, sizeByte);
    } else if (kind === "xor") {
      result = leftValue ^ rightValue;
      setLogicFlag(result, sizeByte);
    } else throw new RuntimeFault("unsupported_opcode", `Unsupported arithmetic operation ${kind}`);
    return writeValue && kind !== "cmp" && kind !== "test" ? result >>> 0 : result >>> 0;
  }

  function executeInstruction(opcode, operandSizeByte, repeatPrefix = null) {
    if (opcode === 0x90) return;
    if (opcode >= 0xb8 && opcode <= 0xbf) {
      const immediate = operandSizeByte === 2 ? fetchWord() : fetchDword();
      setRegister(opcode - 0xb8, immediate, operandSizeByte);
      return;
    }
    if (opcode >= 0xb0 && opcode <= 0xb7) {
      setRegister(opcode - 0xb0, fetchByte(), 1);
      return;
    }
    if (opcode >= 0x50 && opcode <= 0x57) {
      pushSized(getRegister(opcode - 0x50, operandSizeByte), operandSizeByte);
      return;
    }
    if (opcode >= 0x58 && opcode <= 0x5f) {
      setRegister(opcode - 0x58, popSized(operandSizeByte), operandSizeByte);
      return;
    }
    if (opcode >= 0x40 && opcode <= 0x47) {
      const target = opcode - 0x40;
      const left = getRegister(target, operandSizeByte);
      const carryValue = flag.carry;
      const result = arithmetic("add", left, 1, operandSizeByte);
      setRegister(target, result, operandSizeByte);
      flag.carry = carryValue;
      return;
    }
    if (opcode >= 0x48 && opcode <= 0x4f) {
      const target = opcode - 0x48;
      const left = getRegister(target, operandSizeByte);
      const carryValue = flag.carry;
      const result = arithmetic("sub", left, 1, operandSizeByte);
      setRegister(target, result, operandSizeByte);
      flag.carry = carryValue;
      return;
    }
    if (opcode >= 0x70 && opcode <= 0x7f) {
      const displacement = signExtend(fetchByte(), 8);
      if (conditionValue(opcode & 0x0f, flag)) instructionPointer = unsigned(instructionPointer + displacement);
      return;
    }
    if (opcode >= 0x91 && opcode <= 0x97) {
      const target = opcode - 0x90;
      const old = registerValue[registerIndex.eax];
      registerValue[registerIndex.eax] = registerValue[target];
      registerValue[target] = old;
      return;
    }
    if (opcode === 0x68) {
      push(operandSizeByte === 2 ? fetchWord() : fetchDword());
      return;
    }
    if (opcode === 0x6a) {
      push(signExtend(fetchByte(), 8));
      return;
    }
    if (opcode === 0x9c) {
      if (operandSizeByte === 2) throw new RuntimeFault("unsupported_opcode", "16-bit pushf is outside the bounded 32-bit probe", { opcode });
      push(flagValue(flag));
      return;
    }
    if (opcode === 0x9d) {
      if (operandSizeByte === 2) throw new RuntimeFault("unsupported_opcode", "16-bit popf is outside the bounded 32-bit probe", { opcode });
      const value = pop();
      flag.carry = (value & flagMask.carry) !== 0;
      flag.parity = (value & flagMask.parity) !== 0;
      flag.adjust = (value & flagMask.adjust) !== 0;
      flag.zero = (value & flagMask.zero) !== 0;
      flag.sign = (value & flagMask.sign) !== 0;
      flag.direction = (value & flagMask.direction) !== 0;
      flag.overflow = (value & flagMask.overflow) !== 0;
      return;
    }
    if (opcode === 0xe8) {
      if (operandSizeByte === 2) throw new RuntimeFault("unsupported_opcode", "16-bit call is outside the bounded 32-bit probe", { opcode });
      const displacement = signed(fetchDword());
      push(instructionPointer);
      instructionPointer = unsigned(instructionPointer + displacement);
      return;
    }
    if (opcode === 0xe9) {
      if (operandSizeByte === 2) throw new RuntimeFault("unsupported_opcode", "16-bit jmp is outside the bounded 32-bit probe", { opcode });
      const displacement = signed(fetchDword());
      instructionPointer = unsigned(instructionPointer + displacement);
      return;
    }
    if (opcode === 0xeb) {
      const displacement = signExtend(fetchByte(), 8);
      instructionPointer = unsigned(instructionPointer + displacement);
      return;
    }
    if (opcode === 0xc3) {
      if (operandSizeByte === 2) throw new RuntimeFault("unsupported_opcode", "16-bit ret is outside the bounded 32-bit probe", { opcode });
      const target = pop();
      instructionPointer = target;
      if (target === returnSentinel) advancePhase();
      return;
    }
    if (opcode === 0xc2) {
      if (operandSizeByte === 2) throw new RuntimeFault("unsupported_opcode", "16-bit ret is outside the bounded 32-bit probe", { opcode });
      const amount = fetchWord();
      const target = pop();
      registerValue[registerIndex.esp] = unsigned(registerValue[registerIndex.esp] + amount);
      instructionPointer = target;
      if (target === returnSentinel) advancePhase();
      return;
    }
    if (opcode === 0xc9) {
      registerValue[registerIndex.esp] = registerValue[registerIndex.ebp];
      registerValue[registerIndex.ebp] = pop();
      return;
    }
    if (opcode === 0x0f) {
      const extension = fetchByte();
      if (extension === 0xa2) {
        // CPUID over a declared leaf table (BPTK-009): the guest reads a
        // deterministic processor identity instead of the host's.
        const leaf = registerValue[registerIndex.eax];
        const leafValue = { 0: [0x1, 0x756e6547, 0x6c65746e, 0x49656e69], 1: [0x663, 0, 0, 0] }[leaf];
        if (leafValue === undefined) throw new RuntimeFault("unsupported_opcode", `CPUID leaf 0x${leaf.toString(16)} is outside the declared processor table`, { opcode: 0x0fa2 });
        setRegister(registerIndex.eax, leafValue[0], 4);
        setRegister(registerIndex.ebx, leafValue[1], 4);
        setRegister(registerIndex.ecx, leafValue[2], 4);
        setRegister(registerIndex.edx, leafValue[3], 4);
        return;
      }
      if (extension === 0x31) {
        // RDTSC is served from the one monotonic guest clock in virtual
        // mode: every read advances the same base by the declared cycle
        // amount, which keeps the probe deterministic and monotonic.
        const counter = clock.rdtsc();
        setRegister(registerIndex.eax, counter >>> 0);
        setRegister(registerIndex.edx, Math.floor(counter / 0x100000000) >>> 0);
        return;
      }
      if (extension >= 0x80 && extension <= 0x8f) {
        const displacement = signed(fetchDword());
        if (conditionValue(extension & 0x0f, flag)) instructionPointer = unsigned(instructionPointer + displacement);
        return;
      }
      if (extension >= 0x90 && extension <= 0x9f) {
        const decoded = decodeModrm(1);
        operandWrite(decoded, conditionValue(extension & 0x0f, flag) ? 1 : 0, 1);
        return;
      }
      if (extension === 0xaf) {
        const decoded = decodeModrm(operandSizeByte);
        const target = getRegister(decoded.reg, operandSizeByte);
        const source = operandRead(decoded, operandSizeByte);
        imulTwoOperand(decoded.reg, target, source, operandSizeByte);
        return;
      }
      if (extension === 0xb6 || extension === 0xb7 || extension === 0xbe || extension === 0xbf) {
        const decoded = decodeModrm(extension === 0xb7 || extension === 0xbf ? 2 : 1);
        const value = operandRead(decoded, extension === 0xb7 || extension === 0xbf ? 2 : 1);
        const isSigned = extension === 0xbe || extension === 0xbf;
        setRegister(decoded.reg, isSigned ? signExtend(value, decoded.size_byte * 8) : value, operandSizeByte);
        return;
      }
      if (extension === 0x0d || (extension >= 0x18 && extension <= 0x1f)) {
        // The hint NOP family (prefetch and the multi-byte NOP): the ModRM
        // is decoded but no memory is accessed and no architectural state
        // changes, exactly like the reference machine.
        decodeModrm(operandSizeByte);
        return;
      }
      if (extension >= 0x40 && extension <= 0x4f) {
        // CMOVcc moves the source only when the condition holds; a false
        // condition changes no register and no flag.
        const decoded = decodeModrm(operandSizeByte);
        if (conditionValue(extension & 0x0f, flag)) setRegister(decoded.reg, operandRead(decoded, operandSizeByte), operandSizeByte);
        return;
      }
      if (extension === 0xa3 || extension === 0xab || extension === 0xb3 || extension === 0xbb) {
        const decoded = decodeModrm(operandSizeByte);
        const operation = extension === 0xa3 ? "bt" : extension === 0xab ? "bts" : extension === 0xb3 ? "btr" : "btc";
        bitOperation(operation, decoded, getRegister(decoded.reg, operandSizeByte), operandSizeByte);
        return;
      }
      if (extension === 0xa4 || extension === 0xa5 || extension === 0xac || extension === 0xad) {
        // SHLD and SHRD shift the concatenated destination and source pair;
        // count zero leaves every flag untouched. SHLD concatenates the
        // destination above the source; SHRD concatenates the source above
        // the destination, because the shift direction moves the opposite
        // half into the destination.
        const isLeft = extension === 0xa4 || extension === 0xa5;
        const decoded = decodeModrm(operandSizeByte);
        const dest = operandRead(decoded, operandSizeByte);
        const source = getRegister(decoded.reg, operandSizeByte);
        const bitCount = operandSizeByte * 8;
        const count = (extension === 0xa4 || extension === 0xac) ? fetchByte() & 0x1f : getRegister(registerIndex.ecx, 1) & 0x1f;
        if (count === 0) return;
        const mask = (1n << BigInt(bitCount)) - 1n;
        let result;
        let carry;
        if (isLeft) {
          const wide = (BigInt(dest) << BigInt(bitCount)) | BigInt(source);
          result = Number(((wide << BigInt(count)) >> BigInt(bitCount)) & mask);
          carry = count < bitCount * 2 ? ((wide >> BigInt(bitCount * 2 - count)) & 1n) === 1n : false;
        } else {
          const wide = (BigInt(source) << BigInt(bitCount)) | BigInt(dest);
          result = Number((wide >> BigInt(count)) & mask);
          carry = ((wide >> BigInt(count - 1)) & 1n) === 1n;
        }
        operandWrite(decoded, result, operandSizeByte);
        flag.carry = carry;
        flag.zero = result === 0;
        flag.sign = (result & (1 << (bitCount - 1))) !== 0;
        flag.parity = parity(result);
        return;
      }
      if (extension === 0xba) {
        const decoded = decodeModrm(operandSizeByte);
        if (decoded.reg < 4) throw new RuntimeFault("unsupported_opcode", `Unsupported 0x0fba group operation /${decoded.reg}`);
        const immediate = fetchByte();
        const operation = decoded.reg === 4 ? "bt" : decoded.reg === 5 ? "bts" : decoded.reg === 6 ? "btr" : "btc";
        bitOperation(operation, decoded, decoded.is_register ? immediate : unsigned(signExtend(immediate, 8)), operandSizeByte);
        return;
      }
      if (extension === 0xbc || extension === 0xbd) {
        // BSF and BSR: zero sets only zero flag and leaves the destination
        // unmodified (the declared choice for the architecturally undefined
        // destination on a zero source).
        const decoded = decodeModrm(operandSizeByte);
        const value = operandRead(decoded, operandSizeByte);
        const bitCount = operandSizeByte * 8;
        if (value === 0) {
          flag.zero = true;
          return;
        }
        flag.zero = false;
        let bitIndex = extension === 0xbc ? 0 : bitCount - 1;
        if (extension === 0xbc) while (((value >>> bitIndex) & 1) === 0) bitIndex += 1;
        else while (((value >>> bitIndex) & 1) === 0) bitIndex -= 1;
        setRegister(decoded.reg, bitIndex, operandSizeByte);
        return;
      }
      if (extension === 0xb0 || extension === 0xb1) {
        // CMPXCHG: compare the accumulator with the destination, write the
        // source on equality, otherwise load the destination into the
        // accumulator. The comparison sets the flags like CMP.
        const sizeByte = extension === 0xb0 ? 1 : operandSizeByte;
        const decoded = decodeModrm(sizeByte);
        const dest = operandRead(decoded, sizeByte);
        const source = getRegister(decoded.reg, sizeByte);
        arithmetic("cmp", getRegister(registerIndex.eax, sizeByte), dest, sizeByte, false);
        if (flag.zero) operandWrite(decoded, source, sizeByte);
        else setRegister(registerIndex.eax, dest, sizeByte);
        return;
      }
      if (extension === 0xc0 || extension === 0xc1) {
        // XADD exchanges then adds: the destination register receives the old
        // destination and the destination the sum, with ADD flag.
        const sizeByte = extension === 0xc0 ? 1 : operandSizeByte;
        const decoded = decodeModrm(sizeByte);
        const dest = operandRead(decoded, sizeByte);
        const source = getRegister(decoded.reg, sizeByte);
        setRegister(decoded.reg, dest, sizeByte);
        const result = arithmetic("add", dest, source, sizeByte, true);
        operandWrite(decoded, result, sizeByte);
        return;
      }
      const ssePrefix = repeatPrefix !== null ? repeatPrefix : (operandSizeByte === 2 ? 0x66 : 0);
      // SSE2 128-bit packed integer: the 0x66-prefixed integer map, plus the
      // 0xf2/0xf3 pshuflw/pshufhw variants of 0x70. Intercepted ahead of the
      // MMX fallback because the 0x66 form shares the extension byte with a
      // 64-bit MMX opcode; the no-prefix form still routes to executeMmx.
      if (extension === 0x70 && ssePrefix !== 0) {
        executeSse2(extension, ssePrefix);
        return;
      }
      if (ssePrefix === 0x66 && sse2PackedOpcode.has(extension)) {
        executeSse2(extension, ssePrefix);
        return;
      }
      if (sseOpcode.has(extension) && (!mmxOpcode.has(extension) || ssePrefix !== 0)) {
        executeSse(extension, ssePrefix);
        return;
      }
      if (mmxOpcode.has(extension)) {
        if (repeatPrefix !== null) throw new RuntimeFault("unsupported_opcode", "The 0xf2/0xf3-prefixed SSE scalar form is outside the bounded MMX subset", { opcode: (0x0f00 | extension) >>> 0 });
        executeMmx(extension, operandSizeByte);
        return;
      }
      throw new RuntimeFault("unsupported_opcode", `Unsupported 0x0f opcode 0x${extension.toString(16)}`, { opcode: (0x0f00 | extension) >>> 0 });
    }
    if (opcode <= 0x3f && (opcode & 7) <= 3) {
      // The full two-operand ALU space, byte and dword forms alike: the kind
      // comes from bits 3-5, the direction from bit 1 (0 writes the r/m
      // operand, 1 writes the register), and bit 0 selects the byte column.
      // The byte form ignores the operand-size override.
      const kind = aluKindName[(opcode >>> 3) & 7];
      const sizeByte = (opcode & 1) === 0 ? 1 : operandSizeByte;
      const toRegister = (opcode & 2) !== 0;
      const decoded = decodeModrm(sizeByte);
      const result = toRegister
        ? arithmetic(kind, getRegister(decoded.reg, sizeByte), operandRead(decoded, sizeByte), sizeByte, kind !== "cmp")
        : arithmetic(kind, operandRead(decoded, sizeByte), getRegister(decoded.reg, sizeByte), sizeByte, kind !== "cmp");
      if (kind !== "cmp") {
        if (toRegister) setRegister(decoded.reg, result, sizeByte);
        else operandWrite(decoded, result, sizeByte);
      }
      return;
    }
    if (opcode === 0x84 || opcode === 0x85) {
      const sizeByte = opcode === 0x84 ? 1 : operandSizeByte;
      const decoded = decodeModrm(sizeByte);
      arithmetic("test", operandRead(decoded, sizeByte), getRegister(decoded.reg, sizeByte), sizeByte, false);
      return;
    }
    if (opcode === 0x88 || opcode === 0x89 || opcode === 0x8a || opcode === 0x8b) {
      const sizeByte = opcode === 0x88 || opcode === 0x8a ? 1 : operandSizeByte;
      const decoded = decodeModrm(sizeByte);
      if (opcode === 0x88 || opcode === 0x89) operandWrite(decoded, getRegister(decoded.reg, sizeByte), sizeByte);
      else setRegister(decoded.reg, operandRead(decoded, sizeByte), sizeByte);
      return;
    }
    if (opcode === 0x86 || opcode === 0x87) {
      const sizeByte = opcode === 0x86 ? 1 : operandSizeByte;
      const decoded = decodeModrm(sizeByte);
      const left = operandRead(decoded, sizeByte);
      operandWrite(decoded, getRegister(decoded.reg, sizeByte), sizeByte);
      setRegister(decoded.reg, left, sizeByte);
      return;
    }
    if (opcode === 0x8d) {
      const decoded = decodeModrm(operandSizeByte);
      if (decoded.is_register) throw new RuntimeFault("unsupported_opcode", "LEA requires a memory operand");
      // LEA loads the effective offset itself, so the segment base never
      // applies — a segment override on LEA is architecturally ignored.
      setRegister(decoded.reg, decoded.effective_offset, operandSizeByte);
      return;
    }
    if (opcode === 0x8f) {
      // POP r/m: the stack pointer is adjusted before the store, so an
      // esp-based effective address sees the post-pop value (the declared
      // memory form of the SDM order).
      const value = popSized(operandSizeByte);
      const decoded = decodeModrm(operandSizeByte);
      if (decoded.reg !== 0) throw new RuntimeFault("unsupported_opcode", `Unsupported 0x8f group operation ${decoded.reg}`);
      operandWrite(decoded, value, operandSizeByte);
      return;
    }
    if (opcode <= 0x3f && (opcode & 7) === 4) {
      // The al,imm8 column of the ALU space: the byte counterpart of the
      // eax,imm32 forms the probe already serves.
      const kind = aluKindName[(opcode >>> 3) & 7];
      const result = arithmetic(kind, getRegister(registerIndex.eax, 1), fetchByte(), 1, kind !== "cmp");
      if (kind !== "cmp") setRegister(registerIndex.eax, result, 1);
      return;
    }
    if (opcode === 0x05 || opcode === 0x0d || opcode === 0x15 || opcode === 0x1d || opcode === 0x25 || opcode === 0x2d || opcode === 0x35 || opcode === 0x3d) {
      const immediate = operandSizeByte === 2 ? fetchWord() : fetchDword();
      const kind = opcode === 0x05 ? "add" : opcode === 0x0d ? "or" : opcode === 0x15 ? "adc" : opcode === 0x1d ? "sbb" : opcode === 0x25 ? "and" : opcode === 0x2d ? "sub" : opcode === 0x35 ? "xor" : "cmp";
      const result = arithmetic(kind, registerValue[registerIndex.eax], immediate, operandSizeByte, kind !== "cmp");
      if (kind !== "cmp") setRegister(registerIndex.eax, result, operandSizeByte);
      return;
    }
    if (opcode === 0x80 || opcode === 0x81 || opcode === 0x82 || opcode === 0x83 || opcode === 0xf6 || opcode === 0xf7 || opcode === 0xff || opcode === 0xc7 || opcode === 0xc6) {
      // 0x80 is the byte immediate group and 0x82 its documented alias.
      const isByte = opcode === 0xc6 || opcode === 0xf6 || opcode === 0x80 || opcode === 0x82;
      const sizeByte = isByte ? 1 : operandSizeByte;
      const decoded = decodeModrm(sizeByte);
      const operation = decoded.reg;
      if (opcode === 0xc7 || opcode === 0xc6) {
        if (operation !== 0) throw new RuntimeFault("unsupported_opcode", "Unsupported MOV immediate group operation");
        const immediate = sizeByte === 1 ? fetchByte() : sizeByte === 2 ? fetchWord() : fetchDword();
        operandWrite(decoded, immediate, sizeByte);
        return;
      }
      if (opcode === 0xff) {
        if (operandSizeByte === 2 && (operation === 2 || operation === 4)) throw new RuntimeFault("unsupported_opcode", "16-bit call/jmp is outside the bounded 32-bit probe", { opcode });
        if (operation === 2) {
          const target = operandRead(decoded, 4);
          const hleEntry = hleGuest !== null && (target & 3) === 0 ? hleGuest.exportAt(target) : null;
          if (hleEntry !== null) {
            dispatchHle(hleEntry, false);
            return;
          }
          push(instructionPointer);
          instructionPointer = target;
          return;
        }
        if (operation === 4) {
          const target = operandRead(decoded, 4);
          const hleEntry = hleGuest !== null && (target & 3) === 0 ? hleGuest.exportAt(target) : null;
          if (hleEntry !== null) {
            dispatchHle(hleEntry, true);
            return;
          }
          instructionPointer = target;
          return;
        }
        if (operation === 6) {
          push(operandRead(decoded, 4));
          return;
        }
        if (operation === 0 || operation === 1) {
          const left = operandRead(decoded, operandSizeByte);
          const carryValue = flag.carry;
          const result = arithmetic(operation === 0 ? "add" : "sub", left, 1, operandSizeByte);
          operandWrite(decoded, result, operandSizeByte);
          flag.carry = carryValue;
          return;
        }
        throw new RuntimeFault("unsupported_opcode", `Unsupported 0xff group operation ${operation}`);
      }
      if (opcode === 0xf6 || opcode === 0xf7) {
        if (operation === 0) {
          const immediate = sizeByte === 1 ? fetchByte() : sizeByte === 2 ? fetchWord() : fetchDword();
          arithmetic("test", operandRead(decoded, sizeByte), immediate, sizeByte, false);
          return;
        }
        if (operation === 2) {
          const value = operandRead(decoded, sizeByte);
          operandWrite(decoded, ~value, sizeByte);
          return;
        }
        if (operation === 3) {
          const value = operandRead(decoded, sizeByte);
          const result = arithmetic("sub", 0, value, sizeByte);
          operandWrite(decoded, result, sizeByte);
          return;
        }
        if (operation >= 4) {
          multiplyDivide(operation === 4 ? "mul" : operation === 5 ? "imul" : operation === 6 ? "div" : "idiv", decoded, sizeByte, opcode);
          return;
        }
        throw new RuntimeFault("unsupported_opcode", `Unsupported 0xf7 group operation ${operation}`);
      }
      const immediate = opcode === 0x83 ? signExtend(fetchByte(), 8) : isByte ? fetchByte() : operandSizeByte === 2 ? signExtend(fetchWord(), 16) : fetchDword();
      const kind = operation === 0 ? "add" : operation === 1 ? "or" : operation === 2 ? "adc" : operation === 3 ? "sbb" : operation === 4 ? "and" : operation === 5 ? "sub" : operation === 6 ? "xor" : "cmp";
      const result = arithmetic(kind, operandRead(decoded, sizeByte), immediate, sizeByte, kind !== "cmp");
      if (kind !== "cmp") operandWrite(decoded, result, sizeByte);
      return;
    }
    if (opcode === 0xa1 || opcode === 0xa3) {
      // The moffs displacement is an offset within the active segment, so the
      // segment base rides it exactly like a ModRM effective offset: zero for
      // the flat cs/ds/es/ss, the TEB linear address under an fs override.
      const address = unsigned(fetchDword() + segmentBaseValue);
      if (opcode === 0xa1) setRegister(registerIndex.eax, readMemory(address, operandSizeByte), operandSizeByte);
      else writeMemory(address, operandSizeByte, getRegister(registerIndex.eax, operandSizeByte));
      return;
    }
    if (opcode === 0xa0 || opcode === 0xa2) {
      // The byte moffs forms: mov al,[moffs8] and mov [moffs8],al. The segment
      // base applies to the direct offset the same way it does to the dword form.
      const address = unsigned(fetchDword() + segmentBaseValue);
      if (opcode === 0xa0) setRegister(registerIndex.eax, readMemory(address, 1), 1);
      else writeMemory(address, 1, getRegister(registerIndex.eax, 1));
      return;
    }
    if (opcode === 0xa8) {
      arithmetic("test", getRegister(registerIndex.eax, 1), fetchByte(), 1, false);
      return;
    }
    if (opcode === 0xa9) {
      const immediate = operandSizeByte === 2 ? fetchWord() : fetchDword();
      arithmetic("test", registerValue[registerIndex.eax], immediate, operandSizeByte, false);
      return;
    }
    if (opcode === 0x98) {
      // CWDE sign-extends ax into eax; the 0x66 form is CBW into ax with the
      // high word of eax preserved.
      if (operandSizeByte === 2) setRegister(registerIndex.eax, signExtend(getRegister(registerIndex.eax, 1), 8), 2);
      else setRegister(registerIndex.eax, signExtend(getRegister(registerIndex.eax, 2), 16), 4);
      return;
    }
    if (opcode === 0x99) {
      // CDQ copies the sign bit of eax across edx; the 0x66 form is CWD into
      // dx with the high word of edx preserved.
      const negative = operandSizeByte === 2 ? (getRegister(registerIndex.eax, 2) & 0x8000) !== 0 : (registerValue[registerIndex.eax] & 0x80000000) !== 0;
      setRegister(registerIndex.edx, negative ? operandSizeByte === 2 ? 0xffff : 0xffffffff : 0, operandSizeByte);
      return;
    }
    if (opcode === 0x60) {
      // PUSHA pushes eax, ecx, edx, ebx, the original esp, ebp, esi, edi.
      const originalEsp = registerValue[registerIndex.esp];
      for (const index of [0, 1, 2, 3]) pushSized(getRegister(index, operandSizeByte), operandSizeByte);
      pushSized(originalEsp, operandSizeByte);
      for (const index of [5, 6, 7]) pushSized(getRegister(index, operandSizeByte), operandSizeByte);
      return;
    }
    if (opcode === 0x61) {
      // POPA pops in reverse; the stored esp value is read and discarded.
      for (const index of [7, 6, 5]) setRegister(index, popSized(operandSizeByte), operandSizeByte);
      popSized(operandSizeByte);
      for (const index of [3, 2, 1, 0]) setRegister(index, popSized(operandSizeByte), operandSizeByte);
      return;
    }
    if (opcode === 0x9e) {
      // SAHF loads the low flags from ah (the 8-bit register index 4):
      // sign, zero, adjust, parity, carry.
      const ah = getRegister(4, 1);
      flag.sign = (ah & 0x80) !== 0;
      flag.zero = (ah & 0x40) !== 0;
      flag.adjust = (ah & 0x10) !== 0;
      flag.parity = (ah & 0x04) !== 0;
      flag.carry = (ah & 0x01) !== 0;
      return;
    }
    if (opcode === 0x9f) {
      // LAHF stores the low flags into ah (the 8-bit register index 4) with
      // the reserved bit 3 and bit 5 zero and the always-one bit 1 set.
      setRegister(4, 0x02 | (flag.sign ? 0x80 : 0) | (flag.zero ? 0x40 : 0) | (flag.adjust ? 0x10 : 0) | (flag.parity ? 0x04 : 0) | (flag.carry ? 0x01 : 0), 1);
      return;
    }
    if (opcode === 0x9b) {
      // FWAIT is the identity here: the bounded model raises no deferred x87
      // exception, so waiting for one changes no state.
      return;
    }
    if (opcode === 0xd7) {
      // XLAT reads the byte at [ebx + al] into al.
      setRegister(registerIndex.eax, readMemory(unsigned(getRegister(registerIndex.ebx, 4) + getRegister(registerIndex.eax, 1)), 1), 1);
      return;
    }
    if (opcode >= 0xe0 && opcode <= 0xe3) {
      // LOOPNE, LOOPE, LOOP, and JECXZ: the short-displacement control
      // family. JECXZ tests ecx directly (the cx form needs the refused
      // address-size override); the loop form decrements first.
      const displacement = signExtend(fetchByte(), 8);
      if (opcode === 0xe3) {
        if (registerValue[registerIndex.ecx] === 0) instructionPointer = unsigned(instructionPointer + displacement);
        return;
      }
      const next = unsigned(registerValue[registerIndex.ecx] - 1);
      registerValue[registerIndex.ecx] = next;
      const taken = opcode === 0xe0 ? next !== 0 && !flag.zero : opcode === 0xe1 ? next !== 0 && flag.zero : next !== 0;
      if (taken) instructionPointer = unsigned(instructionPointer + displacement);
      return;
    }
    if (opcode === 0xf5 || opcode === 0xf8 || opcode === 0xf9) {
      if (opcode === 0xf5) flag.carry = !flag.carry;
      else flag.carry = opcode === 0xf9;
      return;
    }
    if (opcode === 0xfe) {
      const decoded = decodeModrm(1);
      if (decoded.reg > 1) throw new RuntimeFault("unsupported_opcode", `Unsupported 0xfe group operation ${decoded.reg}`);
      const left = operandRead(decoded, 1);
      const carryValue = flag.carry;
      const result = arithmetic(decoded.reg === 0 ? "add" : "sub", left, 1, 1);
      operandWrite(decoded, result, 1);
      flag.carry = carryValue;
      return;
    }
    if (opcode === 0xc8) {
      const frameSize = fetchWord();
      const nesting = fetchByte();
      if (nesting !== 0) throw new RuntimeFault("unsupported_opcode", "ENTER nesting is not supported");
      push(registerValue[registerIndex.ebp]);
      registerValue[registerIndex.ebp] = registerValue[registerIndex.esp];
      registerValue[registerIndex.esp] = unsigned(registerValue[registerIndex.esp] - frameSize);
      return;
    }
    if (opcode === 0xfc || opcode === 0xfd) {
      flag.direction = opcode === 0xfd;
      return;
    }
    if (opcode >= 0xa4 && opcode <= 0xa7) {
      const kind = opcode <= 0xa5 ? "movs" : "cmps";
      stringStep(kind, opcode % 2 === 0 ? 1 : operandSizeByte, repeatPrefix);
      return;
    }
    if (opcode >= 0xaa && opcode <= 0xaf) {
      const kind = opcode <= 0xab ? "stos" : opcode <= 0xad ? "lods" : "scas";
      stringStep(kind, opcode % 2 === 0 ? 1 : operandSizeByte, repeatPrefix);
      return;
    }
    if (opcode === 0xc0 || opcode === 0xc1 || opcode === 0xd0 || opcode === 0xd1 || opcode === 0xd2 || opcode === 0xd3) {
      const sizeByte = opcode === 0xc0 || opcode === 0xd0 || opcode === 0xd2 ? 1 : operandSizeByte;
      const decoded = decodeModrm(sizeByte);
      const kind = decoded.reg === 6 ? "shl" : ["rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar"][decoded.reg];
      const count = opcode === 0xc0 || opcode === 0xc1 ? fetchByte() : opcode === 0xd2 || opcode === 0xd3 ? getRegister(registerIndex.ecx, 1) : 1;
      const value = operandRead(decoded, sizeByte);
      const result = shiftOperation(kind === "sal" ? "shl" : kind, value, count, sizeByte);
      operandWrite(decoded, result, sizeByte);
      return;
    }
    if (opcode === 0x69 || opcode === 0x6b) {
      const decoded = decodeModrm(operandSizeByte);
      const source = operandRead(decoded, operandSizeByte);
      const immediate = opcode === 0x6b ? signExtend(fetchByte(), 8) : operandSizeByte === 2 ? signExtend(fetchWord(), 16) : fetchDword();
      imulTwoOperand(decoded.reg, source, immediate >>> 0, operandSizeByte);
      return;
    }
    if (opcode >= 0xd8 && opcode <= 0xdf) {
      executeX87(opcode, repeatPrefix);
      return;
    }
    if (opcode === 0xf4 || opcode === 0xfa || opcode === 0xfb) {
      // HLT and CLI/STI are privileged: user-mode code cannot execute them
      // (a real CPU raises #GP), so the bounded probe stops with a named
      // diagnostic instead of pretending the flag changed.
      throw new RuntimeFault("unsupported_opcode", `The privileged instruction 0x${opcode.toString(16)} is outside the user-mode bounded probe`, { opcode });
    }
    if (opcode >= 0xe4 && opcode <= 0xe7) throw new RuntimeFault("unsupported_opcode", "The port input family is outside the user-mode bounded probe", { opcode });
    if (opcode >= 0xec && opcode <= 0xef) throw new RuntimeFault("unsupported_opcode", "The port input family is outside the user-mode bounded probe", { opcode });
    if (opcode >= 0xe8 && opcode <= 0xef) {
      // 0xe8/0xe9/0xeb handled above; the rest of the 0xe8-0xef range is the
      // port output family and enters/outs.
      throw new RuntimeFault("unsupported_opcode", `The port output instruction 0x${opcode.toString(16)} is outside the user-mode bounded probe`, { opcode });
    }
    throw new RuntimeFault("unsupported_opcode", `Unsupported opcode 0x${opcode.toString(16).padStart(2, "0")}`, { opcode });
  }

  // Bounded MMX integer subset (BPTK-009): the 64-bit lanes execute through
  // the same checked memory as every other operand, so bounds, permission,
  // and the instruction undo log stay in force on an mm/m64 access.
  function readMmxQword(decoded) {
    return decoded.is_register ? mm[decoded.rm] : BigInt.asUintN(64, readInt64Memory(decoded.address));
  }

  function executeMmx(extension, operandSizeByte) {
    if (operandSizeByte !== 4) throw new RuntimeFault("unsupported_opcode", "The 0x66-prefixed 128-bit SIMD form is outside the bounded MMX subset", { opcode: (0x0f00 | extension) >>> 0 });
    if (extension === 0x77) {
      // EMMS: the x87 tag word becomes empty; the mm lane values are left
      // intact exactly like the hardware.
      fpu.valid.fill(0);
      fpu.top = 0;
      return;
    }
    const decoded = decodeModrm(8);
    // Data movement: movd exchanges the low dword with a 32-bit r/m; movq
    // moves the whole 64-bit lane.
    if (extension === 0x6e) { mm[decoded.reg] = BigInt(operandRead(decoded, 4) >>> 0); return; }
    if (extension === 0x7e) { operandWrite(decoded, Number(mm[decoded.reg] & 0xffffffffn), 4); return; }
    if (extension === 0x6f) { mm[decoded.reg] = readMmxQword(decoded); return; }
    if (extension === 0x7f) {
      if (decoded.is_register) mm[decoded.rm] = mm[decoded.reg];
      else writeInt64Memory(decoded.address, mm[decoded.reg]);
      return;
    }
    // Four-word shuffle: each result word selects a source word by a 2-bit
    // field of the immediate.
    if (extension === 0x70) {
      const source = readMmxQword(decoded);
      const control = fetchByte();
      let result = 0n;
      for (let word = 0; word < 4; word += 1) {
        const select = (control >> (word * 2)) & 3;
        result |= ((source >> BigInt(select * 16)) & 0xffffn) << BigInt(word * 16);
      }
      mm[decoded.reg] = result;
      return;
    }
    // Packed logical: pand/pandn/por/pxor over the full 64 bits.
    const mask64 = 0xffffffffffffffffn;
    if (extension === 0xdb) { mm[decoded.reg] = mm[decoded.reg] & readMmxQword(decoded); return; }
    if (extension === 0xdf) { mm[decoded.reg] = (~mm[decoded.reg] & mask64) & readMmxQword(decoded); return; }
    if (extension === 0xeb) { mm[decoded.reg] = mm[decoded.reg] | readMmxQword(decoded); return; }
    if (extension === 0xef) { mm[decoded.reg] = mm[decoded.reg] ^ readMmxQword(decoded); return; }
    // Packed add/sub in byte, word, and dword lanes, wrapping per lane.
    const addSub = { 0xfc: [1, "add"], 0xfd: [2, "add"], 0xfe: [4, "add"], 0xf8: [1, "sub"], 0xf9: [2, "sub"], 0xfa: [4, "sub"] }[extension];
    if (addSub !== undefined) {
      const [laneByte, kind] = addSub;
      const fn = kind === "add" ? (a, b) => a + b : (a, b) => a - b;
      mm[decoded.reg] = mmxPackedLane(mm[decoded.reg], readMmxQword(decoded), laneByte, fn);
      return;
    }
    // Packed equality compare: each equal lane becomes all-ones, otherwise zero.
    const compare = { 0x74: 1, 0x75: 2, 0x76: 4 }[extension];
    if (compare !== undefined) {
      const laneMask = (1n << BigInt(compare * 8)) - 1n;
      mm[decoded.reg] = mmxPackedLane(mm[decoded.reg], readMmxQword(decoded), compare, (a, b) => (a === b ? laneMask : 0n));
      return;
    }
    // Register-form shifts: the count is the whole source lane, saturated.
    const shiftRegister = { 0xd1: [2, "srl"], 0xd2: [4, "srl"], 0xd3: [8, "srl"], 0xe1: [2, "sra"], 0xe2: [4, "sra"], 0xf1: [2, "sll"], 0xf2: [4, "sll"], 0xf3: [8, "sll"] }[extension];
    if (shiftRegister !== undefined) {
      const [laneByte, kind] = shiftRegister;
      const rawCount = readMmxQword(decoded);
      const count = rawCount > 64n ? 65 : Number(rawCount);
      mm[decoded.reg] = mmxPackedShift(mm[decoded.reg], count, laneByte, kind);
      return;
    }
    // Immediate-group shifts (0x71/0x72/0x73): the /reg field selects the
    // direction; the reserved /reg forms (and the 128-bit byte-shift /reg of
    // 0x73) stay structured refusals.
    const shiftGroup = { 0x71: 2, 0x72: 4, 0x73: 8 }[extension];
    if (shiftGroup !== undefined) {
      const kind = decoded.reg === 2 ? "srl" : decoded.reg === 4 ? "sra" : decoded.reg === 6 ? "sll" : null;
      if (kind === null || (shiftGroup === 8 && kind === "sra")) throw new RuntimeFault("unsupported_opcode", `Unsupported MMX shift group 0x${extension.toString(16)} /${decoded.reg}`, { opcode: (0x0f00 | extension) >>> 0 });
      const count = fetchByte();
      mm[decoded.rm] = mmxPackedShift(mm[decoded.rm], count, shiftGroup, kind);
      return;
    }
    throw new RuntimeFault("unsupported_opcode", `Unsupported MMX opcode 0x${extension.toString(16)}`, { opcode: (0x0f00 | extension) >>> 0 });
  }

  // Bounded SSE/SSE2 subset (BPTK-009): the FP lanes compute in the host's
  // IEEE-754 arithmetic, which is correctly-rounded for every operation the
  // subset serves — a float32 result computed in float64 and rounded back is
  // bit-exact for add/sub/mul/div/sqrt because float64 carries more than
  // 2p+2 bit of a float32 operand — so the reference state is exact within
  // IEEE. The declared strict fallback is this scalar lane computation; a
  // WASM-SIMD acceleration is a deferred performance item, not a semantic
  // one. The MXCSR is fixed at round-nearest, mask-all.
  function executeSse(extension, prefix) {
    const decoded = decodeModrm(16);
    const readOperand128 = () => decoded.is_register ? Buffer.from(xmm[decoded.rm]) : readBlock(decoded.address, 16);
    const writeOperand128 = (buffer) => { if (decoded.is_register) buffer.copy(xmm[decoded.rm]); else writeBlock(decoded.address, buffer); };
    const refuse = () => { throw new RuntimeFault("unsupported_opcode", `Unsupported SSE form 0x${extension.toString(16)} prefix 0x${prefix.toString(16)}`, { opcode: (0x0f00 | extension) >>> 0 }); };

    // --- Aligned and unaligned 128-bit move, and the scalar low-lane move. ---
    if (extension === 0x28 || extension === 0x29) {
      if (prefix === 0xf3 || prefix === 0xf2) refuse();
      if (extension === 0x28) readOperand128().copy(xmm[decoded.reg]);
      else writeOperand128(Buffer.from(xmm[decoded.reg]));
      return;
    }
    if (extension === 0x6f || extension === 0x7f) {
      // movdqa (0x66) / movdqu (0xf3): the whole 128 bit move.
      if (extension === 0x6f) readOperand128().copy(xmm[decoded.reg]);
      else writeOperand128(Buffer.from(xmm[decoded.reg]));
      return;
    }
    if (extension === 0x10 || extension === 0x11) {
      const width = prefix === 0xf3 ? 4 : prefix === 0xf2 ? 8 : 16;
      if (width === 16) {
        if (extension === 0x10) readOperand128().copy(xmm[decoded.reg]);
        else writeOperand128(Buffer.from(xmm[decoded.reg]));
        return;
      }
      if (extension === 0x10) {
        // Scalar load: a register source preserves the upper lanes, a memory
        // source zero-extends the register.
        if (decoded.is_register) { xmm[decoded.rm].copy(xmm[decoded.reg], 0, 0, width); return; }
        const loaded = readBlock(decoded.address, width);
        xmm[decoded.reg].fill(0);
        loaded.copy(xmm[decoded.reg], 0, 0, width);
        return;
      }
      // Scalar store from the low lane.
      if (decoded.is_register) { xmm[decoded.reg].copy(xmm[decoded.rm], 0, 0, width); return; }
      writeBlock(decoded.address, Buffer.from(xmm[decoded.reg].subarray(0, width)));
      return;
    }
    if (extension === 0x6e) {
      // movd xmm, r/m32 (0x66): the register is zero-extended to 128 bit.
      if (prefix !== 0x66) refuse();
      const value = operandRead(decoded, 4) >>> 0;
      xmm[decoded.reg].fill(0);
      xmm[decoded.reg].writeUInt32LE(value, 0);
      return;
    }
    if (extension === 0x7e) {
      if (prefix === 0x66) { operandWrite(decoded, xmm[decoded.reg].readUInt32LE(0), 4); return; }
      if (prefix === 0xf3) {
        // movq xmm, xmm/m64: the low qword loads, the upper qword zeroes.
        const source = decoded.is_register ? Buffer.from(xmm[decoded.rm]) : readBlock(decoded.address, 8);
        xmm[decoded.reg].fill(0);
        source.copy(xmm[decoded.reg], 0, 0, 8);
        return;
      }
      refuse();
    }

    // --- Bitwise 128-bit logical (andps/andnps/orps/xorps). ---
    if (extension >= 0x54 && extension <= 0x57) {
      const dest = Buffer.from(xmm[decoded.reg]);
      const source = readOperand128();
      for (let index = 0; index < 16; index += 1) {
        dest[index] = extension === 0x54 ? dest[index] & source[index]
          : extension === 0x55 ? (~dest[index]) & source[index]
          : extension === 0x56 ? dest[index] | source[index]
          : dest[index] ^ source[index];
      }
      dest.copy(xmm[decoded.reg]);
      return;
    }

    // --- The compare that sets EFLAGS from the low lane (ucomiss/comiss). ---
    if (extension === 0x2e || extension === 0x2f) {
      const isDouble = prefix === 0x66;
      const left = isDouble ? xmm[decoded.reg].readDoubleLE(0) : xmm[decoded.reg].readFloatLE(0);
      const right = decoded.is_register
        ? (isDouble ? xmm[decoded.rm].readDoubleLE(0) : xmm[decoded.rm].readFloatLE(0))
        : (isDouble ? readDoubleMemory(decoded.address) : readFloatMemory(decoded.address));
      flag.overflow = false;
      flag.sign = false;
      flag.adjust = false;
      if (Number.isNaN(left) || Number.isNaN(right)) { flag.zero = true; flag.parity = true; flag.carry = true; }
      else if (left < right) { flag.zero = false; flag.parity = false; flag.carry = true; }
      else if (left > right) { flag.zero = false; flag.parity = false; flag.carry = false; }
      else { flag.zero = true; flag.parity = false; flag.carry = false; }
      return;
    }

    // --- Integer<->float conversion. ---
    if (extension === 0x2a) {
      // cvtsi2ss (0xf3) / cvtsi2sd (0xf2) from a signed r/m32; cvtpi2ps (np)
      // from the mm/m64 integer pair.
      if (prefix === 0xf3) { xmm[decoded.reg].writeFloatLE(Math.fround(signed(operandRead(decoded, 4))), 0); return; }
      if (prefix === 0xf2) { xmm[decoded.reg].writeDoubleLE(signed(operandRead(decoded, 4)), 0); return; }
      const source = decoded.is_register ? mm[decoded.rm] : BigInt.asUintN(64, readInt64Memory(decoded.address));
      xmm[decoded.reg].writeFloatLE(Math.fround(Number(BigInt.asIntN(32, source))), 0);
      xmm[decoded.reg].writeFloatLE(Math.fround(Number(BigInt.asIntN(32, source >> 32n))), 4);
      return;
    }
    if (extension === 0x2c || extension === 0x2d) {
      const truncate = extension === 0x2c;
      if (prefix === 0xf3 || prefix === 0xf2) {
        const isDouble = prefix === 0xf2;
        const value = decoded.is_register
          ? (isDouble ? xmm[decoded.rm].readDoubleLE(0) : xmm[decoded.rm].readFloatLE(0))
          : (isDouble ? readDoubleMemory(decoded.address) : readFloatMemory(decoded.address));
        setRegister(decoded.reg, convertToInt32(value, truncate), 4);
        return;
      }
      // np cvt(t)ps2pi: two float lanes into the mm integer pair.
      const source = decoded.is_register ? Buffer.from(xmm[decoded.rm]) : readBlock(decoded.address, 8);
      const low = BigInt(convertToInt32(source.readFloatLE(0), truncate));
      const high = BigInt(convertToInt32(source.readFloatLE(4), truncate));
      mm[decoded.reg] = low | (high << 32n);
      return;
    }
    if (extension === 0x5a) {
      const dest = xmm[decoded.reg];
      if (prefix === 0xf3) { dest.writeDoubleLE(decoded.is_register ? xmm[decoded.rm].readFloatLE(0) : readFloatMemory(decoded.address), 0); return; }
      if (prefix === 0xf2) { dest.writeFloatLE(Math.fround(decoded.is_register ? xmm[decoded.rm].readDoubleLE(0) : readDoubleMemory(decoded.address)), 0); return; }
      const source = readOperand128();
      const result = Buffer.alloc(16);
      if (prefix === 0x66) { result.writeFloatLE(Math.fround(source.readDoubleLE(0)), 0); result.writeFloatLE(Math.fround(source.readDoubleLE(8)), 4); }
      else { result.writeDoubleLE(source.readFloatLE(0), 0); result.writeDoubleLE(source.readFloatLE(4), 8); }
      result.copy(dest);
      return;
    }

    // --- Packed and scalar arithmetic. The prefix selects the form: none
    //     packed-single, 0x66 packed-double, 0xf3 scalar-single, 0xf2
    //     scalar-double. Scalar forms touch only the low lane and preserve
    //     the destination's upper lanes.
    const form = prefix === 0 ? "ps" : prefix === 0x66 ? "pd" : prefix === 0xf3 ? "ss" : "sd";
    const isDouble = form === "pd" || form === "sd";
    const laneCount = form === "ps" ? 4 : form === "pd" ? 2 : 1;
    const laneByte = isDouble ? 8 : 4;
    const scalarWidth = laneCount === 1 ? laneByte : 16;
    const source = Buffer.alloc(16);
    if (decoded.is_register) xmm[decoded.rm].copy(source, 0, 0, scalarWidth);
    else readBlock(decoded.address, scalarWidth).copy(source, 0, 0, scalarWidth);
    const dest = Buffer.from(xmm[decoded.reg]);
    const result = Buffer.from(dest);
    const binary = { 0x58: (a, b) => a + b, 0x59: (a, b) => a * b, 0x5c: (a, b) => a - b, 0x5e: (a, b) => a / b, 0x5d: (a, b) => (a < b ? a : b), 0x5f: (a, b) => (a > b ? a : b) }[extension];
    if (extension !== 0x51 && binary === undefined) refuse();
    for (let lane = 0; lane < laneCount; lane += 1) {
      const offset = lane * laneByte;
      if (isDouble) {
        const a = dest.readDoubleLE(offset);
        const b = source.readDoubleLE(offset);
        result.writeDoubleLE(extension === 0x51 ? Math.sqrt(b) : binary(a, b), offset);
      } else {
        const a = dest.readFloatLE(offset);
        const b = source.readFloatLE(offset);
        result.writeFloatLE(Math.fround(extension === 0x51 ? Math.sqrt(b) : binary(a, b)), offset);
      }
    }
    result.copy(xmm[decoded.reg]);
  }

  // Bounded SSE2 128-bit packed integer subset (BPTK-009): the packed integer
  // move, shuffle, logical, add/sub, compare, unpack/pack, and shift forms the
  // real CRT and these binaries execute. Every lane computes through the same
  // checked memory as any other operand (an xmm/m128 source reads a bounded
  // 16-byte block), so bounds, permission, and the instruction undo log stay
  // in force. The integer semantics are two's-complement-exact through BigInt;
  // anything still outside the subset is a structured unsupported_opcode stop.
  function executeSse2(extension, prefix) {
    const decoded = decodeModrm(16);
    const readXmm = () => decoded.is_register ? Buffer.from(xmm[decoded.rm]) : readBlock(decoded.address, 16);
    const dest = xmm[decoded.reg];
    const refuse = () => { throw new RuntimeFault("unsupported_opcode", `Unsupported SSE2 form 0x${extension.toString(16)} prefix 0x${prefix.toString(16)}`, { opcode: (0x0f00 | extension) >>> 0 }); };

    // --- movq store (66 0f d6): the low qword stores; a register destination
    //     zero-extends the upper qword. ---
    if (extension === 0xd6) {
      if (decoded.is_register) { xmm[decoded.rm].fill(0); dest.copy(xmm[decoded.rm], 0, 0, 8); }
      else writeBlock(decoded.address, Buffer.from(dest.subarray(0, 8)));
      return;
    }
    // --- pmovmskb (66 0f d7): the sign bit of each of 16 byte lanes into a
    //     zero-extended GPR. ---
    if (extension === 0xd7) {
      let mask = 0;
      for (let index = 0; index < 16; index += 1) if (dest[index] & 0x80) mask |= 1 << index;
      setRegister(decoded.reg, mask >>> 0, 4);
      return;
    }
    // --- pshufd (66) / pshuflw (f2) / pshufhw (f3): each result unit selects a
    //     source unit by a 2-bit field of the immediate. ---
    if (extension === 0x70) {
      const source = readXmm();
      const control = fetchByte();
      const out = Buffer.from(source);
      const pick = (index) => (control >> (index * 2)) & 3;
      if (prefix === 0x66) {
        for (let index = 0; index < 4; index += 1) source.copy(out, index * 4, pick(index) * 4, pick(index) * 4 + 4);
      } else if (prefix === 0xf2) {
        for (let index = 0; index < 4; index += 1) source.copy(out, index * 2, pick(index) * 2, pick(index) * 2 + 2);
        source.copy(out, 8, 8, 16);
      } else if (prefix === 0xf3) {
        source.copy(out, 0, 0, 8);
        for (let index = 0; index < 4; index += 1) source.copy(out, 8 + index * 2, 8 + pick(index) * 2, 8 + pick(index) * 2 + 2);
      } else refuse();
      out.copy(dest);
      return;
    }
    // --- 128-bit logical (pand/pandn/por/pxor). ---
    const mask128 = (1n << 128n) - 1n;
    if (extension === 0xdb) { bigToBuffer(xmmBig(dest) & xmmBig(readXmm())).copy(dest); return; }
    if (extension === 0xdf) { bigToBuffer((~xmmBig(dest) & mask128) & xmmBig(readXmm())).copy(dest); return; }
    if (extension === 0xeb) { bigToBuffer(xmmBig(dest) | xmmBig(readXmm())).copy(dest); return; }
    if (extension === 0xef) { bigToBuffer(xmmBig(dest) ^ xmmBig(readXmm())).copy(dest); return; }
    // --- Packed add/sub in byte, word, dword, and qword lanes, wrapping. ---
    const addSub = { 0xfc: [1, "add"], 0xfd: [2, "add"], 0xfe: [4, "add"], 0xd4: [8, "add"], 0xf8: [1, "sub"], 0xf9: [2, "sub"], 0xfa: [4, "sub"], 0xfb: [8, "sub"] }[extension];
    if (addSub !== undefined) {
      const [laneByte, kind] = addSub;
      const fn = kind === "add" ? (a, b) => a + b : (a, b) => a - b;
      bigToBuffer(packedLane128(xmmBig(dest), xmmBig(readXmm()), laneByte, fn)).copy(dest);
      return;
    }
    // --- Packed equality (pcmpeqb/w/d) and signed greater-than (pcmpgtb/w/d). ---
    const equalLane = { 0x74: 1, 0x75: 2, 0x76: 4 }[extension];
    if (equalLane !== undefined) { pcmpeq128(dest, readXmm(), equalLane).copy(dest); return; }
    const greaterLane = { 0x64: 1, 0x65: 2, 0x66: 4 }[extension];
    if (greaterLane !== undefined) { pcmpgt128(Buffer.from(dest), readXmm(), greaterLane).copy(dest); return; }
    // --- Unpack/interleave, low and high halves. ---
    const unpackLow = { 0x60: 1, 0x61: 2, 0x62: 4, 0x6c: 8 }[extension];
    if (unpackLow !== undefined) { unpack128(Buffer.from(dest), readXmm(), unpackLow, false).copy(dest); return; }
    const unpackHigh = { 0x68: 1, 0x69: 2, 0x6a: 4, 0x6d: 8 }[extension];
    if (unpackHigh !== undefined) { unpack128(Buffer.from(dest), readXmm(), unpackHigh, true).copy(dest); return; }
    // --- Saturating pack: packsswb, packuswb, packssdw. ---
    if (extension === 0x63) { pack128(Buffer.from(dest), readXmm(), 2, false).copy(dest); return; }
    if (extension === 0x67) { pack128(Buffer.from(dest), readXmm(), 2, true).copy(dest); return; }
    if (extension === 0x6b) { pack128(Buffer.from(dest), readXmm(), 4, false).copy(dest); return; }
    // --- Packed multiply: pmullw (low word) and pmuludq (even dword→qword). ---
    if (extension === 0xd5) { bigToBuffer(packedLane128(xmmBig(dest), xmmBig(readXmm()), 2, (a, b) => (a * b) & 0xffffn)).copy(dest); return; }
    if (extension === 0xf4) {
      const source = readXmm();
      const out = Buffer.alloc(16);
      for (let qword = 0; qword < 2; qword += 1) {
        const product = BigInt(dest.readUInt32LE(qword * 8)) * BigInt(source.readUInt32LE(qword * 8));
        out.writeBigUInt64LE(product & 0xffffffffffffffffn, qword * 8);
      }
      out.copy(dest);
      return;
    }
    // --- Register-form shifts: the count is the whole low qword of the source,
    //     saturated at the lane width. ---
    const shiftRegister = { 0xd1: [2, "srl"], 0xd2: [4, "srl"], 0xd3: [8, "srl"], 0xe1: [2, "sra"], 0xe2: [4, "sra"], 0xf1: [2, "sll"], 0xf2: [4, "sll"], 0xf3: [8, "sll"] }[extension];
    if (shiftRegister !== undefined) {
      const [laneByte, kind] = shiftRegister;
      const rawCount = readXmm().readBigUInt64LE(0);
      const count = rawCount > 128n ? 129 : Number(rawCount);
      bigToBuffer(packedShift128(xmmBig(dest), count, laneByte, kind)).copy(dest);
      return;
    }
    // --- Immediate-group shifts (0x71/0x72/0x73): the /reg field selects the
    //     direction. 0x73 /3 and /7 are the whole-register byte shifts
    //     (psrldq/pslldq); the reserved and qword-arithmetic forms refuse. ---
    const shiftGroup = { 0x71: 2, 0x72: 4, 0x73: 8 }[extension];
    if (shiftGroup !== undefined) {
      if (!decoded.is_register) refuse();
      const target = xmm[decoded.rm];
      const reg = decoded.reg;
      const count = fetchByte();
      if (extension === 0x73 && (reg === 3 || reg === 7)) {
        const shiftByte = count > 15 ? 16 : count;
        const out = Buffer.alloc(16);
        if (reg === 3) target.copy(out, 0, shiftByte, 16);
        else target.copy(out, shiftByte, 0, 16 - shiftByte);
        out.copy(target);
        return;
      }
      const kind = reg === 2 ? "srl" : reg === 4 ? "sra" : reg === 6 ? "sll" : null;
      if (kind === null || (shiftGroup === 8 && kind === "sra")) refuse();
      bigToBuffer(packedShift128(xmmBig(target), count, shiftGroup, kind)).copy(target);
      return;
    }
    refuse();
  }

  // Bounded x87 subset (BPTK-009): 64-bit precision load, store, integer
  // conversion, arithmetic, compare, and control-word service. Every other
  // x87 opcode is a structured unsupported stop.
  function executeX87(opcode, repeatPrefix) {
    if (repeatPrefix !== null) throw new RuntimeFault("unsupported_opcode", "Repeat prefix on x87 is outside the bounded probe", { opcode });
    if (opcode === 0xdf && peekModrm() === 0xe0) {
      // FNSTSW AX: the status word moves to AX; the E0 operand byte is
      // consumed by the decode below through the peek-and-fetch form.
      fetchByte();
      setRegister(registerIndex.eax, fpuStatusWord(fpu) & 0xffff, 2);
      return;
    }
    if (opcode === 0xdb && peekModrm() === 0xe2) {
      // FNCLEX: clear the pending x87 exception flags (bits 0-7) and the busy
      // bit (15), leaving the condition-code and top-of-stack field intact.
      fetchByte();
      fpu.status_word &= ~0x80ff;
      return;
    }
    if (opcode === 0xdb && peekModrm() === 0xe3) {
      // FNINIT: reinitialize the x87 unit to its power-on state — default
      // control word, cleared status, empty stack. The CRT floating-point
      // startup issues this before it touches the coprocessor.
      fetchByte();
      fpu.control_word = 0x037f;
      fpu.status_word = 0;
      fpu.top = 0;
      fpu.valid.fill(0);
      return;
    }
    const decoded = decodeModrm(4);
    const isDc = opcode === 0xdc || opcode === 0xde;
    const isD9 = opcode === 0xd9;
    const isDd = opcode === 0xdd;
    const isDb = opcode === 0xdb;
    const isDf = opcode === 0xdf;
    const isD8 = opcode === 0xd8;
    if (isD9 && decoded.mode === 3) {
      const form = (decoded.reg << 3) | decoded.rm;
      if (form !== 0x20 && form !== 0x21 && form !== 0x24 && form !== 0x08 && form !== 0x2e) {
        throw new RuntimeFault("unsupported_opcode", `Unsupported x87 register opcode 0xd9 0x${((0xc0 | (decoded.reg << 3) | decoded.rm) & 0xff).toString(16)}`, { opcode: 0xd900 | ((decoded.reg << 3) | decoded.rm) });
      }
      const st = fpuTop(fpu);
      if (form === 0x20) fpu.stack[fpu.top] = -st; // FCHS
      else if (form === 0x21) fpu.stack[fpu.top] = Math.abs(st); // FABS
      else if (form === 0x24) fpuSetCompareFlag(fpu, st); // FTST
      else if (form === 0x08) fpuPush(fpu, 1); // FLD1
      else if (form === 0x2e) fpuPush(fpu, 0); // FLDZ
      return;
    }
    if (isD9 && decoded.mode !== 3 && decoded.reg === 0) { fpuPush(fpu, readFloatMemory(decoded.address)); return; } // FLD m32
    if (isD9 && decoded.mode !== 3 && decoded.reg === 2) { writeFloatMemory(decoded.address, fpuTop(fpu)); return; } // FST m32
    if (isD9 && decoded.mode !== 3 && decoded.reg === 3) { writeFloatMemory(decoded.address, fpuPop(fpu)); return; } // FSTP m32
    if (isD9 && decoded.mode !== 3 && decoded.reg === 5) { fpu.control_word = readMemory(decoded.address, 2) | 0x0300; return; } // FLDCW (precision mode stays declared)
    if (isD9 && decoded.mode !== 3 && decoded.reg === 7) { writeMemory(decoded.address, 2, fpu.control_word & 0xffff); return; } // FNSTCW
    if (isDd && decoded.mode !== 3 && decoded.reg === 0) { fpuPush(fpu, readDoubleMemory(decoded.address)); return; } // FLD m64
    if (isDd && decoded.mode !== 3 && decoded.reg === 2) { writeDoubleMemory(decoded.address, fpuTop(fpu)); return; } // FST m64
    if (isDd && decoded.mode !== 3 && decoded.reg === 3) { writeDoubleMemory(decoded.address, fpuPop(fpu)); return; } // FSTP m64
    if (isDd && decoded.mode !== 3 && decoded.reg === 7) { writeMemory(decoded.address, 2, fpuStatusWord(fpu) & 0xffff); return; } // FNSTSW m16
    if (isDb && decoded.mode !== 3 && decoded.reg === 0) { fpuPush(fpu, readMemory(decoded.address, 4) | 0); return; } // FILD m32
    if (isDb && decoded.mode !== 3 && decoded.reg === 3) { writeMemory(decoded.address, 4, Math.trunc(fpuPop(fpu)) | 0); return; } // FISTP m32
    if (isDf && decoded.mode !== 3 && decoded.reg === 5) { fpuPush(fpu, Number(readInt64Memory(decoded.address))); return; } // FILD m64
    if (isDf && decoded.mode !== 3 && decoded.reg === 7) { writeInt64Memory(decoded.address, BigInt(Math.trunc(fpuPop(fpu)))); return; } // FISTP m64
    if (opcode === 0xde && decoded.mode === 3) {
      // FADDP/FMULP/FSUBP/FSUBRP/FDIVP/FDIVRP st(i), st(0): register-form
      // arithmetic whose result lands in st(i) with one pop.
      const operation = { 0: "add", 1: "mul", 4: "subr", 5: "sub", 6: "divr", 7: "div" }[decoded.reg];
      if (operation === undefined) throw new RuntimeFault("unsupported_opcode", `Unsupported x87 opcode 0xde /${decoded.reg}`, { opcode: 0xde00 | decoded.reg });
      const targetIndex = (fpu.top + decoded.rm) & 7;
      const top0 = fpuTop(fpu);
      if (!fpu.valid[targetIndex]) throw new RuntimeFault("x87_stack_fault", "FPU stack underflow", {});
      const map = { add: fpu.stack[targetIndex] + top0, mul: fpu.stack[targetIndex] * top0, sub: fpu.stack[targetIndex] - top0, subr: top0 - fpu.stack[targetIndex], div: fpu.stack[targetIndex] / top0, divr: top0 / fpu.stack[targetIndex] };
      fpu.stack[targetIndex] = map[operation];
      fpuPop(fpu);
      return;
    }
    if ((isD8 || isDc) && decoded.mode !== 3) {
      const operand = isD8 ? readFloatMemory(decoded.address) : readDoubleMemory(decoded.address);
      const st = fpuTop(fpu);
      const map = { 0: st + operand, 1: st * operand, 4: st - operand, 5: operand - st, 6: st / operand, 7: operand / st };
      if (decoded.reg === 2 || decoded.reg === 3) {
        fpuSetCompareFlag(fpu, st - operand);
        if (decoded.reg === 3) fpuPop(fpu);
        return;
      }
      if (map[decoded.reg] === undefined) throw new RuntimeFault("unsupported_opcode", `Unsupported x87 arithmetic group /${decoded.reg}`, { opcode: (opcode << 8) | decoded.reg });
      fpu.stack[fpu.top] = map[decoded.reg];
      return;
    }
    throw new RuntimeFault("unsupported_opcode", `Unsupported x87 opcode 0x${opcode.toString(16).padStart(2, "0")} /${decoded.reg}`, { opcode });
  }

  // Process startup phases (BPTK-010): every TLS callback fires before the
  // entry point, each as its own bounded phase over the shared instruction
  // budget. A callback returns to the sentinel exactly like the entry, so
  // one return check drives the whole sequence.
  const phaseAddress = report.tls_callback.map((callback) => callback.address);
  phaseAddress.push(report.entry_address >>> 0);
  let phaseIndex = 0;

  function advancePhase() {
    phaseIndex += 1;
    if (phaseIndex >= phaseAddress.length) {
      stopReason = "entry_return";
      return;
    }
    registerValue[registerIndex.esp] = initialStackPointer;
    if (phaseIndex < report.tls_callback.length) {
      push(0);
      push(1);
      push(0);
    }
    push(returnSentinel);
    instructionPointer = phaseAddress[phaseIndex];
  }

  try {
    instructionPointer = phaseAddress[0];
    if (report.tls_callback.length > 0) {
      push(0);
      push(1);
      push(0);
    }
    push(returnSentinel);
  } catch (fault) {
    stopReason = fault instanceof RuntimeFault ? fault.code : "memory_fault";
    exception = faultValue(fault instanceof RuntimeFault ? fault : new RuntimeFault("memory_fault", String(fault)));
  }

  while (stopReason === null && instructionCount < instructionBudgetCount) {
    const startPointer = instructionPointer;
    const registerUndo = new Uint32Array(registerValue);
    const flagUndo = { ...flag };
    memoryUndo = [];
    instructionByte = [];
    let opcode;
    try {
      opcode = fetchByte();
      instructionCount += 1;
      let operandSizeByte = 4;
      let repeatPrefix = null;
      segmentBaseValue = 0;
      while (opcode === 0x66 || opcode === 0x67 || opcode === 0xf0 || opcode === 0xf2 || opcode === 0xf3 || opcode === 0x26 || opcode === 0x2e || opcode === 0x36 || opcode === 0x3e || opcode === 0x64 || opcode === 0x65) {
        // The operand-size override (0x66) selects the 16-bit operand form of
        // the next instruction. The flat Windows model gives cs, ds, es, and
        // ss a base of zero, so their override byte is the identity there;
        // lock is the identity on the bounded single-guest model because one
        // in-order interpreter serializes every access. The address-size
        // override and the fs/gs overrides (no declared thread-environment
        // block) stay structured stops, never silent identity.
        if (opcode === 0x66) operandSizeByte = 2;
        else if (opcode === 0x67) throw new RuntimeFault("unsupported_opcode", "Address-size override is outside the bounded 32-bit probe", { opcode });
        else if (opcode === 0x64 || opcode === 0x65) {
          // fs resolves against the mapped TEB, gs against a zero base (the
          // flat user-mode model). With no thread-environment block declared
          // there is nothing to describe, so the override stays a structured
          // refusal — the bare CPU-conformance probe keeps that behavior.
          if (teb === null) throw new RuntimeFault("unsupported_opcode", `The ${opcode === 0x64 ? "fs" : "gs"} segment override requires a declared thread-environment block the bounded probe does not map`, { opcode });
          segmentBaseValue = opcode === 0x64 ? fsBase : gsBase;
        }
        else if (opcode === 0xf2 || opcode === 0xf3) repeatPrefix = opcode;
        opcode = fetchByte();
      }
      executeInstruction(opcode, operandSizeByte, repeatPrefix);
    } catch (fault) {
      const currentFault = fault instanceof RuntimeFault ? fault : new RuntimeFault("runtime_fault", fault instanceof Error ? fault.message : String(fault));
      registerValue.set(registerUndo);
      Object.assign(flag, flagUndo);
      instructionPointer = startPointer;
      for (let index = memoryUndo.length - 1; index >= 0; index -= 1) {
        const undo = memoryUndo[index];
        undo.target.set(undo.value, undo.offset);
      }
      stopReason = currentFault.code;
      exception = faultValue(currentFault);
      exception.instruction_address = startPointer >>> 0;
      exception.eip = startPointer >>> 0;
    } finally {
      const traceValue = Buffer.alloc(4 + instructionByte.length);
      traceValue.writeUInt32LE(startPointer >>> 0, 0);
      Buffer.from(instructionByte).copy(traceValue, 4);
      traceHash.update(traceValue);
      instructionByte = null;
      memoryUndo = null;
    }
  }

  if (stopReason === null && instructionCount >= instructionBudgetCount) stopReason = "instruction_budget_exhausted";
  const memory = Buffer.concat([image, stack]);
  const eflagsValue = flagValue(flag);
  const register = createRegisterReport(registerValue, instructionPointer);
  const flagReport = createFlagReport(flag, eflagsValue);
  const hleReport = hleGuest === null ? null : {
    profile: hleProfile.profile,
    served_export_count: listWin32HleExport().length,
    call_count: hleGuest.call_count,
    trace: hleGuest.trace_record.slice(0, 256),
    trace_truncated: hleGuest.call_count > 256,
    trace_sha256: hleGuest.trace_sha256,
    output_byte_count: hleGuest.takeOutput().length,
    output_sha256: sha256(hleGuest.takeOutput()),
  };
  return {
    state: "probe_executed",
    execution_profile: "i386_probe_v1",
    clock: clock.describe(),
    register,
    mm: Array.from(mm, (value) => `0x${value.toString(16).padStart(16, "0")}`),
    xmm: xmm.map((value) => `0x${value.toString("hex")}`),
    flag: flagReport,
    exception,
    exit_code: exception?.exit_code ?? null,
    hle: hleReport,
    thread: teb === null ? null : { teb_base: teb.teb_base, peb_base: teb.peb_base, fs_base: teb.fs_base, stack_base: stackEnd >>> 0, stack_limit: stackBase >>> 0 },
    instruction_count: instructionCount,
    trace_sha256: traceHash.digest("hex"),
    memory_sha256: sha256(memory),
    stop_reason: stopReason,
    is_executed: instructionCount > 0 || stopReason === "entry_return",
    runtime_blocker: hleGuest === null ? [] : ["The Win32 core HLE serves process, module, heap, virtual memory, time, synchronization, TLS, and COM startup only; file, console input, network, and device service do not exist"],
    blocker: report.resolution_blocker,
  };
}

export function refuseI386Execution(mapped, reason, message) {
  const { report, image } = mapped;
  return {
    state: "probe_blocked",
    execution_profile: "i386_probe_v1",
    register: null,
    flag: null,
    exception: { code: reason, type: reason, message },
    instruction_count: 0,
    trace_sha256: sha256(Buffer.alloc(0)),
    memory_sha256: sha256(image),
    stop_reason: reason,
    is_executed: false,
    runtime_blocker: [message],
    blocker: [...report.resolution_blocker, message],
  };
}

export { executeProbe, chooseStackBase, normalizeStackSize, RuntimeFault };
