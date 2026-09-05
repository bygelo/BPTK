// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The static x86-PE→WASM recompiler (BPTK-046 / GS-001): the moat. Ahead of
// time it decodes a mapped PE32 `.text` from the entry point, recovers the
// control-flow graph into basic blocks, and lowers each block to real
// WebAssembly that runs on the same bounded 32-bit guest state the
// interpreter oracle (`executeProbe` in lib/runtime.mjs) exposes — eight GPRs,
// EIP, the six arithmetic flags, and an image+stack linear memory laid out so
// the final `memory_sha256` and per-instruction `trace_sha256` are bit-exact
// against the oracle across the trace.
//
// This is not a faster interpreter and it is not a threaded dispatch: every
// guest basic block becomes straight-line WebAssembly, and the only runtime
// dispatch is the `br_table` that selects the next block. The hot path carries
// NO silent interpreter fallback — an opcode outside the recompiled subset, or
// an unresolved indirect branch, is a hard structured refusal (never quietly
// handed to the interpreter). Breadth grows by adding lowerings here, each of
// which must stay differential-tested bit-exact against the oracle.
//
// The subset lowered here is the register-and-stack 32-bit integer core that a
// CPU-bound workload exercises: mov (immediate and register), the full ALU
// space (add/or/adc/sbb/and/sub/xor/cmp) in register and immediate forms,
// inc/dec, push/pop, test, the conditional and unconditional direct branches,
// and ret to the process return sentinel. Memory operands, wider/narrower
// operand sizes, x87/MMX/SSE, and indirect control flow are declared out of
// this spike and refuse rather than guess.

import { mapPe32ForRuntime } from "./pe.mjs";

// ---------------------------------------------------------------------------
// Guest-state layout inside the emitted module.
//
// WASM globals (all mutable i32, zero-initialised): the eight GPRs in the
// canonical index order, EIP, the six arithmetic flags as 0/1, the executed
// instruction count, the trace write cursor, and the structured stop code.
const G = Object.freeze({
  eax: 0, ecx: 1, edx: 2, ebx: 3, esp: 4, ebp: 5, esi: 6, edi: 7,
  eip: 8,
  cf: 9, pf: 10, af: 11, zf: 12, sf: 13, of: 14,
  count: 15, tracePtr: 16, stop: 17,
});
const GLOBAL_COUNT = 18;
const REGISTER_NAME = Object.freeze(["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]);
const FLAG_MASK = Object.freeze({ carry: 1, parity: 4, adjust: 0x10, zero: 0x40, sign: 0x80, direction: 0x400, overflow: 0x800 });

// The structured stop codes the emitted module reports through the stop global.
const STOP = Object.freeze({ none: 0, entry_return: 1, instruction_budget_exhausted: 2, indirect_branch_unresolved: 3 });
const STOP_NAME = Object.freeze({ 1: "entry_return", 2: "instruction_budget_exhausted", 3: "indirect_branch_unresolved" });

// The bounded stack model, byte-identical to lib/runtime.mjs so the shared
// memory image hashes the same. Keep these in lockstep with runtime.mjs.
const STACK_PAGE_BYTE = 0x1000;
const MAX_STACK_BYTE = 16 * 1024 * 1024;
const STACK_BASE_CANDIDATE = [0x70000000, 0x60000000, 0x50000000, 0x40000000, 0x30000000];
const RETURN_SENTINEL_CANDIDATE = [0xfffff000, 0x20000000, 0x10000000, 0x80000000, 0x90000000];
const WASM_PAGE_BYTE = 65536;

function normalizeStackSize(value) {
  const reserveByte = Number.isSafeInteger(value) && value > 0 ? value : 0x10000;
  return Math.max(STACK_PAGE_BYTE, Math.min(MAX_STACK_BYTE, Math.ceil(reserveByte / STACK_PAGE_BYTE) * STACK_PAGE_BYTE));
}

function chooseStackBase(imageStart, imageEnd, stackSizeByte) {
  for (const base of STACK_BASE_CANDIDATE) {
    const end = base + stackSizeByte;
    if (end <= 0x100000000 && (end <= imageStart || base >= imageEnd)) return base;
  }
  return null;
}

function chooseReturnSentinel(imageStart, imageEnd, stackBase, stackEnd) {
  for (const candidate of RETURN_SENTINEL_CANDIDATE) {
    const isImage = candidate >= imageStart && candidate < imageEnd;
    const isStack = candidate >= stackBase && candidate < stackEnd;
    if (!isImage && !isStack) return candidate;
  }
  return null;
}

// ---------------------------------------------------------------------------
// WebAssembly binary encoder — the minimum needed to emit one module: LEB128,
// sections, and the opcode helpers the lowering uses.

function unsignedLeb(value) {
  const out = [];
  let n = value >>> 0;
  do {
    let byte = n & 0x7f;
    n >>>= 7;
    if (n !== 0) byte |= 0x80;
    out.push(byte);
  } while (n !== 0);
  return out;
}

function signedLeb(value) {
  const out = [];
  let n = value | 0;
  let more = true;
  while (more) {
    let byte = n & 0x7f;
    n >>= 7;
    if ((n === 0 && (byte & 0x40) === 0) || (n === -1 && (byte & 0x40) !== 0)) more = false;
    else byte |= 0x80;
    out.push(byte);
  }
  return out;
}

function signedLeb64(value) {
  const out = [];
  let n = BigInt.asIntN(64, BigInt(value));
  let more = true;
  while (more) {
    let byte = Number(n & 0x7fn);
    n >>= 7n;
    if ((n === 0n && (byte & 0x40) === 0) || (n === -1n && (byte & 0x40) !== 0)) more = false;
    else byte |= 0x80;
    out.push(byte);
  }
  return out;
}

function section(id, payload) {
  return [id, ...unsignedLeb(payload.length), ...payload];
}

function vec(items) {
  return [...unsignedLeb(items.length), ...items.flat()];
}

// Opcode fragments. Each helper returns a byte array; the lowering concatenates
// them into the code body. Stack discipline follows the WebAssembly spec.
const op = {
  gGet: (i) => [0x23, ...unsignedLeb(i)],
  gSet: (i) => [0x24, ...unsignedLeb(i)],
  lGet: (i) => [0x20, ...unsignedLeb(i)],
  lSet: (i) => [0x21, ...unsignedLeb(i)],
  i32: (n) => [0x41, ...signedLeb(n)],
  i64: (n) => [0x42, ...signedLeb64(n)],
  add: [0x6a], sub: [0x6b], mul: [0x6c],
  and: [0x71], or: [0x72], xor: [0x73],
  shl: [0x74], shrU: [0x76], popcnt: [0x69],
  eqz: [0x45], eq: [0x46], ne: [0x47], geU: [0x4f],
  i64ExtU: [0xad], i64Add: [0x7c], i64GtU: [0x56], i64LtU: [0x54],
  call: (i) => [0x10, ...unsignedLeb(i)],
  select: [0x1b],
  br: (d) => [0x0c, ...unsignedLeb(d)],
  brIf: (d) => [0x0d, ...unsignedLeb(d)],
  load32: [0x28, 0x02, 0x00],
  store32: [0x36, 0x02, 0x00],
  blockVoid: [0x02, 0x40],
  loopVoid: [0x03, 0x40],
  ifVoid: [0x04, 0x40],
  end: [0x0b],
  unreachable: [0x00],
};

// ---------------------------------------------------------------------------
// Static decoder for the recompiled subset. Returns a per-instruction record
// or a structured refusal; never guesses an undecoded form.

class RecompileRefuse {
  constructor(code, message, detail = {}) {
    this.code = code;
    this.message = message;
    this.detail = detail;
  }
}

// The dword two-operand ALU space this spike lowers (register-direct forms).
const ALU_RR_OPCODE = new Set([
  0x01, 0x03, 0x09, 0x0b, 0x11, 0x13, 0x19, 0x1b,
  0x21, 0x23, 0x29, 0x2b, 0x31, 0x33, 0x39, 0x3b,
]);
const ALU_EAX_IMM = new Map([
  [0x05, 0], [0x0d, 1], [0x15, 2], [0x1d, 3], [0x25, 4], [0x2d, 5], [0x35, 6], [0x3d, 7],
]);

// The optional decode cache (BPTK-048): a Map keyed by instruction address to
// its previously decoded record. When the bytes at an address are unchanged the
// cached decode is reused (an untouched block never re-decodes); when a code
// write has changed them the entry is invalidated and re-decoded. `stat`
// records which addresses were re-decoded versus reused.
function decodeSubset(image, imageStart, imageEnd, entryAddress, cache = null, stat = null) {
  const at = (addr) => {
    if (addr < imageStart || addr >= imageEnd) return null;
    return image[addr - imageStart];
  };
  const u32 = (addr) => {
    if (addr < imageStart || addr + 4 > imageEnd) return null;
    return image.readUInt32LE(addr - imageStart) >>> 0;
  };
  const s8 = (v) => (v << 24) >> 24;
  const s32 = (v) => v | 0;

  function decodeOne(addr) {
    const b0 = at(addr);
    if (b0 === null) return new RecompileRefuse("fetch_fault", `Instruction fetch at 0x${addr.toString(16)} is outside the mapped image`, { address: addr >>> 0 });
    const bytes = [b0];
    const rel8Target = (from) => (from + s8(at(addr + 1))) >>> 0;

    if (b0 === 0x90) return { addr, len: 1, bytes, kind: "nop" };
    if (b0 >= 0xb8 && b0 <= 0xbf) {
      const imm = u32(addr + 1);
      if (imm === null) return new RecompileRefuse("fetch_fault", "mov imm32 immediate is outside the mapped image", { address: addr >>> 0 });
      for (let i = 1; i <= 4; i += 1) bytes.push(at(addr + i));
      return { addr, len: 5, bytes, kind: "mov_imm", reg: b0 - 0xb8, imm };
    }
    if (b0 >= 0x40 && b0 <= 0x47) return { addr, len: 1, bytes, kind: "inc", reg: b0 - 0x40 };
    if (b0 >= 0x48 && b0 <= 0x4f) return { addr, len: 1, bytes, kind: "dec", reg: b0 - 0x48 };
    if (b0 >= 0x50 && b0 <= 0x57) return { addr, len: 1, bytes, kind: "push", reg: b0 - 0x50 };
    if (b0 >= 0x58 && b0 <= 0x5f) return { addr, len: 1, bytes, kind: "pop", reg: b0 - 0x58 };
    if (b0 >= 0x70 && b0 <= 0x7f) {
      const disp = at(addr + 1);
      if (disp === null) return new RecompileRefuse("fetch_fault", "jcc rel8 displacement is outside the mapped image", { address: addr >>> 0 });
      bytes.push(disp);
      return { addr, len: 2, bytes, kind: "jcc", cc: b0 & 0x0f, target: (addr + 2 + s8(disp)) >>> 0 };
    }
    if (b0 === 0xeb) {
      const disp = at(addr + 1);
      if (disp === null) return new RecompileRefuse("fetch_fault", "jmp rel8 displacement is outside the mapped image", { address: addr >>> 0 });
      bytes.push(disp);
      return { addr, len: 2, bytes, kind: "jmp", target: (addr + 2 + s8(disp)) >>> 0 };
    }
    if (b0 === 0xe9) {
      const disp = u32(addr + 1);
      if (disp === null) return new RecompileRefuse("fetch_fault", "jmp rel32 displacement is outside the mapped image", { address: addr >>> 0 });
      for (let i = 1; i <= 4; i += 1) bytes.push(at(addr + i));
      return { addr, len: 5, bytes, kind: "jmp", target: (addr + 5 + s32(disp)) >>> 0 };
    }
    if (b0 === 0xc3) return { addr, len: 1, bytes, kind: "ret" };
    if (b0 === 0x0f) {
      const b1 = at(addr + 1);
      if (b1 === null) return new RecompileRefuse("fetch_fault", "0x0f escape is outside the mapped image", { address: addr >>> 0 });
      if (b1 >= 0x80 && b1 <= 0x8f) {
        const disp = u32(addr + 2);
        if (disp === null) return new RecompileRefuse("fetch_fault", "jcc rel32 displacement is outside the mapped image", { address: addr >>> 0 });
        bytes.push(b1);
        for (let i = 2; i <= 5; i += 1) bytes.push(at(addr + i));
        return { addr, len: 6, bytes, kind: "jcc", cc: b1 & 0x0f, target: (addr + 6 + s32(disp)) >>> 0 };
      }
      return new RecompileRefuse("unsupported_opcode", `The two-byte opcode 0x0f 0x${b1.toString(16)} is outside the recompiled subset`, { opcode: (0x0f00 | b1) >>> 0, address: addr >>> 0 });
    }
    if (ALU_RR_OPCODE.has(b0)) {
      const modrm = at(addr + 1);
      if (modrm === null) return new RecompileRefuse("fetch_fault", "ALU ModRM is outside the mapped image", { address: addr >>> 0 });
      if (modrm >>> 6 !== 3) return new RecompileRefuse("unsupported_opcode", "Memory-operand ALU forms are outside the register-direct recompiled subset", { opcode: b0, address: addr >>> 0 });
      bytes.push(modrm);
      return { addr, len: 2, bytes, kind: "alu_rr", opIndex: (b0 >>> 3) & 7, toRegister: (b0 & 2) !== 0, reg: (modrm >>> 3) & 7, rm: modrm & 7 };
    }
    if (ALU_EAX_IMM.has(b0)) {
      const imm = u32(addr + 1);
      if (imm === null) return new RecompileRefuse("fetch_fault", "ALU eax,imm32 immediate is outside the mapped image", { address: addr >>> 0 });
      for (let i = 1; i <= 4; i += 1) bytes.push(at(addr + i));
      return { addr, len: 5, bytes, kind: "alu_imm", opIndex: ALU_EAX_IMM.get(b0), rm: G.eax, imm };
    }
    if (b0 === 0x81 || b0 === 0x83) {
      const modrm = at(addr + 1);
      if (modrm === null) return new RecompileRefuse("fetch_fault", "ALU group ModRM is outside the mapped image", { address: addr >>> 0 });
      if (modrm >>> 6 !== 3) return new RecompileRefuse("unsupported_opcode", "Memory-operand ALU group forms are outside the register-direct recompiled subset", { opcode: b0, address: addr >>> 0 });
      bytes.push(modrm);
      const rm = modrm & 7;
      const opIndex = (modrm >>> 3) & 7;
      if (b0 === 0x83) {
        const disp = at(addr + 2);
        if (disp === null) return new RecompileRefuse("fetch_fault", "ALU imm8 is outside the mapped image", { address: addr >>> 0 });
        bytes.push(disp);
        return { addr, len: 3, bytes, kind: "alu_imm", opIndex, rm, imm: s8(disp) >>> 0 };
      }
      const imm = u32(addr + 2);
      if (imm === null) return new RecompileRefuse("fetch_fault", "ALU imm32 is outside the mapped image", { address: addr >>> 0 });
      for (let i = 2; i <= 5; i += 1) bytes.push(at(addr + i));
      return { addr, len: 6, bytes, kind: "alu_imm", opIndex, rm, imm };
    }
    if (b0 === 0x89 || b0 === 0x8b) {
      const modrm = at(addr + 1);
      if (modrm === null) return new RecompileRefuse("fetch_fault", "mov ModRM is outside the mapped image", { address: addr >>> 0 });
      if (modrm >>> 6 !== 3) return new RecompileRefuse("unsupported_opcode", "Memory-operand mov forms are outside the register-direct recompiled subset", { opcode: b0, address: addr >>> 0 });
      bytes.push(modrm);
      return { addr, len: 2, bytes, kind: "mov_rr", toRegister: b0 === 0x8b, reg: (modrm >>> 3) & 7, rm: modrm & 7 };
    }
    if (b0 === 0x85) {
      const modrm = at(addr + 1);
      if (modrm === null) return new RecompileRefuse("fetch_fault", "test ModRM is outside the mapped image", { address: addr >>> 0 });
      if (modrm >>> 6 !== 3) return new RecompileRefuse("unsupported_opcode", "Memory-operand test forms are outside the register-direct recompiled subset", { opcode: b0, address: addr >>> 0 });
      bytes.push(modrm);
      return { addr, len: 2, bytes, kind: "test_rr", reg: (modrm >>> 3) & 7, rm: modrm & 7 };
    }
    if (b0 === 0xff) {
      const modrm = at(addr + 1);
      if (modrm === null) return new RecompileRefuse("fetch_fault", "0xff ModRM is outside the mapped image", { address: addr >>> 0 });
      const reg = (modrm >>> 3) & 7;
      const mode = modrm >>> 6;
      const rm = modrm & 7;
      if (reg === 2) return new RecompileRefuse("indirect_call_unsupported", "Indirect call recovery is a declared follow-up to indirect-jump recovery", { opcode: 0xff02, address: addr >>> 0 });
      if (reg !== 4) return new RecompileRefuse("unsupported_opcode", `The 0xff group operation ${reg} is outside the recompiled subset`, { opcode: 0xff00 | reg, address: addr >>> 0 });
      // jmp r/m32 — the switch/vtable dispatch this pass recovers.
      const ins = { addr, kind: "jmp_indirect", bytes: [b0, modrm] };
      if (mode === 3) { ins.len = 2; ins.ea = { register: true, reg: rm }; return ins; }
      let p = addr + 2;
      let base = rm, index = null, scale = 1, disp = 0;
      const pushByte = (v) => { if (v === null) return false; ins.bytes.push(v); return true; };
      if (rm === 4) {
        const sib = at(p);
        if (!pushByte(sib)) return new RecompileRefuse("fetch_fault", "SIB byte is outside the mapped image", { address: addr >>> 0 });
        p += 1;
        scale = 1 << (sib >>> 6);
        const sibIndex = (sib >>> 3) & 7;
        const sibBase = sib & 7;
        index = sibIndex === 4 ? null : sibIndex;
        if (mode === 0 && sibBase === 5) { base = null; disp = s32(u32(p)); for (let i = 0; i < 4; i += 1) pushByte(at(p + i)); p += 4; }
        else base = sibBase;
      } else if (mode === 0 && rm === 5) {
        base = null; disp = s32(u32(p)); for (let i = 0; i < 4; i += 1) pushByte(at(p + i)); p += 4;
      }
      if (mode === 1) { const d = at(p); if (!pushByte(d)) return new RecompileRefuse("fetch_fault", "disp8 is outside the mapped image", { address: addr >>> 0 }); disp += s8(d); p += 1; }
      else if (mode === 2) { disp = (disp + s32(u32(p))) | 0; for (let i = 0; i < 4; i += 1) pushByte(at(p + i)); p += 4; }
      ins.len = p - addr;
      ins.ea = { register: false, base, index, scale, disp: disp >>> 0 };
      // A `[disp32 + index*scale]` form with no base is a jump table: its base
      // address is a static pointer array into the image.
      ins.tableAddr = base === null && index !== null ? (disp >>> 0) : null;
      return ins;
    }
    return new RecompileRefuse("unsupported_opcode", `The opcode 0x${b0.toString(16)} is outside the recompiled subset`, { opcode: b0, address: addr >>> 0 });
  }

  const MAX_TABLE_ENTRY = 1024;
  const decoded = new Map();
  const entry = entryAddress >>> 0;
  const indirectLeader = new Set();
  const flaggedRegion = [];
  const work = [entry];
  // Recover a jump table: read code pointers from a static base address while
  // each entry lands in the executable image, stop at the first non-code dword
  // (the code-as-data boundary) and flag it, never a crash.
  function recoverTable(tableAddr) {
    const target = [];
    for (let k = 0; k < MAX_TABLE_ENTRY; k += 1) {
      const slot = (tableAddr + k * 4) >>> 0;
      const value = u32(slot);
      if (value === null) break;
      if (value < imageStart || value >= imageEnd) {
        flaggedRegion.push({ kind: "table_boundary", address: slot, value: value >>> 0 });
        break;
      }
      target.push(value >>> 0);
      indirectLeader.add(value >>> 0);
      work.push(value >>> 0);
    }
    return target;
  }
  while (work.length > 0) {
    let addr = work.pop();
    while (true) {
      if (decoded.has(addr)) break;
      let ins = null;
      const cached = cache ? cache.get(addr) : null;
      if (cached && cached.len && addr + cached.len <= imageEnd) {
        let same = true;
        for (let i = 0; i < cached.len; i += 1) { if (image[addr - imageStart + i] !== cached.bytes[i]) { same = false; break; } }
        if (same) { ins = cached; if (stat) stat.kept.push(addr >>> 0); }
      }
      if (ins === null) {
        ins = decodeOne(addr);
        if (ins instanceof RecompileRefuse) return { refuse: ins };
        if (cache) cache.set(addr, ins);
        if (stat) stat.reDecoded.push(addr >>> 0);
      }
      decoded.set(addr, ins);
      if (ins.kind === "ret") break;
      if (ins.kind === "jmp") { addr = ins.target; continue; }
      if (ins.kind === "jcc") { work.push(ins.target); addr = (addr + ins.len) >>> 0; continue; }
      if (ins.kind === "jmp_indirect") {
        if (ins.tableAddr !== null && ins.tableAddr !== undefined) ins.recoveredTarget = recoverTable(ins.tableAddr);
        break;
      }
      addr = (addr + ins.len) >>> 0;
    }
  }
  return { decoded, entry, indirectLeader, flaggedRegion };
}

// Recover basic blocks from the decoded instruction stream (GS-002 groundwork).
function recoverBlock(decoded, entry, indirectLeader = new Set()) {
  const leader = new Set([entry, ...indirectLeader]);
  for (const ins of decoded.values()) {
    if (ins.kind === "jcc") { leader.add(ins.target); leader.add((ins.addr + ins.len) >>> 0); }
    else if (ins.kind === "jmp") leader.add(ins.target);
  }
  const sorted = [...decoded.keys()].sort((a, b) => a - b);
  const block = [];
  let current = null;
  for (const addr of sorted) {
    const ins = decoded.get(addr);
    if (current === null || leader.has(addr) || current.end !== addr) {
      current = { start: addr, instruction: [], end: addr };
      block.push(current);
    }
    current.instruction.push(ins);
    current.end = (addr + ins.len) >>> 0;
    if (ins.kind === "jmp" || ins.kind === "jcc" || ins.kind === "ret" || ins.kind === "jmp_indirect") current = null;
  }
  const indexOf = new Map();
  block.forEach((entryBlock, index) => indexOf.set(entryBlock.start, index));
  // Resolve every successor to a block index; a target that lands mid-block is
  // a misaligned branch this spike refuses rather than mistranslate.
  for (const currentBlock of block) {
    const last = currentBlock.instruction[currentBlock.instruction.length - 1];
    if (last.kind === "ret") { currentBlock.successor = { kind: "halt" }; continue; }
    if (last.kind === "jmp_indirect") { currentBlock.successor = { kind: "indirect", ea: last.ea }; continue; }
    if (last.kind === "jmp") {
      if (!indexOf.has(last.target)) return { refuse: new RecompileRefuse("misaligned_branch_target", `jmp target 0x${last.target.toString(16)} is not a block boundary`, { address: last.target }) };
      currentBlock.successor = { kind: "jump", target: indexOf.get(last.target) };
      continue;
    }
    if (last.kind === "jcc") {
      const fall = (last.addr + last.len) >>> 0;
      if (!indexOf.has(last.target) || !indexOf.has(fall)) return { refuse: new RecompileRefuse("misaligned_branch_target", `jcc target 0x${last.target.toString(16)} or fallthrough is not a block boundary`, { address: last.target }) };
      currentBlock.successor = { kind: "branch", cc: last.cc, taken: indexOf.get(last.target), fall: indexOf.get(fall) };
      continue;
    }
    // Straight-line block split by a leader: fall through to the next block.
    if (!indexOf.has(currentBlock.end)) return { refuse: new RecompileRefuse("misaligned_branch_target", `fallthrough 0x${currentBlock.end.toString(16)} is not a block boundary`, { address: currentBlock.end }) };
    currentBlock.successor = { kind: "fall", target: indexOf.get(currentBlock.end) };
  }
  return { block, indexOf };
}

// ---------------------------------------------------------------------------
// Lowering: per-instruction and per-block WebAssembly emission.

// Local indices inside $run: param $budget=0, then scratch locals.
const L = Object.freeze({ budget: 0, block: 1, a: 2, b: 3, c: 4, savecf: 5, d: 6 });
// Function indices: helper functions then the exported $run.
const F = Object.freeze({ translate: 0, setAdd: 1, setSub: 2, setLogic: 3, run: 4 });

function conditionExpr(cc) {
  // Evaluate a Jcc condition from the flag globals; result is an i32 0/1,
  // matching conditionValue() in lib/runtime.mjs exactly.
  const g = (name) => op.gGet(G[name]);
  switch (cc & 0x0f) {
    case 0x0: return g("of");
    case 0x1: return [...g("of"), ...op.eqz];
    case 0x2: return g("cf");
    case 0x3: return [...g("cf"), ...op.eqz];
    case 0x4: return g("zf");
    case 0x5: return [...g("zf"), ...op.eqz];
    case 0x6: return [...g("cf"), ...g("zf"), ...op.or];
    case 0x7: return [...g("cf"), ...g("zf"), ...op.or, ...op.eqz];
    case 0x8: return g("sf");
    case 0x9: return [...g("sf"), ...op.eqz];
    case 0xa: return g("pf");
    case 0xb: return [...g("pf"), ...op.eqz];
    case 0xc: return [...g("sf"), ...g("of"), ...op.ne];
    case 0xd: return [...g("sf"), ...g("of"), ...op.eq];
    case 0xe: return [...g("zf"), ...g("sf"), ...g("of"), ...op.ne, ...op.or];
    case 0xf: return [...g("zf"), ...g("sf"), ...g("of"), ...op.ne, ...op.or, ...op.eqz];
    default: return op.i32(0);
  }
}

// Compute the ALU result value expression given left/right in locals a/b.
function aluResultExpr(opIndex) {
  switch (opIndex) {
    case 0: return [...op.lGet(L.a), ...op.lGet(L.b), ...op.add]; // add
    case 1: return [...op.lGet(L.a), ...op.lGet(L.b), ...op.or]; // or
    case 2: return [...op.lGet(L.a), ...op.lGet(L.b), ...op.add, ...op.gGet(G.cf), ...op.add]; // adc
    case 3: return [...op.lGet(L.a), ...op.lGet(L.b), ...op.sub, ...op.gGet(G.cf), ...op.sub]; // sbb
    case 4: return [...op.lGet(L.a), ...op.lGet(L.b), ...op.and]; // and
    case 5: return [...op.lGet(L.a), ...op.lGet(L.b), ...op.sub]; // sub
    case 6: return [...op.lGet(L.a), ...op.lGet(L.b), ...op.xor]; // xor
    case 7: return [...op.lGet(L.a), ...op.lGet(L.b), ...op.sub]; // cmp
    default: return op.i32(0);
  }
}

function aluFlagCall(opIndex) {
  // add/adc → setAdd(a,b,cin,res); sub/sbb/cmp → setSub(a,b,bin,res);
  // and/or/xor → setLogic(res). Carry-in is the current CF for adc/sbb.
  if (opIndex === 0 || opIndex === 2) {
    const cin = opIndex === 2 ? op.gGet(G.cf) : op.i32(0);
    return [...op.lGet(L.a), ...op.lGet(L.b), ...cin, ...op.lGet(L.c), ...op.call(F.setAdd)];
  }
  if (opIndex === 3 || opIndex === 5 || opIndex === 7) {
    const bin = opIndex === 3 ? op.gGet(G.cf) : op.i32(0);
    return [...op.lGet(L.a), ...op.lGet(L.b), ...bin, ...op.lGet(L.c), ...op.call(F.setSub)];
  }
  return [...op.lGet(L.c), ...op.call(F.setLogic)];
}

const ALU_WRITEBACK = (opIndex) => opIndex !== 7; // cmp (7) has no writeback.

function emitAlu(opIndex, leftExpr, rightExpr, writebackGlobal) {
  const body = [];
  body.push(...leftExpr, ...op.lSet(L.a));
  body.push(...rightExpr, ...op.lSet(L.b));
  body.push(...aluResultExpr(opIndex), ...op.lSet(L.c));
  body.push(...aluFlagCall(opIndex));
  if (ALU_WRITEBACK(opIndex) && writebackGlobal !== null) body.push(...op.lGet(L.c), ...op.gSet(writebackGlobal));
  return body;
}

function emitInstruction(ins, traceEnabled) {
  const body = [];
  // EIP tracks this instruction's address so a budget-exhaust or return
  // reports the byte-exact instruction pointer the oracle would.
  body.push(...op.i32(ins.addr), ...op.gSet(G.eip));
  // Budget guard, checked before the instruction runs (loop-condition parity).
  body.push(...op.gGet(G.count), ...op.lGet(L.budget), ...op.geU);
  body.push(...op.ifVoid);
  body.push(...op.i32(STOP.instruction_budget_exhausted), ...op.gSet(G.stop));
  body.push(...op.br(0)); // placeholder depth; patched by the block assembler.
  const budgetBrIndex = body.length - 1; // index of the last br byte's start
  body.push(...op.end);
  body.push(...op.gGet(G.count), ...op.i32(1), ...op.add, ...op.gSet(G.count));
  if (traceEnabled) body.push(...emitTrace(ins));

  switch (ins.kind) {
    case "nop":
      break;
    case "mov_imm":
      body.push(...op.i32(ins.imm | 0), ...op.gSet(ins.reg));
      break;
    case "mov_rr":
      if (ins.toRegister) body.push(...op.gGet(ins.rm), ...op.gSet(ins.reg));
      else body.push(...op.gGet(ins.reg), ...op.gSet(ins.rm));
      break;
    case "test_rr":
      body.push(...op.gGet(ins.rm), ...op.gGet(ins.reg), ...op.and, ...op.lSet(L.c));
      body.push(...op.lGet(L.c), ...op.call(F.setLogic));
      break;
    case "inc":
    case "dec": {
      const isInc = ins.kind === "inc";
      body.push(...op.gGet(ins.reg), ...op.lSet(L.a));
      body.push(...op.gGet(G.cf), ...op.lSet(L.savecf));
      body.push(...op.lGet(L.a), ...op.i32(1), ...(isInc ? op.add : op.sub), ...op.lSet(L.c));
      body.push(...op.lGet(L.a), ...op.i32(1), ...op.i32(0), ...op.lGet(L.c), ...op.call(isInc ? F.setAdd : F.setSub));
      body.push(...op.lGet(L.c), ...op.gSet(ins.reg));
      body.push(...op.lGet(L.savecf), ...op.gSet(G.cf)); // inc/dec preserve CF
      break;
    }
    case "push":
      body.push(...op.gGet(G.esp), ...op.i32(4), ...op.sub, ...op.gSet(G.esp));
      body.push(...op.gGet(G.esp), ...op.call(F.translate), ...op.gGet(ins.reg), ...op.store32);
      break;
    case "pop":
      body.push(...op.gGet(G.esp), ...op.call(F.translate), ...op.load32, ...op.gSet(ins.reg));
      body.push(...op.gGet(G.esp), ...op.i32(4), ...op.add, ...op.gSet(G.esp));
      break;
    case "alu_rr": {
      const left = ins.toRegister ? op.gGet(ins.reg) : op.gGet(ins.rm);
      const right = ins.toRegister ? op.gGet(ins.rm) : op.gGet(ins.reg);
      const writeback = ins.opIndex === 7 ? null : ins.toRegister ? ins.reg : ins.rm;
      body.push(...emitAlu(ins.opIndex, left, right, writeback));
      break;
    }
    case "alu_imm": {
      const writeback = ins.opIndex === 7 ? null : ins.rm;
      body.push(...emitAlu(ins.opIndex, op.gGet(ins.rm), op.i32(ins.imm | 0), writeback));
      break;
    }
    default:
      // Control-flow kinds (jmp/jcc/ret) are lowered by the block terminator.
      break;
  }
  return { body, budgetBrIndex };
}

function emitTrace(ins) {
  // Write [eip:u32le][instruction bytes] to the trace region, reproducing the
  // interpreter's running trace hash byte-for-byte.
  const body = [];
  const traceBaseExpr = () => [...op.gGet(G.tracePtr)];
  body.push(...traceBaseExpr(), ...op.i32(ins.addr), ...op.store32);
  body.push(...op.gGet(G.tracePtr), ...op.i32(4), ...op.add, ...op.gSet(G.tracePtr));
  for (const byte of ins.bytes) {
    body.push(...op.gGet(G.tracePtr), ...op.i32(byte), 0x3a, 0x00, 0x00); // i32.store8
    body.push(...op.gGet(G.tracePtr), ...op.i32(1), ...op.add, ...op.gSet(G.tracePtr));
  }
  return body;
}

// ---------------------------------------------------------------------------
// Module assembly.

export function recompileImage(mapped, option = {}) {
  const traceEnabled = option.trace !== false;
  const budgetHint = Number.isSafeInteger(option.budget) && option.budget > 0 ? option.budget : 4096;
  const { report, image } = mapped;
  const imageStart = report.load_base >>> 0;
  const imageLength = image.length;
  const imageEnd = (imageStart + imageLength) >>> 0;
  const stackSizeByte = normalizeStackSize(report.stack_reserve_byte);
  const stackBase = chooseStackBase(imageStart, imageEnd, stackSizeByte);
  if (stackBase === null) return { refuse: new RecompileRefuse("memory_fault", "No bounded stack range is available") };
  const stackEnd = stackBase + stackSizeByte;
  const returnSentinel = chooseReturnSentinel(imageStart, imageEnd, stackBase, stackEnd);
  if (returnSentinel === null) return { refuse: new RecompileRefuse("memory_fault", "No reserved return sentinel is available") };
  if (report.tls_callback && report.tls_callback.length > 0) {
    return { refuse: new RecompileRefuse("unsupported_startup", "TLS-callback startup phases are outside the recompiled entry spike", {}) };
  }

  const decodeResult = decodeSubset(image, imageStart, imageEnd, report.entry_address >>> 0, option.cache ?? null, option.decodeStat ?? null);
  if (decodeResult.refuse) return { refuse: decodeResult.refuse };
  const blockResult = recoverBlock(decodeResult.decoded, decodeResult.entry, decodeResult.indirectLeader);
  if (blockResult.refuse) return { refuse: blockResult.refuse };
  const { block, indexOf } = blockResult;
  const blockCount = block.length;
  const entryBlockIndex = indexOf.get(decodeResult.entry);

  // memory_sha256 covers [0, imageLength + stackSizeByte); the trace region
  // sits beyond it so it never perturbs the hashed image.
  const dataRegionByte = imageLength + stackSizeByte;
  const traceBase = dataRegionByte;
  const traceReserveByte = traceEnabled ? budgetHint * 16 + 256 : 0;
  const memoryByte = dataRegionByte + traceReserveByte;
  const memoryPage = Math.ceil(memoryByte / WASM_PAGE_BYTE) + 1;

  const translate = (addr) => (addr - imageStart) >>> 0; // image offset
  const stackOffset = (addr) => (imageLength + (addr - stackBase)) >>> 0;

  // Segment (seg[x]) body for each block: straight-line instructions then the
  // terminator, computing the next block index and branching to $loop, or
  // halting to $exit. Depth of $loop/$exit from seg[x] is fixed by nesting.
  function emitBlock(index, loopDepth, exitDepth) {
    const body = [];
    const currentBlock = block[index];
    for (const ins of currentBlock.instruction) {
      const emitted = emitInstruction(ins, traceEnabled);
      // Patch the budget-exhaust br to reach $exit through the surrounding
      // `if` (which adds one nesting level) at this block's depth.
      patchBudgetBr(emitted, exitDepth + 1);
      body.push(...emitted.body);
    }
    const successor = currentBlock.successor;
    if (successor.kind === "halt") {
      // ret: pop the return address into EIP, report entry_return, leave.
      body.push(...op.gGet(G.esp), ...op.call(F.translate), ...op.load32, ...op.gSet(G.eip));
      body.push(...op.gGet(G.esp), ...op.i32(4), ...op.add, ...op.gSet(G.esp));
      body.push(...op.i32(STOP.entry_return), ...op.gSet(G.stop));
      body.push(...op.br(exitDepth));
    } else if (successor.kind === "indirect") {
      // Read the branch target at runtime, match it against every recovered
      // code leader, and dispatch — or declare an unresolved fallback. This is
      // faithful for switch tables and vtable dispatch alike: whatever pointer
      // the guest computes, if it names a recovered block we jump there.
      const ea = successor.ea;
      if (ea.register) body.push(...op.gGet(ea.reg), ...op.lSet(L.a));
      else {
        const addrExpr = [];
        addrExpr.push(...(ea.base !== null && ea.base !== undefined ? op.gGet(ea.base) : op.i32(0)));
        if (ea.index !== null && ea.index !== undefined) addrExpr.push(...op.gGet(ea.index), ...op.i32(ea.scale), ...op.mul, ...op.add);
        addrExpr.push(...op.i32(ea.disp | 0), ...op.add);
        body.push(...addrExpr, ...op.call(F.translate), ...op.load32, ...op.lSet(L.a));
      }
      body.push(...op.i32(0), ...op.lSet(L.c)); // block accumulator
      body.push(...op.i32(0), ...op.lSet(L.d)); // found flag
      for (const [leaderAddr, blockIdx] of indexOf) {
        const match = [...op.lGet(L.a), ...op.i32(leaderAddr | 0), ...op.eq];
        body.push(...op.i32(blockIdx), ...op.lGet(L.c), ...match, ...op.select, ...op.lSet(L.c));
        body.push(...op.lGet(L.d), ...match, ...op.or, ...op.lSet(L.d));
      }
      body.push(...op.lGet(L.c), ...op.lSet(L.block));
      body.push(...op.lGet(L.d), ...op.brIf(loopDepth));
      body.push(...op.i32(STOP.indirect_branch_unresolved), ...op.gSet(G.stop), ...op.br(exitDepth));
    } else if (successor.kind === "jump" || successor.kind === "fall") {
      body.push(...op.i32(successor.target), ...op.lSet(L.block));
      body.push(...op.br(loopDepth));
    } else {
      // branch: block = cond ? taken : fall; select(taken, fall, cond).
      body.push(...op.i32(successor.taken), ...op.i32(successor.fall), ...conditionExpr(successor.cc), ...op.select, ...op.lSet(L.block));
      body.push(...op.br(loopDepth));
    }
    return body;
  }

  // Prologue: initialise ESP, push the return sentinel, select the entry block.
  const prologue = [];
  prologue.push(...op.i32((stackEnd - 4) | 0), ...op.gSet(G.esp));
  prologue.push(...op.gGet(G.esp), ...op.i32(4), ...op.sub, ...op.gSet(G.esp));
  prologue.push(...op.gGet(G.esp), ...op.call(F.translate), ...op.i32(returnSentinel | 0), ...op.store32);
  if (traceEnabled) prologue.push(...op.i32(traceBase), ...op.gSet(G.tracePtr));
  prologue.push(...op.i32(entryBlockIndex), ...op.lSet(L.block));

  // The dispatch nest: block $exit { loop $loop { block*N { br_table } seg* } }
  const runBody = [];
  runBody.push(...prologue);
  runBody.push(...op.blockVoid); // $exit
  runBody.push(...op.loopVoid); // $loop
  for (let i = 0; i < blockCount; i += 1) runBody.push(...op.blockVoid); // B{N-1}..B0
  // br_table over $block: index i → depth i (block Bi), default → $exit.
  runBody.push(...op.lGet(L.block));
  runBody.push(0x0e, ...unsignedLeb(blockCount));
  for (let i = 0; i < blockCount; i += 1) runBody.push(...unsignedLeb(i));
  runBody.push(...unsignedLeb(blockCount + 1)); // default → $exit
  for (let x = 0; x < blockCount; x += 1) {
    runBody.push(...op.end); // close block Bx
    const loopDepth = blockCount - 1 - x;
    const exitDepth = blockCount - x;
    runBody.push(...emitBlock(x, loopDepth, exitDepth));
  }
  runBody.push(...op.end); // close $loop
  runBody.push(...op.end); // close $exit
  runBody.push(...op.end); // close function

  const wasm = assembleModule({
    runBody,
    memoryPage,
    imageStart,
    imageEnd,
    imageLength,
    stackBase,
    stackEnd,
    image,
  });

  return {
    wasm,
    block,
    instructionCount: decodeResult.decoded.size,
    blockCount,
    entryBlockIndex,
    fallbackCount: 0,
    flaggedRegion: decodeResult.flaggedRegion ?? [],
    indirectLeaderCount: decodeResult.indirectLeader ? decodeResult.indirectLeader.size : 0,
    traceBase,
    dataRegionByte,
    layout: { imageStart, imageEnd, imageLength, stackBase, stackEnd, stackSizeByte, returnSentinel },
    translate,
    stackOffset,
    refuse: null,
  };
}

// Patch the budget-exhaust branch depth once the block nesting is known.
function patchBudgetBr(emitted, depth) {
  // emitted.budgetBrIndex points at the first byte after 0x0c (the depth LEB).
  // We re-encode a single-byte LEB for the depth (depths here fit in 7 bits for
  // the block counts this spike targets).
  const bytes = emitted.body;
  const brByte = emitted.budgetBrIndex - 1;
  // Replace [0x0c, 0x00] placeholder with [0x0c, ...uleb(depth)].
  const encoded = unsignedLeb(depth);
  bytes.splice(brByte, 2, 0x0c, ...encoded);
}

function assembleModule(spec) {
  const { runBody, memoryPage, imageStart, imageEnd, imageLength, stackBase, stackEnd, image } = spec;

  // Types: t0 (i32)->i32; t1 (i32,i32,i32,i32)->(); t2 (i32)->().
  const types = section(0x01, vec([
    [0x60, ...vec([[0x7f]]), ...vec([[0x7f]])],
    [0x60, ...vec([[0x7f], [0x7f], [0x7f], [0x7f]]), 0x00],
    [0x60, ...vec([[0x7f]]), 0x00],
  ]));
  // Functions: translate=t0, setAdd=t1, setSub=t1, setLogic=t2, run=t2.
  const functions = section(0x03, vec([[0x00], [0x01], [0x01], [0x02], [0x02]]));
  // Memory: one memory with a fixed minimum page count.
  const memory = section(0x05, vec([[0x00, ...unsignedLeb(memoryPage)]]));
  // Globals: GLOBAL_COUNT mutable i32, zero-initialised.
  const globalEntry = [];
  for (let i = 0; i < GLOBAL_COUNT; i += 1) globalEntry.push([0x7f, 0x01, ...op.i32(0), ...op.end]);
  const globals = section(0x06, vec(globalEntry));
  // Exports: memory, run, and every global by name.
  const exportEntry = [
    [...vec([..."memory"].map((c) => c.charCodeAt(0))), 0x02, 0x00],
    [...vec([..."run"].map((c) => c.charCodeAt(0))), 0x00, ...unsignedLeb(F.run)],
  ];
  const exportName = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip", "cf", "pf", "af", "zf", "sf", "of", "count", "tracePtr", "stop"];
  exportName.forEach((name, index) => {
    exportEntry.push([...vec([...name].map((c) => c.charCodeAt(0))), 0x03, ...unsignedLeb(index)]);
  });
  const exports = section(0x07, vec(exportEntry));

  const code = section(0x0a, vec([
    functionBody(translateBody(imageStart, imageEnd, imageLength, stackBase, stackEnd), []),
    functionBody(setAddBody(), []),
    functionBody(setSubBody(), []),
    functionBody(setLogicBody(), []),
    functionBody(runBody, [[6, 0x7f]]), // 6 i32 locals ($block,$a,$b,$c,$savecf + one spare)
  ]));

  // Data: the mapped image bytes at memory offset 0 (active segment).
  const data = section(0x0b, vec([
    [0x00, ...op.i32(0), ...op.end, ...unsignedLeb(image.length), ...image],
  ]));

  const header = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
  return Uint8Array.from([...header, ...types, ...functions, ...memory, ...globals, ...exports, ...code, ...data]);
}

function functionBody(body, locals) {
  const localVec = vec(locals.map(([count, type]) => [...unsignedLeb(count), type]));
  const payload = [...localVec, ...body];
  return [...unsignedLeb(payload.length), ...payload];
}

// $translate(addr) → linear memory offset, trapping outside the mapped image
// and bounded stack, exactly like checkRange() in lib/runtime.mjs.
function translateBody(imageStart, imageEnd, imageLength, stackBase, stackEnd) {
  const a = [0x20, 0x00]; // local.get 0
  return [
    // if (addr >= imageStart && addr < imageEnd) return addr - imageStart
    ...a, ...op.i32(imageStart | 0), 0x4f, // ge_u
    ...a, ...op.i32(imageEnd | 0), 0x49, // lt_u
    ...op.and,
    0x04, 0x7f, // if (result i32)
    ...a, ...op.i32(imageStart | 0), ...op.sub,
    0x05, // else
    ...a, ...op.i32(stackBase | 0), 0x4f,
    ...a, ...op.i32(stackEnd | 0), 0x49,
    ...op.and,
    0x04, 0x7f, // if (result i32)
    ...op.i32(imageLength), ...a, ...op.i32(stackBase | 0), ...op.sub, ...op.add,
    0x05, // else
    ...op.unreachable,
    0x0b, // end inner if
    0x0b, // end outer if
    ...op.end,
  ];
}

// Flag helpers, mirroring setAddFlag/setSubFlag/setLogicFlag (dword) exactly.
function boolExpr(valueExpr) {
  // (value != 0) → 0/1
  return [...valueExpr, ...op.eqz, ...op.eqz];
}
function parityExpr(resExpr) {
  // (popcnt(res & 0xff) & 1) == 0 → PF
  return [...resExpr, ...op.i32(0xff), ...op.and, ...op.popcnt, ...op.i32(1), ...op.and, ...op.eqz];
}
function setAddBody() {
  const l = [0x20, 0x00], r = [0x20, 0x01], cin = [0x20, 0x02], res = [0x20, 0x03];
  const body = [];
  // CF = (u64)l + (u64)r + cin > 0xffffffff
  body.push(...l, ...op.i64ExtU, ...r, ...op.i64ExtU, ...op.i64Add, ...cin, ...op.i64ExtU, ...op.i64Add, ...op.i64(0xffffffff), ...op.i64GtU, ...op.gSet(G.cf));
  // AF = ((l ^ r ^ res) & 0x10) != 0
  body.push(...boolExpr([...l, ...r, ...op.xor, ...res, ...op.xor, ...op.i32(0x10), ...op.and]), ...op.gSet(G.af));
  // ZF = res == 0
  body.push(...res, ...op.eqz, ...op.gSet(G.zf));
  // SF = res >>> 31
  body.push(...res, ...op.i32(31), ...op.shrU, ...op.gSet(G.sf));
  // OF = (~(l ^ r) & (l ^ res) & 0x80000000) != 0
  body.push(...boolExpr([...l, ...r, ...op.xor, ...op.i32(-1), ...op.xor, ...l, ...res, ...op.xor, ...op.and, ...op.i32(0x80000000 | 0), ...op.and]), ...op.gSet(G.of));
  // PF
  body.push(...parityExpr(res), ...op.gSet(G.pf));
  body.push(...op.end);
  return body;
}
function setSubBody() {
  const l = [0x20, 0x00], r = [0x20, 0x01], bin = [0x20, 0x02], res = [0x20, 0x03];
  const body = [];
  // CF = (u64)l < (u64)r + bin
  body.push(...l, ...op.i64ExtU, ...r, ...op.i64ExtU, ...bin, ...op.i64ExtU, ...op.i64Add, ...op.i64LtU, ...op.gSet(G.cf));
  body.push(...boolExpr([...l, ...r, ...op.xor, ...res, ...op.xor, ...op.i32(0x10), ...op.and]), ...op.gSet(G.af));
  body.push(...res, ...op.eqz, ...op.gSet(G.zf));
  body.push(...res, ...op.i32(31), ...op.shrU, ...op.gSet(G.sf));
  // OF = ((l ^ r) & (l ^ res) & 0x80000000) != 0
  body.push(...boolExpr([...l, ...r, ...op.xor, ...l, ...res, ...op.xor, ...op.and, ...op.i32(0x80000000 | 0), ...op.and]), ...op.gSet(G.of));
  body.push(...parityExpr(res), ...op.gSet(G.pf));
  body.push(...op.end);
  return body;
}
function setLogicBody() {
  const res = [0x20, 0x00];
  const body = [];
  body.push(...op.i32(0), ...op.gSet(G.cf));
  body.push(...op.i32(0), ...op.gSet(G.of));
  body.push(...op.i32(0), ...op.gSet(G.af));
  body.push(...res, ...op.eqz, ...op.gSet(G.zf));
  body.push(...res, ...op.i32(31), ...op.shrU, ...op.gSet(G.sf));
  body.push(...parityExpr(res), ...op.gSet(G.pf));
  body.push(...op.end);
  return body;
}

// ---------------------------------------------------------------------------
// Runner — instantiate the emitted module and report the oracle 5-tuple.

function flagValueFromGlobals(exportsObject) {
  let value = 0x2;
  if (exportsObject.cf.value) value |= FLAG_MASK.carry;
  if (exportsObject.pf.value) value |= FLAG_MASK.parity;
  if (exportsObject.af.value) value |= FLAG_MASK.adjust;
  if (exportsObject.zf.value) value |= FLAG_MASK.zero;
  if (exportsObject.sf.value) value |= FLAG_MASK.sign;
  if (exportsObject.of.value) value |= FLAG_MASK.overflow;
  return value >>> 0;
}

export async function runRecompiled(mapped, option = {}) {
  const compiled = recompileImage(mapped, option);
  if (compiled.refuse) {
    return {
      state: "recompile_refused",
      execution_profile: "i386_recompiled_v1",
      recompiled: true,
      refuse: { code: compiled.refuse.code, message: compiled.refuse.message, ...compiled.refuse.detail },
      fallback_count: 0,
    };
  }
  const budget = Number.isSafeInteger(option.budget) && option.budget > 0 ? option.budget : 4096;
  const { instance } = await WebAssembly.instantiate(compiled.wasm, {});
  const exportsObject = instance.exports;
  exportsObject.run(budget);

  const register = {};
  for (let i = 0; i < REGISTER_NAME.length; i += 1) register[REGISTER_NAME[i]] = exportsObject[REGISTER_NAME[i]].value >>> 0;
  register.eip = exportsObject.eip.value >>> 0;
  const flag = {
    carry: Boolean(exportsObject.cf.value),
    parity: Boolean(exportsObject.pf.value),
    adjust: Boolean(exportsObject.af.value),
    zero: Boolean(exportsObject.zf.value),
    sign: Boolean(exportsObject.sf.value),
    overflow: Boolean(exportsObject.of.value),
    eflags: flagValueFromGlobals(exportsObject),
  };
  const memory = new Uint8Array(exportsObject.memory.buffer);
  const dataRegion = Buffer.from(memory.subarray(0, compiled.dataRegionByte));
  const { createHash } = await import("node:crypto");
  const memorySha = createHash("sha256").update(dataRegion).digest("hex");
  let traceSha = null;
  if (option.trace !== false) {
    const tracePtr = exportsObject.tracePtr.value >>> 0;
    const traceRegion = Buffer.from(memory.subarray(compiled.traceBase, tracePtr));
    traceSha = createHash("sha256").update(traceRegion).digest("hex");
  }
  const stopCode = exportsObject.stop.value >>> 0;
  return {
    state: "probe_executed",
    execution_profile: "i386_recompiled_v1",
    recompiled: true,
    register,
    flag,
    instruction_count: exportsObject.count.value >>> 0,
    trace_sha256: traceSha,
    memory_sha256: memorySha,
    stop_reason: STOP_NAME[stopCode] ?? "runtime_fault",
    block_count: compiled.blockCount,
    fallback_count: compiled.fallbackCount,
    flagged_region: compiled.flaggedRegion,
    indirect_leader_count: compiled.indirectLeaderCount,
  };
}

// Hybrid interpreter/recompiler fallback for self-modifying code (BPTK-048 /
// GS-003). A recompiled image is fast until the guest rewrites its own code;
// the hybrid layer holds a mutable image and a per-instruction decode cache, so
// a code write invalidates only the instructions it overlaps. On the next
// compile the affected block re-decodes to the freshly written behavior while
// every untouched instruction is reused from the cache — never re-decoded.
export function createHybridRecompiler(mapped, option = {}) {
  const image = Buffer.from(mapped.image);
  const hybridMapped = { report: mapped.report, image, section: mapped.section };
  const imageStart = mapped.report.load_base >>> 0;
  const cache = new Map();
  let compileCount = 0;

  function writeCode(address, bytes) {
    const start = address >>> 0;
    const offset = start - imageStart;
    if (offset < 0 || offset + bytes.length > image.length) throw new RangeError("Code write is outside the mapped image");
    for (let i = 0; i < bytes.length; i += 1) image[offset + i] = bytes[i] & 0xff;
    // Invalidate every cached instruction whose byte range overlaps the write,
    // so exactly the modified block re-decodes on the next compile.
    for (const [addr, ins] of cache) {
      const insStart = addr >>> 0;
      const insEnd = insStart + ins.len;
      if (insStart < start + bytes.length && start < insEnd) cache.delete(addr);
    }
  }

  function compile(compileOption = {}) {
    const stat = { reDecoded: [], kept: [] };
    compileCount += 1;
    const compiled = recompileImage(hybridMapped, { ...option, ...compileOption, cache, decodeStat: stat });
    if (compiled.refuse) return { refuse: compiled.refuse, stat };
    compiled.reDecodedInstruction = stat.reDecoded;
    compiled.keptInstruction = stat.kept;
    compiled.compileCount = compileCount;
    return compiled;
  }

  async function run(compileOption = {}) {
    const stat = { reDecoded: [], kept: [] };
    compileCount += 1;
    const result = await runRecompiled(hybridMapped, { ...option, ...compileOption, cache, decodeStat: stat });
    result.reDecodedInstruction = stat.reDecoded;
    result.keptInstruction = stat.kept;
    result.compileCount = compileCount;
    return result;
  }

  return { writeCode, compile, run, mapped: hybridMapped };
}

// Convenience wrapper: map a PE32 buffer/path and recompile in one call.
export function recompilePe32(input, option = {}) {
  const mapped = mapPe32ForRuntime(input, option.load_base ?? null, null);
  return recompileImage(mapped, option);
}
