// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The x86-64 → WebAssembly recompilation fast path for runtime v2 milestone M3
// (doc/runtime-v2-scope.md §2 "(D) recompiler"). It takes ONE lifted lift64.mjs
// basic block — the straight-line integer/mov/lea/logic/shift/flag subset — and
// hand-assembles a REAL WebAssembly module in the binary format (magic 00 61 73
// 6d, version 1, the type/function/memory/export/code sections; no bundler, no
// dependency), then instantiates and runs it. Guest GPRs are sixteen i64 WASM
// locals threaded through a register-file scratch region of a single exported
// WASM memory; guest memory is that same linear memory addressed as
// (guestAddress − loadBase); IR ops map to WASM integer instructions
// (i64.add/sub/mul/and/or/xor/shl/shr_u/shr_s, iN.load/iN.store, popcnt for
// parity). EFLAGS are materialized EAGERLY per flag-defining op into six i32
// flag locals whose end-of-block value equals what lib/lift64.mjs's lazy oracle
// would materialize — the last flag-defining op wins in both, bit for bit.
//
// This is the enabler for real-time speed: the interpreter is the correctness
// ORACLE (lib/lift64.mjs), this is the compiled equivalent, and test/wasm64
// asserts interpreter == WASM bit-exact over a corpus of microprograms. An op
// the codegen cannot yet emit (inter-block branch/call, div/mul-pair, SSE, x87,
// 64-bit IMUL overflow, rotate) is an HONEST unsupported stop that names the
// opcode — never a stub that secretly re-invokes the interpreter and claims WASM.

const MASK64 = (1n << 64n) - 1n;
const NAME64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
const FLAG_ORDER = ["cf", "pf", "af", "zf", "sf", "of"];
const DEFAULT_FLAG = { cf: false, pf: true, af: false, zf: true, sf: false, of: false };

function sizeMask(sizeBit) {
  return (1n << BigInt(sizeBit)) - 1n;
}

function signBitOf(sizeBit) {
  return 1n << BigInt(sizeBit - 1);
}

// ---- LEB128 ----

function uLEB(value) {
  let v = BigInt(value);
  const bytes = [];
  do {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v !== 0n) byte |= 0x80;
    bytes.push(byte);
  } while (v !== 0n);
  return bytes;
}

function sLEB(value) {
  let v = BigInt(value);
  const bytes = [];
  for (;;) {
    let byte = Number(v & 0x7fn);
    v >>= 7n; // BigInt >> is arithmetic (sign-propagating)
    const done = (v === 0n && (byte & 0x40) === 0) || (v === -1n && (byte & 0x40) !== 0);
    if (!done) byte |= 0x80;
    bytes.push(byte);
    if (done) return bytes;
  }
}

// A WASM instruction cheat-sheet. Load/store carry a natural [align=0, offset=0]
// memarg; every guest access computes its full byte address on the stack first.
const I = {
  localGet: (i) => [0x20, ...uLEB(i)],
  localSet: (i) => [0x21, ...uLEB(i)],
  i32Const: (v) => [0x41, ...sLEB(BigInt.asIntN(32, BigInt(v)))],
  i64Const: (v) => [0x42, ...sLEB(BigInt.asIntN(64, BigInt(v)))],
  i64Load: [0x29, 0x00, 0x00],
  i64Load8u: [0x30, 0x00, 0x00],
  i64Load16u: [0x33, 0x00, 0x00],
  i64Load32u: [0x35, 0x00, 0x00],
  i64Store: [0x37, 0x00, 0x00],
  i64Store8: [0x3c, 0x00, 0x00],
  i64Store16: [0x3d, 0x00, 0x00],
  i64Store32: [0x3e, 0x00, 0x00],
  i32Load8u: [0x2d, 0x00, 0x00],
  i32Store8: [0x3a, 0x00, 0x00],
  i64Add: [0x7c],
  i64Sub: [0x7d],
  i64Mul: [0x7e],
  i64And: [0x83],
  i64Or: [0x84],
  i64Xor: [0x85],
  i64Shl: [0x86],
  i64ShrS: [0x87],
  i64ShrU: [0x88],
  i64Eqz: [0x50],
  i64Ne: [0x52],
  i64LtU: [0x54],
  i64Popcnt: [0x7b],
  i64ExtendI32U: [0xad],
  i32WrapI64: [0xa7],
  i32Or: [0x72],
  i32Xor: [0x73],
  ifVoid: [0x04, 0x40],
  else_: [0x05],
  end: [0x0b],
};

// Local layout. Twenty-four i64 slots: g0..g15 = the guest GPRs, then eight
// scratch temporaries; seven i32 slots hold the six flags plus one scratch.
const T = { a: 16, b: 17, r: 18, cin: 19, s1: 20, s2: 21 };
const F = { cf: 24, pf: 25, af: 26, zf: 27, sf: 28, of: 29, i: 30 };
const I64_LOCAL_COUNT = 24;
const I32_LOCAL_COUNT = 7;

const SUPPORTED_ALU = new Set(["add", "adc", "sbb", "sub", "cmp", "and", "test", "or", "xor"]);
const SUPPORTED_SHIFT = new Set(["shl", "shr", "sar"]);

// Emits a WebAssembly module for the straight-line prefix of `block.node`. The
// prefix ends at the first control transfer (RET is modeled as an rsp fixup and
// terminates the block; any other branch/call is an honest unsupported stop) or
// the first op the codegen cannot emit. Returns the module bytes, the scratch
// layout the host pokes the register file through, and a coverage report.
export function compileBlock(block, option = {}) {
  const loadBase = BigInt(option.loadBase ?? 0x140000000n);
  const stackSizeByte = option.stackSizeByte ?? 0x10000;
  const guestLen = option.guestLen ?? stackSizeByte;
  const regBase = (guestLen + 7) & ~7; // 8-byte aligned, just above guest memory
  const flagBase = regBase + 16 * 8;
  const scratchEnd = flagBase + 8;
  const pages = Math.ceil(scratchEnd / 65536);

  const body = [];
  const push = (bytes) => { for (const b of bytes) body.push(b); };

  // ---- operand primitives ----

  const emitReadReg = (op) => {
    push(I.localGet(op.index));
    if (op.size === 64) return;
    if (op.size === 32) { push(I.i64Const(0xffffffffn)); push(I.i64And); return; }
    if (op.size === 16) { push(I.i64Const(0xffffn)); push(I.i64And); return; }
    if (op.high8) { push(I.i64Const(8n)); push(I.i64ShrU); push(I.i64Const(0xffn)); push(I.i64And); return; }
    push(I.i64Const(0xffn)); push(I.i64And);
  };

  // Leaves the full 64-bit guest effective address on the stack (i64).
  const emitEffectiveAddress = (mem, node) => {
    if (mem.rip_relative) {
      const addr = (loadBase + BigInt(node.address) + BigInt(node.length) + BigInt(mem.disp)) & MASK64;
      push(I.i64Const(addr));
      return;
    }
    let started = false;
    if (mem.base !== null) { push(I.localGet(mem.base)); started = true; }
    if (mem.index !== null) {
      push(I.localGet(mem.index)); push(I.i64Const(BigInt(mem.scale))); push(I.i64Mul);
      if (started) push(I.i64Add); else started = true;
    }
    if (mem.disp !== 0 || !started) {
      push(I.i64Const(BigInt(mem.disp)));
      if (started) push(I.i64Add);
    }
  };

  // Converts the address on the stack (i64) into an i32 WASM-memory offset.
  const emitToOffset = () => {
    push(I.i64Const(loadBase)); push(I.i64Sub); push(I.i32WrapI64);
  };

  const memLoadOp = (sizeBit) => sizeBit === 8 ? I.i64Load8u : sizeBit === 16 ? I.i64Load16u : sizeBit === 32 ? I.i64Load32u : I.i64Load;
  const memStoreOp = (sizeBit) => sizeBit === 8 ? I.i64Store8 : sizeBit === 16 ? I.i64Store16 : sizeBit === 32 ? I.i64Store32 : I.i64Store;

  const emitReadMem = (op, node) => {
    emitEffectiveAddress(op, node); emitToOffset(); push(memLoadOp(op.size));
  };

  // Leaves an i64 value (masked to the operand size) on the stack.
  const emitReadOperand = (op, node) => {
    if (op.kind === "imm") { push(I.i64Const(op.value & sizeMask(op.size))); return; }
    if (op.kind === "reg") { emitReadReg(op); return; }
    emitReadMem(op, node);
  };

  const emitWriteRegFrom = (op, tl) => {
    const gi = op.index;
    if (op.size === 64) { push(I.localGet(tl)); push(I.localSet(gi)); return; }
    if (op.size === 32) { push(I.localGet(tl)); push(I.i64Const(0xffffffffn)); push(I.i64And); push(I.localSet(gi)); return; }
    if (op.size === 16) {
      push(I.localGet(gi)); push(I.i64Const(~0xffffn & MASK64)); push(I.i64And);
      push(I.localGet(tl)); push(I.i64Const(0xffffn)); push(I.i64And);
      push(I.i64Or); push(I.localSet(gi)); return;
    }
    if (op.high8) {
      push(I.localGet(gi)); push(I.i64Const(~0xff00n & MASK64)); push(I.i64And);
      push(I.localGet(tl)); push(I.i64Const(0xffn)); push(I.i64And); push(I.i64Const(8n)); push(I.i64Shl);
      push(I.i64Or); push(I.localSet(gi)); return;
    }
    push(I.localGet(gi)); push(I.i64Const(~0xffn & MASK64)); push(I.i64And);
    push(I.localGet(tl)); push(I.i64Const(0xffn)); push(I.i64And);
    push(I.i64Or); push(I.localSet(gi));
  };

  const emitWriteOperandFrom = (op, node, tl) => {
    if (op.kind === "reg") { emitWriteRegFrom(op, tl); return; }
    emitEffectiveAddress(op, node); emitToOffset();
    push(I.localGet(tl));
    push(memStoreOp(op.size));
  };

  // ---- flag primitives (bit-exact with lib/lift64.mjs materializeFlag) ----

  const emitSignZeroParity = (size, sign) => {
    push(I.localGet(T.r)); push(I.i64Eqz); push(I.localSet(F.zf));
    push(I.localGet(T.r)); push(I.i64Const(sign)); push(I.i64And); push(I.i64Const(0n)); push(I.i64Ne); push(I.localSet(F.sf));
    push(I.localGet(T.r)); push(I.i64Const(0xffn)); push(I.i64And); push(I.i64Popcnt); push(I.i64Const(1n)); push(I.i64And); push(I.i64Eqz); push(I.localSet(F.pf));
  };

  const emitZeroFlag = (f) => { push(I.i32Const(0)); push(I.localSet(f)); };

  const emitAddFlags = (size, sign) => {
    // af = ((a ^ b ^ r) & 0x10) != 0
    push(I.localGet(T.a)); push(I.localGet(T.b)); push(I.i64Xor); push(I.localGet(T.r)); push(I.i64Xor);
    push(I.i64Const(0x10n)); push(I.i64And); push(I.i64Const(0n)); push(I.i64Ne); push(I.localSet(F.af));
    // of = (((a ^ r) & (b ^ r)) & sign) != 0
    push(I.localGet(T.a)); push(I.localGet(T.r)); push(I.i64Xor);
    push(I.localGet(T.b)); push(I.localGet(T.r)); push(I.i64Xor); push(I.i64And);
    push(I.i64Const(sign)); push(I.i64And); push(I.i64Const(0n)); push(I.i64Ne); push(I.localSet(F.of));
    if (size < 64) {
      push(I.localGet(T.a)); push(I.localGet(T.b)); push(I.i64Add); push(I.localGet(T.cin)); push(I.i64Add);
      push(I.i64Const(BigInt(size))); push(I.i64ShrU); push(I.i64Const(1n)); push(I.i64And); push(I.i64Const(0n)); push(I.i64Ne); push(I.localSet(F.cf));
    } else {
      push(I.localGet(T.a)); push(I.localGet(T.b)); push(I.i64Add); push(I.localSet(T.s1));
      push(I.localGet(T.s1)); push(I.localGet(T.a)); push(I.i64LtU);
      push(I.localGet(T.s1)); push(I.localGet(T.cin)); push(I.i64Add); push(I.localSet(T.s2));
      push(I.localGet(T.s2)); push(I.localGet(T.s1)); push(I.i64LtU);
      push(I.i32Or); push(I.localSet(F.cf));
    }
  };

  const emitSubFlags = (size, sign) => {
    // af = ((a ^ b ^ r) & 0x10) != 0
    push(I.localGet(T.a)); push(I.localGet(T.b)); push(I.i64Xor); push(I.localGet(T.r)); push(I.i64Xor);
    push(I.i64Const(0x10n)); push(I.i64And); push(I.i64Const(0n)); push(I.i64Ne); push(I.localSet(F.af));
    // of = (((a ^ b) & (a ^ r)) & sign) != 0
    push(I.localGet(T.a)); push(I.localGet(T.b)); push(I.i64Xor);
    push(I.localGet(T.a)); push(I.localGet(T.r)); push(I.i64Xor); push(I.i64And);
    push(I.i64Const(sign)); push(I.i64And); push(I.i64Const(0n)); push(I.i64Ne); push(I.localSet(F.of));
    // cf via borrow: (a <u b) | ((a - b) <u cin)
    push(I.localGet(T.a)); push(I.localGet(T.b)); push(I.i64LtU);
    push(I.localGet(T.a)); push(I.localGet(T.b)); push(I.i64Sub); push(I.localSet(T.s1));
    push(I.localGet(T.s1)); push(I.localGet(T.cin)); push(I.i64LtU);
    push(I.i32Or); push(I.localSet(F.cf));
  };

  const emitMaskToSize = (size) => { if (size !== 64) { push(I.i64Const(sizeMask(size))); push(I.i64And); } };
  const emitSignExtendTo64 = (size) => {
    const sh = BigInt(64 - size);
    if (sh > 0n) { push(I.i64Const(sh)); push(I.i64Shl); push(I.i64Const(sh)); push(I.i64ShrS); }
  };

  // ---- per-op emitters ----

  const emitAlu = (node) => {
    const size = node.size;
    const sign = signBitOf(size);
    const aluOp = node.aluOp;
    emitReadOperand(node.dst, node); push(I.localSet(T.a));
    emitReadOperand(node.src, node); push(I.localSet(T.b));
    if (aluOp === "adc" || aluOp === "sbb") { push(I.localGet(F.cf)); push(I.i64ExtendI32U); push(I.localSet(T.cin)); }
    else { push(I.i64Const(0n)); push(I.localSet(T.cin)); }

    if (aluOp === "add" || aluOp === "adc") {
      push(I.localGet(T.a)); push(I.localGet(T.b)); push(I.i64Add); push(I.localGet(T.cin)); push(I.i64Add); emitMaskToSize(size); push(I.localSet(T.r));
    } else if (aluOp === "sub" || aluOp === "sbb" || aluOp === "cmp") {
      push(I.localGet(T.a)); push(I.localGet(T.b)); push(I.i64Sub); push(I.localGet(T.cin)); push(I.i64Sub); emitMaskToSize(size); push(I.localSet(T.r));
    } else if (aluOp === "and" || aluOp === "test") {
      push(I.localGet(T.a)); push(I.localGet(T.b)); push(I.i64And); emitMaskToSize(size); push(I.localSet(T.r));
    } else if (aluOp === "or") {
      push(I.localGet(T.a)); push(I.localGet(T.b)); push(I.i64Or); emitMaskToSize(size); push(I.localSet(T.r));
    } else {
      push(I.localGet(T.a)); push(I.localGet(T.b)); push(I.i64Xor); emitMaskToSize(size); push(I.localSet(T.r));
    }

    if (node.writeBack) emitWriteOperandFrom(node.dst, node, T.r);

    emitSignZeroParity(size, sign);
    if (aluOp === "and" || aluOp === "test" || aluOp === "or" || aluOp === "xor") {
      emitZeroFlag(F.cf); emitZeroFlag(F.af); emitZeroFlag(F.of);
    } else if (aluOp === "add" || aluOp === "adc") {
      emitAddFlags(size, sign);
    } else {
      emitSubFlags(size, sign);
    }
  };

  const emitIncDec = (node) => {
    const size = node.size;
    const sign = signBitOf(size);
    const isInc = node.op === "inc";
    emitReadOperand(node.dst, node); push(I.localSet(T.a));
    push(I.localGet(T.a)); push(I.i64Const(1n)); push(isInc ? I.i64Add : I.i64Sub); emitMaskToSize(size); push(I.localSet(T.r));
    emitWriteOperandFrom(node.dst, node, T.r);
    // CF is preserved (the inc/dec contract); F.cf keeps its incoming value.
    emitSignZeroParity(size, sign);
    push(I.localGet(T.a)); push(I.i64Const(1n)); push(I.i64Xor); push(I.localGet(T.r)); push(I.i64Xor);
    push(I.i64Const(0x10n)); push(I.i64And); push(I.i64Const(0n)); push(I.i64Ne); push(I.localSet(F.af));
    if (isInc) {
      push(I.localGet(T.a)); push(I.localGet(T.r)); push(I.i64Xor);
      push(I.i64Const(1n)); push(I.localGet(T.r)); push(I.i64Xor); push(I.i64And);
    } else {
      push(I.localGet(T.a)); push(I.i64Const(1n)); push(I.i64Xor);
      push(I.localGet(T.a)); push(I.localGet(T.r)); push(I.i64Xor); push(I.i64And);
    }
    push(I.i64Const(sign)); push(I.i64And); push(I.i64Const(0n)); push(I.i64Ne); push(I.localSet(F.of));
  };

  const emitNeg = (node) => {
    const size = node.size;
    const sign = signBitOf(size);
    emitReadOperand(node.dst, node); push(I.localSet(T.b));
    push(I.i64Const(0n)); push(I.localSet(T.a));
    push(I.i64Const(0n)); push(I.localSet(T.cin));
    push(I.localGet(T.a)); push(I.localGet(T.b)); push(I.i64Sub); emitMaskToSize(size); push(I.localSet(T.r));
    emitWriteOperandFrom(node.dst, node, T.r);
    emitSignZeroParity(size, sign);
    emitSubFlags(size, sign);
  };

  const emitNot = (node) => {
    const size = node.size;
    emitReadOperand(node.dst, node); push(I.i64Const(-1n)); push(I.i64Xor); emitMaskToSize(size); push(I.localSet(T.r));
    emitWriteOperandFrom(node.dst, node, T.r);
  };

  const emitMov = (node) => {
    emitReadOperand(node.src, node); push(I.localSet(T.r)); emitWriteOperandFrom(node.dst, node, T.r);
  };

  const emitMovzx = (node) => {
    emitReadOperand(node.src, node); push(I.localSet(T.r)); emitWriteRegFrom(node.dst, T.r);
  };

  const emitMovsx = (node) => {
    const srcSize = node.srcSize ?? 32;
    emitReadOperand(node.src, node); emitSignExtendTo64(srcSize); push(I.localSet(T.r)); emitWriteRegFrom(node.dst, T.r);
  };

  const emitLea = (node) => {
    emitEffectiveAddress(node.src, node); push(I.localSet(T.r)); emitWriteRegFrom(node.dst, T.r);
  };

  const emitShift = (node) => {
    const size = node.size;
    const sign = signBitOf(size);
    const sop = node.shiftOp;
    const countMask = size === 64 ? 0x3fn : 0x1fn;
    emitReadOperand(node.dst, node); push(I.localSet(T.a));
    emitReadOperand(node.src, node); push(I.i64Const(countMask)); push(I.i64And); push(I.localSet(T.cin));
    push(I.localGet(T.cin)); push(I.i64Eqz); push(I.ifVoid);
    push(I.localGet(T.a)); push(I.localSet(T.r)); // zero count: value unchanged, flags untouched
    push(I.else_);
    if (sop === "shl") {
      push(I.localGet(T.a)); push(I.localGet(T.cin)); push(I.i64Shl); emitMaskToSize(size); push(I.localSet(T.r));
      push(I.localGet(T.a)); push(I.i64Const(BigInt(size))); push(I.localGet(T.cin)); push(I.i64Sub); push(I.i64ShrU);
      push(I.i64Const(1n)); push(I.i64And); push(I.i64Const(0n)); push(I.i64Ne); push(I.localSet(F.cf));
      emitSignZeroParity(size, sign);
      push(I.localGet(F.sf)); push(I.localGet(F.cf)); push(I.i32Xor); push(I.localSet(F.of));
    } else if (sop === "shr") {
      push(I.localGet(T.a)); push(I.localGet(T.cin)); push(I.i64ShrU); push(I.localSet(T.r));
      push(I.localGet(T.a)); push(I.localGet(T.cin)); push(I.i64Const(1n)); push(I.i64Sub); push(I.i64ShrU);
      push(I.i64Const(1n)); push(I.i64And); push(I.i64Const(0n)); push(I.i64Ne); push(I.localSet(F.cf));
      emitSignZeroParity(size, sign);
      push(I.localGet(T.a)); push(I.i64Const(sign)); push(I.i64And); push(I.i64Const(0n)); push(I.i64Ne); push(I.localSet(F.of));
    } else { // sar
      push(I.localGet(T.a)); emitSignExtendTo64(size); push(I.localGet(T.cin)); push(I.i64ShrS); emitMaskToSize(size); push(I.localSet(T.r));
      push(I.localGet(T.a)); push(I.localGet(T.cin)); push(I.i64Const(1n)); push(I.i64Sub); push(I.i64ShrU);
      push(I.i64Const(1n)); push(I.i64And); push(I.i64Const(0n)); push(I.i64Ne); push(I.localSet(F.cf));
      emitSignZeroParity(size, sign);
      emitZeroFlag(F.of);
    }
    push(I.end);
    emitWriteOperandFrom(node.dst, node, T.r);
  };

  const emitImul = (node) => {
    const size = node.size;
    const sign = signBitOf(size);
    emitReadOperand(node.src, node); emitSignExtendTo64(size); push(I.localSet(T.a));
    const bsrc = node.op === "imul3" ? node.src2 : node.dst;
    emitReadOperand(bsrc, node); emitSignExtendTo64(size); push(I.localSet(T.b));
    push(I.localGet(T.a)); push(I.localGet(T.b)); push(I.i64Mul); push(I.localSet(T.s1)); // full signed product (fits i64 for size<=32)
    push(I.localGet(T.s1)); push(I.i64Const(sizeMask(size))); push(I.i64And); push(I.localSet(T.r));
    emitWriteRegFrom(node.dst, T.r);
    // overflow = sign_extend(truncated) != full_product
    push(I.localGet(T.r)); emitSignExtendTo64(size); push(I.localGet(T.s1)); push(I.i64Ne); push(I.localSet(F.i));
    push(I.localGet(F.i)); push(I.localSet(F.cf));
    push(I.localGet(F.i)); push(I.localSet(F.of));
    push(I.localGet(T.r)); push(I.i64Const(sign)); push(I.i64And); push(I.i64Const(0n)); push(I.i64Ne); push(I.localSet(F.sf));
    push(I.localGet(T.r)); push(I.i64Eqz); push(I.localSet(F.zf));
    push(I.localGet(T.r)); push(I.i64Const(0xffn)); push(I.i64And); push(I.i64Popcnt); push(I.i64Const(1n)); push(I.i64And); push(I.i64Eqz); push(I.localSet(F.pf));
    emitZeroFlag(F.af);
  };

  const emitPush = (node) => {
    const size = node.size;
    const sizeByte = size / 8;
    emitReadOperand(node.src, node); emitMaskToSize(size); push(I.localSet(T.r));
    push(I.localGet(4)); push(I.i64Const(BigInt(sizeByte))); push(I.i64Sub); push(I.localSet(4));
    push(I.localGet(4)); emitToOffset();
    push(I.localGet(T.r));
    push(memStoreOp(size));
  };

  const emitPop = (node) => {
    const size = node.size;
    const sizeByte = size / 8;
    push(I.localGet(4)); emitToOffset(); push(memLoadOp(size)); push(I.localSet(T.r));
    push(I.localGet(4)); push(I.i64Const(BigInt(sizeByte))); push(I.i64Add); push(I.localSet(4));
    emitWriteOperandFrom(node.dst, node, T.r);
  };

  const emitRet = (node) => {
    push(I.localGet(4)); push(I.i64Const(BigInt(8 + (node.pop || 0)))); push(I.i64Add); push(I.localSet(4));
  };

  const emitNode = (node) => {
    switch (node.op) {
      case "nop": break;
      case "mov": emitMov(node); break;
      case "movzx": emitMovzx(node); break;
      case "movsx": case "movsxd": emitMovsx(node); break;
      case "lea": emitLea(node); break;
      case "alu": emitAlu(node); break;
      case "shift": emitShift(node); break;
      case "inc": case "dec": emitIncDec(node); break;
      case "neg": emitNeg(node); break;
      case "not": emitNot(node); break;
      case "imul2": case "imul3": emitImul(node); break;
      case "push": emitPush(node); break;
      case "pop": emitPop(node); break;
      default: throw new Error(`wasm64: no emitter for op ${node.op}`);
    }
  };

  // ---- prologue: hydrate GPRs + flags from the scratch region ----
  for (let i = 0; i < 16; i += 1) { push(I.i32Const(regBase + i * 8)); push(I.i64Load); push(I.localSet(i)); }
  FLAG_ORDER.forEach((name, k) => { push(I.i32Const(flagBase + k)); push(I.i32Load8u); push(I.localSet(F[name])); });

  // ---- body: emit the straight-line prefix ----
  const emitted = new Set();
  const unsupported = [];
  let blockLength = 0;
  for (const node of block.node) {
    if (!node.served) { unsupported.push({ op: node.op, mnemonic: node.mnemonic, reason: "not_served" }); break; }
    if (node.op === "ret") { emitRet(node); emitted.add("ret"); blockLength += 1; break; }
    if (node.control && node.control !== "none") { unsupported.push({ op: node.op, mnemonic: node.mnemonic, reason: "control_flow" }); break; }
    if ((node.op === "imul2" || node.op === "imul3") && node.size === 64) { unsupported.push({ op: node.op, mnemonic: node.mnemonic, reason: "imul64_overflow" }); break; }
    if (node.op === "shift" && !SUPPORTED_SHIFT.has(node.shiftOp)) { unsupported.push({ op: node.op, mnemonic: node.mnemonic, reason: `rotate_${node.shiftOp}` }); break; }
    if (node.op === "alu" && !SUPPORTED_ALU.has(node.aluOp)) { unsupported.push({ op: node.op, mnemonic: node.mnemonic, reason: `alu_${node.aluOp}` }); break; }
    if (!EMITTABLE.has(node.op)) { unsupported.push({ op: node.op, mnemonic: node.mnemonic, reason: "unsupported_op" }); break; }
    emitNode(node);
    emitted.add(node.op === "alu" ? `alu:${node.aluOp}` : node.op === "shift" ? `shift:${node.shiftOp}` : node.op);
    blockLength += 1;
  }

  // ---- epilogue: write GPRs + flags back to the scratch region ----
  for (let i = 0; i < 16; i += 1) { push(I.i32Const(regBase + i * 8)); push(I.localGet(i)); push(I.i64Store); }
  FLAG_ORDER.forEach((name, k) => { push(I.i32Const(flagBase + k)); push(I.localGet(F[name])); push(I.i32Store8); });
  push(I.end);

  const bytes = assembleModule(body, pages);

  return {
    bytes,
    regBase,
    flagBase,
    pages,
    guestLen,
    complete: unsupported.length === 0,
    coverage: { emitted: [...emitted].sort(), unsupported },
    blockLength,
  };
}

const EMITTABLE = new Set(["nop", "mov", "movzx", "movsx", "movsxd", "lea", "alu", "shift", "inc", "dec", "neg", "not", "imul2", "imul3", "push", "pop"]);

// Hand-assembles the five WASM sections into a complete module: one () -> ()
// function that owns and exports a single memory, both exported by name.
function assembleModule(body, pages) {
  const section = (id, payload) => [id, ...uLEB(payload.length), ...payload];
  const nameBytes = (name) => [...uLEB(name.length), ...[...name].map((c) => c.charCodeAt(0))];

  const typeSection = section(1, [...uLEB(1), 0x60, ...uLEB(0), ...uLEB(0)]);
  const funcSection = section(3, [...uLEB(1), ...uLEB(0)]);
  const memSection = section(5, [...uLEB(1), 0x00, ...uLEB(pages)]);
  const exportSection = section(7, [
    ...uLEB(2),
    ...nameBytes("mem"), 0x02, ...uLEB(0),
    ...nameBytes("run"), 0x00, ...uLEB(0),
  ]);

  const localDecl = [
    ...uLEB(2),
    ...uLEB(I64_LOCAL_COUNT), 0x7e,
    ...uLEB(I32_LOCAL_COUNT), 0x7f,
  ];
  const funcBody = [...localDecl, ...body];
  const codeSection = section(10, [...uLEB(1), ...uLEB(funcBody.length), ...funcBody]);

  return Uint8Array.from([
    0x00, 0x61, 0x73, 0x6d,
    0x01, 0x00, 0x00, 0x00,
    ...typeSection,
    ...funcSection,
    ...memSection,
    ...exportSection,
    ...codeSection,
  ]);
}

// Compiles the block, then instantiates the module and runs it against the same
// initial architectural state lib/lift64.mjs's interpret() sets up (all GPRs
// zero except rsp near the stack top, the sentinel return address pushed, the
// default lazy flags). Returns the end-of-block register file, flags, and a
// copy of guest memory — the exact surfaces the oracle comparison inspects.
export function runBlock(block, option = {}) {
  const image = option.image;
  if (!Buffer.isBuffer(image) && !(image instanceof Uint8Array)) throw new TypeError("runBlock requires an image buffer");
  const loadBase = BigInt(option.loadBase ?? 0x140000000n);
  const stackSizeByte = option.stackSizeByte ?? 0x10000;
  const guestLen = image.length + stackSizeByte;

  const compiled = compileBlock(block, { loadBase, stackSizeByte, guestLen });
  const module = new WebAssembly.Module(compiled.bytes);
  const instance = new WebAssembly.Instance(module, {});
  const buffer = instance.exports.mem.buffer;
  const mem = new Uint8Array(buffer);
  const view = new DataView(buffer);

  mem.set(image, 0);

  const stackTop = loadBase + BigInt(image.length + stackSizeByte - 16);
  const sentinel = 0xdead000000000000n | (loadBase & 0xffffn);
  const rsp0 = stackTop - 8n;
  view.setBigUint64(Number(rsp0 - loadBase), sentinel, true);

  const reg = new Array(16).fill(0n);
  reg[4] = rsp0;
  if (option.register) {
    for (const [name, value] of Object.entries(option.register)) {
      const index = NAME64.indexOf(name);
      if (index >= 0) reg[index] = BigInt(value) & MASK64;
    }
  }
  for (let i = 0; i < 16; i += 1) view.setBigUint64(compiled.regBase + i * 8, reg[i] & MASK64, true);

  const flag = { ...DEFAULT_FLAG, ...(option.flag ?? {}) };
  FLAG_ORDER.forEach((name, k) => { mem[compiled.flagBase + k] = flag[name] ? 1 : 0; });

  instance.exports.run();

  const register = {};
  for (let i = 0; i < 16; i += 1) register[NAME64[i]] = view.getBigUint64(compiled.regBase + i * 8, true);
  const outFlag = {};
  FLAG_ORDER.forEach((name, k) => { outFlag[name] = mem[compiled.flagBase + k] !== 0; });

  return {
    register,
    flag: outFlag,
    memory: mem.slice(0, guestLen),
    complete: compiled.complete,
    coverage: compiled.coverage,
    blockLength: compiled.blockLength,
  };
}
