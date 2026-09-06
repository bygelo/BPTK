// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The x86-64 → WebAssembly recompilation fast path for runtime v2 milestone M3
// (doc/runtime-v2-scope.md §2 "(D) recompiler"). It takes lifted lift64.mjs IR —
// either ONE straight-line basic block (compileBlock) or a MULTI-BLOCK function
// wired by intra-function branches (compileFunction) — and hand-assembles a REAL
// WebAssembly module in the binary format (magic 00 61 73 6d, version 1; the
// type/function/memory/export/code sections; no bundler, no dependency), then
// instantiates and runs it. Guest GPRs are sixteen i64 WASM locals threaded
// through a register-file scratch region of a single exported WASM memory; guest
// memory is that same linear memory addressed as (guestAddress − loadBase); IR
// ops map to WASM integer instructions (i64.add/sub/mul/and/or/xor/shl/shr_u/
// shr_s, iN.load/iN.store, popcnt for parity). EFLAGS are materialized EAGERLY
// per flag-defining op into six i32 flag locals whose end-of-block value equals
// what lib/lift64.mjs's lazy oracle would materialize — the last flag-defining op
// wins in both, bit for bit.
//
// The multi-block path recovers the control-flow graph from lift64 (blocks split
// on jcc/jmp/ret and at every branch target) and emits WASM structured control:
// a `(block (loop (block…(br_table))))` dispatch over a "current block index" i32
// local. Each guest block computes its body, evaluates its guest branch condition
// from the SAME flag locals the interpreter's conditionHolds reads, sets the next
// block index, and `br`s back to the dispatch; a guest RET returns. The loop is
// bounded by an iteration budget so a guest infinite loop stops with a
// budget-exhausted status instead of hanging the module.
//
// The multi-block path also compiles a DIRECT CALL graph: a `call rel32/rel8`
// (E8/near) to another lifted guest function in the compiled set is followed as
// one cross-function CFG. A call pushes the return address on the SAME guest
// stack the block codegen uses (rsp-=8, store next-rip) and transfers to the
// callee entry block; a RET pops that address and dispatches back to the caller's
// resume block (or, at the entry-frame sentinel, terminates the module). The
// recursion/loop depth is the SAME bounded iteration budget, so a runaway
// recursion stops with budget_exhausted instead of hanging.
//
// An INDIRECT jmp/call (0xFF /4, 0xFF /2) is compiled as a RETURN-TO-DISPATCH
// terminator rather than rejected: the module computes the target operand with
// the same addressing/region path every other access uses, records it in the
// resume-rip slot, and exits with a FALLBACK status. The function stays
// `complete: true` — the straight-line code before the transfer runs at WASM
// speed and only the transfer itself costs a tier exit, which is what makes a
// function containing an indirect branch worth compiling at all.
//
// Every exit also reports a RESUME RIP: the exact guest virtual address the
// interpreter must continue at. See the `RIP` local below for the invariant.
//
// This is the enabler for real-time speed: the interpreter is the correctness
// ORACLE (lib/lift64.mjs), this is the compiled equivalent, and test/wasm64
// asserts interpreter == WASM bit-exact over a corpus of microprograms. An op
// the codegen cannot yet emit (call outside the compiled set without a host
// binding, a 16-bit-operand indirect transfer, div/mul-pair, SSE float
// horizontal ops, x87, 64-bit IMUL overflow, rotate) is an HONEST named
// fallback — never a stub that secretly re-invokes the interpreter and claims
// WASM.

const MASK64 = (1n << 64n) - 1n;
const MASK128 = (1n << 128n) - 1n;
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

// A single SIMD instruction: the 0xFD prefix, then the sub-opcode as a uLEB, then
// any immediate tail (a memarg, a lane index, or the 16 shuffle/const bytes). The
// v128 family the SSE codegen leans on is hand-assembled exactly like the integer
// opcodes below — no bundler, no dependency, real WebAssembly SIMD bytes.
const SD = (sub, ...tail) => [0xfd, ...uLEB(sub), ...tail];

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
  i64Eq: [0x51],
  i64Ne: [0x52],
  i64LtU: [0x54],
  i64Popcnt: [0x7b],
  i64ExtendI32U: [0xad],
  i32WrapI64: [0xa7],
  i32Add: [0x6a],
  i32Sub: [0x6b],
  i32Eqz: [0x45],
  i32Eq: [0x46],
  i32Ne: [0x47],
  i32And: [0x71],
  i32Or: [0x72],
  i32Xor: [0x73],
  i32Sub_: [0x6b],
  i64GeU: [0x5a],
  i32Select: [0x1b],
  // ---- v128 SIMD (0xFD family), hand-assembled for the SSE/SSE2 codegen ----
  v128Load: SD(0x00, 0x00, 0x00),
  v128Store: SD(0x0b, 0x00, 0x00),
  v128Const: (b16) => SD(0x0c, ...b16),
  i8x16Shuffle: (lane16) => SD(0x0d, ...lane16),
  i8x16Splat: SD(0x0f),
  i16x8ExtractLaneU: (lane) => SD(0x19, lane),
  i8x16Eq: SD(0x23), i8x16GtS: SD(0x27),
  i16x8Eq: SD(0x2d), i16x8GtS: SD(0x31),
  i32x4Eq: SD(0x37), i32x4GtS: SD(0x3b),
  v128And: SD(0x4e), v128Andnot: SD(0x4f), v128Or: SD(0x50), v128Xor: SD(0x51),
  i8x16Bitmask: SD(0x64), i32x4Bitmask: SD(0xa4),
  i8x16NarrowI16x8S: SD(0x65), i8x16NarrowI16x8U: SD(0x66), i16x8NarrowI32x4S: SD(0x85),
  i8x16Shl: SD(0x6b), i8x16ShrS: SD(0x6c), i8x16ShrU: SD(0x6d),
  i8x16Add: SD(0x6e), i8x16Sub: SD(0x71),
  i16x8Shl: SD(0x8b), i16x8ShrS: SD(0x8c), i16x8ShrU: SD(0x8d),
  i16x8Add: SD(0x8e), i16x8Sub: SD(0x91), i16x8Mul: SD(0x95),
  i32x4Shl: SD(0xab), i32x4ShrS: SD(0xac), i32x4ShrU: SD(0xad),
  i32x4Add: SD(0xae), i32x4Sub: SD(0xb1),
  i64x2Shl: SD(0xcb), i64x2ShrU: SD(0xcd),
  i64x2Add: SD(0xce), i64x2Sub: SD(0xd1),
  blockVoid: [0x02, 0x40],
  loopVoid: [0x03, 0x40],
  ifVoid: [0x04, 0x40],
  else_: [0x05],
  br: (depth) => [0x0c, ...uLEB(depth)],
  brTable: (targets, dflt) => [0x0e, ...uLEB(targets.length), ...targets.flatMap((t) => uLEB(t)), ...uLEB(dflt)],
  call: (funcIdx) => [0x10, ...uLEB(funcIdx)],
  end: [0x0b],
};

// The imported host-call function's index. When the module imports
// (import "env" "hostCall" (func (param i64) (result i32))) that import is
// function index 0, so the module's OWN defined function becomes index 1.
const HOST_FUNC_INDEX = 0;

// Local layout. Twenty-four i64 slots: g0..g15 = the guest GPRs, then eight
// scratch temporaries; seven i32 slots hold the six flags plus one scratch.
const T = { a: 16, b: 17, r: 18, cin: 19, s1: 20, s2: 21 };
const F = { cf: 24, pf: 25, af: 26, zf: 27, sf: 28, of: 29, i: 30 };
const I64_LOCAL_COUNT = 24;
const I32_LOCAL_COUNT = 7;

// The multi-block function module reuses every i64/i32 local above and appends
// three i32 dispatch locals: the current guest-block index the loop switches on,
// the remaining iteration budget, and the run status the function returns.
const D = { blk: 31, iter: 32, status: 33 };
// The multi-region address-translation locals (used only by the function path):
// FAULT records an access that landed in NO mapped region (an honest fallback,
// never a wrapped/wrong access); DISP.off is the resolved compact byte offset,
// DISP.matched whether a region claimed the address, DISP.va the guest VA under
// test (reuses i64 scratch slot 22, unused by the T/register file). The compact
// map packs every guest region back-to-back in ONE 32-bit WASM memory, so a
// truly-computed pointer resolves through a small inline region dispatch.
const FAULT = 34;
const DISP = { off: 35, matched: 36, va: 22 };
// The RESUME-RIP local (i64 slot 23, the last free one). It always holds the
// guest virtual address at which the INTERPRETER would continue if the module
// stopped right now: the entry VA on seed, the start VA of the block a branch
// dispatches to, the address a RET popped, and — at a mid-run exit — the exact
// address the host must resume interpretation from. At an INDIRECT transfer it is
// the transfer instruction's OWN address: the module stops before it and lets the
// interpreter perform it (see the terminator for why that judgement is not the
// module's to make). It is flushed to the
// `ripBase` scratch slot once, on the way out through $exit, so maintaining it
// costs a single local.set per guest branch and no memory traffic in the loop.
const RIP = 23;
const I32_LOCAL_COUNT_FN = 13;
// Status codes the exported run() returns (multi-block path). The split that
// matters to a host is RESUMABLE vs DISCARD, so it is encoded in the status
// itself rather than left for the caller to infer:
//
//   OK       — the guest RET unwound the entry frame. Terminal, bit-exact.
//   BUDGET   — the iteration cap fired at a block boundary, BEFORE that block ran.
//              Every architectural surface is a state the interpreter could have
//              produced, so the run is RESUMABLE at resumeRip.
//   FALLBACK — a clean, mid-run hand-back: the return-to-dispatch terminator of an
//              indirect jmp/call, an unhandled import boundary (the module undoes
//              its own return-address push first), an unmatched RET address, and
//              the compile-time fallback module (which runs nothing at all). In
//              every one of those the module's registers/flags/xmm/memory are a
//              valid interpreter state and execution continues at resumeRip, so
//              the run is RESUMABLE.
//   FAULT    — the module touched a guest address NO region maps. The access was
//              redirected to the trap scratch page, so a guest store was LOST and
//              a guest load returned a value that is not the guest's. The
//              end-of-run state is therefore NOT a state interpretation could
//              produce: resumeRip is only meaningful against the PRE-run state and
//              the host MUST DISCARD the whole run and re-interpret from the entry.
//              Committing a FAULT run silently corrupts the guest.
//
// `runFunction` surfaces the distinction as `resumable` (false only for FAULT), so
// a host never has to re-derive it from a status name.
const STATUS_OK = 0;
const STATUS_BUDGET = 1;
const STATUS_FALLBACK = 2;
const STATUS_FAULT = 3;

const SUPPORTED_ALU = new Set(["add", "adc", "sbb", "sub", "cmp", "and", "test", "or", "xor"]);
const SUPPORTED_SHIFT = new Set(["shl", "shr", "sar"]);
const EMITTABLE = new Set(["nop", "mov", "movzx", "movsx", "movsxd", "lea", "alu", "shift", "inc", "dec", "neg", "not", "imul2", "imul3", "push", "pop"]);

// The lane-width → v128 opcode grid for the packed-integer arithmetic/compare/
// shift ops. Keyed by the same laneWidthBit lib/lift64.mjs's SSE_PACKED carries,
// so the WASM lane math matches the interpreter's lane math exactly.
const V_ADD = { 8: I.i8x16Add, 16: I.i16x8Add, 32: I.i32x4Add, 64: I.i64x2Add };
const V_SUB = { 8: I.i8x16Sub, 16: I.i16x8Sub, 32: I.i32x4Sub, 64: I.i64x2Sub };
const V_EQ = { 8: I.i8x16Eq, 16: I.i16x8Eq, 32: I.i32x4Eq };
const V_GTS = { 8: I.i8x16GtS, 16: I.i16x8GtS, 32: I.i32x4GtS };
const V_SHL = { 8: I.i8x16Shl, 16: I.i16x8Shl, 32: I.i32x4Shl, 64: I.i64x2Shl };
const V_SHRU = { 8: I.i8x16ShrU, 16: I.i16x8ShrU, 32: I.i32x4ShrU, 64: I.i64x2ShrU };
const V_SHRS = { 8: I.i8x16ShrS, 16: I.i16x8ShrS, 32: I.i32x4ShrS };

// The SSE/SSE2 (+ a few SSE3 mov) node.sseOp kinds the codegen emits as real
// v128 SIMD (or bit-exact integer for the scalar/transfer moves). Every op here
// matches lib/lift64.mjs executeSse per lane, all 128 bits. The float horizontal/
// interleaved ops (hadd/hsub/addsub) stay HONEST named fallbacks — WASM cannot
// express their exact IEEE lane pairing 1:1 without risking a NaN-bit divergence.
const SSE_EMITTABLE = new Set([
  "mov128", "movss", "movsd", "movq_load", "movq_store", "movd_load", "movd_store",
  "bitwise", "pshufd", "pshuflw", "pshufhw", "padd", "psub", "pcmpeq", "pcmpgt",
  "pmullw", "pmuludq", "punpckl", "punpckh", "packsswb", "packssdw", "packuswb",
  "psll", "psrl", "psra", "pslldq", "psrldq", "movmskps", "pmovmskb", "pextrw",
  "movlp_load", "movhp_load", "movlp_store", "movhp_store", "movhlps", "movlhps",
  "movddup", "movsldup", "movshdup",
]);

// The reason a body node cannot be emitted, or null when it can. Control nodes
// (jcc/jmp/ret) never reach here — they are block terminators, not body ops.
function nodeSupport(node) {
  if (!node.served) return "not_served";
  if (node.op === "sse") return SSE_EMITTABLE.has(node.sseOp) ? null : `sse_${node.sseOp}`;
  if ((node.op === "imul2" || node.op === "imul3") && node.size === 64) return "imul64_overflow";
  if (node.op === "shift" && !SUPPORTED_SHIFT.has(node.shiftOp)) return `rotate_${node.shiftOp}`;
  if (node.op === "alu" && !SUPPORTED_ALU.has(node.aluOp)) return `alu_${node.aluOp}`;
  if (!EMITTABLE.has(node.op)) return "unsupported_op";
  return null;
}

// The reason an INDIRECT jmp/call's target operand cannot be computed bit-exactly,
// or null when it can. The 0xFF /2 and /4 forms carry the target in a plain modrm
// rm operand: a 64-bit register (read straight out of the guest register file) or
// a 64-bit memory operand (the SAME base+index*scale+disp / rip-relative address
// the rest of the codegen emits, translated through the SAME region map). Anything
// else — the 0x66 16-bit operand-size form, or an rm width the addressing path
// does not model — stays an honest, named compile-time fallback.
function indirectSupport(node) {
  const src = node.src;
  if (!src) return "control_indirect_no_operand";
  if (node.size !== 64) return `control_indirect_operand_size_${node.size}`;
  if (src.kind === "reg") return src.size === 64 && !src.high8 ? null : `control_indirect_reg_size_${src.size}`;
  if (src.kind === "mem") return src.size === 64 ? null : `control_indirect_mem_size_${src.size}`;
  return `control_indirect_operand_${src.kind}`;
}

function coverKey(node) {
  if (node.op === "sse") return `sse:${node.sseOp}`;
  return node.op === "alu" ? `alu:${node.aluOp}` : node.op === "shift" ? `shift:${node.shiftOp}` : node.op;
}

// Builds the per-op WASM emitters over a `push` sink and the image load base.
// Shared verbatim by the single-block (compileBlock) and multi-block
// (compileFunction) paths so neither can diverge from the other's semantics.
// Returns emitNode (one straight-line IR op), emitRet (the RET rsp fixup), and
// emitCondition (a guest condition code → i32 boolean from the flag locals,
// bit-exact with lib/lift64.mjs conditionHolds).
function createEmitter(push, loadBase, xmmBase = 0, plan = null) {
  // The compact region map (or null → the historical single flat region, where a
  // guest VA maps to `VA − loadBase`). When multi-region, each guest access is
  // translated through emitToOffset below.
  const multi = plan !== null && plan.multi;
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

  // Converts the guest virtual address on the stack (i64) into an i32 compact
  // WASM-memory byte offset. In the single flat region this is the historical
  // `VA − loadBase` (no branching). In the multi-region map it is a small inline
  // region dispatch: for each region compare VA against [base, base+size) and, on
  // a hit, compute `wasmOffset + (VA − base)`; a VA that hits NO region sets the
  // FAULT flag and resolves to the trap scratch page, so the run reports an honest
  // fallback and never reads or writes a wrong/wrapped guest byte.
  const emitToOffset = () => {
    if (!multi) {
      push(I.i64Const(plan ? plan.fastBase : loadBase)); push(I.i64Sub); push(I.i32WrapI64);
      if (plan && plan.fastOffset) { push(I.i32Const(plan.fastOffset)); push(I.i32Add); }
      return;
    }
    push(I.localSet(DISP.va));
    push(I.i32Const(0)); push(I.localSet(DISP.matched));
    push(I.i32Const(plan.trapOffset)); push(I.localSet(DISP.off));
    for (const r of plan.region) {
      push(I.localGet(DISP.va)); push(I.i64Const(r.base)); push(I.i64GeU);
      push(I.localGet(DISP.va)); push(I.i64Const(BigInt.asUintN(64, r.base + BigInt(r.size)))); push(I.i64LtU);
      push(I.i32And);
      push(I.ifVoid);
      push(I.localGet(DISP.va)); push(I.i64Const(r.base)); push(I.i64Sub); push(I.i32WrapI64);
      if (r.wasmOffset) { push(I.i32Const(r.wasmOffset)); push(I.i32Add); }
      push(I.localSet(DISP.off));
      push(I.i32Const(1)); push(I.localSet(DISP.matched));
      push(I.end);
    }
    push(I.localGet(DISP.matched)); push(I.i32Eqz); push(I.ifVoid);
    push(I.i32Const(1)); push(I.localSet(FAULT));
    push(I.end);
    push(I.localGet(DISP.off));
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

  // ---- SSE / SSE2 emitters (bit-exact per lane with lib/lift64.mjs executeSse) ----
  //
  // The sixteen xmm registers live as 16-byte little-endian slots in a scratch
  // region of the SAME exported memory the GPR file uses (xmmBase + index*16). A
  // v128 loaded from those bytes aliases the interpreter's little-endian lane
  // packing exactly (i8x16 lane 0 = low byte, i32x4 lane 0 = low dword, …), so the
  // v128 lane opcodes below compute the identical 128-bit result the oracle does.
  const xmmAddr = (idx) => xmmBase + idx * 16;
  const ZERO16 = new Array(16).fill(0);

  // Pushes an operand as a v128 (an xmm slot, or an m128 at its guest address).
  const emitReadV128 = (op, node) => {
    if (op.kind === "xmm") { push(I.i32Const(xmmAddr(op.index))); push(I.v128Load); return; }
    emitEffectiveAddress(op, node); emitToOffset(); push(I.v128Load);
  };
  // Pushes ONLY the destination byte address (for a trailing v128.store).
  const emitV128DstAddr = (op, node) => {
    if (op.kind === "xmm") { push(I.i32Const(xmmAddr(op.index))); return; }
    emitEffectiveAddress(op, node); emitToOffset();
  };
  // Pushes an integer sub-lane load (byteOff into an xmm slot, or into an m64/m128).
  const emitLoadIntAt = (op, node, byteOff, loadOp) => {
    if (op.kind === "xmm") push(I.i32Const(xmmAddr(op.index) + byteOff));
    else { emitEffectiveAddress(op, node); emitToOffset(); if (byteOff) { push(I.i32Const(byteOff)); push(I.i32Add); } }
    push(loadOp);
  };
  // Stores an i64 already in a local to the low or high 64-bit half of an xmm slot.
  const emitStoreXmm64 = (idx, byteOff, local) => {
    push(I.i32Const(xmmAddr(idx) + byteOff)); push(I.localGet(local)); push(I.i64Store);
  };

  const emitSse = (node) => {
    const s = node.sseOp;
    const dst = node.dst;
    const src = node.src;
    switch (s) {
      case "mov128":
        emitV128DstAddr(dst, node); emitReadV128(src, node); push(I.v128Store);
        return;
      case "movss": case "movsd": {
        const bits = s === "movss" ? 32 : 64;
        const loadOp = bits === 32 ? I.i64Load32u : I.i64Load;
        const storeOp = bits === 32 ? I.i64Store32 : I.i64Store;
        if (dst.kind === "mem") {
          emitEffectiveAddress(dst, node); emitToOffset();
          push(I.i32Const(xmmAddr(src.index))); push(loadOp); push(storeOp);
          return;
        }
        if (src.kind === "xmm") {
          // reg→reg: merge the low lane, preserve the upper bits of dst.
          push(I.i32Const(xmmAddr(dst.index)));
          push(I.i32Const(xmmAddr(src.index))); push(loadOp); push(storeOp);
          return;
        }
        // load from memory zero-fills the rest of the register.
        push(I.i32Const(xmmAddr(dst.index)));
        emitEffectiveAddress(src, node); emitToOffset(); push(loadOp); push(I.i64Store);
        push(I.i32Const(xmmAddr(dst.index) + 8)); push(I.i64Const(0n)); push(I.i64Store);
        return;
      }
      case "movd_load": {
        emitReadOperand(src, node); push(I.localSet(T.r));
        emitStoreXmm64(dst.index, 0, T.r);
        push(I.i32Const(xmmAddr(dst.index) + 8)); push(I.i64Const(0n)); push(I.i64Store);
        return;
      }
      case "movd_store": {
        push(I.i32Const(xmmAddr(src.index))); push(node.width === 64 ? I.i64Load : I.i64Load32u); push(I.localSet(T.r));
        emitWriteOperandFrom(dst, node, T.r);
        return;
      }
      case "movq_load": {
        emitLoadIntAt(src, node, 0, I.i64Load); push(I.localSet(T.r));
        emitStoreXmm64(dst.index, 0, T.r);
        push(I.i32Const(xmmAddr(dst.index) + 8)); push(I.i64Const(0n)); push(I.i64Store);
        return;
      }
      case "movq_store": {
        push(I.i32Const(xmmAddr(src.index))); push(I.i64Load); push(I.localSet(T.r));
        if (dst.kind === "xmm") {
          emitStoreXmm64(dst.index, 0, T.r);
          push(I.i32Const(xmmAddr(dst.index) + 8)); push(I.i64Const(0n)); push(I.i64Store);
        } else {
          emitEffectiveAddress(dst, node); emitToOffset(); push(I.localGet(T.r)); push(I.i64Store);
        }
        return;
      }
      case "bitwise": {
        emitV128DstAddr(dst, node);
        const logic = node.logic;
        if (logic === "andnps" || logic === "pandn") {
          // (~dst & src) == andnot(src, dst) == src & ~dst.
          emitReadV128(src, node); emitReadV128(dst, node); push(I.v128Andnot);
        } else {
          emitReadV128(dst, node); emitReadV128(src, node);
          push(logic === "andps" || logic === "pand" ? I.v128And : logic === "orps" || logic === "por" ? I.v128Or : I.v128Xor);
        }
        push(I.v128Store);
        return;
      }
      case "pshufd": {
        const lane = [];
        for (let j = 0; j < 4; j += 1) { const sel = Number((node.imm >> BigInt(2 * j)) & 3n); for (let b = 0; b < 4; b += 1) lane.push(4 * sel + b); }
        emitV128DstAddr(dst, node); emitReadV128(src, node); emitReadV128(src, node); push(I.i8x16Shuffle(lane)); push(I.v128Store);
        return;
      }
      case "pshuflw": {
        const lane = [];
        for (let j = 0; j < 4; j += 1) { const sel = Number((node.imm >> BigInt(2 * j)) & 3n); lane.push(2 * sel, 2 * sel + 1); }
        for (let b = 8; b < 16; b += 1) lane.push(b);
        emitV128DstAddr(dst, node); emitReadV128(src, node); emitReadV128(src, node); push(I.i8x16Shuffle(lane)); push(I.v128Store);
        return;
      }
      case "pshufhw": {
        const lane = [];
        for (let b = 0; b < 8; b += 1) lane.push(b);
        for (let j = 0; j < 4; j += 1) { const sel = 4 + Number((node.imm >> BigInt(2 * j)) & 3n); lane.push(2 * sel, 2 * sel + 1); }
        emitV128DstAddr(dst, node); emitReadV128(src, node); emitReadV128(src, node); push(I.i8x16Shuffle(lane)); push(I.v128Store);
        return;
      }
      case "padd": case "psub": case "pcmpeq": case "pcmpgt": case "pmullw": {
        const w = node.w;
        const op = s === "padd" ? V_ADD[w] : s === "psub" ? V_SUB[w] : s === "pcmpeq" ? V_EQ[w] : s === "pcmpgt" ? V_GTS[w] : I.i16x8Mul;
        emitV128DstAddr(dst, node); emitReadV128(dst, node); emitReadV128(src, node); push(op); push(I.v128Store);
        return;
      }
      case "pmuludq": {
        // dst.dword0 * src.dword0 (low 64) | dst.dword2 * src.dword2 (high 64).
        emitLoadIntAt(dst, node, 0, I.i64Load32u); emitLoadIntAt(src, node, 0, I.i64Load32u); push(I.i64Mul); push(I.localSet(T.a));
        emitLoadIntAt(dst, node, 8, I.i64Load32u); emitLoadIntAt(src, node, 8, I.i64Load32u); push(I.i64Mul); push(I.localSet(T.s1));
        emitStoreXmm64(dst.index, 0, T.a); emitStoreXmm64(dst.index, 8, T.s1);
        return;
      }
      case "punpckl": case "punpckh": {
        const w = node.w;
        const bpl = w / 8;
        const half = 64 / w;
        const base = s === "punpckh" ? half : 0;
        const lane = [];
        for (let i = 0; i < half; i += 1) {
          for (let b = 0; b < bpl; b += 1) lane.push((base + i) * bpl + b);        // from dst (0..15)
          for (let b = 0; b < bpl; b += 1) lane.push(16 + (base + i) * bpl + b);   // from src (16..31)
        }
        emitV128DstAddr(dst, node); emitReadV128(dst, node); emitReadV128(src, node); push(I.i8x16Shuffle(lane)); push(I.v128Store);
        return;
      }
      case "packsswb": case "packssdw": case "packuswb": {
        // The interpreter packs only the LOW 64 bits of each operand (dst then
        // src) into the low half of the result, zeroing the high half. WASM
        // narrow instead saturates all eight source lanes of BOTH operands, so
        // first gather dst.low64 ‖ src.low64 into one v128, then narrow it against
        // a zero operand — the high half then narrows to zero, matching the oracle.
        const op = s === "packssdw" ? I.i16x8NarrowI32x4S : s === "packuswb" ? I.i8x16NarrowI16x8U : I.i8x16NarrowI16x8S;
        const gather = [0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23];
        emitV128DstAddr(dst, node);
        emitReadV128(dst, node); emitReadV128(src, node); push(I.i8x16Shuffle(gather));
        push(I.v128Const(ZERO16));
        push(op);
        push(I.v128Store);
        return;
      }
      case "psll": case "psrl": case "psra": {
        const w = node.w;
        const shiftOp = (s === "psll" ? V_SHL : s === "psrl" ? V_SHRU : V_SHRS)[w];
        emitV128DstAddr(dst, node);
        if (node.imm !== undefined) {
          const cnt = node.imm;
          if (s === "psra") {
            const eff = cnt >= BigInt(w) ? w - 1 : Number(cnt);
            emitReadV128(dst, node); push(I.i32Const(eff)); push(shiftOp);
          } else if (cnt >= BigInt(w)) {
            push(I.v128Const(ZERO16));
          } else {
            emitReadV128(dst, node); push(I.i32Const(Number(cnt))); push(shiftOp);
          }
          push(I.v128Store);
          return;
        }
        // Register count: the low 64 bits of src. WASM iNxM shifts mask the count
        // to the lane width, so a count >= width must be clamped (psra) or zeroed
        // (psll/psrl) to match the interpreter's saturating semantics.
        emitLoadIntAt(src, node, 0, I.i64Load); push(I.localSet(T.cin));
        if (s === "psra") {
          emitReadV128(dst, node);
          push(I.i32Const(w - 1));
          push(I.localGet(T.cin)); push(I.i32WrapI64);
          push(I.localGet(T.cin)); push(I.i64Const(BigInt(w))); push(I.i64GeU);
          push(I.i32Select); // big ? (w-1) : count
          push(shiftOp);
        } else {
          emitReadV128(dst, node);
          push(I.localGet(T.cin)); push(I.i32WrapI64);
          push(shiftOp);
          // mask = (count < w) ? 0xFF.. : 0x00 → AND the raw shift.
          push(I.i32Const(0));
          push(I.localGet(T.cin)); push(I.i64Const(BigInt(w))); push(I.i64GeU); push(I.i32Eqz); // small
          push(I.i32Sub_); // 0 - small
          push(I.i8x16Splat);
          push(I.v128And);
        }
        push(I.v128Store);
        return;
      }
      case "pslldq": case "psrldq": {
        const n = Number(node.imm);
        const lane = [];
        for (let i = 0; i < 16; i += 1) {
          const from = s === "pslldq" ? i - n : i + n;
          lane.push(s === "pslldq" ? (from >= 0 ? 16 + from : 0) : (from < 16 ? 16 + from : 0));
        }
        emitV128DstAddr(dst, node); push(I.v128Const(ZERO16)); emitReadV128(dst, node); push(I.i8x16Shuffle(lane)); push(I.v128Store);
        return;
      }
      case "movmskps": case "pmovmskb": {
        emitReadV128(src, node);
        push(s === "movmskps" ? I.i32x4Bitmask : I.i8x16Bitmask);
        push(I.i64ExtendI32U); push(I.localSet(T.r));
        emitWriteRegFrom(dst, T.r);
        return;
      }
      case "pextrw": {
        emitReadV128(src, node);
        push(I.i16x8ExtractLaneU(Number(node.imm & 7n)));
        push(I.i64ExtendI32U); push(I.localSet(T.r));
        emitWriteRegFrom(dst, T.r);
        return;
      }
      case "movlp_load": {
        push(I.i32Const(xmmAddr(dst.index)));
        emitEffectiveAddress(src, node); emitToOffset(); push(I.i64Load); push(I.i64Store);
        return;
      }
      case "movhp_load": {
        push(I.i32Const(xmmAddr(dst.index) + 8));
        emitEffectiveAddress(src, node); emitToOffset(); push(I.i64Load); push(I.i64Store);
        return;
      }
      case "movlp_store": {
        emitEffectiveAddress(dst, node); emitToOffset();
        push(I.i32Const(xmmAddr(src.index))); push(I.i64Load); push(I.i64Store);
        return;
      }
      case "movhp_store": {
        emitEffectiveAddress(dst, node); emitToOffset();
        push(I.i32Const(xmmAddr(src.index) + 8)); push(I.i64Load); push(I.i64Store);
        return;
      }
      case "movhlps": {
        push(I.i32Const(xmmAddr(dst.index)));
        push(I.i32Const(xmmAddr(src.index) + 8)); push(I.i64Load); push(I.i64Store);
        return;
      }
      case "movlhps": {
        push(I.i32Const(xmmAddr(dst.index) + 8));
        push(I.i32Const(xmmAddr(src.index))); push(I.i64Load); push(I.i64Store);
        return;
      }
      case "movddup": {
        emitLoadIntAt(src, node, 0, I.i64Load); push(I.localSet(T.r));
        emitStoreXmm64(dst.index, 0, T.r); emitStoreXmm64(dst.index, 8, T.r);
        return;
      }
      case "movsldup": case "movshdup": {
        const map = s === "movsldup" ? [0, 0, 2, 2] : [1, 1, 3, 3];
        const lane = [];
        for (const sel of map) for (let b = 0; b < 4; b += 1) lane.push(4 * sel + b);
        emitV128DstAddr(dst, node); emitReadV128(src, node); emitReadV128(src, node); push(I.i8x16Shuffle(lane)); push(I.v128Store);
        return;
      }
      default:
        throw new Error(`wasm64: no SSE emitter for ${s}`);
    }
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
      case "sse": emitSse(node); break;
      default: throw new Error(`wasm64: no emitter for op ${node.op}`);
    }
  };

  // Leaves an i32 boolean (0/1) on the stack: whether guest condition code `cc`
  // holds over the current flag locals. Mirrors lib/lift64.mjs conditionHolds.
  const emitCondition = (cc) => {
    const gf = (name) => push(I.localGet(F[name]));
    switch (cc) {
      case 0: gf("of"); break;                                             // o
      case 1: gf("of"); push(I.i32Eqz); break;                             // no
      case 2: gf("cf"); break;                                             // b
      case 3: gf("cf"); push(I.i32Eqz); break;                             // ae
      case 4: gf("zf"); break;                                             // e
      case 5: gf("zf"); push(I.i32Eqz); break;                             // ne
      case 6: gf("cf"); gf("zf"); push(I.i32Or); break;                    // be
      case 7: gf("cf"); gf("zf"); push(I.i32Or); push(I.i32Eqz); break;    // a
      case 8: gf("sf"); break;                                             // s
      case 9: gf("sf"); push(I.i32Eqz); break;                             // ns
      case 10: gf("pf"); break;                                            // p
      case 11: gf("pf"); push(I.i32Eqz); break;                            // np
      case 12: gf("sf"); gf("of"); push(I.i32Ne); break;                   // l
      case 13: gf("sf"); gf("of"); push(I.i32Eq); break;                   // ge
      case 14: gf("zf"); gf("sf"); gf("of"); push(I.i32Ne); push(I.i32Or); break;                 // le
      default: gf("zf"); gf("sf"); gf("of"); push(I.i32Ne); push(I.i32Or); push(I.i32Eqz); break; // g
    }
  };

  return { emitNode, emitRet, emitCondition, emitToOffset, emitReadOperand };
}

// Builds the COMPACT MULTI-REGION map for one run. The real runtime's guest space
// is sparse (image at ~0x140000000, a high stack at ~0x7ff000000000, TEB/PEB, an
// HLE arena at ~0xF8000000, thunk pages) — far too wide for a flat 32-bit WASM
// memory. This packs each mapped region back-to-back into ONE 32-bit WASM memory
// (region 0 at wasmOffset 0, region 1 next, …), then a trap scratch page, then the
// register-file / flag / xmm scratch. Total compact size is small (image + a 1 MiB
// stack + TEB + arena tens of MiB), so `ceil(total / 65536)` pages fit a 32-bit
// memory. Without option.region the plan is the degenerate SINGLE flat region
// (image+stack contiguous at loadBase) — byte-for-byte the historical layout, so a
// guest VA still maps to `VA − loadBase` with no dispatch and every existing test
// path is unchanged.
//
// A region is { base (guest VA), size (byte), kind, init? }. `kind: "image"` is
// seeded from the guest image; `kind: "stack"` supplies the initial rsp / entry
// sentinel; any other region is zero-filled unless `init` bytes are given.
function buildRegionPlan(option, loadBase, guestLen) {
  const userRegion = option.region;
  if (!userRegion || userRegion.length === 0) {
    const regBase = (guestLen + 7) & ~7;
    const flagBase = regBase + 16 * 8;
    const xmmBase = (flagBase + 8 + 15) & ~15;
    const ripBase = xmmBase + 16 * 16; // 8-byte resume-rip slot (16-aligned + 256)
    const scratchEnd = ripBase + 8;
    const region = [{ base: loadBase, size: guestLen, wasmOffset: 0, kind: "flat" }];
    const plan = {
      multi: false, region,
      fastBase: loadBase, fastOffset: 0, trapOffset: 0,
      regBase, flagBase, xmmBase, ripBase, pages: Math.ceil(scratchEnd / 65536),
      stackRegionIndex: 0, imageRegionIndex: 0,
      stackTop: loadBase + BigInt(guestLen - 16),
    };
    plan.translateJs = (addr) => {
      const a = BigInt.asUintN(64, BigInt(addr));
      return a >= loadBase && a < loadBase + BigInt(guestLen) ? Number(a - loadBase) : null;
    };
    return plan;
  }

  const region = [];
  let cursor = 0;
  let stackRegionIndex = -1;
  let imageRegionIndex = -1;
  userRegion.forEach((r, i) => {
    const base = BigInt.asUintN(64, BigInt(r.base));
    const size = Number(r.size);
    region.push({ base, size, wasmOffset: cursor, kind: r.kind ?? "region", init: r.init });
    if (r.kind === "stack") stackRegionIndex = i;
    if (r.kind === "image") imageRegionIndex = i;
    cursor = (cursor + size + 15) & ~15;
  });
  const trapOffset = cursor;
  cursor = (cursor + 16 + 7) & ~7;
  const regBase = cursor;
  const flagBase = regBase + 16 * 8;
  const xmmBase = (flagBase + 8 + 15) & ~15;
  const ripBase = xmmBase + 16 * 16; // 8-byte resume-rip slot (16-aligned + 256)
  const scratchEnd = ripBase + 8;
  const single = region.length === 1 && region[0].wasmOffset === 0 && region[0].base === loadBase;
  const stk = stackRegionIndex >= 0 ? region[stackRegionIndex] : region[0];
  const plan = {
    multi: !single, region,
    fastBase: region[0].base, fastOffset: region[0].wasmOffset, trapOffset,
    regBase, flagBase, xmmBase, ripBase, pages: Math.ceil(scratchEnd / 65536),
    stackRegionIndex: stackRegionIndex >= 0 ? stackRegionIndex : 0,
    imageRegionIndex,
    stackTop: BigInt.asUintN(64, stk.base + BigInt(stk.size - 16)),
  };
  plan.translateJs = (addr) => {
    const a = BigInt.asUintN(64, BigInt(addr));
    for (const r of region) if (a >= r.base && a < BigInt.asUintN(64, r.base + BigInt(r.size))) return r.wasmOffset + Number(a - r.base);
    return null;
  };
  return plan;
}

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
  const xmmBase = (flagBase + 8 + 15) & ~15; // 16-byte aligned xmm scratch region
  const ripBase = xmmBase + 16 * 16; // 8-byte resume-rip slot (16-aligned + 256)
  const scratchEnd = ripBase + 8;
  const pages = Math.ceil(scratchEnd / 65536);

  const body = [];
  const push = (bytes) => { for (const b of bytes) body.push(b); };
  const { emitNode, emitRet, emitToOffset } = createEmitter(push, loadBase, xmmBase);

  // ---- prologue: hydrate GPRs + flags from the scratch region ----
  emitPrologue(push, regBase, flagBase);

  // ---- body: emit the straight-line prefix ----
  const emitted = new Set();
  const unsupported = [];
  let blockLength = 0;
  // The guest VA the INTERPRETER continues at once this module stops. It advances
  // past every instruction the codegen emits, so when the prefix stops early it is
  // the address of the first instruction the codegen could NOT emit; when the
  // prefix ends at a RET it is the address that RET popped (emitted below).
  let resumeRva = block.start_rva ?? (block.node[0]?.address ?? 0);
  let resumeFromRet = false;
  for (const node of block.node) {
    resumeRva = node.address ?? resumeRva;
    if (!node.served) { unsupported.push({ op: node.op, mnemonic: node.mnemonic, reason: "not_served" }); break; }
    if (node.op === "ret") {
      // Read the return address at [rsp] into the rip slot BEFORE emitRet moves
      // rsp — that value is exactly what the interpreter assigns to machine.rip.
      push(I.i32Const(ripBase));
      push(I.localGet(4)); emitToOffset(); push(I.i64Load);
      push(I.i64Store);
      resumeFromRet = true;
      emitRet(node); emitted.add("ret"); blockLength += 1; break;
    }
    if (node.control && node.control !== "none") { unsupported.push({ op: node.op, mnemonic: node.mnemonic, reason: "control_flow" }); break; }
    const reason = nodeSupport(node);
    if (reason) { unsupported.push({ op: node.op, mnemonic: node.mnemonic, reason }); break; }
    emitNode(node);
    emitted.add(coverKey(node));
    blockLength += 1;
    resumeRva = node.address + node.length;
  }
  // A non-RET stop resolves to a compile-time-constant resume address.
  if (!resumeFromRet) {
    push(I.i32Const(ripBase));
    push(I.i64Const((loadBase + BigInt(resumeRva)) & MASK64));
    push(I.i64Store);
  }

  // ---- epilogue: write GPRs + flags back to the scratch region ----
  emitEpilogue(push, regBase, flagBase);
  push(I.end);

  const bytes = assembleModule(body, pages, { i32Count: I32_LOCAL_COUNT, returnI32: false });

  return {
    bytes,
    regBase,
    flagBase,
    xmmBase,
    ripBase,
    pages,
    guestLen,
    complete: unsupported.length === 0,
    coverage: { emitted: [...emitted].sort(), unsupported },
    blockLength,
  };
}

// Hydrates the sixteen GPR i64 locals and six flag i32 locals from the scratch
// region at the top of guest memory.
function emitPrologue(push, regBase, flagBase) {
  for (let i = 0; i < 16; i += 1) { push(I.i32Const(regBase + i * 8)); push(I.i64Load); push(I.localSet(i)); }
  FLAG_ORDER.forEach((name, k) => { push(I.i32Const(flagBase + k)); push(I.i32Load8u); push(I.localSet(F[name])); });
}

// Flushes the GPR and flag locals back to the scratch region.
function emitEpilogue(push, regBase, flagBase) {
  for (let i = 0; i < 16; i += 1) { push(I.i32Const(regBase + i * 8)); push(I.localGet(i)); push(I.i64Store); }
  FLAG_ORDER.forEach((name, k) => { push(I.i32Const(flagBase + k)); push(I.localGet(F[name])); push(I.i32Store8); });
}

// -------------------- multi-block control-flow graph --------------------

// Recovers the intra-function CFG from a raw guest image by following control
// flow from the entry RVA: every jcc/jmp/ret splits a block, and every branch
// target (plus the fall-through after a jcc) becomes a block leader. Returns the
// ordered block list (entry first, index 0), a leader→index map, and the decoded
// instruction table. Any shape the codegen does not model (call, indirect
// branch, unserved op, a target outside the image, or a target that is not an
// instruction boundary) is recorded as a block fallback and stops that block.
function buildCfg(decodeStructured, image, entryRva, decodeBudget = 4096, isExternal = () => false) {
  const ins = new Map(); // rva -> decoded node (address-annotated)
  const leader = new Set([entryRva]);
  const work = [entryRva];
  let guard = 0;

  const decodeAt = (rva) => {
    if (ins.has(rva)) return ins.get(rva);
    const node = { ...decodeStructured(image, rva), address: rva };
    ins.set(rva, node);
    return node;
  };

  while (work.length > 0) {
    let rva = work.pop();
    while (rva >= 0 && rva < image.length && guard < decodeBudget) {
      guard += 1;
      if (ins.has(rva)) break; // already decoded this run onward
      const dec = decodeAt(rva);
      const next = rva + dec.length;
      if (!dec.served) break; // unserved: the block ends here as a fallback
      const ctrl = dec.control ?? "none";
      if (ctrl === "none") { rva = next; continue; }
      if (dec.op === "jcc") {
        const taken = next + Number(dec.rel);
        leader.add(next); leader.add(taken);
        if (!ins.has(next)) work.push(next);
        if (taken >= 0 && taken < image.length && !ins.has(taken)) work.push(taken);
      } else if (dec.op === "jmp") {
        const taken = next + Number(dec.rel);
        leader.add(taken);
        if (taken >= 0 && taken < image.length && !ins.has(taken)) work.push(taken);
      } else if (dec.op === "call") {
        // A direct call rel32/rel8: the callee entry (taken) and the return
        // address after the call (next) are both block leaders. Following the
        // callee grows one cross-function CFG; the return address is where the
        // callee's RET dispatches back to. A target outside the image stays a
        // leaderless address that compileFunction resolves as an external call.
        const taken = next + Number(dec.rel);
        leader.add(next);
        if (!ins.has(next)) work.push(next);
        // A call whose target is an HLE import (out of the image, or explicitly
        // marked external) is NOT followed into a callee — it becomes an import
        // boundary. Its return address (next) is still a leader above.
        if (taken >= 0 && taken < image.length && !isExternal(taken)) { leader.add(taken); if (!ins.has(taken)) work.push(taken); }
      }
      // ret / callIndirect / jmpIndirect: no in-function successor to enqueue.
      break;
    }
  }

  const leaderList = [...leader].filter((rva) => rva >= 0 && rva < image.length && ins.has(rva)).sort((a, b) => a - b);
  // Entry must be block index 0 so the dispatch starts there.
  leaderList.sort((a, b) => (a === entryRva ? -1 : b === entryRva ? 1 : a - b));
  const indexOf = new Map(leaderList.map((rva, i) => [rva, i]));
  const leaderSet = new Set(leaderList);

  const block = leaderList.map((startRva) => {
    const bodyNode = [];
    let term = null;
    let rva = startRva;
    for (;;) {
      const dec = ins.get(rva);
      if (!dec) { term = { kind: "fallback", reason: "decode_gap", mnemonic: "(gap)" }; break; }
      if (rva !== startRva && leaderSet.has(rva)) { term = { kind: "fallthrough", target: rva }; break; }
      if (!dec.served) { term = { kind: "fallback", reason: "not_served", mnemonic: dec.mnemonic, op: dec.op }; break; }
      const ctrl = dec.control ?? "none";
      if (ctrl === "none") {
        const reason = nodeSupport(dec);
        if (reason) { term = { kind: "fallback", reason, mnemonic: dec.mnemonic, op: dec.op }; break; }
        bodyNode.push(dec);
        rva += dec.length;
        continue;
      }
      if (dec.op === "ret") { term = { kind: "ret", node: dec }; break; }
      if (dec.op === "jmp") { term = { kind: "jmp", target: rva + dec.length + Number(dec.rel), node: dec }; break; }
      if (dec.op === "jcc") { term = { kind: "jcc", cc: dec.cc, taken: rva + dec.length + Number(dec.rel), fallthrough: rva + dec.length, node: dec }; break; }
      if (dec.op === "call") { term = { kind: "call", target: rva + dec.length + Number(dec.rel), returnRva: rva + dec.length, node: dec }; break; }
      // An INDIRECT transfer is a real terminator: the target is computed at run
      // time, so the module cannot dispatch to it, but it CAN compute it exactly
      // and hand it back as a resume rip (return-to-dispatch). The straight-line
      // code before it still runs on the WASM tier.
      if (dec.op === "jmpIndirect") { term = { kind: "jmpIndirect", node: dec }; break; }
      if (dec.op === "callIndirect") { term = { kind: "callIndirect", returnRva: rva + dec.length, node: dec }; break; }
      // leave and any other computed transfer: an honest named fallback.
      const reasonName = `control_${dec.control}`;
      term = { kind: "fallback", reason: reasonName, mnemonic: dec.mnemonic, op: dec.op };
      break;
    }
    return { startRva, node: bodyNode, term };
  });

  return { block, indexOf, entryIndex: indexOf.get(entryRva) ?? 0 };
}

// Compiles a MULTI-BLOCK guest function starting at `entryRva` into one WASM
// module with a `(block (loop (block…(br_table))))` dispatch over a current-block
// index local. Each guest block emits its straight-line body, then either returns
// (RET), jumps to the taken/fall-through block index (jcc/jmp/fall-through), or —
// for a shape the codegen does not model — makes the whole function an honest
// fallback (complete=false) with a named reason. The loop honours `iterationCap`
// block dispatches: a runaway guest loop stops with a budget-exhausted status
// rather than hanging the module.
export function compileFunction(image, option = {}) {
  const loadBase = BigInt(option.loadBase ?? 0x140000000n);
  const stackSizeByte = option.stackSizeByte ?? 0x10000;
  const guestLen = option.guestLen ?? (image.length + stackSizeByte);
  const entryRva = option.entryRva ?? 0;
  const decodeStructured = option.decodeStructured;
  if (typeof decodeStructured !== "function") throw new TypeError("compileFunction requires option.decodeStructured (from lib/lift64.mjs)");

  // The compact multi-region map (or the degenerate single flat region). All
  // scratch offsets (register file, flags, xmm, the trap page) come from it, and
  // every guest memory access the emitter makes is translated through it.
  const plan = buildRegionPlan(option, loadBase, guestLen);
  const { regBase, flagBase, xmmBase, ripBase, pages } = plan;
  const entryVa = (loadBase + BigInt(entryRva)) & MASK64;

  // An external call boundary (an x86 `call` to an HLE import outside the compiled
  // set) is emitted as a real WASM import call ONLY when a host callback is bound.
  // Without one it stays an honest, named fallback — never a wrong result. A target
  // is external when it is out of the image or explicitly listed in option.externalRva
  // (the latter lets a test place an in-image stub the interpreter runs while the
  // WASM path treats that same address as an import boundary — same image, bit-exact).
  const allowExternal = typeof option.hostCall === "function";
  const externalRva = new Set((option.externalRva ?? []).map(Number));
  const isExternalTarget = (rva) => externalRva.has(rva) || rva < 0 || rva >= image.length;

  const { block, indexOf, entryIndex } = buildCfg(decodeStructured, image, entryRva, 4096, isExternalTarget);
  const N = block.length;
  let usesHost = false;

  // Resolve every terminator to a concrete plan, deciding completeness up front.
  const emitted = new Set();
  const unsupported = [];
  const branchKind = new Set();
  const targetIndex = (rva) => (indexOf.has(rva) ? indexOf.get(rva) : -1);

  // Every direct call's return address (a compile-time-constant guest virtual
  // address) → the block index it resumes at. A RET dispatches by matching the
  // value it popped off the guest stack against this table (or the sentinel).
  const returnTarget = [];

  for (const b of block) {
    for (const node of b.node) emitted.add(coverKey(node));
    const t = b.term;
    if (!t || t.kind === "fallback") {
      unsupported.push({ op: t?.op ?? "(none)", mnemonic: t?.mnemonic ?? "(none)", reason: t?.reason ?? "no_terminator" });
      continue;
    }
    if (t.kind === "ret") { branchKind.add("ret"); emitted.add("ret"); continue; }
    if (t.kind === "jmpIndirect" || t.kind === "callIndirect") {
      // A RETURN-TO-DISPATCH terminator: the module computes the target exactly,
      // reports it as the resume rip, and exits. The function stays complete.
      const reason = indirectSupport(t.node);
      if (reason) { unsupported.push({ op: t.node.op, mnemonic: t.node.mnemonic, reason }); continue; }
      const kind = t.kind === "jmpIndirect" ? "jmp_indirect" : "call_indirect";
      branchKind.add(kind);
      emitted.add(kind);
      continue;
    }
    if (t.kind === "call") {
      const calleeIdx = targetIndex(t.target);
      const returnIdx = targetIndex(t.returnRva);
      if (calleeIdx < 0) {
        // The target is outside the compiled set: an HLE import boundary. With a
        // bound host callback, emit a real WASM import call; without one, stay an
        // honest, named fallback.
        if (!allowExternal) { unsupported.push({ op: "call", mnemonic: t.node.mnemonic, reason: "control_call_external" }); continue; }
        if (returnIdx < 0) { unsupported.push({ op: "call", mnemonic: t.node.mnemonic, reason: "control_call_return_out_of_function" }); continue; }
        t.external = true;
        t.returnIdx = returnIdx;
        usesHost = true;
        branchKind.add("call_external");
        emitted.add("call_external");
        continue;
      }
      if (returnIdx < 0) { unsupported.push({ op: "call", mnemonic: t.node.mnemonic, reason: "control_call_return_out_of_function" }); continue; }
      returnTarget.push({ addr: (loadBase + BigInt(t.returnRva)) & MASK64, index: returnIdx });
      branchKind.add("call");
      emitted.add("call");
      continue;
    }
    if (t.kind === "jmp") {
      const idx = targetIndex(t.target);
      if (idx < 0) { unsupported.push({ op: "jmp", mnemonic: t.node.mnemonic, reason: "jmp_target_out_of_function" }); continue; }
      branchKind.add("jmp");
      continue;
    }
    if (t.kind === "jcc") {
      const takenIdx = targetIndex(t.taken);
      const fallIdx = targetIndex(t.fallthrough);
      if (takenIdx < 0 || fallIdx < 0) { unsupported.push({ op: "jcc", mnemonic: t.node.mnemonic, reason: "jcc_target_out_of_function" }); continue; }
      branchKind.add("jcc");
      continue;
    }
    if (t.kind === "fallthrough") {
      const idx = targetIndex(t.target);
      if (idx < 0) { unsupported.push({ op: "(fallthrough)", mnemonic: "(fallthrough)", reason: "fallthrough_target_out_of_function" }); continue; }
      branchKind.add("fallthrough");
    }
  }

  const complete = unsupported.length === 0;

  // The half-open guest-image byte span this compilation READ: every block's start
  // through the end of its last decoded instruction. A host that caches the compiled
  // module across invocations validates it by re-checking these bytes, so a guest
  // that rewrites its own code can never keep executing a stale module.
  const codeRange = (() => {
    let lo = Infinity;
    let hi = 0;
    for (const b of block) {
      lo = Math.min(lo, b.startRva);
      hi = Math.max(hi, b.startRva);
      for (const node of b.node) hi = Math.max(hi, (node.address ?? 0) + (node.length ?? 0));
      const tn = b.term?.node;
      if (tn) hi = Math.max(hi, (tn.address ?? 0) + (tn.length ?? 0));
    }
    return { startRva: Number.isFinite(lo) ? lo : entryRva, endRva: Math.max(hi, Number.isFinite(lo) ? lo : entryRva) };
  })();

  const body = [];
  const push = (bytes) => { for (const b of bytes) body.push(b); };
  const { emitNode, emitRet, emitCondition, emitToOffset } = createEmitter(push, loadBase, xmmBase, plan);
  const iterationCap = option.iterationCap ?? 1_000_000;
  // The entry-frame sentinel return address, identical to seedState's: a RET that
  // pops it unwound the entry frame and terminates the module (STATUS_OK).
  const sentinel = 0xdead000000000000n | (loadBase & 0xffffn);

  emitPrologue(push, regBase, flagBase);

  if (!complete) {
    // An honest fallback: emit a valid, instantiable module that does nothing but
    // flush the (unchanged) state and report FALLBACK, so the host can detect the
    // unmodelled shape without ever running a wrong result. FALLBACK (resumable),
    // not FAULT: the module executes no guest instruction and touches no guest
    // byte, so its end-of-run state IS the seeded state and resuming at the entry
    // VA is trivially the state interpretation would have at that address.
    push(I.i32Const(STATUS_FALLBACK)); push(I.localSet(D.status));
    // Nothing ran, so the interpreter resumes at the function entry itself.
    push(I.i32Const(ripBase)); push(I.i64Const(entryVa)); push(I.i64Store);
    emitEpilogue(push, regBase, flagBase);
    push(I.localGet(D.status));
    push(I.end);
    return {
      bytes: assembleModule(body, pages, { i32Count: I32_LOCAL_COUNT_FN, returnI32: true, importHostCall: false }),
      regBase, flagBase, xmmBase, ripBase, pages, guestLen, plan,
      complete: false,
      blockCount: N,
      codeRange,
      coverage: { emitted: [...emitted].sort(), unsupported },
      branchKind: [...branchKind].sort(),
      statusCode: { OK: STATUS_OK, BUDGET: STATUS_BUDGET, FALLBACK: STATUS_FALLBACK, FAULT: STATUS_FAULT },
    };
  }

  // Transfers control to guest block `idx`: the dispatch index AND the resume-rip
  // local move together, so RIP always names the block about to execute. Every
  // mid-run exit then reports a resume address without any per-site bookkeeping.
  const blockVa = (idx) => (loadBase + BigInt(block[idx].startRva)) & MASK64;
  const emitGoto = (idx) => {
    push(I.i32Const(idx)); push(I.localSet(D.blk));
    push(I.i64Const(blockVa(idx))); push(I.localSet(RIP));
  };

  // Seed the dispatch: current block = entry, remaining budget = iterationCap.
  emitGoto(entryIndex);
  push(I.i32Const(iterationCap)); push(I.localSet(D.iter));
  if (plan.multi) { push(I.i32Const(0)); push(I.localSet(FAULT)); } // no out-of-region access yet

  // Depth bookkeeping. From inside body_i the enclosing labelled constructs are
  // $case_{i+1..N-1} ((N-1-i) blocks), then $default, then $loop, then $exit.
  const loopDepthFrom = (i) => (N - 1 - i) + 1;   // → $loop
  const exitDepthFrom = (i) => (N - 1 - i) + 2;   // → $exit

  push(I.blockVoid); // $exit
  push(I.loopVoid);  // $loop

  // Iteration budget: if the counter hit zero, record BUDGET and leave via $exit
  // (inside the if, $exit is at depth 2: if=0, loop=1, exit=2).
  push(I.localGet(D.iter)); push(I.i32Eqz); push(I.ifVoid);
  push(I.i32Const(STATUS_BUDGET)); push(I.localSet(D.status));
  push(I.br(2));
  push(I.end);
  push(I.localGet(D.iter)); push(I.i32Const(1)); push(I.i32Sub); push(I.localSet(D.iter));

  // An out-of-region access on the previous dispatch set FAULT: stop honestly with
  // a FAULT status and leave via $exit (depth 2 inside the if) rather than ever
  // acting on a wrapped/wrong address. The faulting access itself was redirected to
  // the trap scratch page, so no wrong guest byte reached a mapped region — but the
  // guest byte it SHOULD have written is gone, so this run is NOT resumable and the
  // host must discard it (STATUS_FAULT, never STATUS_FALLBACK).
  if (plan.multi) {
    push(I.localGet(FAULT)); push(I.ifVoid);
    push(I.i32Const(STATUS_FAULT)); push(I.localSet(D.status));
    push(I.br(2));
    push(I.end);
  }

  // Open $default then $case_{N-1..0}. br_table (inside $case_0) targets $case_i
  // at depth i and $default at depth N.
  push(I.blockVoid); // $default
  for (let k = 0; k < N; k += 1) push(I.blockVoid); // $case_{N-1} … $case_0 (innermost)
  push(I.localGet(D.blk));
  push(I.brTable(Array.from({ length: N }, (_, i) => i), N));
  push(I.end); // end $case_0 → body_0 begins here

  for (let i = 0; i < N; i += 1) {
    const b = block[i];
    for (const node of b.node) emitNode(node);
    // An out-of-region access anywhere in this block's body set FAULT: stop with a
    // FAULT status via $exit BEFORE the terminator commits (a RET terminator
    // exits directly and would otherwise bypass the loop-top fault check). The
    // access was redirected to the trap scratch page, so a guest store was LOST:
    // the run is a DISCARD, not a resume. Inside the if, $exit is one deeper.
    if (plan.multi) {
      push(I.localGet(FAULT)); push(I.ifVoid);
      push(I.i32Const(STATUS_FAULT)); push(I.localSet(D.status));
      push(I.br(exitDepthFrom(i) + 1));
      push(I.end);
    }
    const t = b.term;
    if (t.kind === "ret") {
      // Pop the return address off the guest stack (bit-exact with the interpreter:
      // read [rsp] first, then rsp += 8 + pop), then dispatch on it. The sentinel
      // unwinds the entry frame (OK); a known call-return address resumes that
      // block; anything else is a defensive FALLBACK. Each comparison lives inside
      // its own `if`, so a matching `br` is one deeper than the bare terminator.
      push(I.localGet(4)); emitToOffset(); // stack offset (region-translated)
      push(I.i64Load); push(I.localSet(T.s1)); // s1 = [rsp]
      emitRet(t.node); // rsp += 8 + pop
      // The popped address IS what the interpreter assigns to rip, whatever the
      // dispatch below decides — so it is the resume address for the unmatched
      // case, and identical to the block VA on a matched call-return.
      push(I.localGet(T.s1)); push(I.localSet(RIP));
      push(I.localGet(T.s1)); push(I.i64Const(sentinel)); push(I.i64Eq); push(I.ifVoid);
      push(I.i32Const(STATUS_OK)); push(I.localSet(D.status));
      push(I.br(exitDepthFrom(i) + 1));
      push(I.end);
      for (const rt of returnTarget) {
        push(I.localGet(T.s1)); push(I.i64Const(rt.addr)); push(I.i64Eq); push(I.ifVoid);
        emitGoto(rt.index);
        push(I.br(loopDepthFrom(i) + 1));
        push(I.end);
      }
      // No return address matched (only possible if the guest corrupted its stack):
      // stop honestly with a FALLBACK status rather than dispatching to a wrong block.
      push(I.i32Const(STATUS_FALLBACK)); push(I.localSet(D.status));
      push(I.br(exitDepthFrom(i)));
    } else if (t.kind === "jmpIndirect" || t.kind === "callIndirect") {
      // RETURN TO DISPATCH — a PRE-TRANSFER stop. The block's straight-line body has
      // run; the module now stops immediately BEFORE the indirect instruction, having
      // performed none of its effects, and reports that instruction's own VA as the
      // resume rip. The host commits the state and lets the INTERPRETER execute the
      // one transfer instruction.
      //
      // It is tempting — and it is what this terminator used to do — to compute the
      // target here and resume at it, since the operand emission can read it exactly.
      // That is WRONG, and the PuTTY oracle proves it. An indirect transfer through an
      // IAT slot is not a transfer at all in this runtime: lib/exec64.mjs executeNode
      // returns `import_present` for `call/jmp [iat]` BEFORE any stack effect, and the
      // import machinery serves the symbol. A module that instead pushes a return
      // address and hands back the resolved thunk leaves the guest one qword deeper
      // than interpretation — the exact 8-byte rsp divergence the 1:1 corpus test
      // caught. The module cannot see which slots are import slots, so it must not
      // decide: stopping before the instruction hands that judgement to the one engine
      // that models it, and everything before the transfer still ran at WASM speed.
      //
      // Stopping early also removes two failure modes the target computation created:
      // an unmapped target read (a FAULT that discarded the whole run) and an unmapped
      // return-address push. Nothing is read, nothing is stored, nothing to undo.
      push(I.i64Const((loadBase + BigInt(t.node.address)) & MASK64)); push(I.localSet(RIP));
      push(I.i32Const(STATUS_FALLBACK)); push(I.localSet(D.status));
      push(I.br(exitDepthFrom(i)));
    } else if (t.kind === "call" && t.external) {
      // An HLE import boundary. Push the return address exactly as a normal call
      // (rsp -= 8, store next-rip), SPILL the live register file + flags to the
      // shared memory scratch (so the host sees current guest state), then CALL the
      // imported host function with the target virtual address. The host performs
      // the effect (reading args from regBase/stack, writing e.g. rax back) and
      // returns 0 (handled) or nonzero (unhandled). On unhandled, the whole module
      // returns FALLBACK — never a wrong result. On handled, RELOAD the register
      // file + flags (the host may have changed rax etc.), pop the return address
      // (rsp += 8, matching the callee's RET), and resume at the return block.
      push(I.localGet(4)); push(I.i64Const(8n)); push(I.i64Sub); push(I.localSet(4)); // rsp -= 8
      push(I.localGet(4)); emitToOffset(); // stack offset (region-translated)
      push(I.i64Const((loadBase + BigInt(t.returnRva)) & MASK64)); // return address value
      push(I.i64Store);
      emitEpilogue(push, regBase, flagBase); // spill GPRs + flags for the host to read
      push(I.i64Const((loadBase + BigInt(t.target)) & MASK64)); // target VA as the host arg
      push(I.call(HOST_FUNC_INDEX)); push(I.localSet(F.i)); // status = hostCall(targetVA)
      push(I.localGet(F.i)); push(I.ifVoid); // nonzero → the host did not handle it
      push(I.i32Const(STATUS_FALLBACK)); push(I.localSet(D.status));
      // UNDO the return-address push (rsp += 8) and resume at the CALL itself, so
      // the interpreter re-executes it cleanly — it will push the identical return
      // address back into the identical stack slot, so the bytes stay bit-exact.
      push(I.localGet(4)); push(I.i64Const(8n)); push(I.i64Add); push(I.localSet(4));
      push(I.i64Const((loadBase + BigInt(t.node.address)) & MASK64)); push(I.localSet(RIP));
      push(I.br(exitDepthFrom(i) + 1)); // inside the if, $exit is one deeper
      push(I.end);
      emitPrologue(push, regBase, flagBase); // reload GPRs + flags (host may have changed rax)
      push(I.localGet(4)); push(I.i64Const(8n)); push(I.i64Add); push(I.localSet(4)); // rsp += 8 (pop return addr)
      emitGoto(t.returnIdx);
      push(I.br(loopDepthFrom(i)));
    } else if (t.kind === "call") {
      // Push the return address (rsp -= 8, store next-rip) exactly as the
      // interpreter does, then transfer to the callee's entry block. The callee's
      // RET pops this address and dispatches back via returnTarget.
      push(I.localGet(4)); push(I.i64Const(8n)); push(I.i64Sub); push(I.localSet(4)); // rsp -= 8
      push(I.localGet(4)); emitToOffset(); // stack offset (region-translated)
      push(I.i64Const((loadBase + BigInt(t.returnRva)) & MASK64)); // return address value
      push(I.i64Store);
      emitGoto(indexOf.get(t.target));
      push(I.br(loopDepthFrom(i)));
    } else if (t.kind === "jmp") {
      emitGoto(indexOf.get(t.target));
      push(I.br(loopDepthFrom(i)));
    } else if (t.kind === "fallthrough") {
      emitGoto(indexOf.get(t.target));
      push(I.br(loopDepthFrom(i)));
    } else { // jcc: choose taken vs fall-through from the guest condition
      emitCondition(t.cc); push(I.ifVoid);
      emitGoto(indexOf.get(t.taken));
      push(I.else_);
      emitGoto(indexOf.get(t.fallthrough));
      push(I.end);
      // Inside neither branch now (past the if/end); $loop depth is unchanged.
      push(I.br(loopDepthFrom(i)));
    }
    if (i < N - 1) push(I.end); // end $case_{i+1} → body_{i+1} begins here
  }

  push(I.end); // end $default → default handler begins here
  // Default (an index never assigned by a complete graph): the dispatch invariant
  // is broken, so report FAULT — a DISCARD, never a resume — and leave via $exit
  // (here $loop is depth 0, $exit depth 1). Unreachable in a complete module.
  push(I.i32Const(STATUS_FAULT)); push(I.localSet(D.status));
  push(I.br(1));

  push(I.end); // end $loop
  push(I.end); // end $exit

  // Flush the resume-rip local to its scratch slot on the single way out, so the
  // host reads the guest address interpretation must continue at.
  push(I.i32Const(ripBase)); push(I.localGet(RIP)); push(I.i64Store);
  emitEpilogue(push, regBase, flagBase);
  push(I.localGet(D.status));
  push(I.end); // end function

  return {
    bytes: assembleModule(body, pages, { i32Count: I32_LOCAL_COUNT_FN, returnI32: true, importHostCall: usesHost }),
    regBase, flagBase, xmmBase, ripBase, pages, guestLen, plan,
    complete: true,
    usesHost,
    blockCount: N,
    codeRange,
    coverage: { emitted: [...emitted].sort(), unsupported },
    branchKind: [...branchKind].sort(),
    statusCode: { OK: STATUS_OK, BUDGET: STATUS_BUDGET, FALLBACK: STATUS_FALLBACK, FAULT: STATUS_FAULT },
  };
}

// Hand-assembles the five WASM sections into a complete module: one function that
// owns and exports a single memory, both exported by name. The function type is
// () -> () (single-block path) or () -> i32 (multi-block path, returning the run
// status). `i32Count` selects how many i32 locals the function declares.
function assembleModule(body, pages, option = {}) {
  const i32Count = option.i32Count ?? I32_LOCAL_COUNT;
  const returnI32 = option.returnI32 ?? false;
  const importHostCall = option.importHostCall ?? false;
  const section = (id, payload) => [id, ...uLEB(payload.length), ...payload];
  const nameBytes = (name) => [...uLEB(name.length), ...[...name].map((c) => c.charCodeAt(0))];

  // The run function's type. When a host import is present it gets type index 0
  // ((i64) -> i32) and run takes type index 1; otherwise run is the sole type 0.
  const runResult = returnI32 ? [...uLEB(1), 0x7f] : [...uLEB(0)];
  const runType = [0x60, ...uLEB(0), ...runResult]; // () -> (run result)
  const hostType = [0x60, ...uLEB(1), 0x7e, ...uLEB(1), 0x7f]; // (i64) -> i32

  const typeSection = importHostCall
    ? section(1, [...uLEB(2), ...hostType, ...runType])
    : section(1, [...uLEB(1), ...runType]);

  // When importing the host call it occupies function index 0, so the module's own
  // defined function is index 1 and is what the "run" export names.
  const runFuncIndex = importHostCall ? 1 : 0;
  const runTypeIndex = importHostCall ? 1 : 0;

  const importSection = importHostCall
    ? section(2, [...uLEB(1), ...nameBytes("env"), ...nameBytes("hostCall"), 0x00, ...uLEB(0)])
    : null;

  const funcSection = section(3, [...uLEB(1), ...uLEB(runTypeIndex)]);
  const memSection = section(5, [...uLEB(1), 0x00, ...uLEB(pages)]);
  const exportSection = section(7, [
    ...uLEB(2),
    ...nameBytes("mem"), 0x02, ...uLEB(0),
    ...nameBytes("run"), 0x00, ...uLEB(runFuncIndex),
  ]);

  const localDecl = [
    ...uLEB(2),
    ...uLEB(I64_LOCAL_COUNT), 0x7e,
    ...uLEB(i32Count), 0x7f,
  ];
  const funcBody = [...localDecl, ...body];
  const codeSection = section(10, [...uLEB(1), ...uLEB(funcBody.length), ...funcBody]);

  return Uint8Array.from([
    0x00, 0x61, 0x73, 0x6d,
    0x01, 0x00, 0x00, 0x00,
    ...typeSection,
    ...(importSection ?? []),
    ...funcSection,
    ...memSection,
    ...exportSection,
    ...codeSection,
  ]);
}

// Sets up the same initial architectural state lib/lift64.mjs's interpret() does
// (GPRs zero except rsp near the stack top, the sentinel return address pushed,
// default flags plus caller overrides) inside the module's exported memory,
// returning the DataView/typed-array handles and the derived rsp0. Shared by the
// single-block and multi-block runners so both seed state identically.
function seedState(instance, image, loadBase, stackSizeByte, guestLen, regBase, flagBase, xmmBase, ripBase, entryVa, option) {
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
  for (let i = 0; i < 16; i += 1) view.setBigUint64(regBase + i * 8, reg[i] & MASK64, true);

  const flag = { ...DEFAULT_FLAG, ...(option.flag ?? {}) };
  FLAG_ORDER.forEach((name, k) => { mem[flagBase + k] = flag[name] ? 1 : 0; });

  // The resume-rip slot starts at the entry VA: if the module stopped before
  // executing anything, that is exactly where the interpreter would continue.
  view.setBigUint64(ripBase, BigInt.asUintN(64, entryVa), true);

  // Seed the sixteen xmm registers as 16-byte little-endian slots (same layout the
  // codegen reads/writes as v128). option.xmm is an array (or index→value object)
  // of up to sixteen 128-bit BigInts; unspecified lanes stay zero.
  if (option.xmm) {
    const entry = Array.isArray(option.xmm) ? option.xmm.entries() : Object.entries(option.xmm).map(([k, v]) => [Number(k), v]);
    for (const [i, value] of entry) {
      if (value === undefined || i < 0 || i >= 16) continue;
      const v = BigInt(value) & MASK128;
      view.setBigUint64(xmmBase + i * 16, v & MASK64, true);
      view.setBigUint64(xmmBase + i * 16 + 8, (v >> 64n) & MASK64, true);
    }
  }

  return { mem, view };
}

// Builds the context object handed to option.hostCall at an import boundary. It
// exposes the SAME shared memory the module runs on: the live mem/view, the
// register-file base, the flag base, and read/write helpers over the sixteen GPRs
// keyed by name (rax..r15). `state` is a holder whose mem/view are populated after
// instantiation (seedState creates them), so the closure always sees the live bytes.
function makeHostContext(state, plan, loadBase) {
  const regBase = plan.regBase;
  const flagBase = plan.flagBase;
  const idx = (name) => {
    const i = NAME64.indexOf(name);
    if (i < 0) throw new RangeError(`hostCall: unknown register ${name}`);
    return i;
  };
  // A guest VA → compact byte offset via the SAME region map the codegen uses, so
  // the host reads/writes exactly the bytes the WASM run does. An unmapped VA is a
  // RangeError rather than a silent wrong access.
  const off = (addr, sizeByte) => {
    const o = plan.translateJs(addr);
    if (o === null) throw new RangeError(`hostCall: guest address 0x${BigInt.asUintN(64, BigInt(addr)).toString(16)} is outside the mapped regions`);
    return o;
  };
  return {
    regBase,
    flagBase,
    loadBase,
    get mem() { return state.mem; },
    get view() { return state.view; },
    readReg: (name) => state.view.getBigUint64(regBase + idx(name) * 8, true),
    writeReg: (name, value) => state.view.setBigUint64(regBase + idx(name) * 8, BigInt(value) & MASK64, true),
    readFlag: (name) => state.mem[flagBase + FLAG_ORDER.indexOf(name)] !== 0,
    writeFlag: (name, value) => { state.mem[flagBase + FLAG_ORDER.indexOf(name)] = value ? 1 : 0; },
    readMem: (addr, sizeByte) => {
      const o = off(addr, sizeByte);
      if (sizeByte === 8) return state.view.getBigUint64(o, true);
      if (sizeByte === 4) return BigInt(state.view.getUint32(o, true));
      if (sizeByte === 2) return BigInt(state.view.getUint16(o, true));
      return BigInt(state.mem[o]);
    },
    writeMem: (addr, sizeByte, value) => {
      const o = off(addr, sizeByte);
      const v = BigInt(value) & MASK64;
      if (sizeByte === 8) state.view.setBigUint64(o, v, true);
      else if (sizeByte === 4) state.view.setUint32(o, Number(v & 0xffffffffn), true);
      else if (sizeByte === 2) state.view.setUint16(o, Number(v & 0xffffn), true);
      else state.mem[o] = Number(v & 0xffn);
    },
  };
}

// Seeds the initial architectural state into the module's memory through the
// COMPACT region map: each mapped region is copied to its wasmOffset (the image
// region from the guest image, others from their `init` bytes or zero), rsp and
// the entry sentinel are placed in the stack region, and the register file / flags
// / xmm are written to the scratch region. The single flat region reproduces the
// historical layout exactly, so the function path seeds identically whether or not
// a multi-region map was supplied.
function seedStatePlan(instance, image, plan, loadBase, option) {
  const buffer = instance.exports.mem.buffer;
  const mem = new Uint8Array(buffer);
  const view = new DataView(buffer);

  // The initial bytes come from THIS call's region list, never from the plan's. The
  // plan is cached with the compiled module and is reused across invocations, but a
  // region's `init` is live guest state that differs every time — seeding from the
  // plan's copy would replay the first invocation's memory into every later one.
  // Only the LAYOUT (base/size/kind/offset, all cache-key material) comes from the plan.
  const initRegion = option.region;
  plan.region.forEach((r, i) => {
    if (r.kind === "image" || r.kind === "flat") {
      const src = image.subarray ? image.subarray(0, Math.min(image.length, r.size)) : image.slice(0, Math.min(image.length, r.size));
      mem.set(src, r.wasmOffset);
      return;
    }
    const init = initRegion?.[i]?.init ?? r.init;
    if (init) mem.set(init.subarray(0, Math.min(init.length, r.size)), r.wasmOffset);
    else mem.fill(0, r.wasmOffset, r.wasmOffset + r.size); // a zero region must be zero on EVERY run, not just the first
  });

  const sentinel = 0xdead000000000000n | (loadBase & 0xffffn);
  const rsp0 = BigInt.asUintN(64, plan.stackTop - 8n);
  const rspOff = plan.translateJs(rsp0);
  if (rspOff === null) throw new RangeError(`seedState: initial rsp 0x${rsp0.toString(16)} is outside the stack region`);
  view.setBigUint64(rspOff, sentinel, true);

  const reg = new Array(16).fill(0n);
  reg[4] = rsp0;
  if (option.register) {
    for (const [name, value] of Object.entries(option.register)) {
      const index = NAME64.indexOf(name);
      if (index >= 0) reg[index] = BigInt(value) & MASK64;
    }
  }
  for (let i = 0; i < 16; i += 1) view.setBigUint64(plan.regBase + i * 8, reg[i] & MASK64, true);

  const flag = { ...DEFAULT_FLAG, ...(option.flag ?? {}) };
  FLAG_ORDER.forEach((name, k) => { mem[plan.flagBase + k] = flag[name] ? 1 : 0; });

  // The resume-rip slot starts at the entry VA (see seedState).
  view.setBigUint64(plan.ripBase, BigInt.asUintN(64, loadBase + BigInt(option.entryRva ?? 0)), true);

  if (option.xmm) {
    const entry = Array.isArray(option.xmm) ? option.xmm.entries() : Object.entries(option.xmm).map(([k, v]) => [Number(k), v]);
    for (const [i, value] of entry) {
      if (value === undefined || i < 0 || i >= 16) continue;
      const v = BigInt(value) & MASK128;
      view.setBigUint64(plan.xmmBase + i * 16, v & MASK64, true);
      view.setBigUint64(plan.xmmBase + i * 16 + 8, (v >> 64n) & MASK64, true);
    }
  }

  return { mem, view };
}

// Reads the end-of-run register file, flags, xmm, and the mutated bytes of every
// mapped region back out of the compact memory. `region[i].bytes` is the region's
// post-run contents at its guest base — the surface the multi-region oracle
// comparison inspects; `memory` is the first region's bytes (the flat guest memory
// in the degenerate single-region case).
function readStatePlan(mem, view, plan, rawRegion = false) {
  const register = {};
  for (let i = 0; i < 16; i += 1) register[NAME64[i]] = view.getBigUint64(plan.regBase + i * 8, true);
  const flag = {};
  FLAG_ORDER.forEach((name, k) => { flag[name] = mem[plan.flagBase + k] !== 0; });
  const xmm = [];
  for (let i = 0; i < 16; i += 1) {
    const low = view.getBigUint64(plan.xmmBase + i * 16, true);
    const high = view.getBigUint64(plan.xmmBase + i * 16 + 8, true);
    xmm.push(low | (high << 64n));
  }
  // `rawRegion` skips materializing a private copy of every region — a host that
  // splices the bytes straight back into its own buffers (lib/tierrun.mjs) reads
  // them from `mem` at each region's wasmOffset instead, which halves the copy
  // traffic per invocation. The bytes are identical either way.
  const region = plan.region.map((r) => ({ base: r.base, size: r.size, kind: r.kind, wasmOffset: r.wasmOffset, bytes: rawRegion ? null : mem.slice(r.wasmOffset, r.wasmOffset + r.size) }));
  const memory = rawRegion ? null : (region.length ? region[0].bytes : mem.slice(0, 0));
  const resumeRip = view.getBigUint64(plan.ripBase, true);
  return { register, flag, xmm, region, memory, resumeRip };
}

// Reads the end-of-run GPR file and flags back out of the module memory.
function readState(mem, view, regBase, flagBase, xmmBase, ripBase, guestLen) {
  const register = {};
  for (let i = 0; i < 16; i += 1) register[NAME64[i]] = view.getBigUint64(regBase + i * 8, true);
  const flag = {};
  FLAG_ORDER.forEach((name, k) => { flag[name] = mem[flagBase + k] !== 0; });
  const xmm = [];
  for (let i = 0; i < 16; i += 1) {
    const low = view.getBigUint64(xmmBase + i * 16, true);
    const high = view.getBigUint64(xmmBase + i * 16 + 8, true);
    xmm.push(low | (high << 64n));
  }
  const resumeRip = view.getBigUint64(ripBase, true);
  return { register, flag, xmm, memory: mem.slice(0, guestLen), resumeRip };
}

// Compiles the block, then instantiates the module and runs it against the same
// initial architectural state lib/lift64.mjs's interpret() sets up. Returns the
// end-of-block register file, flags, and a copy of guest memory — the exact
// surfaces the oracle comparison inspects.
export function runBlock(block, option = {}) {
  const image = option.image;
  if (!Buffer.isBuffer(image) && !(image instanceof Uint8Array)) throw new TypeError("runBlock requires an image buffer");
  const loadBase = BigInt(option.loadBase ?? 0x140000000n);
  const stackSizeByte = option.stackSizeByte ?? 0x10000;
  const guestLen = image.length + stackSizeByte;

  const compiled = compileBlock(block, { loadBase, stackSizeByte, guestLen });
  const module = new WebAssembly.Module(compiled.bytes);
  const instance = new WebAssembly.Instance(module, {});

  const entryVa = (loadBase + BigInt(block.start_rva ?? (block.node[0]?.address ?? 0))) & MASK64;
  const { mem, view } = seedState(instance, image, loadBase, stackSizeByte, guestLen, compiled.regBase, compiled.flagBase, compiled.xmmBase, compiled.ripBase, entryVa, option);
  instance.exports.run();
  const state = readState(mem, view, compiled.regBase, compiled.flagBase, compiled.xmmBase, compiled.ripBase, guestLen);

  return {
    register: state.register,
    flag: state.flag,
    xmm: state.xmm,
    memory: state.memory,
    resumeRip: state.resumeRip,
    complete: compiled.complete,
    coverage: compiled.coverage,
    blockLength: compiled.blockLength,
  };
}

const STATUS_NAME = { [STATUS_OK]: "ok", [STATUS_BUDGET]: "budget_exhausted", [STATUS_FALLBACK]: "fallback", [STATUS_FAULT]: "fault" };

// ---- the compiled-module cache ----
//
// Compiling a function to WASM bytes and handing them to WebAssembly.Module is by
// far the most expensive part of one tier invocation, and a tiered host invokes the
// SAME entry over and over (a callee in a loop; a function that hands control back
// at an indirect transfer and is entered again on the next call). The cache keys a
// compiled module by everything compileFunction's output actually depends on and
// REVALIDATES the guest code bytes before every reuse, so self-modifying guest code
// can never keep running a stale module: a byte change re-compiles.
const compiledCache = new WeakMap(); // image object → { byKey: Map(key → entry), hot: entry[] }

// How many INSTANCES one image may keep alive. A module is a few KB of compiled
// code, so caching every entry's module costs almost nothing — but an instance owns
// a whole compact guest memory (every mapped region plus scratch), and a real binary
// has hundreds of eligible entries. Retaining one instance each would multiply the
// guest's memory by the number of functions ever tiered.
//
// The ceiling is therefore in BYTES, not instances: a count-based limit means
// nothing when one guest's compact memory can be a hundred megabytes (PuTTY x64
// under the Win32 HLE measures 101 MiB — a 1.6 MiB image beside a 32 MiB arena and a
// 64 MiB virtual region), so eight of those would pin most of a gigabyte. Retention
// stops at the byte budget or the count, whichever binds first; the most recent
// entry is always kept, so a big-memory guest still gets reuse for the function it is
// currently hammering.
const INSTANCE_LIMIT = 8;
const INSTANCE_BYTE_LIMIT = 64 * 1024 * 1024;

// Marks `entry` as the most recently used instance holder and drops the coldest
// instances past either ceiling. Dropping only clears the instance — the compiled
// module stays cached, so a re-entry costs an instantiation, never a re-compile.
function retainInstance(bucket, entry) {
  const at = bucket.hot.indexOf(entry);
  if (at >= 0) bucket.hot.splice(at, 1);
  bucket.hot.push(entry);
  let byteHeld = 0;
  for (const held of bucket.hot) byteHeld += held.byteSize;
  while (bucket.hot.length > 1 && (bucket.hot.length > INSTANCE_LIMIT || byteHeld > INSTANCE_BYTE_LIMIT)) {
    const cold = bucket.hot.shift();
    byteHeld -= cold.byteSize;
    if (cold !== entry && !cold.busy) cold.instance = null;
  }
}

// A cheap order-sensitive checksum over the guest bytes a compilation read. Only
// the function's own code range is summed (tens to hundreds of bytes), so the
// validation costs a small fraction of the compile it saves.
function codeChecksum(image, startRva, endRva) {
  const lo = Math.max(0, startRva | 0);
  const hi = Math.min(image.length, endRva | 0);
  let h = 0x811c9dc5;
  for (let i = lo; i < hi; i += 1) {
    h ^= image[i];
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return (h ^ (hi - lo)) >>> 0;
}

function cacheKey(option, loadBase, stackSizeByte, guestLen) {
  const region = (option.region ?? []).map((r) => `${BigInt.asUintN(64, BigInt(r.base)).toString(16)}:${Number(r.size)}:${r.kind ?? "region"}`).join(",");
  const external = [...new Set((option.externalRva ?? []).map(Number))].sort((a, b) => a - b).join(",");
  return [
    option.entryRva ?? 0, loadBase.toString(16), stackSizeByte, guestLen,
    option.iterationCap ?? 1_000_000, typeof option.hostCall === "function" ? 1 : 0,
    external, region,
  ].join("|");
}

// Returns a cache entry { compiled, module, instance, busy } for this compilation,
// compiling on a miss or on a guest-code change.
function acquireCompiled(image, option) {
  const { loadBase, stackSizeByte, guestLen } = option;
  let bucket = compiledCache.get(image);
  if (bucket === undefined) { bucket = { byKey: new Map(), hot: [] }; compiledCache.set(image, bucket); }
  const byKey = bucket.byKey;
  const key = cacheKey(option, loadBase, stackSizeByte, guestLen);
  const hit = byKey.get(key);
  if (hit !== undefined && !hit.busy) {
    const sum = codeChecksum(image, hit.compiled.codeRange.startRva, hit.compiled.codeRange.endRva);
    if (sum === hit.checksum) return hit;
  }
  const compiled = compileFunction(image, option);
  const module = new WebAssembly.Module(compiled.bytes);
  const entry = {
    compiled, module, instance: null, busy: false, bucket,
    byteSize: compiled.plan.pages * 65536,
    checksum: codeChecksum(image, compiled.codeRange.startRva, compiled.codeRange.endRva),
  };
  // A re-entrant (busy) entry must not have its live instance replaced under it, so
  // only a non-busy slot is overwritten; the recursive call simply runs uncached.
  if (hit === undefined || !hit.busy) byKey.set(key, entry);
  return entry;
}

// Compiles a MULTI-BLOCK function from the raw guest image (entry at option.entryRva,
// default 0), instantiates it, seeds the interpreter's initial state, and runs the
// dispatch loop. Returns the end-of-run register file, flags, guest-memory copy,
// the run status (OK / BUDGET / FALLBACK), and the CFG/coverage report. Requires
// option.decodeStructured (lib/lift64.mjs's decoder) to recover the CFG.
export function runFunction(image, option = {}) {
  if (!Buffer.isBuffer(image) && !(image instanceof Uint8Array)) throw new TypeError("runFunction requires an image buffer");
  const loadBase = BigInt(option.loadBase ?? 0x140000000n);
  const stackSizeByte = option.stackSizeByte ?? 0x10000;
  const guestLen = image.length + stackSizeByte;

  const usesHostCall = typeof option.hostCall === "function";
  const entry = acquireCompiled(image, { ...option, loadBase, stackSizeByte, guestLen });
  const compiled = entry.compiled;

  // Bind the imported host call to option.hostCall. The wrapper hands the guest
  // target virtual address (an unsigned 64-bit BigInt) and a context with live,
  // closure-shared access to the same memory seedState fills — the register file at
  // regBase, the flag bytes at flagBase, and the whole guest memory — so the host
  // reads args and writes its return value directly into the shared state. A missing
  // callback (or a thrown/undefined result) reports "unhandled" (nonzero) so the
  // module falls back honestly rather than returning a wrong result.
  const hostState = { mem: null, view: null };
  const importObject = {};
  if (usesHostCall) {
    const ctx = makeHostContext(hostState, compiled.plan, loadBase);
    importObject.env = {
      hostCall: (targetAddr) => {
        const status = option.hostCall(BigInt.asUintN(64, targetAddr), ctx);
        return Number.isInteger(status) ? status | 0 : status ? 0 : 1;
      },
    };
  }
  // A cached instance is reusable ONLY when nothing can re-enter it while it runs
  // and no per-call import closure has to be bound into it: a host call can recurse
  // into the same entry, and its import object differs per call. seedStatePlan
  // rewrites every mapped region and the whole scratch area on each run, so a reused
  // instance carries no stale guest byte — only the trap page keeps residue, and any
  // access that touches it exits FAULT (discarded) by construction.
  const reusable = !usesHostCall && !entry.busy;
  let instance = reusable ? entry.instance : null;
  if (instance === null) instance = new WebAssembly.Instance(entry.module, importObject);
  if (reusable) {
    entry.instance = instance;
    retainInstance(entry.bucket, entry);
  }

  entry.busy = true;
  let status;
  let state;
  try {
    const { mem, view } = seedStatePlan(instance, image, compiled.plan, loadBase, option);
    hostState.mem = mem;
    hostState.view = view;
    status = instance.exports.run();
    state = readStatePlan(mem, view, compiled.plan, option.rawRegion === true);
    state.mem = mem;
  } finally {
    entry.busy = false;
  }

  return {
    register: state.register,
    flag: state.flag,
    xmm: state.xmm,
    memory: state.memory,
    region: state.region,
    // The compact WASM memory the run just used, exposed so a `rawRegion` host can
    // splice each region's bytes straight out of it at region.wasmOffset. It stays
    // valid until the NEXT run of this same entry, which is after the host has read
    // it back — a cached instance is never handed to two live runs at once.
    mem: state.mem,
    plan: compiled.plan,
    resumeRip: state.resumeRip,
    status,
    statusName: STATUS_NAME[status] ?? "fault",
    // Whether the end-of-run state is one the interpreter could have produced, and
    // therefore whether the host may COMMIT it and continue at resumeRip. False for
    // FAULT alone: that run touched an unmapped address, lost a store to the trap
    // page, and must be discarded and re-interpreted from the function entry.
    resumable: status !== STATUS_FAULT,
    complete: compiled.complete,
    blockCount: compiled.blockCount,
    coverage: compiled.coverage,
    branchKind: compiled.branchKind,
    codeRange: compiled.codeRange,
  };
}
