# Lane AH — x86-64 → WebAssembly recompilation fast path (M3 foundation)

## Goal
Emit a REAL WebAssembly module from a lift64 x86-64 IR basic block and prove it
reproduces the interpreter oracle (lib/lift64.mjs `interpret`) bit-exact. This is
the enabler for real-time speed: the interpreter is too slow for live play, so
hot code must run compiled at near-native speed while staying architecturally
identical to the oracle.

## What shipped
- `lib/wasm64.mjs` — hand-assembles a valid WebAssembly binary (magic 00 61 73
  6d, version 1; type/function/memory/export/code sections; no bundler, no
  dependency) for the straight-line prefix of one lifted basic block, then
  instantiates and runs it via Node's `WebAssembly` global.
  - Guest GPRs are sixteen i64 WASM locals hydrated from / flushed to a
    register-file scratch region of a single exported WASM `memory`.
  - Guest memory IS that linear memory, addressed as `(guestAddr − loadBase)`
    (`i32.wrap_i64` after the 64-bit effective-address math).
  - IR ops map to WASM integer instructions (i64.add/sub/mul/and/or/xor/shl/
    shr_u/shr_s, iN.load/iN.store, `i64.popcnt` for the parity flag).
  - EFLAGS are materialized EAGERLY per flag-defining op into six i32 flag
    locals; the end-of-block value equals what lift64's lazy oracle would
    materialize (last flag-defining op wins in both), so CF/PF/AF/ZF/SF/OF match
    bit for bit — including inc/dec CF preservation and adc/sbb carry chaining.
- `test/wasm64.test.mjs` — 17 tests. Each microprogram is lifted once and run
  through BOTH the interpreter oracle and the emitted WASM module; all sixteen
  GPRs and all six flags are asserted identical. Includes a guest-memory
  round-trip (store then load, plus a direct DataView check of the emitted
  memory) and an honest-fallback case (indirect jmp stops the codegen, named).

## Coverage (measured, from the test run)
- IR op kinds the WASM codegen EMITS (16): alu, dec, imul2, imul3, inc, lea,
  mov, movsx, movsxd, movzx, neg, not, pop, push, ret, shift.
- Emitted variants (24): alu:{add,adc,sbb,sub,cmp,and,test,or,xor},
  shift:{shl,shr,sar}, plus the rest.
- Interpret FALLBACKS (honest, deferred to a later milestone, named in the
  coverage report): inter-block jcc/jmp/call and non-terminal ret branches,
  div/mul accumulator-pair, rotates (rol/ror/rcl/rcr), 64-bit IMUL overflow flag
  (needs a 128-bit product), SSE, x87, string ops. A fallback op stops codegen at
  that instruction and is reported as `unsupported` with a reason — never a stub
  that re-invokes the interpreter and claims WASM.

## Bit-exact result
- Microprograms passing interpreter == WASM bit-exact: 16 (across 17 tests; the
  17th is the coverage/honest-fallback assertion).
- `npm run gate` exits 0 (637 pass, 1 pre-existing skip, 0 fail; check:package
  PASS, 64 files).

## Gate surfaces registered (same commit)
- `tool/validate.py` ALLOWED_MJS_PATH (lib + test), reviewed-tarball expected_file
  (lib-only).
- `bench/npm/content.json` file manifest (lib-only).

`passing` stays 0 — a validated codegen block is not a running game.
