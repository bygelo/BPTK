# Lane BA — compact multi-region guest memory for wasm64

## Goal
Replace `lib/wasm64.mjs`'s single flat 32-bit guest memory with a COMPACT
MULTI-REGION map so a compiled WASM function can address the real runtime's
sparse 64-bit space (image + high stack + TEB + HLE arena), bit-exact against the
interpreter. Unblocks WASM running real binaries.

## Mechanism
- **Compact remap** (`buildRegionPlan`): the caller's region list
  `[{ base, size, kind }]` is packed back-to-back into ONE 32-bit WASM memory
  (region 0 at wasmOffset 0, region 1 next, …), then a 16-byte trap scratch page,
  then the register-file / flag / xmm scratch. `pages = ceil(total / 65536)` — the
  compact total (image + ~1 MiB stack + arena) fits a 32-bit memory; the 140 TB
  span is never materialized.
- **Per-access translation** (`emitToOffset`): the single flat region keeps the
  historical `VA − loadBase` fast path (no branching, byte-identical behaviour). A
  multi-region map emits a small INLINE region dispatch: for each region compare
  the guest VA against `[base, base+size)` and, on a hit, compute
  `wasmOffset + (VA − base)`. A VA that hits NO region sets the FAULT flag and
  resolves to the trap scratch page — so the run reports an honest `fallback` and
  never reads or writes a wrong/wrapped guest byte.
- **Fault handling**: a per-block-body check (before the terminator) and a
  loop-top check both convert FAULT into a `STATUS_FALLBACK` exit, covering both
  body accesses (a RET terminator exits directly) and terminator accesses.
- **seed/read** (`seedStatePlan` / `readStatePlan`): each region is copied to its
  wasmOffset before the run (image from the guest image, others from `init`/zero),
  rsp and the entry sentinel are placed in the stack region, and every region's
  mutated bytes are read back per-region afterwards.
- The register file / flags / SSE emitters funnel all memory through the same
  translation; `compileBlock` (single-block path) and the default `compileFunction`
  layout stay on the flat fast path, so all prior tests are unchanged.

## Approach chosen
Inline runtime region dispatch for the general (register-based, incl. rsp/rip)
case, and the flat fast path for the degenerate single region. The import-general
`env.translate` route was NOT needed — the inline dispatch keeps the single-block
path (which has no host import) working uniformly and produces the honest-fallback
guarantee without a host round-trip.

## Bit-exact shapes verified (test/wasm64.test.mjs)
- Stack push/pop at a HIGH base `0x7ff000000000` round-trips (the case that traps
  a flat memory today).
- An image rip-relative load and a stack rsp-relative store in one function.
- A fully-computed pointer that lands in the arena region (`0xF8000000`).
- An out-of-region access → honest `fallback`, never a wrapped access (the oracle
  also rejects the VA).
- The single flat region as the degenerate case (function path unchanged).
- Oracle fidelity is CROSS-CHECKED against `lib/lift64.mjs` `interpret()` on a
  flat program before it is trusted for the sparse layouts (the reference reuses
  the shared `materializeFlag` and `decodeStructured`).

## Gate
`npm run gate` exits 0 — validate.py, 682 pass / 0 fail / 1 skipped (pre-existing),
check:package PASS. The 52 pre-existing wasm64 tests still pass; `passing` unchanged.
