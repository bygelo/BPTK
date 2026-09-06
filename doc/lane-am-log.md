# Lane AM — tiered runner (WASM fast path + interpreter fallback)

Milestone M3 (doc/runtime-v2-scope.md). Builds the TIERED runner that actually
USES the x86-64 → WebAssembly fast path, additively, in a NEW file — the proven
interpreter/exec64 run loop is untouched.

## What shipped
- `lib/tier.mjs` — `runTiered(image, option)`. Executes a guest program function
  by function, tier chosen per entry RVA and cached:
  - WASM tier: a function whose single-function CFG compiles (lib/wasm64.mjs
    `compileFunction` complete === true, every other entry marked external) runs
    as real WebAssembly via `runFunction`.
  - interpreter tier: a function that hits a codegen fallback runs through the
    lib/lift64.mjs interpreter semantics. tier.mjs re-declares the same Machine +
    integer/control executor (that core is not a lift64 export) and DELEGATES every
    complex op (SSE, x87, string, cpuid, cmpxchg, bit/bswap/xchg) to lib/lift64.mjs's
    EXPORTED executors, so the tier is bit-exact with the oracle by construction.
  - One shared guest state (register file + single linear memory). Cross-tier calls
    bridge both directions: WASM→interpreter over the wasm64 `hostCall` import
    boundary (live shared memory); interpreter→WASM as a nested WASM frame.
  - Bounded (interpreter instruction budget + WASM iteration cap), deterministic.
  - Returns final register/flag/xmm/memory + a tier report (per-function tier,
    interpreter instructions retired, wall-time per tier).
- `test/tier.test.mjs` — correctness + speed conformance.
- Gate surfaces: validate.py ALLOWED set + reviewed-tarball manifest,
  bench/npm/content.json (lib/tier.mjs), validate.py test list (test/tier.test.mjs).

## Verification
- Correctness: a WASM-tier entry (integer + SSE) calls an interpreter-tier fallback
  (`rol`), and the reverse (interpreter-tier `rol` entry calls a WASM-tier leaf).
  Both bit-exact to lib/lift64.mjs `interpret` over the whole program (all 16 GPRs +
  6 flags), and guest MEMORY bit-exact to a whole-program interpreter reference
  (including the stale cross-tier return address on the shared stack).
- Speed: a counted-loop sum (N=100000) is chosen for the WASM tier (0 interpreter
  instructions retired) and correct; measured ~73–81x faster than the interpreter
  (logged, not hard-asserted — a strict clock ratio is flaky).
- `npm run gate` exits 0 (676 pass, 1 skipped, 0 fail; package content 65 files).

`passing` stays 0 — a tiered microbenchmark is not a playable game.
