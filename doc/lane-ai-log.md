# Lane AI — multi-block control flow in the WASM codegen (M3)

## Goal
Extend `lib/wasm64.mjs` (Lane AH: ONE lifted x86-64 basic block → a real,
bit-exact WebAssembly module) to compile a MULTI-BLOCK guest function with
intra-function control flow, still bit-exact against the `lift64.mjs` interpreter
oracle.

## What shipped
- `lib/wasm64.mjs`
  - Refactored the per-op emitters into a shared `createEmitter(push, loadBase)`
    factory so the single-block and multi-block paths cannot diverge on ALU/flag
    semantics. `compileBlock` / `runBlock` keep their exact behaviour.
  - `buildCfg` recovers the intra-function control-flow graph from lift64's
    `decodeStructured`: it follows control flow from the entry RVA, marks every
    jcc/jmp target (and each jcc fall-through) as a block leader, and splits the
    instruction stream into blocks. Blocks terminate as `ret`, `jmp`, `jcc`,
    `fallthrough` (a straight run cut by a leader), or a named `fallback`.
  - `compileFunction` emits ONE module with a `(block $exit (loop $loop (block
    $default (block $case…(br_table)))))` dispatch over an i32 current-block-index
    local. Each guest block emits its straight-line body, then: `ret` → fix rsp,
    set status OK, `br $exit`; `jmp`/`fallthrough` → set next index, `br $loop`;
    `jcc` → evaluate the guest condition from the SAME six flag locals the
    interpreter's `conditionHolds` reads (new `emitCondition`, all 16 CCs), pick
    taken vs fall-through index, `br $loop`.
  - Bounded: an `iterationCap` (default 1,000,000) block-dispatch budget decrements
    at the loop head; on exhaustion the module records a budget status and leaves
    via `$exit` — a guest infinite loop stops instead of hanging.
  - The exported `run` returns an i32 status (OK / BUDGET / FALLBACK); the type and
    i32-local count are parameterised in `assembleModule`.
  - `runFunction` instantiates, seeds the interpreter's exact initial state
    (shared `seedState`/`readState`), runs, and returns registers/flags/memory,
    the run status, block count, coverage, and branch kinds.
  - Honest fallbacks (named, never a wrong result): direct/indirect `call`,
    indirect/computed `jmp`, any branch target outside the function, an unserved
    op, or any body op the codegen already could not emit. A fallback still emits
    a VALID, instantiable module that flushes unchanged state and reports FALLBACK.
- `test/wasm64.test.mjs` — 8 new tests driving REAL control flow through BOTH the
  interpreter oracle and the multi-block WASM module, bit-exact on all 16 GPRs and
  6 flags.

## Coverage (measured, from the test run)
- Control-flow shapes bit-exact interpreter == WASM (7 microprograms): a forward
  conditional skip taken, a forward conditional skip not-taken, a backward counted
  loop summing 1..5 = 15, an if/else register select (both arms), a four-block
  fall-through chain, and a memory-touching loop (store + reload each iteration).
- Branch kinds emitted bit-exact (4): `jcc`, `jmp`, `fallthrough`, `ret`.
- Branch kinds still on HONEST fallback: `call` / `callIndirect`, `jmpIndirect`
  (computed jmp), and any out-of-function / non-boundary branch target.
- Iteration cap: a `jmp` self-loop (`eb fe`) stops with `budget_exhausted` at both
  a 1000-dispatch and a 5-dispatch cap — proving the cap is honoured, not luck.

## Bit-exact result
- Multi-block microprograms passing interpreter == WASM bit-exact: 7.
- `npm run gate` exits 0 (645 pass, 1 pre-existing skip, 0 fail; check:package
  PASS, 64 files). `passing` stays 0 — a validated codegen function is not a
  running game.

## Gate surfaces
- No new files: `lib/wasm64.mjs` + `test/wasm64.test.mjs` were already registered
  in the gate surfaces by Lane AH; the log is documentation only.
