# Lane AJ — WASM codegen: direct CALL/RET across guest functions

Milestone M3 (doc/runtime-v2-scope.md). Extends `lib/wasm64.mjs`'s multi-block
recompiler so a direct `call rel32/rel8` (E8/near) to another lifted guest
function in the compiled set compiles to real cross-function control flow,
bit-exact vs the lift64 interpreter oracle.

## What was added

- **Cross-function CFG.** `buildCfg` now follows a direct `call`: the callee
  entry (`next + rel`) and the return address after the call (`next`) both become
  block leaders of one graph. A `call` terminator resolves to `{ kind: "call",
  target, returnRva }`.
- **Call ABI over the guest stack.** A `call` emits `rsp -= 8`, stores the
  return address (`loadBase + returnRva`, a compile-time constant) at `[rsp]`,
  then transfers to the callee entry block — the SAME single guest linear memory
  the block codegen already uses, so interpreter and WASM agree on stack bytes.
- **Generalized RET dispatch.** A `ret` reads `[rsp]` first, then `rsp += 8 +
  pop` (bit-exact with the interpreter), then dispatches: the entry-frame
  sentinel unwinds the module (STATUS_OK); a known call-return address resumes
  that block via the `(loop (br_table))` dispatch; anything else is a defensive
  FALLBACK.
- **Bounded depth.** Recursion/loops share the existing iteration budget, so a
  runaway recursion stops with `budget_exhausted` — never a hang.

## Call shapes covered bit-exact (microprogram counts)

| shape                    | count | evidence |
|--------------------------|-------|----------|
| leaf call (value in eax) | 1     | eax = 42 + 8 = 50; return address on stack |
| nested A→B→C             | 1     | eax = 10 + 1 = 11; two frames' return addresses on stack |
| call inside a loop       | 1     | 3× leaf add5 → eax = 15; last return address on stack |
| recursive factorial      | 1     | 5! = 120 through five self-recursive frames |
| runaway recursion (cap)  | 1     | infinite self-recursion → budget_exhausted at cap 1000 and 5 |

Each of the four terminating shapes runs through BOTH the interpreter oracle and
the emitted WASM module, asserting identical 16 GPRs + 6 flags AND the exact
return-address stack bytes the call/ret touched.

## Depth-cap behavior

The per-block iteration budget (`iterationCap`, default 1,000,000) bounds total
block dispatches. Infinite direct recursion (`call self; ret`) returns
`budget_exhausted` at cap 1000 and cap 5; guest-stack growth stays well within
the 0x10000-byte stack (≤ 8 bytes/level), so it never faults before the cap.

## Call shapes still on honest named fallback

- Indirect / computed call (FF /2) → `control_call_indirect`
- Direct call to a target outside the compiled set (e.g. an HLE import thunk) →
  `control_call_external` (no HLE binding attempted here — that is a later lane)
- Indirect jmp (FF /4) → `control_jmpIndirect`

Each emits a valid, instantiable module that flushes unchanged state and reports
the FALLBACK status — never a stub that re-invokes the interpreter.

## Gate

`npm run gate` exits 0; `0 passing` unchanged. `test/wasm64.test.mjs`: 30 tests
pass. Files touched: `lib/wasm64.mjs`, `test/wasm64.test.mjs`.
