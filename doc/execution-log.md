# Execution lane log

Lane `lane/execution` — PILLAR 1 (execution core) + PILLAR 10 (performance bars).
Verifier: `npm run gate` exit 0 after every commit. `passing` stays 0 (no real
benchmark passes yet); `implemented` = real code + an active red contract.

## Cycle 1 — BPTK-046 (GS-001) static x86-PE→WASM recompiler

- **Done:** `lib/recompile.mjs` — a real ahead-of-time translator. It maps a
  PE32, decodes the `.text` from the entry point over a worklist, recovers
  basic blocks + a CFG (GS-002 groundwork), and lowers each block to genuine
  WebAssembly (a hand-written binary encoder: types/functions/memory/globals/
  exports/code/data). Guest state = 8 GPR + EIP + 6 flags as WASM globals over
  an image+stack linear memory laid out byte-identically to the interpreter, so
  the emitted module reproduces the oracle's exact `memory_sha256`,
  `trace_sha256`, register, eflags, `stop_reason`, and instruction count.
  Control flow is a `br_table` dispatch loop; every basic block is straight-line
  WASM (recompilation, not threaded dispatch). No silent fallback: any opcode
  outside the subset or an indirect branch is a hard structured refusal.
- **Subset lowered:** mov (imm + register-direct), the full ALU space
  (add/or/adc/sbb/and/sub/xor/cmp) in register and immediate forms, inc/dec
  (CF-preserving), push/pop, test, jcc (rel8/rel32, all 16 condition codes),
  jmp (rel8/rel32), ret to the process return sentinel.
- **Evidence:** `test/recompile.test.mjs` (13 tests) — differential bit-exact
  vs `executeProbe` across mov/ALU/loop/push-pop/branch/adc-sbb/every-cc/rel32/
  budget-exhaust, plus refusal (structured, `fallback_count` 0) on an
  out-of-subset opcode (0xf7 mul) and a memory-operand form.
- **Why still red:** the subset is bounded — memory operands, wider/narrower
  sizes, x87/MMX/SSE, and indirect control flow refuse, so a whole real `.text`
  cannot recompile end-to-end. Promotes to passing when a whole fixture `.text`
  is bit-exact with zero fallback for every instruction it reaches.
- **Counts:** implemented 43 → 44; passing 0. Gate exit 0.
- **Next:** BPTK-047 (CFG + indirect-branch recovery) formalizes the block
  graph and adds a resolvable indirect-jump/return model; then the perf bars
  (BPTK-136/137, GS-092/093) can measure recompiled throughput vs interpreter.
