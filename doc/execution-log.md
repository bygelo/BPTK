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
- **Next:** BPTK-047 (CFG + indirect-branch recovery).

## Cycle 2 — BPTK-047 (GS-002) CFG + indirect-branch recovery

- **Done:** extended `lib/recompile.mjs` with indirect-jump recovery. Decodes
  `0xff /4` (jmp r/m32) including full ModRM+SIB+disp parsing; recognises the
  `[disp32 + index*scale]` switch form and recovers the jump table by scanning
  code pointers from the static base while each lands in the executable image,
  stopping at (and flagging) the first non-code dword — the code-as-data
  boundary. Recovered arms become block leaders. Dispatch is faithful: at run
  time it reads the branch target and matches it against every recovered code
  leader (switch AND vtable alike), dispatching to the match or declaring an
  `indirect_branch_unresolved` fallback — never a crash, never a silent
  interpreter fallback. Indirect call (`0xff /2`) is a declared structured
  refusal (its return-path recovery is a follow-up).
- **Evidence:** `test/recompile.test.mjs` (+4, now 17) — a 3-arm switch
  dispatches bit-exact per arm vs the oracle (register/eflags/trace/memory/eip/
  stop), the post-table dword is flagged, a register-indirect jump to an
  unrecovered target declares the fallback, and an indirect call refuses.
- **Why still red:** indirect-call return-path recovery and function-boundary
  inference beyond reachable decode are follow-ups, so a whole image with
  virtual `call`-dispatch can't recompile end to end.
- **Counts:** implemented 44 → 45; passing 0. Gate exit 0 (302 tests).
- **Next:** perf bars — BPTK-137 (GS-093 recompile-vs-interpret speedup, the
  moat metric) and BPTK-136 (GS-092 MIPS floor), now measurable against the
  real recompiler; or BPTK-048 (SMC hybrid fallback).

## Cycle 3 — BPTK-136 (GS-092) + BPTK-137 (GS-093) performance bars

- **Done:** `lib/performance.mjs` gains `benchmarkRecompiler()` + a frozen
  CPU-bound workload (FIX-016, a mixed integer loop pinned as bytes). It runs
  the workload through the interpreter oracle and the recompiled WebAssembly
  module on this host, proves they compute the same result (register + count),
  and measures sustained MIPS + the recompile-over-interpret speedup — the moat
  metric. Measured here: recompiled ~300 MIPS vs interpreter ~4.4 MIPS ≈ **68×**
  (bar is ≥5×), same computation verified, zero fallback.
- **Evidence:** `test/performance.test.mjs` (4) — equivalence + zero fallback,
  recompiled MIPS > interpreter MIPS with a real multiple > 1, and the honest
  red boundary (native_fraction null, measured_on_reference_desktop false,
  is_bar_cleared false, both blockers declared).
- **Why still red:** the 770-MIPS floor is defined against the BPTK-002
  reference desktop (not this host), and no native baseline exists to measure
  the ≥50%-of-native fraction of GS-093 — so neither bar is *certified*.
- **Counts:** implemented 45 → 47; passing 0. Gate exit 0 (306 tests).
- **Next:** BPTK-048 (SMC hybrid fallback) or BPTK-052 (SSE/x87 breadth).

## Cycle 4 — BPTK-055 (GS-010) CPU-deterministic record & replay

- **Done:** `lib/replay.mjs` — `recordRun`/`replayRun`. A run is fully
  determined by workload bytes + budget + pinned nondeterminism sources
  (virtual-monotonic clock, no host RNG/input, single-thread schedule), none
  read from the host. Recording captures the full architectural state hash
  (8 GPR + EIP + EFLAGS + memory + stop) at instruction-count checkpoints via
  the recompiler; replay re-derives them and hash-matches. Cross-engine check:
  recompiler and interpreter agree at every checkpoint — the cross-machine
  foundation (pure integer WASM is host-independent).
- **Evidence:** `test/replay.test.mjs` (5) — two replays hash-match, cross-engine
  match, host-source-free, tampered-checkpoint divergence detected, and the
  second-machine + SMP legs declared red.
- **Why still red:** the literal second-machine replay isn't run in-suite, and
  multi-threaded schedule determinism (BPTK-051 guest SMP) is outside the
  single-thread record.
- **Counts:** implemented 47 → 48; passing 0. Gate exit 0 (311 tests, 52 files).
- **Next:** BPTK-048 (SMC hybrid fallback) or BPTK-052 (SSE/x87 breadth).
