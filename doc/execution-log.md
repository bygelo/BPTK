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

## Cycle 5 — BPTK-048 (GS-003) hybrid interpreter fallback for SMC

- **Done:** `createHybridRecompiler` in `lib/recompile.mjs` + a decode cache
  threaded through `decodeSubset`. It holds a mutable image and a per-instruction
  decode cache; `writeCode(addr,bytes)` applies a self-modification and
  invalidates only the cache entries whose byte range overlaps the write. The
  next compile re-decodes exactly the affected block and reuses every untouched
  instruction from the cache (never re-decoding it).
- **Evidence:** `test/recompile.test.mjs` (+2, now 19) — after patching a
  `mov ebx` immediate, `reDecodedInstruction` is the single patched address and
  `keptInstruction` covers the rest; the rewritten result is bit-exact against
  the interpreter oracle over the modified image (register/memory/trace).
- **Why still red:** the trigger is an explicit host `writeCode`, not a guest
  store into its own page detected mid-run through the recompiled memory-write
  surface, so an in-run patch-then-re-enter fixture isn't closed end to end.
- **Counts:** implemented 48 → 49; passing 0. Gate exit 0 (313 tests).
- **Next:** BPTK-052 (SSE/x87 breadth) or BPTK-051 (guest SMP).

## Cycle 6 — BPTK-051 (GS-006) guest SMP determinism

- **Done:** `runContentionFixture` in `lib/thread.mjs` over the existing
  deterministic cooperative scheduler. N workers contend on an interlocked
  counter and a critical-section-guarded RMW and hand a token around an
  auto-reset event for wakeup accounting. Returns the guest-state hash (the two
  counters), the schedule hash, lost_wakeup_count, and a deadlock flag.
- **Evidence:** `test/thread.test.mjs` (+3, now 27) — both counters reach the
  expected total; guest-state + schedule hashes are byte-reproducible across
  repeated runs; the guest-state hash is identical across worker counts (1 vs 8)
  with zero lost wakeup and no deadlock; is_worker_backed false keeps the real
  cross-core leg red.
- **Why still red:** the reproducible schedule is a cooperative model; a real
  SharedArrayBuffer-backed Worker pool (true cross-core parallelism) is not
  deployed on the run surface.
- **Counts:** implemented 49 → 50; passing 0. Gate exit 0 (316 tests).
- **Next:** BPTK-052 (SSE/x87 breadth) or BPTK-056 (ABI thunk lowering).

## Cycle 7 — BPTK-056 (GS-011) guest↔host ABI / import-thunk lowering

- **Done:** `lib/abi.mjs` — `lowerThunk`/`verifyStackCleanup` for cdecl,
  stdcall, fastcall, thiscall (register split + correct callee/caller stack
  cleanup), and `measureCrossing` which times the real recompiled-guest↔host
  boundary as a WebAssembly import call (a tiny hand-built module calling an
  imported host function N times). ~4.9 ns/crossing here, every crossing
  reaching host emulation.
- **Evidence:** `test/abi.test.mjs` (5) — every convention balances the stack
  across arg counts, stdcall/cdecl cleanup sides correct, register conventions
  pass the first args in registers, the crossing reaches host every call, and
  the cost is reported against the bar honestly red.
- **Why still red:** the crossing-cost bar is a BPTK-002 reference-desktop
  figure (not this host), and the whole Win32 HLE isn't wired into the
  recompiled crossing (the measured boundary is the raw WASM import call).
- **Counts:** implemented 50 → 51; passing 0. Gate exit 0 (321 tests, 53 files).
- **Next:** BPTK-052 (SSE/x87 breadth) or BPTK-050 (memory64).

## Cycle 8 — BPTK-139/140/142 (GS-095/096/098) perf bars vs the recompiler

- **Done:** `lib/performance.mjs` gains three harnesses measured against the
  real recompiled module:
  - `benchmarkColdStart` (139): cold = recompile + WASM compile + instantiate;
    warm = re-instantiate. ~2.5 ms cold / ~0.03 ms warm here.
  - `benchmarkMemory` (140): recompiled linear memory is bounded and does not
    grow between a short and a long run (~192 KB, well under the 2-GB ceiling);
    guest-host crossing cost reused from lib/abi.mjs.
  - `benchmarkStability` (142): repeats the workload, measures run-to-run jitter
    and confirms memory returns to baseline.
- **Evidence:** `test/performance.test.mjs` (+3, now 7) — warm ≤ cold and no
  asset streaming (139); growth bounded + under ceiling + positive crossing
  (140); positive median, non-negative jitter, memory-to-baseline (142); all
  three keep is_bar_cleared false.
- **Why still red:** 139 measures time-to-first-*executable*, not first frame
  (no graphics/streaming runtime); 140's 2-GB ceiling is a whole-game figure;
  142's 30-minute sustained bound needs a game runtime.
- **Counts:** implemented 51 → 54; passing 0. Gate exit 0 (324 tests).
- **Next:** BPTK-052 (SSE/x87 breadth) or BPTK-050 (memory64).
