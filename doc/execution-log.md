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
