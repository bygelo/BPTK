# Runtime v2 — the x86-64-first, recompilation-first core (scope)

Status: **scope, pre-code** · Decision of record: BPTK-001 = **build-new** (2026-09-06) ·
Baseline it must beat: `data/corpus-run.json` — **0 of 11 binaries reach `entry`**.

This document scopes the successor execution core. It does not change any code. It
exists so the build starts from a named architecture, a named reuse boundary, and a
measurable first milestone — not from feel.

## 1. The mandate (measured, not asserted)

`bptk corpus run` at tip `7666fc4` (101 implemented, 429 tests) on 11 lawful freeware
binaries:

| stage | n | binaries | wall |
|---|---|---|---|
| `entry` | **0** | — | — |
| `loaded` | 4 | OpenTTD 1.10.3 win32, Plink 0.74 win32, jq i386, PuTTYgen win32 | import wall (BPTK-010) |
| `packaged` | 6 | PuTTY/Plink 0.83 w64, jq amd64, OpenTTD 13.4 win64, Dwarf Fortress, Chocolate Doom | **x86-64** (BPTK-031) |
| `classified` | 1 | 7-Zip `.7z` | archive extract (BPTK-007) |

Two facts drive everything below:

1. **The majority of real freeware is x86-64.** An i386-only core is refused at the
   machine-class gate on 6 of 11 payloads before it can load them. **v2 is x86-64-first**;
   i386 is a supported sibling, not the primary.
2. **The interpreter + opt-in-probe model is the ceiling, not a coverage gap.** The four
   i386 binaries map cleanly and still never execute. Growing HLE coverage to green does
   not move a binary to `entry`. The execution *model* has to change.

## 2. What v2 is: static recompilation (AOT), not interpretation

The v1 core (`lib/runtime.mjs`, `lib/i386.mjs`) is a bounded fetch–decode–execute
interpreter: every guest instruction is a JS decode + `switch`, stepped to an instruction
budget. That is the v86 / BottleShip ~174-MIPS class and it is why nothing reaches a real
session.

v2 statically lifts the guest image to a WebAssembly module **at build time**, then runs
that module at near-native speed:

```
PE image ──▶ (A) loader ──▶ (B) code discovery / CFG ──▶ (C) x86-64 → SSA IR
                                                              │
   (G) runtime harness ◀── (F) ABI thunks ◀── (E) WASM codegen ◀── (D) IR opt
```

- **(A) Loader** — sections, imports (IAT), TLS + callbacks, relocations, exception
  directory (`.pdata`/`.xdata` for x64 unwind), entry. Reused from the existing PE path.
- **(B) Code discovery** — recursive-descent from entry + exports + TLS callbacks, jump-table
  and indirect-branch recovery; unresolved targets fall to the hybrid interpreter (§4), never
  guessed.
- **(C) Lifter** — x86-64 (and i386) → a typed SSA register-transfer IR. Flags computed
  lazily (materialize EFLAGS only when observed). This is the single largest new component.
- **(D) IR opt** — dead-flag elimination, constant folding, block merging. Correctness-first;
  every pass is identity-verifiable against the interpreter oracle (§5).
- **(E) WASM codegen** — guest memory = one WASM linear memory (**memory64** for the x64
  address space); guest registers = WASM locals/globals; each recovered guest function = a
  WASM function; computed transfers = a `call_indirect` over a function table; **tail-calls**
  for the block dispatcher; **SIMD** for SSE/AVX; **exnref** for SEH/fault dispatch.
- **(F) ABI thunks** — guest↔host lowering. A guest import call becomes a WASM import bound
  to the existing JS HLE; blocking calls suspend via **JSPI** so a message loop / WaitFor* /
  Sleep yields instead of spinning.
- **(G) Runtime harness** — instantiates the module, wires imports to the HLE, owns the
  linear memory, drives the frame/audio clock.

The four enabling web features (JSPI, tail-calls, SIMD, memory64/exnref) are the reason
recompilation is now viable in-browser and interpretation is not. v2's honest-caps layer
must probe each and refuse (red) where absent, never silently degrade.

## 3. Reuse boundary — harvest, don't rewrite

**Replace** (the ceiling): `lib/runtime.mjs` interpreter loop, `lib/i386.mjs` bounded probe.

**Keep as the services/HLE layer, bound as WASM imports** (this is ~90% of the 101
subsystems and stays valuable verbatim):

- `lib/hle.mjs` (3202 lines) — Win32 core, **widened to the Win64 ABI** (register calling
  convention, shadow space) as the new work here.
- `lib/thread.mjs`, `lib/seh.mjs` — TEB/scheduler and SEH; SEH re-expressed over `exnref`.
- `lib/user.mjs` `lib/gdi.mjs` `lib/audio.mjs` `lib/net.mjs` `lib/input.mjs` `lib/storage.mjs`
  `lib/clock.mjs` — services, unchanged.
- `lib/shader.mjs` `lib/graphics.mjs` — the graphics translation layer, unchanged.
- `lib/corpus.mjs` `lib/conformance.mjs` `lib/report.mjs` — the measurement harness **is the
  judge of v2** and does not change.

**Harvest from the stranded branches** (both need rebase onto tip regardless):
- `lane/cpu-followup` — SSE/SSE2 semantics → feed the v2 lifter's SIMD lowering.
- `thread/cycle3-wip` — multi-thread TEB windowing / scheduler → the v2 harness thread model.

## 4. Hybrid fallback (correctness is never traded for speed)

Self-modifying code, JIT'd guest code, and any target code discovery could not resolve run
on the **existing v1 interpreter**, invoked from the recompiled module at the unresolved
edge. v2 is therefore recompiled-fast-path + interpreter-correct-path. A page becomes
recompiled only when proven non-self-modifying; a write into recompiled code invalidates and
falls back. This keeps v1 alive as the safety net, not dead weight.

## 5. Honesty + measurement contract (unchanged discipline)

- **The corpus is the judge.** v2's success metric is `reached_stage`, not test count. The
  first milestone is **≥1 real binary at `entry`** — the thing v1 never did.
- **Interpreter as oracle.** Every lifted block must produce bit-exact architectural state
  vs. the v1 interpreter on a reference trace before its recompiled form is trusted. This is
  the regression instrument, red by construction until it matches.
- **passing stays 0** until a real benchmark passes. "Reached `entry`" is not "playable."
- **x86-64 as a real target, not a research P4.** BPTK-031 promotes from research to the
  spine; the honest-caps gate declares what the host WASM engine actually supports.

## 6. First milestones (sequenced by the baseline's own walls)

1. **M1 — load x86-64.** PE64 loader + machine-class acceptance so the 6 blocked payloads
   reach `packaged`→ at least `loaded` instead of being refused at the gate. Smallest step
   that touches the biggest slice of the corpus (6/11).
2. **M2 — lifter spine + oracle.** x86-64 → IR for the common integer/branch/call subset,
   validated bit-exact against the v1 interpreter on a microprogram corpus. No codegen yet.
3. **M3 — WASM codegen of a leaf function**, JSPI-bound to one HLE import, first recompiled
   guest function executes → drive one i386 binary (PuTTYgen/jq) from `loaded` to `entry`.
4. **M4 — Win64 ABI HLE** so an x86-64 program (jq amd64 — batch, no window) reaches `entry`.

Each milestone is a promotable roadmap item under the 8-file contract, gate-green, with its
own red corpus/oracle contract. M3 is the first time the baseline number changes.

## 7. Explicitly out of scope for v2 core (stay P4 / refuse-by-identity)

DRM / anti-cheat / online titles (detected and refused by identity, never circumvented);
console recompilation; D3D10–12 authoring. These do not gate the "move a real binary to
`entry`" mandate and must not dilute it.
