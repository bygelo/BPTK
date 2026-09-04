# Research note — per-title static recompilation as a fourth lane, 2026-09

A bounded, no-marketing feasibility note for BPTK-036. It records what a
static machine-code to WebAssembly lane would mean for this toolkit, what the
prior art proves, and what evidence is still missing before the lane can be
accepted, deferred with a prototype, or rejected. This is a dated snapshot;
[ROADMAP.md](../ROADMAP.md) stays authoritative.

## 1. The lane in one paragraph

Static recompilation translates one title's machine code into C or C++ ahead
of time with a per-title pipeline, then compiles the result to WebAssembly
with the normal source toolchain. Unlike the general binary lane, the
pipeline is allowed to be per-title: symbol tables, address maps, and
hand-written reconstructions are all legitimate inputs, because the output is
built once and shipped once.

## 2. What the prior art proves

- **N64Recomp** and **PSXRecomp** demonstrate that a static recompilation
  pipeline can take a commercial console title's machine code and produce a
  C output that builds and plays with correct behavior, using per-title
  relocation and symbol data.
- **XenonRecomp** extends the approach to a multi-core PowerPC title class.
- The tradition shows the practical requirements BPTK would inherit: a
  disassembler with correct semantics for the exact processor stepping, a
  relocatable addressing model or a symbol map, an event/scheduling bridge
  for anything the title polls, and a legal input path for the code.

## 3. What BPTK already owns that the lane can reuse

- The bounded PE32 mapper, declared import resolution, and structured fault
  model under `lib/pe.mjs` and `lib/run.mjs` are the same static-reading
  foundation a per-title pipeline needs for analysis.
- The bounded i386 execution subset in `lib/runtime.mjs` doubles as a
  semantic reference while building a recompiler: the interpreter and a
  recompiler can be differential-tested against each other on generated
  microprograms.
- The source lane's pinned-toolchain work (BPTK-042) is the same build and
  packaging back-end the recompiled C output would consume.

## 4. What is missing before the lane can be accepted

1. A per-title pipeline does not exist; there is no disassembler, symbol
   model, or code generator in this repository.
2. No representative title comparison has been measured on effort, coverage,
   or performance against the binary and source lane on a frozen corpus.
3. The legal input path is unresolved: a recompiled title derivative sits in
   the same rights question as any other distribution of game code, and
   BPTK-001 owns that decision.
4. The differential oracle (interpreter against recompiler on generated
   microprograms) exists only as an idea and has no committed harness.

## 5. Honest positioning against the other lane

For a title whose general high-level-emulation path fails on a niche CPU
feature or an undocumented coupling, a per-title static recompilation is
credible precisely because it trades generality for per-title effort. For
everything else it is strictly more work than the source lane when source is
available and no better than the binary lane when the general interpreter
already covers the instruction set. The decision input BPTK lacks is a
measured title, not an architecture opinion.

## 6. Decision

Stay **deferred**. The fourth lane is feasible in the tradition cited above
but unevaluated for this toolkit; promotion requires the measured comparison
named in [BENCH-036](../bench/roadmap/spec/bptk-036.json). The
`bptk foundation compare` surface now carries the fourth option so the
deferral is visible at the product surface instead of only in this note.
