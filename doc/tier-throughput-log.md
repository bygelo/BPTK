# WASM tier throughput — the measured negative result

## Why this file exist

The recompilation tier is **correct** (bit-exact against the interpreter oracle
on a real binary) and its **eligibility** is now good (57.7% of Chocolate Doom's
candidate function entry compile; see [the eligibility log](eligibility-log.md)).
Neither fact makes anything faster. Measured on a real binary the tier is a large
**slowdown**, and the cause is architectural rather than a missing opcode.

That is worth a file of its own, because the obvious next move after an
eligibility win — widen coverage further — does not address it. Recording the
negative result stop a later session from re-deriving it or, worse, quoting the
eligibility number as though it were a speed number.

## The measurement

PuTTY x64 startup to its dialog-creation frontier through `runTieredImage`,
tiered versus the same runner with `forceInterpreter: true`. Median of three
runs, budget 200000, 26,416 instruction executed, both path reaching
`tier_unsupported_specialization` with identical state.

| Path | at `76d1a96` | at `5bf3f2e` |
| --- | ---: | ---: |
| Pure interpreter | 256 ms | 285 ms |
| WASM tier | **5921 ms** | **646 ms** |
| Ratio | **23x slower** | **2.3x slower** |

Same benchmark, same host, so the two column are directly comparable: the
tiered path got **9.2x faster** once the copy was removed. It is still
**2.3x slower** than interpreting the same program.

Measured on a Windows host with the corpus staged. The ratio, not the absolute
millisecond, is the durable part — the absolute number move with the host. The
same change is visible cross-platform: the `1:1 PuTTY x64` gate test fell from
4337 ms to 917 ms on macOS.

## The cause — FIXED at `5bf3f2e`

`seedStatePlan` walked `plan.region` and `mem.set(...)` every region's byte into
the WASM instance's memory on **every invocation**, and the host spliced the byte
back out afterwards. So one WASM-tier call cost O(total guest memory map), not
O(instruction executed).

PuTTY's map is the image plus the stack plus the HLE arena plus a large virtual
region. A tier function that runs a few hundred instruction still pay a full
copy of the whole guest space in and out. The instruction it saves by running
compiled code do not come close to paying for that copy.

This is why widening eligibility does not convert into throughput: every newly
eligible function is one more function that pays the copy.

## What this does NOT mean

- It is **not** a correctness problem. The tier stay bit-exact; the 1:1 PuTTY
  oracle test pass.
- It is **not** user-facing today. `runTiered` / `runTieredImage` are referenced
  only by `lib/tier.mjs`, `lib/tierrun.mjs` and their test — the tier is **not**
  wired into `bin/bptk.mjs`, `lib/run.mjs`, or the browser host. The product's
  execution path is the interpreter, so nothing shipped is slowed by this.
- It does **not** retire the eligibility work. Eligibility is a precondition for
  throughput; it is simply not sufficient on its own.

## The fix that landed

The two engines now **share one memory**. `buildGuestContext64` allocates every
guest region as a view into one `WebAssembly.Memory`, and a compiled module
IMPORTS that memory instead of defining its own, so a tier transition is a
register and rip handoff. Only the scratch area (GPR, flag, xmm, resume rip —
all outside every mapped region) is written per call, and there is no readback.

Both hazard were handled:

1. Growing a `WebAssembly.Memory` **detaches** its `ArrayBuffer` and would
   silently invalidate every region view — a wrong answer with no symptom. The
   map is sized up front and the memory is created with `maximum === initial`,
   so it **cannot** grow. No region may be appended after the context is built.
2. A shared buffer removes the "throw the private copy away" safety net, so a
   FAULT can no longer be discarded — and re-running is not idempotent
   (`inc [mem]` would apply twice). The module therefore stops **at** the
   out-of-region access having performed none of its effects, reports that
   instruction's own VA, and the host commits it; the interpreter then faults on
   the same access. That is a strictly stronger contract than the old
   block-start-and-discard, and the non-idempotent regression case still asserts
   the final memory is bit-identical to pure interpretation.

## What is still slower, and why

The tier remains **2.3x slower** than interpretation on PuTTY (1.5x on plink).
The cause has moved and is measured: with the tier disabled but the shared
memory on, the tiered runner measures **1.01x** of pure interpretation, so the
handoff itself is free and **all** of the remaining gap is **compilation** —
roughly 2.4 ms per compile across 116 call target, for a run whose WASM tier
carries only ~5,400 of 26,416 instruction (about 45 per invocation). The fixed
cost is compiling function too small and too cold to repay it.

The obvious next lever is a **hotness threshold** (compile a callee only after N
entry). It was measured — threshold 2 gives 1.63x, threshold 6 gives 1.30x — and
deliberately **not shipped**, because it removes the WASM tier from the synthetic
1:1 proof (`wasm_tier_function >= 1` fails when a callee is entered once) and
making those pass would mean rewriting the test program to manufacture a green.
That is a real option owned by whoever decides it, not a change to smuggle in.

## Honesty

`passing` stays 0. A faster tier would not be proven playability either; a
throughput ratio is not a compatibility claim.
