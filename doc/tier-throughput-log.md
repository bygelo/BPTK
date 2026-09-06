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

| Path | Wall time |
| --- | ---: |
| Pure interpreter | **256 ms** |
| WASM tier | **5921 ms** |

The tier is roughly **23x slower** than interpreting the same program.

Measured at `76d1a96` on a Windows host with the corpus staged. The ratio, not
the absolute millisecond, is the durable part — the absolute number move with
the host.

## The cause

`seedStatePlan` in `lib/wasm64.mjs` walks `plan.region` and `mem.set(...)` every
region's byte into the WASM instance's memory on **every invocation**, and the
host splices the byte back out afterwards. So one WASM-tier call cost
O(total guest memory map), not O(instruction executed).

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

## The fix direction

The two engines must **share one memory** rather than the module receiving a
private copy of the guest per call — `lib/exec64.mjs`'s `Machine` holding its
guest byte in the WebAssembly memory buffer, so a tier transition is a pointer
and rip handoff instead of a copy. Then an invocation cost O(instruction
executed) and the eligibility already won start to pay.

Two hazard that fix must respect, both already known:

1. Growing a `WebAssembly.Memory` **detaches** every existing `ArrayBuffer` view,
   so a cached `Uint8Array`/`DataView` must be re-derived after a grow. A stale
   view is a silent-corruption bug, not a crash.
2. A shared buffer removes the "throw the private copy away" safety net that
   currently makes an out-of-region FAULT recoverable, so a faulted run must be
   unable to write anything real in the first place.

## Honesty

`passing` stays 0. A faster tier would not be proven playability either; a
throughput ratio is not a compatibility claim.
