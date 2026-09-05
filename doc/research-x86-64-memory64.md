# Research: x86-64 recompilation and memory64 guest address space (P4)

> Status: **research / prototype only — no support claim.** GS-004 (BPTK-049,
> x86-64 recompilation) and GS-005 (BPTK-050, memory64 guest address space) are
> **P4** in the execution lane: this note records feasibility and the prototype
> path, and the roadmap rows stay `planned`. Nothing here is a runtime support
> claim, and `npm run gate` keeps `passing` at 0 for both.

## Where the execution core is today

The static recompiler (BPTK-046) and its CFG/indirect-branch recovery
(BPTK-047), SMC fallback (BPTK-048), and ABI lowering (BPTK-056) target the
**32-bit i386** guest: eight 32-bit GPRs, EIP, the six arithmetic flags, and a
flat 32-bit address space modelled as an image+stack linear memory. The
interpreter oracle (`executeProbe`) is the semantic reference the recompiler is
bit-exact against, and it too is 32-bit. This is the foundation everything else
in the lane rebases onto.

## GS-004 — x86-64 (AMD64) recompilation

**Feasibility:** tractable but a distinct, large decode+state surface, not a
tweak. What it requires:

- **State widening.** Sixteen 64-bit GPRs (`rax`..`r15`), the extended SSE/AVX
  register file, and 64-bit RIP. In the recompiler's WASM lowering the GPRs
  become `i64` globals; flag computation moves to 64-bit intermediates. The
  interpreter oracle would need a parallel 64-bit mode to stay the differential
  reference — the differential-oracle discipline in
  [research-static-recomp.md](research-static-recomp.md) is what keeps such a
  widening honest.
- **REX prefix decoding.** The `0x40`–`0x4f` REX byte selects operand width and
  the extended register bank; every ModRM/SIB path gains an extra register bit.
  Until this lands, the recompiler's correct behaviour is to **detect and refuse**
  a REX-prefixed stream with a structured code, never to mis-decode it as the
  32-bit form (the existing "opcode outside the recompiled subset" refusal
  already fails closed here).
- **RIP-relative addressing** and the SysV/Win64 register calling conventions
  (the ABI lowering in `lib/abi.mjs` covers the 32-bit conventions; Win64's
  four-register + shadow-space convention is additive).

**Why P4:** the 32-bit lane is the measured moat; 64-bit doubles the decode and
conformance surface before it returns a single new measured title, and the
honest interim posture (detect-and-refuse) is already in place.

## GS-005 — memory64 guest address space

**Feasibility:** gated on the WebAssembly **memory64** proposal (64-bit linear
memory addresses). The recompiler's `translate(addr)` helper and the
image/stack layout are the only address-space-shaped pieces; widening them to
64-bit offsets is mechanical **once the host runtime exposes a 64-bit memory**.
The interpreter's `checkRange`/`readMemory`/`writeMemory` would widen in lock
step. Guest pointers become 64-bit, so this rides on GS-004 landing first.

**Why P4:** it is downstream of x86-64, and its value is unmeasurable until a
64-bit guest actually executes. The bounded 32-bit address space (a 4 GB guest
mapped as image+stack) is sufficient for every workload the lane measures today.

## Prototype path (no support claim)

1. Add a 64-bit differential mode to the interpreter oracle behind an explicit
   flag, keeping the 32-bit path untouched and default.
2. Extend the recompiler decoder to consume REX and emit `i64` state ops for a
   bounded 64-bit register-and-stack subset, differential-tested bit-exact
   against that oracle mode on generated 64-bit microprograms.
3. Only then widen the address space (memory64) behind the host capability.

Each step is a separate promotion with its own committed red benchmark; none is
claimed until its differential fixture is bit-exact and gate-green.
