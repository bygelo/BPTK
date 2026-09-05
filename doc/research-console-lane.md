# Research: console recompilation lanes — PowerPC and MIPS (P4)

> Status: **research / prototype only — no support claim.** GS-012 (BPTK-057,
> PowerPC — Xbox 360 / GameCube / Wii) and GS-013 (BPTK-058, MIPS — N64 / PS1
> + a PS2 spike) are **P4** in the execution lane. This note records feasibility
> and prior art; the roadmap rows stay `planned` and `npm run gate` keeps
> `passing` at 0. Nothing here claims console support, and the legal rail below
> is absolute.

## The recompiler generalizes; the ISA front-end does not (yet)

The static recompiler's shape — decode `.text` from entry, recover a CFG into
basic blocks, lower each block to straight-line WebAssembly over a guest-state
model, stay bit-exact against an interpreter oracle, refuse rather than guess —
is **ISA-independent**. The i386 front-end (decoder, register/flag model,
interpreter oracle) is the part that is x86-specific. A console lane reuses the
whole block/CFG/codegen/differential spine and swaps in a new front-end.

## Prior art (the bet this lane is modelled on)

Static machine-code→C→native recompilation is proven for exactly these consoles:
**XenonRecomp** (Xbox 360 PowerPC), **N64Recomp** (MIPS R4300i), and
**PSXRecomp** (MIPS R3000). They validate the core thesis — AOT recompilation
beats interpretation for fixed-ISA console binaries — which is why the execution
lane is recompilation-first (see
[research-static-recomp.md](research-static-recomp.md)).

## GS-012 — PowerPC (Xbox 360 / GameCube / Wii)

- **Front-end:** big-endian, fixed-width 32-bit instructions, 32 GPRs + 32 FPRs
  + condition register + link/count registers; the 360 adds VMX128 SIMD. The
  fixed width makes decode simpler than x86; the CFG/indirect-branch recovery
  (BPTK-047) applies directly to `bctr`/`blr` dispatch.
- **Endianness** is the one pervasive difference the shared codegen must thread.

## GS-013 — MIPS (N64 / PS1) + PS2 spike

- **Front-end:** fixed 32-bit instructions, branch **delay slots** (the one
  structural quirk the block former must model), 32 GPRs, and the PS1/PS2 GTE/VU
  coprocessors as separate units. N64Recomp/PSXRecomp are the direct templates.

## Legal rail (absolute, overrides feasibility)

Console content is overwhelmingly **not** DRM-free / offline / redistributable
freeware. The lane's hard rule holds: **detect-and-refuse** DRM, copy
protection, and any online/anti-cheat title by identity — never circumvent,
never touch a live service, never emit an unwrap/patch artifact. A console
front-end changes nothing here: an input that is not provably redistributable is
routed to `refuse`, which is why these lanes are P4 and gated behind the legal
and provenance rails, not a near-term support target.

## Prototype path (no support claim)

1. Stand up an interpreter oracle for a bounded fixed-ISA subset (PPC or MIPS)
   as the differential reference — the same discipline used for i386.
2. Add the front-end decoder + guest-state model; reuse the existing CFG,
   block, WASM-codegen, and differential-test spine unchanged.
3. Prove a generated microprogram bit-exact against the oracle before any claim,
   with the legal/provenance rail enforced on every input.
