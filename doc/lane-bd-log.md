<!--
Copyright 2026 Maphy Technologies
SPDX-License-Identifier: Apache-2.0
-->

# Lane BD — tiered x86-64 execution, proven 1:1

## Milestone

A real x86-64 image executed through a **tiered** runner — a WebAssembly fast
path for eligible functions plus the interpreter for the rest, over **one shared
guest state** — produces architectural state **bit-exact** to pure
interpretation.

## What was built

- `lib/tierrun.mjs` — `runTieredImage(option)`. Builds the single shared guest
  context with `lib/exec64.mjs` `buildGuestContext64` (multi-region Machine +
  Win32 HLE), then drives it function-by-function. At each direct-call site the
  callee's tier is decided once (cached by entry VA):
  - **WASM tier** iff `lib/wasm64.mjs` `compileFunction` reports `complete` AND
    the coverage names no `control_call_external` / `control_call_indirect` /
    `control_jmpIndirect` / `not_served` (a pure-compute subtree of direct calls
    only). Such a function runs as a real `WebAssembly` module (`runFunction`)
    seeded from the live register file + region bytes and read back at the
    boundary. No host/HLE call happens inside it, so no mid-function sync is ever
    needed.
  - **Interpreter tier** otherwise. The executor is a **byte-for-byte port** of
    `lib/exec64.mjs`'s `executeNode` / `executeAlu` / `executeShift` /
    `executeDoubleShift` and its gs/fs segment-aware decode, so it cannot diverge
    from `runImage64`. Reached imports are served through the exported
    `serveImport64` / `serveImportAt64` — never re-implemented.
- `test/tierrun.test.mjs` — the 1:1 proof.
- Gate-surface registration (3 places): `tool/validate.py` ALLOWED list +
  reviewed-tarball manifest, `bench/npm/content.json`.

## The 1:1 result

- **Synthetic real-shaped image** (image at 0x140000000, a HIGH 140 TB stack):
  entry (interpreter tier) calls one pure leaf (WASM tier: mov/add + stack
  push/pop) and one rotate leaf (interpreter tier — the codegen cannot emit
  `ror`). Tiered final state — 16 GPRs, 6 flags, rip, stop, **and every region's
  bytes** — is bit-exact to pure interpretation; result carries through both
  tiers (`rax = (5+3+7) ror 4 = 0xF000000000000000`). ≥1 function ran WASM-tier.
- **PuTTY x64** (staged corpus binary): anchored to `runImage64` at a 20 000
  instruction budget (registers/flags/rip/stop/instruction-count identical, the
  proof that the ported interpreter tier IS the reference interpreter), then run
  to its first natural frontier (the `CreateDialogParam` dialog specialization
  the tiered runner declines to drive, reached deep in the real CRT startup).
  Tiered vs pure interpretation there: **bit-exact** registers, flags, rip, stop,
  and all region memory.
  - **WASM tier: 20 functions, 69 invocations.**
  - Interpreter tier: 96 functions, 21 387 instructions.

## Gate

`npm run gate` → exit 0 (689 tests, 688 pass, 1 skipped, 0 fail; `passing`
stays 0). No divergence anywhere — the WASM tier genuinely carries the guest
state forward and does not re-invoke the interpreter (the default path runs no
interpreter for a WASM-tier function; `option.wasmAudit` is an opt-in test-time
cross-check only).

## Honest scope note

The tiered runner declines the CRT-initializer / dialog / window-message
specializations (`_initterm`, `CreateDialogParam*`, the message pump) that
`lib/exec64.mjs`'s loop drives through private multi-step resumes not exposed by
any export. PuTTY reaches the first of these (`CreateDialogParamA`) after ~26 400
instructions, which is the deterministic frontier the proof stops at. Driving
those specializations end-to-end (to run PuTTY past CoInitialize and to windowed
frames) is the same mechanism at greater surface and is the next increment.
