# Lane G log — deepen i386 execution (CORPUS-009 Plink)

Scoreboard: Plink `runPackage` bounded probe, instruction_count before vs after.

## Cycle 1 — fs segment base missing on the moffs forms

- Hypothesis: the fault at instruction 67, a `write_fault` to address 0 while
  executing `64 a3 00 00 00 00` (`mov fs:[0], eax`, the SEH-prologue store, not
  the security cookie), means the `fs` segment base is not applied to the
  direct-offset moffs forms. The ModRM path adds `segmentBaseValue`; the
  0xa0-0xa3 moffs path fetched a bare displacement and resolved it against a
  zero base, so `mov fs:[0], eax` wrote linear address 0.
- Fix: `lib/runtime.mjs` — the 0xa0/0xa1/0xa2/0xa3 handlers now add
  `segmentBaseValue` to the fetched displacement (identity for the flat
  cs/ds/es/ss, the TEB linear address under fs).
- Result: 67 -> 102. Fault moves to `d3 c8` (`ror eax, cl`).

## Cycle 2 — Number/BigInt mix in the rotate group

- Hypothesis: `ror`/`rol` by CL throws a JS TypeError ("Cannot mix BigInt and
  other types") from `BigInt(bitCount - shift)` where `bitCount` is a Number and
  `shift` a BigInt.
- Fix: `lib/runtime.mjs` — use `(BigInt(bitCount) - shift)` in both `rol` and
  `ror`.
- Result: 102 -> 2255. Fault moves to `0f af 75 0c` (`imul esi, [ebp+0xc]`).

## Cycle 3 — asIntN bit-count argument passed as BigInt (imul)

- Hypothesis: `imulTwoOperand` calls `BigInt.asIntN(BigInt(bits), ...)`;
  `asIntN`'s first argument must be a plain Number, so it throws "Cannot convert
  a BigInt value to a number".
- Fix: `lib/runtime.mjs` — pass `bits` (Number) to the three `asIntN` calls in
  `imulTwoOperand`.
- Result: 2255 -> 7466. Fault moves to `c1 f9 06` (`sar ecx, 6`).

## Cycle 4 — same asIntN bug in the arithmetic-shift path

- Hypothesis: `shiftOperation` (sar) calls `BigInt.asIntN(bigBits, ...)` /
  `BigInt.asUintN(bigBits, ...)` with a BigInt bit count.
- Fix: `lib/runtime.mjs` — pass `bitCount` (Number) to the `asIntN`/`asUintN`
  calls in the sar branch.
- Result: 7466 -> 16762. Fault moves to `db e2` (`FNCLEX`), a structured
  `unsupported_opcode` refusal.

## Cycle 5 — x87 control forms FNCLEX / FNINIT

- Hypothesis: the CRT floating-point startup issues `FNINIT`/`FNCLEX` (0xdb /4
  register forms), which the bounded x87 subset refused.
- Fix: `lib/runtime.mjs` — serve `db e2` (FNCLEX: clear pending exception and
  busy bits) and `db e3` (FNINIT: default control word, cleared status, empty
  stack).
- Result: 16762 -> 28805. Fault moves to `66 0f 70` (`pshufd`), a 128-bit SSE2
  form the bounded MMX subset declares out of scope. Stopping here — deepening
  further requires the 128-bit SSE2 integer register file, a materially larger
  addition, not a bug.

## Summary

- Before: `instruction_count` 67, `stop_reason` `write_fault` (NULL store).
- After:  `instruction_count` 28805, `stop_reason` `unsupported_opcode`
  (`pshufd`, a declared architectural bound).
- Root cause of the reported fault: the moffs forms ignored the segment base, so
  the SEH-prologue `mov fs:[0], eax` resolved to linear address 0. Cycles 2-5
  were latent CPU/x87 gaps the deeper run then exposed.
- CORPUS-009 stays at `entry`; `passing` stays 0 (deeper entry is still not
  playable).
- Regression tests: `test/i386.test.mjs` (ror/rol by CL, sar imm, two-operand
  imul both flag paths, FNINIT/FNCLEX round-trip); `test/runtime.test.mjs`
  (fs moffs load against the TEB self pointer, fs moffs store round-trip).
