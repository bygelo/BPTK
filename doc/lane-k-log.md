# Lane K log — x86-64 SSE/SSE2 so x64 binaries execute deeper

Scope: lib/lift64.mjs, lib/exec64.mjs, test/lift64.test.mjs, test/exec64.test.mjs.
Base: build/product-first @ 26d1d89 (lane J merge — that lane touched lib/runtime.mjs,
the i386 runtime; the x86-64 lift64/exec64 pipeline carried NO SSE).

## Starting frontier (base 26d1d89)

The x86-64 corpus binaries stopped at `unsupported_opcode` earlier than the mission
narrative assumed — not at an SSE op, but at the two-byte integer ops the CRT init runs
before its SSE code:

| corpus | binary | instr | stop opcode |
| --- | --- | --- | --- |
| 001 | PuTTY x64 | 62 | 0F A2 CPUID |
| 003 | jq amd64 | 17 | 0F B1 CMPXCHG |
| 007 | Chocolate Doom x64 | 20 | 0F B1 CMPXCHG |

## Work

Added, bit-exact, to both the lift64 oracle and the exec64 bounded probe (the SSE/CPUID/
CMPXCHG/string executors live in lift64 and are imported by exec64, so the two files
cannot diverge on a result):

- SSE/SSE2 register file: 16 × 128-bit xmm, little-endian lane packing.
- Moves: movups/movupd, movaps/movapd, movdqa/movdqu, movss, movsd, movd, movq
  (load/store, reg/mem, REX.W movq), movmskps, pmovmskb.
- Bitwise: andps/andnps/orps/xorps, pand/pandn/por/pxor.
- Shuffle: pshufd, pshuflw, pshufhw.
- Packed integer: paddb/w/d/q, psubb/w/d/q, pcmpeqb/w/d, pcmpgtb/w/d, pmullw, pmuludq,
  punpckl/h bw/wd/dq/qdq, packsswb/packssdw/packuswb.
- Shifts: psllw/d/q, psrlw/d/q, psraw/d (register and immediate forms), psrldq/pslldq.
- Integer prerequisites the binaries hit before/around the SSE code: CPUID (served
  against exactly the emulated feature set — x87/TSC/CMOV/MMX/FXSR/SSE/SSE2, nothing
  more), CMPXCHG, BT/BTS/BTR/BTC (imm + reg), BSF/BSR, XADD, XCHG, BSWAP, CBW/CWDE/CDQE,
  CWD/CDQ/CQO, the REP/REPE/REPNE string ops (MOVS/CMPS/STOS/LODS/SCAS — one counted
  instruction per element), and CLD/STD.

The F2 mandatory prefix is relaxed only for the SSE 0F map and the CMPS/SCAS string ops;
a plain F2 on any other one-byte opcode stays an honest `unsupported` refusal.

## Ending frontier

| corpus | instr before → after | stop before → after |
| --- | --- | --- |
| 001 PuTTY x64 | 62 → 1646 | CPUID → import_present kernel32!FlsAlloc |
| 003 jq amd64 | 17 → 33 | CMPXCHG → import_present crt!_initterm |
| 007 Chocolate Doom x64 | 20 → 102 | CMPXCHG → import_present crt!_set_invalid_parameter_handler |

All three now execute through the SSE/integer-op families and stop at a genuine Win64 HLE
import boundary (milestone M4, out of lane K scope), not an unsupported opcode. `corpus run`
reached-stage unchanged (entry 8, loaded 3 — no regression). `passing` stays 0 — real
execution, no faked results.

Tests: 12 bit-exact SSE/CPUID/CMPXCHG/string microprograms added to test/lift64.test.mjs
(hand-encoded bytes → hand-derived xmm/GPR end state, read back through movq/pmovmskb),
2 mirror microprograms in test/exec64.test.mjs proving the probe agrees with the oracle.
The plink .text cross-check served fraction rose 50%+ → 90.2% with 0 disagreements. Gate
green: 517 pass, 0 fail.
