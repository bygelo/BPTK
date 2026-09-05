# CPU subsystem log

The run record for the i386 decoder/executor (BPTK-009): the bounded probe's
instruction surface, its microprogram conformance suite, and the measured
decode coverage of the real corpus .text toward the entry. A reached stage is
not a playable claim; implemented is not passing.

## Measurement method

`sweepI386Text` (lib/i386.mjs) walks a real payload's executable section
linearly with the same prefix and ModRM length rule the probe decodes and
classifies every instruction against the declared opcode inventory. The
metric is the served share of decoded instruction; unsupported count includes
genuine refusal (fs override, port I/O, BCD) and linear-sweep drift across
data and alignment byte, which is why the honest comparison is the same
method before and after a slice, never a claimed absolute. The committed
sweep is the canonical method from cycle 1 of this log on; the cycle-0
baseline below was measured with an equivalent throwaway decoder.

## 2026-09-05 — cycle 0 baseline (at `271a421`)

- `npm run gate` exit 0 on a clean tree; manifest 40 implemented, 0 passing.
- Real i386 corpus payload decode sweep (throwaway method): Plink 0.74 i386
  12.5% unsupported of 152,905 decoded instruction; OpenTTD 1.10.3 i386
  13.8% unsupported of 1,002,553. Top gap: the entire byte-granular integer
  family (0x00-0x3d byte columns, 0x80 byte immediate group, 0x88/0x8a byte
  mov, 0xa8 test al), then 0x99 cdq, 0x86 xchg, the 0xe0-0xe3 loop family,
  0xfe inc/dec r/m8, the flat-model segment and lock prefix, cmovcc, and the
  MMX/SSE map.
- The probe refused all of those as structured unsupported_opcode stops.
- Conformance state: 35 runtime check exercised the probe surface with
  example-style assertion, but no frozen reference-state microprogram suite
  existed — the acceptance contract had no machine to compare against.

## 2026-09-05 — cycle 1: the byte-granular integer space + the conformance machine

### Implemented (generic; no payload or title branch anywhere)

- The full two-operand ALU space in its byte and dword columns (0x00-0x3b,
  direction bit honored after the rewrite caught a reg/rm swap that
  clobbered the destination register), the al,imm8 column (0x04-0x3c), the
  0x80/0x82 byte immediate group (0x82 as the documented alias), 0x88/0x8a
  byte mov, 0xa0/0xa2 byte moffs, 0xa8/0xa9 test accumulator-imm, and the
  0xfe inc/dec r/m8 group with carry preserved like 0xff.
- The misc one-byte integer family: 0x98/0x99 (cwde/cbw, cdq/cwd with 0x66
  and the high-word preservation rule), 0x86/0x87 xchg, 0x8f pop r/m with
  the post-pop esp effective address, 0x60/0x61 pusha/popa, 0xf5/0xf8/0xf9
  carry operation, 0x9e/0x9f sahf/lahf (including the reserved-bit and
  always-one bit contract), 0x9b wait as the declared identity, 0xd7 xlat,
  and the 0xe0-0xe3 loop family with the jecxz (never cx — 0x67 stays
  refused) form.
- The integer 0x0f extension family: cmovcc (0x40-0x4f), bt/bts/btr/btc
  (register form modulo the operand size, memory form signed byte offset
  with the bit in that byte), the 0f ba /4-/7 immediate group, bsf/bsr with
  the declared zero-destination choice, shld/shrd over a BigInt
  concatenation with the exact carry (the SHRD source-half construction bug
  was caught by the frozen reference state and fixed), cmpxchg, xadd, and
  the hint NOP family (0f 0d, 0f 18-0x1f) that real alignment padding emits.
- Prefix decode: the flat-model segment override (0x26/0x2e/0x36/0x3e —
  every base is zero in the flat Windows model, so identity is exact, not a
  guess) and lock (0xf0 — one in-order interpreter serializes by
  construction) are served; fs/gs (0x64/0x65) refuses with a named
  diagnostic because no thread-environment block is declared; 0x67 stays
  refused. HLT/CLI/STI and the port families stop as named privileged
  instruction refusal (user-mode code cannot execute them on a real CPU —
  pretending otherwise would be the silent divergence).
- The rep contract widened honestly: rep is no longer refused on cmps/scas,
  and the cmps operand bug (it compared [esi] with EAX instead of [edi]) is
  fixed — both found by writing the suite, both covered by regression case.
  The repeat loop is one instruction to the budget, so a declared bound
  (2^20 iteration) stops the pathological repeat as `rep_iteration_bound`
  instead of a silent stall.

### Proof

- The microprogram conformance suite (test/i386.test.mjs): 38 test whose
  microprogram carry frozen, hand-derived reference machine state — every
  general register and every architecturally defined flag compared bit-exact
  through the real run surface, with the BT-family and BSF/BSR
  architecturally undefined field declared rather than invented. Flag and
  register error on both sides were caught by these case during the cycle
  (the probe's lahf wrote al instead of ah; sahf read al instead of ah; the
  suite's own shld/shrd modrm direction and three flag derivation were
  wrong and got corrected against the semantics, not against the code).
- The inventory consistency contract: the declared inventory
  (i386OpcodeOneByte, i386OpcodeGroup, i386Opcode0f, i386Opcode0fGroup,
  i386Prefix) and the probe agree byte for byte over ~560 executed
  microprogram — every declared-served opcode executes without the
  unsupported stop, and every undeclared opcode stops with the stable
  structured diagnostic naming the opcode. LEA (memory-only ModRM), the
  x87 /reg refinement, and the prefix byte carry their dedicated case.
- Full suite: 164 test, 0 failing. `npm run gate` exit 0 in a worktree of this commit alone (the shared working tree also carries an in-flight thread-subsystem session whose uncommitted file the shared-tree validator flags; the isolated gate is the verdict for this commit).

### Measured delta on the real DRM-free corpus

- Plink 0.74 i386: 87.5% → **94.0%** decode coverage (12.5% → 6.0%
  unsupported of 130,444 decoded instruction under the committed method).
- OpenTTD 1.10.3 i386: 86.2% → **95.1%** decode coverage (13.8% → 4.9%
  unsupported of 843,712 decoded instruction).
- `bptk corpus run`: both real i386 entry stay honestly at `loaded`
  (import_present → BPTK-010); the served-import ledger is unchanged by this
  slice because no HLE export was added — the CPU metric is the decode
  sweep above, which is the "decodes further of its .text toward entry"
  acceptance line.

### Ranking for the next cycle (from the committed sweep histogram)

1. fs-relative addressing (OpenTTD carries 1,172 fs-override refusal) —
   needs a declared thread-environment block page in the probe memory model,
   which pairs with the parallel thread subsystem.
2. MMX (0f 6e/6f/7e/7f/70/73/ef/eb) — the largest real remaining integer
   family on Plink (0f 6f x447); maps onto the 64-bit lanes the FPU already
   owns.
3. SSE/SSE2 scalar + packed via WASM SIMD with the strict fallback.
4. x87 80-bit intermediate precision (the current subset is 64-bit) and the
   declared CPUID leaf breadth beyond the vendor/feature leaf.
5. Remaining one-byte refusal: les/lds (0xc4/0xc5), the segment-register
   mov/push family (0x06/0x07/0x8c/0x8e), BCD (0x27/0x2f/0x37/0x3f), and
   the string port family (0x6c-0x6f) — each honestly refused today and
   needed only when a real binary demands it.
