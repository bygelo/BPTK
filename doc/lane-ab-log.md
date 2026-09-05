# Lane AB log — SSE3 for Chocolate Doom

Lane AB adds the SSE3 instruction family to the x86-64 lifter/interpreter so
Chocolate Doom (corpus-007) advances past its MOVDDUP opcode wall.

The SSE execution and structured decode live in `lib/lift64.mjs` and are shared
by `lib/exec64.mjs` through direct import (`executeSse`, `decodeStructured`), so
the oracle and the bounded probe cannot diverge on a lane result — there is one
implementation, not a re-derived copy.

## Cycle 1 — SSE3 family

Added to `liftSse` / `executeSse` (lib/lift64.mjs), bit-exact per lane:

| Instruction | Encoding | Semantics |
| --- | --- | --- |
| MOVDDUP   | F2 0F 12 | replicate low 64-bit lane across both halves |
| MOVSLDUP  | F3 0F 12 | duplicate even 32-bit lanes (0,0,2,2) |
| MOVSHDUP  | F3 0F 16 | duplicate odd 32-bit lanes (1,1,3,3) |
| HADDPD    | 66 0F 7C | horizontal add, packed double |
| HADDPS    | F2 0F 7C | horizontal add, packed single |
| HSUBPD    | 66 0F 7D | horizontal subtract, packed double |
| HSUBPS    | F2 0F 7D | horizontal subtract, packed single |
| ADDSUBPD  | 66 0F D0 | subtract lane 0 / add lane 1 (double) |
| ADDSUBPS  | F2 0F D0 | subtract even lanes / add odd lanes (single) |
| LDDQU     | F2 0F F0 | unaligned 128-bit load (aliases the shared 128-bit move) |

The float horizontal/interleaved forms decode each lane to its IEEE value via the
existing f32/f64 helpers, apply the operation at full precision, and re-encode —
bit-exact for any value the lane holds.

`lib/x64decode.mjs` (the independent integer-only length decoder) is unchanged:
it already refuses all SSE (SSE2 included) honestly, and its cross-check with the
structured decode only compares the instructions the structured decode SERVES, so
it needed no new lengths. Extending it for SSE3 alone would break its documented
integer-only scope.

Tests: 9 bit-exact SSE3 microprograms in `test/lift64.test.mjs` (hand-encoded
bytes → known xmm end-state, read back through movq/pshufd), mirrored by an
exec64 microprogram in `test/exec64.test.mjs` proving the probe agrees with the
oracle on movddup/haddpd/addsubps.

### Chocolate Doom advance

- Before: 2338 instructions, stop `unsupported_opcode` F2 0F 12 (MOVDDUP) at
  RVA 0x25334.
- After: 2753 instructions, stop `import_present` at
  `api-ms-win-crt-filesystem-l1-1-0.dll!_wmkdir` (RVA of call site 0x3eb6).

The opcode wall is cleared; the new frontier is an M4 HLE import gap (owned by
another lane), not an unsupported opcode. Did NOT yet reach `I_InitGraphics` /
`SDL_CreateWindow` — the `_wmkdir` filesystem import blocks first.

No regression: PuTTY (corpus-001) still runs 32073 instructions to
`ole32!CoInitialize`; jq (corpus-003) still stops at its prior HLE fault (516
instructions); `corpus run` keeps 9 at entry. `npm run gate` exits 0.
