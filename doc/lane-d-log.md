# Lane D log — runtime v2 milestone M2 (x86-64 lifter spine + interpreter oracle)

## Cycle 1 (2026-09-06)

Base corrected from a stale ancestor to `build/product-first` tip `d3340f0`
(both `lib/pe64.mjs` and `lib/x64decode.mjs` present) before any work.

### Built
- `lib/lift64.mjs` (new): independent structured decode → small typed IR →
  interpreter oracle.
  - Structured decode of the integer/branch/call/stack subset yielding register
    index 0-15, operand size 8/16/32/64, memory `{base,index,scale,disp,
    rip_relative}`, immediate as BigInt. Honors REX.W/R/X/B, ModRM+SIB,
    RIP-relative, disp8/32, the 0x66/0x67 prefixes. Reuses no x64decode output
    (that returns a rendered string); shares only the mnemonic vocabulary so the
    cross-check can compare classes.
  - IR nodes carry singular fields (`op`, `dst`, `src`, `src2`, `size`,
    `control`), never `operands`. `liftBlock` splits a run into a basic block
    terminated by the first branch/call/ret/leave/unsupported node.
  - Interpreter over a 16-entry 64-bit register file and flat guest memory
    (image copy + a bounded stack region). Deterministic, instruction-budget
    bounded. EFLAGS are lazy: add/sub/logic/cmp/test/inc/dec/neg record only the
    last flag source (kind + masked inputs + result); the six flags materialize
    only when read (a Jcc, SETcc, CMOVcc, or a query).
  - Families served end to end (decode+lift+interpret): MOV/MOVZX/MOVSX/MOVSXD,
    the ADD/OR/ADC/SBB/AND/SUB/XOR/CMP grid + 0x80/81/83 group, TEST, LEA,
    PUSH/POP (reg/imm/mem), INC/DEC, shifts (group 2), IMUL (1/2/3-operand),
    MUL/DIV/IDIV, NEG/NOT, CALL/JMP/Jcc/RET/LEAVE/NOP/ENDBR, SETcc/CMOVcc.
  - Outside the subset: an `unsupported` IR node naming the opcode; the
    interpreter stops with `unsupported_opcode`. Never a wrong lift.
- `test/lift64.test.mjs` (new): 8 microprograms with hand-frozen end state plus
  a basic-block split case, an honest-refusal case, and the plink cross-check.

### Verified
- `node --test test/lift64.test.mjs`: 11/11 pass.
- plink `.text` cross-check (read-only MIT freeware): decoded 212521, served
  183663 (86.4%), **0 disagreements** on length + mnemonic class vs
  `decodeX64Instruction`.
- `npm run gate`: exit 0 (validate.py + 466 tests + check:package, 58 files).
- New files registered in the three gate surfaces (validate ALLOWED set,
  reviewed-tarball list, bench/npm/content.json) in this commit.

### Honesty
No WASM emitted. No x86-64 execution claim beyond: the IR interpreter reproduces
the reference architectural state on the microprogram corpus. `passing` stays 0.
IMUL asserts only the SDM-defined flags (CF/OF); the undefined ones are not
frozen.
