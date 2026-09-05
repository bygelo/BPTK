# Lane AD log — clearing the opcode wall to Chocolate Doom's first frame

Base: `9648ffa` (build/product-first). Owns lib/lift64.mjs, lib/exec64.mjs,
lib/x64decode.mjs and their tests. Verifies against corpus-007 (Chocolate Doom,
x86-64, GPL) loading the staged Freedoom Phase 1 WAD, driven through
`executeProbe64` with the WAD served as a host file.

## Cycle 1 — SHRD / SHLD (double-precision shifts)

Doom stopped at `unsupported_opcode SHRD (0F AC)` at `0x140020a04`
(`41 0f ac c9 1d` = `shrd r9d, ecx, 0x1d`) after 4,864,357 instructions.

Added the double-precision shift family to the decoder, the oracle interpreter
(lift64), the ported probe executor (exec64), and the disassembler (x64decode):

- `0F A4` SHLD Ev, Gv, imm8
- `0F A5` SHLD Ev, Gv, CL
- `0F AC` SHRD Ev, Gv, imm8
- `0F AD` SHRD Ev, Gv, CL

Semantics (bit-exact): count masked to the operand size (0x3f for 64-bit, else
0x1f); a zero count is a no-op that touches no flag. Vacated bits fill from the
source operand across the operand boundary. CF is the last bit shifted out of
the destination; SF/ZF/PF follow the result; OF is the destination sign-bit
change (defined for a 1-bit shift, left deterministic otherwise); AF cleared.

New microprograms: SHRD/SHLD imm8 (32-bit), REX.W SHRD (64-bit, 0x3f mask),
SHLD-by-CL, and a zero-count no-op — added to both test/lift64.test.mjs and
test/exec64.test.mjs, each frozen by hand from the semantics.

### Result

With SHRD/SHLD served, no further unsupported opcode is reachable from the
former wall to graphics init. Doom runs the full pre-graphics init and reaches
the SDL2 video subsystem:

```
R_Init: Init DOOM refresh daemon - ...............................
P_Init: Init Playloop state.
S_Init: Setting up sound.
D_CheckNetGame: Checking network game status.
HU_Init: Setting up heads up display.
ST_Init: Init status bar.
```

- Real 10,000,000-instruction budget: `instruction_budget_exhausted`, mid
  `R_Init` — no opcode wall (was `unsupported_opcode SHRD` at 4,864,357).
- Beyond the budget (investigation only; the bound was restored to 10,000,000):
  Doom reaches `sdl2.dll!SDL_GetNumVideoDisplays` (inside `I_InitGraphics`) at
  13,055,021 instructions, stop `import_present`.

The next blocker is NOT an opcode: it is the SDL2 video HLE
(`SDL_GetNumVideoDisplays`), owned by the SDL lane (lib/sdl.mjs). No framebuffer
was produced (`guest.sdl.has_video` false, no window created) — I_InitGraphics
has not yet opened the SDL window. SHRD/SHLD is the only opcode this lane needed.

Corpus: 9 at entry, 2 loaded (no regression); PuTTY (001) / jq (003) unaffected.
`npm run gate` exits 0.
