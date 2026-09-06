# Lane AG log — clearing opcodes from Doom's menu to a first in-level frame

Goal: drive corpus-007 Chocolate Doom past the main menu into a first in-level
gameplay frame by serving the x86-64 opcode(s) the New-Game path reaches. Verify
recipe: `runImage64` with the WAD host-file + a scripted input trace (Escape to
open the menu, then six spaced RETURN presses to select New Game -> episode ->
skill -> start), budget up to 80,000,000. Each opcode is lifted bit-exact
(decode + IR + interpret) with a microprogram test in `test/lift64.test.mjs`.

## Cycle 1 — PEXTRW (66 0F C5 /r ib)

- Fault at instruction_count 22,279,804, address 0x140041949 (rva 0x41949).
- Faulting bytes: `66 0f c5 d0 00` = `pextrw edx, xmm0, 0`.
- Served in `lib/lift64.mjs`: decode (reg field -> GPR dst, r/m -> xmm src, imm8
  word selector) and interpret (`getLane(src, 16, imm&7)` zero-extended into the
  GPR via `writeReg`). No `lib/exec64.mjs` change — the existing `case "sse"`
  already routes to `executeSse`.
- Microprogram test: extracts word 3 (0x7777) and word 6 (0xAAAA), zero-extended.

## Cycle 2 — MOVLPS/MOVHPS family (NP/66 0F 12,13,16,17)

- Next fault at instruction_count 22,537,500, address 0x140041e9c (rva 0x41e9c).
- Faulting bytes: `0f 16 4c 24 20` = `movhps xmm1, [rsp+0x20]` (load high lane).
- Served in `lib/lift64.mjs` the whole low/high-lane move family, each preserving
  the untouched 64-bit lane:
  - NP/66 0F 12 MOVLPS/MOVLPD load (mem) and MOVHLPS (reg form, NP only).
  - NP/66 0F 13 MOVLPS/MOVLPD store (mem only).
  - NP/66 0F 16 MOVHPS/MOVHPD load (mem) and MOVLHPS (reg form, NP only).
  - NP/66 0F 17 MOVHPS/MOVHPD store (mem only).
- Microprogram tests: MOVHLPS/MOVLHPS lane copies, and a store+reload round trip
  of both lanes through the stack for the NP and the 66 encodings.

## Result

With both cycles served the New-Game trace no longer reaches an unsupported
opcode: the run advances to the 80,000,000 budget still executing its game loop
(stop_reason `instruction_budget_exhausted`), all 14 scripted input events
delivered, present_count 91.

Frame comparison (FNV-1a over the presented RGBA):

| frame | hash | present | painted frac | avg RGB |
| --- | --- | --- | --- | --- |
| title | (red-dominant attract) | 14 | — | avgR high, low G/B |
| menu  | 2e4f7f87fbd7841 | 10 | 0.983 | 98.3 / 19.3 / 15.9 |
| game  | cfc859b3fc136f7d | 91 | 0.934 | 45.1 / 42.7 / 33.1 |

The gameplay frame is non-blank, distinct from BOTH the title and the menu
hashes, and carries a balanced neutral palette (R~G~B) consistent with the
rendered 3D level view + status bar rather than the red menu palette — a first
in-level gameplay frame.

`npm run gate` exits 0 (620 pass, 1 skipped corpus-gated). Corpus unchanged:
loaded 2, entry 9. `passing` stays 0 (a rendered frame is not a playability
claim).
