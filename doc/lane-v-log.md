# Lane V — dialog-unit layout (DLU → pixel)

## Problem
`runImageBytes` composited PuTTY's "About PuTTY" #32770 dialog to the GDI
surface, but the compositor consumed the RT_DIALOG template coordinates as raw
pixels. Windows dialog templates are in **dialog units (DLU)**, not pixels: with
the buttons treated as raw DLU, their 70-DLU width became 70 px — too narrow for
the 8-px-per-glyph captions ("View &Licence", "Visit &Web Site"), so the ink
spilled across the buttons.

## Fix (real DLU math from the template, not tuned constants)
The conversion is applied in `lib/user.mjs` `instantiateDialog`, exactly where
Win32's CreateDialogIndirect maps a DLU template to pixel windows. Only dialog
windows go through it; regular `CreateWindowExW` windows are already pixels.

- Base unit pair derives from the dialog font. The classic MS Sans Serif 8 pt
  reference (and the default when a template names no font) is `(6, 13)` px per
  the 4-horizontal / 8-vertical DLU quantum. A named font scales that 8 pt
  reference by its point size (`dialogBaseUnit`).
- `pixelX = MulDiv(dluX, baseX, 4)`, `pixelY = MulDiv(dluY, baseY, 8)`, same for
  width/height (`mulDiv`, `dialogRectToPixel`). `MulDiv` rounds to nearest.
- The frame, its position, and every control's x/y/cx/cy all go through the
  conversion. The template cx/cy is the CLIENT extent, so the frame window height
  is the converted client height plus the caption band the compositor draws
  inside the frame top — this keeps every control (positioned client-relative,
  below the caption) within the frame rather than spilling past its bottom edge.

PuTTY's About dialog declares **MS Shell Dlg 8 pt**, so `dialogBaseUnit` computes
`(mulDiv(6,8,8), mulDiv(13,8,8)) = (6, 13)` — generic, keyed off the template
font, never hardcoded to PuTTY.

## Compositor exposure (for the test)
`lib/gdi.mjs` `compositeDesktop` now also returns `frame_rect` and `control_rect`
— the exact screen rectangles it painted — so a fixture asserts placement and
non-overlap directly.

## PuTTY's three buttons: before → after (screen pixel rects)
Template (DLU), font MS Shell Dlg 8 pt, base unit (6, 13). Frame DLU (140,40)
270×136 → pixel (210,65) 405×(221+14 caption)=405×235. Children are placed at
the frame origin plus the 14-px caption band.

| Button          | DLU x,y,cx,cy   | before (raw DLU as px, screen) | after (converted, screen) |
|-----------------|-----------------|--------------------------------|---------------------------|
| View &Licence   | 6,118,70,14     | 146..216 × 172..186            | 219..324 × 271..294       |
| Visit &Web Site | 140,118,70,14   | 280..350 × 172..186            | 420..525 × 271..294       |
| &Close          | 216,118,48,14   | 356..404 × 172..186            | 534..606 × 271..294       |

After conversion the three buttons are 105/105/72 px wide (wide enough for their
captions), sit side by side left-to-right sharing top edge 271, and are pairwise
non-overlapping (324 ≤ 420, 525 ≤ 534). All lie within the frame (210..615 ×
65..300) on the 640×480 surface.

## Verification
- `test/present.test.mjs`: PuTTY x64 painted control rects are non-overlapping and
  each matches `dialogRectToPixel` applied to the real template for its own font;
  the dialog frame lands at its converted pixel location; determinism holds.
- `test/user.test.mjs`: `mulDiv`/`dialogBaseUnit`/`dialogRectToPixel` unit tests;
  synthetic two-button dialog converts to non-overlapping pixel rects.
- `test/gdi.test.mjs`: compositor rect exposure and non-overlap for a synthetic
  two-button dialog; existing frame/caption/static/button/edit tests updated to
  the converted geometry.
- `node bin/bptk.mjs corpus run` unchanged: entry 9, loaded 2.
- `npm run gate` exits 0; roadmap `passing` stays 0.
