# Lane U — paint the window/dialog into the RGBA surface and expose it

Milestone 3 of `doc/browser-display-scope.md`: turn "the window object exists in
memory" into "you can see it." `runImageBytes` now returns the pixels the
runtime actually painted for the windows it created, not a zeroed surface.

## What changed

- **`lib/user.mjs` — a persistent paint log.** A window is snapshotted into an
  ordered `paintLog` the moment it is shown (`ShowWindow`), its paint is flushed
  (`UpdateWindow` / a synthesized `WM_PAINT`), or a dialog is instantiated
  (`instantiateDialog` captures the frame before its controls). The snapshot
  carries geometry, class, and caption, and it **survives the window's later
  destruction** — exactly as a real screen keeps painted pixels. The About
  dialog's frame is torn down by PuTTY before the probe stops, but its
  show-time paint remains. New accessors: `windowList()`, `paintSnapshot()`.
  Window objects now store `text` (RT_DIALOG title / control caption).

- **`lib/gdi.mjs` — the desktop compositor.** `compositeDesktop(snapshot, w, h)`
  clears the desktop, then paints each logged snapshot back-to-front using the
  existing primitives (`fillRect`, `TextOut`): a top-level snapshot as a window
  frame (COLOR_BTNFACE client, black border, active-caption band + title text),
  a child snapshot by its class — STATIC → caption `TextOut`, BUTTON → beveled
  face + centered caption, EDIT → sunken white client. Painting is generic **by
  class, never by title**. The stock 8x8 font was widened to full A–Z / 0–9 /
  punctuation so captions render as real ink. Deterministic: same log → same
  bytes.

- **`lib/exec64.mjs` — expose the guest.** `runImage64` returns the live HLE
  guest; `executeProbe64` attaches it only under `option.capture_guest` (never
  serialized into the corpus/run record).

- **`lib/present.mjs` — composite the surface.** `runImageBytes64` runs with
  `capture_guest`, then composites `guest.user.paintSnapshot()` through
  `guest.gdi.compositeDesktop`. Falls back to the cleared surface only when no
  guest is exposed or the paint log is empty.

## Verification

- `test/gdi.test.mjs`: a synthetic dialog (STATIC "About PuTTY" + OK BUTTON) is
  instantiated through the real window manager and composited; frame, caption,
  STATIC ink, and BUTTON bevel/ink land at the template geometry (offset by the
  caption band). Determinism, empty-log fallback, and EDIT sunken client covered.
- `test/present.test.mjs`: PuTTY x64 bytes → a surface that is no longer all
  zero; 12.6% of pixels are non-background; the About dialog's COLOR_BTNFACE
  client and active-caption band land at its stored location (140,40 / 270x136);
  byte-identical across two runs.
- `node bin/bptk.mjs corpus run`: unchanged — 9 at `entry`, 2 at `loaded`.
- `npm run gate`: exits 0 (565 pass, 1 skipped).

## Honesty

The pixels are what the compositor painted from the real RT_DIALOG template +
control geometry the runtime instantiated — no hardcoded "About PuTTY" bitmap,
no mock, generic by control class. `passing` stays 0: a painted dialog is not a
playable game.
