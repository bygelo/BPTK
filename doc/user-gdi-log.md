# USER32 / GDI subsystem log (BPTK-011 / BPTK-012)

The windowing, message-loop, input, and 2D GDI slice. This log records what
each cycle lands, the coverage delta on the real corpus, and the exact state of
the acceptance contracts. Nothing here claims playable; the gate is the judge.

## Acceptance contracts

From the lane brief, the subsystem is accepted when:

1. a USER32 message-order fixture replays deterministically;
2. a GDI draw fixture renders within tolerance of a **test-time** reference
   (no committed golden, per `doc/TESTING.md`);
3. an input trace yields the exact message sequence.

All three contracts are **green**: contracts 1 and 3 as of cycle 1
(`test/user.test.mjs`), contract 2 as of cycle 2 (`test/gdi.test.mjs`).

## Dependency state

The subsystem depends on the thread core (the message queue is per-thread) and
the SEH core. Neither `lib/thread.mjs` nor `lib/seh.mjs` exists in this
worktree yet — they are built in sibling lanes and merged threads-first. So:

- The per-thread message queue keys on the single declared guest thread id
  (`userBound.thread_id_default`) instead of a live thread registry. When the
  thread core lands and this lane rebases onto it, the queue keys on the real
  registry — a one-line change in `createUserSubsystem`.
- The USER32 export table (`userExportTable` in `lib/user.mjs`) is authored but
  **not yet registered** into `lib/hle.mjs`. Registering it edits the guest
  literal in the shared HLE file; that edit is held until after the
  threads-first rebase to avoid a premature merge conflict. Until then the
  live corpus export-coverage ledger is unchanged (the surface is real code
  with a green module contract, but not yet reachable from a guest PE).

The honest consequence: **0 passing corpus benchmark stays 0.** No real `.exe`
stage moves until the whole thread → seh → cpu → user/gdi block lands. Cycle 1
delivers verifiable generic logic and its acceptance fixtures, not a playable.

## Cycle 1 — USER32 window class, lifecycle, message loop, input

`lib/user.mjs`, `test/user.test.mjs`. Generic throughout — a window is a
window; no branch on any title identity.

Delivered:

- **Class registry** — `RegisterClass` / `RegisterClassEx` / `UnregisterClass`,
  duplicate-name and in-use refusals with the exact Win32 last-error codes.
- **Window lifecycle** — `CreateWindowEx` sends the exact `WM_NCCREATE`,
  `WM_CREATE` creation pair; a `WM_NCCREATE` that returns FALSE or a
  `WM_CREATE` that returns −1 aborts creation and yields NULL. `DestroyWindow`
  releases focus and activation, then delivers `WM_DESTROY`, `WM_NCDESTROY`.
- **Show / activation cascade** — `ShowWindow` drives `WM_SHOWWINDOW`,
  `WM_ACTIVATEAPP`, `WM_ACTIVATE`, `WM_SETFOCUS`; `UpdateWindow` flushes a
  pending `WM_PAINT` synchronously; `InvalidateRect`-shaped paint marking.
- **Message loop** — a per-thread FIFO queue; `GetMessage` / `PeekMessage`
  with correct ordering (posted messages first, then a synthesized `WM_PAINT`
  for a visible window that needs one, then `WM_QUIT` after `PostQuitMessage`
  drains the queue); `TranslateMessage` (`WM_KEYDOWN` → `WM_CHAR` for a mapped
  key); `DispatchMessage` routing to the target `WndProc`; `DefWindowProc`
  (`WM_CLOSE` → self-destroy).
- **Input translation** — `injectKey` / `injectMouse` post `WM_KEYDOWN` /
  `WM_KEYUP` / `WM_CHAR` / `WM_MOUSEMOVE` / `WM_{L,R,M}BUTTON{DOWN,UP}` to the
  focused window, position packed into `lParam`. The trace never names a
  window; the target is always the current focus/active window.

Acceptance evidence (all green, `node --test test/user.test.mjs`):

| Contract | Test |
| --- | --- |
| Message-order fixture, deterministic | "the message-order fixture replays identically across two runs" |
| Lifecycle exact order | "the lifecycle fixture delivers create, show cascade, paint, and quit in exact order" |
| Input trace → exact WM_* sequence | "an input trace yields the exact WM_* message sequence" |
| Coverage complete over the served surface | "conformance: every served USER32 export carries a case and matches the oracle" |

The conformance case uses the shared apparatus (`lib/conformance.mjs`): every
symbol in `userExportTable` carries at least one oracle case, so a zero-case
export is caught as a coverage hole — the same discipline the core HLE holds.

Gate: `npm run gate` exits 0 (174 tests pass; 45-file package manifest).

## Cycle 2 — GDI device context, primitives, raster ops, text, packed formats

`lib/gdi.mjs`, `test/gdi.test.mjs`. Generic throughout — a surface is a
surface, a DC is a DC.

Delivered:

- **Device context over a bounded surface** — `CreateCompatibleDC`,
  `DeleteDC`, an RGBA surface bounded by `gdiBound.dimension_max`; the surface
  is the buffer the browser present path reads (`surfacePixel`).
- **Objects** — stock objects (`GetStockObject`: the brush/pen/font/palette
  set at fixed handles), `CreateSolidBrush`, `CreatePen`, `DeleteObject`
  (a stock object cannot be deleted), and `SelectObject` returning the
  previous object of the same kind.
- **Primitives** — `FillRect` (region-exact, null-brush aware), `Rectangle`
  (pen outline + brush fill), `MoveToEx` / `LineTo` (integer Bresenham with
  the selected pen), `SetPixel` / `GetPixel`.
- **Text** — `TextOut` with a deterministic stock 8x8 bitmap font,
  `SetTextColor` / `SetBkColor` / `SetBkMode` (OPAQUE fills the cell, else
  the glyph paints only its set bits).
- **Raster operations** — `BitBlt` (SRCCOPY / SRCPAINT / SRCAND / SRCINVERT /
  BLACKNESS / WHITENESS / PATCOPY; an unknown ROP is refused, never guessed)
  and `StretchBlt` (nearest-neighbor scale under the same ROP set).
- **Packed pixel formats** — `pack565` / `unpack565`, `pack555` / `unpack555`
  with bit-replication expansion so white stays white.

Acceptance evidence (all green, `node --test test/gdi.test.mjs`):

| Contract | Test |
| --- | --- |
| Draw fixture within tolerance of a test-time reference | "the GDI draw fixture renders within tolerance of a test-time reference" |
| No committed golden; drift is caught | "the draw fixture fails when the rendered surface drifts from the reference" |
| Coverage complete over the served surface | "conformance: every served GDI32 export carries a case and matches the oracle" |

The draw fixture reuses `computeFrameDiff` (`lib/shader.mjs`): the reference is
computed in the suite from the same declared scene, `committed_baseline` is
`false`, and a drifted surface fails — the test-time-reference discipline of
`doc/TESTING.md`.

Gate: `npm run gate` exits 0 (185 tests pass; 46-file package manifest).

## Next

- Post-rebase: register `userExportTable` and `gdiExportTable` into
  `lib/hle.mjs`, attach the `user` and `gdi` subsystems to the guest, key the
  message queue on the real thread registry, and record the live corpus
  export-coverage delta here.
- Deepen the surface as the corpus demands: `GetMessage` blocking against the
  timer slice, `WM_TIMER` from `SetTimer`, palette animation, and the DIB
  section bit-depth paths (8-bit palettized alongside 555/565).
