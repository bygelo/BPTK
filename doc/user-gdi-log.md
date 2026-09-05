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
worktree yet — they are built in sibling lanes and merged threads-first. The
USER32/GDI export logic does not depend on either file (it operates on the
guest memory model), so it is registered now; two bindings remain for the
rebase:

- The per-thread message queue keys on the single declared guest thread id
  (`hleProfile.thread_id`) instead of a live thread registry. When the thread
  core lands and this lane rebases onto it, the queue keys on the real
  registry — a one-line change where `createUserSubsystem` is constructed.
- The class `WndProc` field is a guest code pointer, stored as a number, so the
  window manager falls back to `DefWindowProc` for every message. When the CPU
  core lands, dispatch invokes the real guest procedure through it. The HLE
  conformance measures the DefWindowProc-observable result, which is exact.

The honest consequence: **0 passing corpus benchmark stays 0.** No real `.exe`
stage moves until the whole thread → seh → cpu → user/gdi block lands and a
game's WndProc actually runs. What is real now: a guest PE that imports
`user32.dll` / `gdi32.dll` binds its IAT to these thunks and dispatches through
the subsystem, and the HLE conformance covers every one of the served exports.

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

## Cycle 3 — register the surface into the Win32 HLE

`lib/hle.mjs` (registration/wiring only), `lib/user.mjs`, `lib/gdi.mjs`.

Delivered:

- `userExportTable` and `gdiExportTable` are spread into the HLE export
  registry; the `user` and `gdi` subsystems are attached to the per-run guest;
  `user32.dll` and `gdi32.dll` join the module table so `GetModuleHandle` /
  `GetProcAddress` resolve them.
- The `RegisterClass(Ex)W` rows parse the WNDCLASS(EX)W struct from guest
  memory; `TextOutW` reads the explicit `cchString` count; `MoveToEx` writes
  the previous point back to the guest `LPPOINT`. The dll names are lowercase
  to match the case-sensitive import join the core uses.
- The HLE conformance case table (`buildConformanceCaseTable`) gains a case for
  every registered USER32/GDI export, driven through real guest memory, so
  `test/hle.test.mjs`'s coverage-complete assertion now covers this surface.

Coverage delta on the served Win32 surface:

| | Served export |
| --- | --- |
| Before | 118 |
| After | 150 (+14 user32, +18 gdi32) |

The **live corpus benchmark coverage is still 0 passing** — a served export is
reachable and conformance-covered, but no real game reaches a passing state
until the whole thread → seh → cpu → user/gdi block lands. The gain here is
that the USER/GDI surface is now honestly served and measured, not stubbed.

Gate: `npm run gate` exits 0 (185 tests pass; 46-file package manifest).

## Next

- On the threads-first rebase: key the message queue on the real thread
  registry, and route `WndProc` dispatch through the CPU core so a guest's own
  window procedure runs.
- Deepen the surface as the corpus demands: `GetMessage` blocking against the
  timer slice, `WM_TIMER` from `SetTimer`, palette animation, and the DIB
  section bit-depth paths (8-bit palettized alongside 555/565).
