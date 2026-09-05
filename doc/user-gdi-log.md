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

Contracts 1 and 3 are **green** as of cycle 1 (`test/user.test.mjs`). Contract 2
is **not yet implemented** — GDI lands in cycle 2.

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

## Next

- Cycle 2: GDI device context + BitBlt / StretchBlt, rect / line, `TextOut`
  with a stock font, palettes and 555/565, into a bounded surface. The draw
  fixture reuses `computeFrameDiff` (`lib/shader.mjs`) for the test-time
  reference so no golden is committed (contract 2).
- Post-rebase: register `userExportTable` (and the GDI table) into
  `lib/hle.mjs`, key the queue on the real thread registry, and record the
  live corpus export-coverage delta here.
