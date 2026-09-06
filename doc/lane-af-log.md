# Lane AF — Doom responds to input

Goal: make Chocolate Doom react to a scripted SDL input trace and advance from
its attract-mode title into its menu (and, if reachable, gameplay).

## Cycle 1 — scripted SDL2 event trace; Escape opens Doom's menu

What shipped:
- `lib/sdl.mjs`: a scripted input-trace event queue. `loadInputTrace(trace)`
  installs a normalized sequence of `{ type, scancode, sym, mod, frame }`
  events (type "keydown"/"keyup"/"quit" or numeric SDL type). `pollEvent`,
  `peepEvents`, and `waitEvent` now marshal REAL SDL2 `SDL_Event` structs into
  the guest buffer (type@0, timestamp@4, windowID@8, state@12, repeat@13,
  keysym.scancode@16, keysym.sym@20, keysym.mod@24 — the SDL2 layout). Delivery
  is gated by a present-count (frame) schedule so a caller can script "press
  Escape after the title has drawn". Default (no trace) stays the honest empty
  queue — no regression. Exported `sdlEventType`, `sdlScancode`, `sdlKeycode`.
  Introspection: `input_delivered` / `input_pending` / `inputStat`.
- `lib/exec64.mjs`: threads `option.hle.inputTrace` and calls
  `guest.sdl.loadInputTrace()` on the live guest right after HLE construction
  (the SDL subsystem is built inside the read-only HLE with a fixed dependency
  set, so it is configured here). `executeProbe64` reads `option.input_trace`.
- `lib/present.mjs`: threads `input_trace` through `resolveHostOption` and
  `runImageBytes64` so the browser byte-path can script input too.
- `test/sdl.test.mjs`: unit coverage for the SDL2 marshal, the frame schedule,
  and WaitEvent; plus a corpus-gated interactivity test.

Evidence (corpus-007 Chocolate Doom + Freedoom1, `runImage64`, budget 20M):
- No input:        present 11, hash 9e727f486be414b0 (title, STABLE at 20M/24M).
- Escape @frame 2: present 10, hash 62c2e5486363257c (menu, non-blank, distinct).
- Unmapped key:    present 11, hash 9e727f486be414b0 (== title) — isolation
  control: delivering two events with no menu semantics does NOT perturb the
  frame, so the change is Doom reacting to the Escape KEY, not to event traffic.
- Both scripted events consumed by Doom's own poll loop (`input_delivered == 2`).

Not reached: a full in-level gameplay frame. Driving New Game -> episode ->
skill -> start (Escape, then Enter x3 across frames, budget 60M) consumed all 8
events but stopped at `unsupported_opcode` at ~20.8M instr — an x86-64 opcode
outside the bounded lift subset (lib/lift64.mjs / lib/x64decode.mjs, read-only,
not mine to extend). Honest frontier: this proves the menu, not playability.
`passing` stays 0.

Gate: `npm run gate` exit 0. Corpus: entry 9 / loaded 2 (unchanged).
