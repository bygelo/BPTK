# Lane CA log — resumable, input-driven live sessions

Goal: make x86-64 execution RESUMABLE so a host (a browser render loop) can run a
guest in chunks, feed live input between chunks, and read the current frame each
chunk — the foundation for an interactive, live display.

## What shipped

- `lib/exec64.mjs` (additive resume export only): the monolithic `runImage64`
  interpreter loop was extracted verbatim into `runInterpreterStep(context,
  runState, stepBudget)`. `runImage64` is now a thin driver over it (build the
  context, run one step of the whole budget, read the terminal bookkeeping), so
  its behavior is byte-identical. New export `stepContext(context,
  instructionBudget)` resumes the SAME context for up to `instructionBudget` more
  instructions, threading one continuous run over one Machine via
  `context.runState`. K calls of budget B are bit-for-bit identical to a single
  `runImage64` at K*B, because both drive the SAME loop over the same guest state.

- `lib/sdl.mjs` (live-input append only): a module-scope `normalizeInputEvent`
  now backs both `loadInputTrace` (fixed pre-schedule) and the new
  `appendInputEvent(event | [event, ...])` (live, appendable injection forced to
  frame 0 so the guest's next poll drain consumes it in FIFO order). The event
  vocabulary gained mouse events (mousemove / mousedown / mouseup) alongside
  keydown / keyup / quit, and `writeEvent` marshals the SDL2 MouseMotion /
  MouseButton struct bodies.

- `lib/live.mjs` (new): `createLiveSession(bytes, option)` maps the PE32+ image,
  wires the Win32 core HLE (hostFile / environment / commandLine), builds the
  persistent context ONCE, and returns a session:
  - `step(instructionBudget)` — resume the guest for up to that many more
    instructions; returns cumulative + per-step instruction/present counts, the
    stop reason, and `done`.
  - `frame()` — the current RGBA surface (SDL video framebuffer when up, else the
    gdi desktop composite, else a cleared surface); callable after any step.
  - `sendInput(events)` — inject live SDL2 events into the guest's queue for the
    next step to consume.
  - `done` / `stopReason` / `instructionCount` / `presentCount` / `hasVideo`
    status getters.

- `test/live.test.mjs` (new) + gate-surface registration for `lib/live.mjs`
  (tool/validate.py ALLOWED_MJS_PATH + expected_file, bench/npm/content.json) and
  `test/live.test.mjs` (tool/validate.py).

## Proof (gate 0)

- Resumability, synthetic: a never-returning loop stepped in K=11 chunks of B=97
  (boundaries INSIDE the 4-instruction loop body) reaches bit-exact registers,
  XMM, rip, direction flag, and every mapped memory byte vs one-shot; its
  register/rip surface equals `runImage64` at K*B.
- Resumability, real PuTTY x64: 500 chunks of 1000 instructions match a
  monolithic `runImage64` at 500000 — instruction count, stop reason, rip, all 16
  GPRs, and full memory bit-exact.
- `done` latches: after a structured stop, further steps run 0 instructions.
- Live Chocolate Doom (corpus-007): first non-blank frame after 17 steps
  (17,000,000 instructions), present_count 4. A LIVE Escape injected through
  `sendInput` (not a pre-baked trace) is consumed by Doom's own poll loop
  (input_delivered 2) and changes the presented frame's pixel hash after 1 more
  step — the menu, proving live incremental input.

## Gate

`npm run gate` exits 0: validator PASS (145 accepted / 101 implemented / 0
passing — passing stays 0), 693 tests pass / 0 fail / 1 skip, package content
PASS. Existing exec64 / sdl / corpus tests unchanged.
