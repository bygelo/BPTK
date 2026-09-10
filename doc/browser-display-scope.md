# Browser display layer — scope (first pixels)

Status: **scope, building** · Chosen 2026-09-06 (the "B" in BPTK) · Tip at scoping: `9942a70`.

Goal: run a real binary **in a real browser** and **present what the runtime actually painted** to a
canvas — turn "the window object exists in memory" (PuTTY now creates its About dialog + main window)
into "you can see it." No faked pixels: the canvas shows the runtime's own GDI RGBA surface.

## What already exists (reuse, do not rebuild)
- `lib/gdi.mjs` — `makeSurface(w,h)` produces an **RGBA host-memory surface** ("the buffer the browser
  present path reads"), stock bitmap font, rects/lines, BitBlt, TextOut, 565/555 conversions.
- `lib/user.mjs` — window model, `WM_PAINT`/`invalidate`/`UpdateWindow` dispatch to the guest WndProc,
  a message queue that synthesizes `WM_PAINT`.
- `lib/graphics.mjs` — the WebGL2/WebGPU **capability probe** (canvas context detection) already exists.
- `lib/exec64.mjs` + `lib/rsrc.mjs` — x64 execution + RT_DIALOG instantiation (WM_INITDIALOG dispatched).

## The two real blockers
1. **No browser host / present path.** Nothing draws the RGBA surface to a canvas, and there is no page.
2. **Browser-incompat imports** in the execution path (all narrow): `node:crypto` (sha256 of trace/
   memory/output — determinism record), `node:fs` (payload + manifest read), `node:path`, and pervasive
   **`Buffer`** (Node-only). The project is **zero-dependency with no bundler** — so the fix is **native
   browser ESM + an import map**, not a bundler or an npm polyfill.

## Architecture (zero-dep, no bundler)
```
web/index.html  ── import map: node:fs|path|crypto|buffer -> ./shim/*.mjs ── loads web/host.mjs
web/shim/buffer.mjs  minimal Buffer over Uint8Array (only the methods the runtime uses:
                     alloc/from/copy/slice/toString/indexOf + read/writeUInt8/16/32LE + readBigUInt64LE…)
web/shim/crypto.mjs  createHash("sha256") backed by a pure-JS SHA-256 (sync, ~70 lines)
web/shim/fs.mjs      stub (throws if called — the browser entry never reads files)
web/shim/path.mjs    basename/join/resolve/relative/sep shim (~20 lines)
web/host.mjs         fetch a staged freeware payload (or <input type=file>), run the probe from BYTES,
                     read the GDI surface, ctx.putImageData(surface_rgba, w, h) on a 2D canvas
```
- **Byte-driven entry (`runImageBytes`)**: a new export that takes `(peBytes: Uint8Array, profile)` and
  runs the probe **without `resolvePackage`/`readExecutable`** (no fs), returning `{ state, stop_reason,
  instruction_count, surface: { rgba, width, height } }`. This is the seam the host calls. It must be
  reachable from the existing exec core without duplicating it.
- **Present = 2D canvas `putImageData`** first (no WebGL needed for first pixels); WebGL/WebGPU upload of
  the same surface is a later optimization the `graphics.mjs` probe already anticipates.

## Milestones
1. **M1 (gate-testable, no browser): bytes → surface.** The `node:*` shims (proven in Node to match the
   real APIs the runtime uses) + `runImageBytes` producing a real RGBA surface from a PE byte array.
   Test in the gate: run a staged payload's bytes, assert a non-empty surface with real painted pixels.
   This is the foundation and it is verifiable headless.
2. **M2 (browser): first pixels.** `web/` host page + present path. Test in **Chrome-for-Testing via the
   repo's `agent-browser` lane** (never the daily Chrome; per the account browser law): load the page,
   run PuTTY, screenshot the canvas, confirm real output. First visible pixels.
3. **M3: window/control compositing.** Paint the dialog frame + standard controls (button/static chrome,
   "About PuTTY" text) so the surface is a *recognizable* window, not just a cleared client area.

## Honesty + rules
- The canvas shows the runtime's **own** surface bytes — never a mock or a screenshot of real Windows.
- this work moves no benchmark: `passing` is 1 (BPTK-001, the approved license and reuse decision) and none of it is game-runtime, because a visible dialog is not a playable game.
- Determinism holds: same bytes → same surface hash, Node and browser.
- New `web/*.mjs` must be admitted to `tool/validate.py`'s allowed surface (like lib/) + `content.json`
  in the same commit, or the gate fails.
- Browser testing uses **Chrome-for-Testing rooted at this repo** (`agent-browser`, a `9800–9899` port),
  never `channel:'chrome'`, never the daily user-data dir.
