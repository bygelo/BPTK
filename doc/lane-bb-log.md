# Lane BB — exec64 tiered-runner export boundary

Additive, export-only refactor of `lib/exec64.mjs`. Exposes the pieces a future
tiered runner needs to bind a WASM `hostCall(targetVA)` to the real HLE import
dispatch, WITHOUT changing any interpreter behavior. Base: `build/product-first`
tip `f4aa903`.

## What shipped (new exports of lib/exec64.mjs)

- `buildGuestContext64(option)` — EXTRACTED from `runImage64`. Builds the
  multi-region guest Machine (register file + image/stack/TEB memory, plus the
  HLE arena/virtual/thunk regions and the low-address image alias when an HLE
  layout is declared), constructs the live Win32 core HLE guest, binds every
  IAT slot, seeds the unserved-import sentinel map, the window/dialog
  environment, rsp/return-sentinel/rip. Returns a context bundle:
  `{ machine, hleContext, unservedSentinel, dialogEnv, region, layout, imageBuf,
  loadBase, entryRva, budget, importSet, balancedRsp, teb, stackHigh, stackLow }`.
  `runImage64` now calls it and drives the returned Machine — the setup path is
  one shared function, so the existing exec64/sdl/corpus tests prove no behavior
  change.

- `layout` (field on the context) — the region bases/sizes another module builds
  a matching compact memory from: `image`, `stack`, `teb` always present;
  `arena`, `virtual`, `thunk`, `image_alias` added when an HLE layout is wired.
  Bases are BigInt, sizes are byte counts drawn from the live region buffers.

- `serveImport64(machine, stop, nextRip, hleContext)` — the existing private
  dispatcher, now EXPORTED unchanged (only the `export` keyword added). Serves
  one reached import through the Win64 ABI marshal against the shared guest
  memory; the interpreter still calls it exactly as before.

- `serveImportAt64(context, targetVA)` — NEW thin wrapper. Serves the import
  bound at guest address `targetVA` against the context's live Machine, using
  the SAME specialization order and dispatchers the interpreter loop uses at an
  HLE thunk (initterm, dialog-create, window struct/scalar, then the general
  Win64 marshal). This is what a WASM fast-tier `hostCall(targetVA)` invokes; the
  register/memory mutation and control transfer are byte-identical to the loop's
  thunk branch. The interpreter loop never calls it, so it changes no behavior.

## Verification (all green)

- `npm run gate` exits 0. 681 node:test tests, 680 pass, 1 skip, 0 fail
  (was 677/676/1/0 at base; +4 new exec64 assertions). `check:package` PASS.
- New test/exec64.test.mjs assertions: buildGuestContext64 region bases (image
  `0x140000000`, stack `0x7ff000000000`, TEB `0x7ff800000000`); the HLE
  arena/virtual/thunk/image_alias appear only with a layout; serveImportAt64
  lands the same RAX (GetCurrentThreadId → 1) and rebalanced RSP/rip that
  `runImage64` produces end-to-end for that import; not_a_thunk for a non-thunk.
- `bptk corpus run` unchanged: loaded 2, entry 9.
- Chocolate Doom presents its non-blank first frame and responds to scripted
  input; PuTTY x64 executes past its first import. Both via the gate suite.

## Entangled — not forced

The interpreter loop's thunk branch owns loop-local bookkeeping (instructionCount
increments, stopReason/fault/reachedImport, break/continue). That could not be
extracted into `serveImportAt64` without touching control flow, so the wrapper
duplicates the dispatch decision additively (same private dispatchers, same
order) and returns a structured outcome (`kind`) instead of mutating loop state.
The loop is left byte-for-byte as it was. A later lane can converge the two on
the shared wrapper only if it can prove the counter/break semantics unchanged.
