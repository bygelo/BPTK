# Lane Z log — Chocolate Doom to a first frame

Lane Z drives Chocolate Doom (corpus-007, pure C + SDL2, x86-64) from its CRT
startup toward a first rendered frame, through the bounded x86-64 interpreter
(lib/exec64.mjs) and the Win32/ucrt core HLE (lib/hle.mjs, lib/sdl.mjs).

## Cycle 1 — root-cause the early return, serve the CRT/shell/SDL startup path

Base: build/product-first at bc60519. Stage: ../bptk-corpus (out of git).

### The early return (root cause)
Chocolate Doom stopped at `entry_return` after 186 instructions: the CRT startup
`__scrt_common_main_seh` returned before `main`. The cause was a bug in the
harness, not the image. `_initterm_e` (the C-initializer runner) is reached as a
jmp-thunk; its C-initializer table is empty, and `startInitterm`'s empty-table
path resumed at `nextRip` (the byte after the `jmpIndirect` *inside the import
thunk*) instead of the real caller `returnRip`, with the caller return address
left on the stack. Execution fell through the import thunk table into the next
thunk, corrupting the startup's `_initterm_e` result check so it bailed to the
epilogue and returned before `main`. Fix: the empty-table path resumes at
`returnRip` with `rsp0` restored — the same resume a completed table uses.

### Frontier fixes that followed (each real, each general)
- **Flat-base segment prefixes** (exec64): the CRT emits a multi-byte NOP padded
  with a `0x2e` CS override (`66 66 2e 0f 1f …`). `decodeStructured` refuses a
  segment prefix; the harness only stripped fs/gs. Now it also strips the flat
  (CS/SS/DS/ES, base 0 in x64) overrides and decodes at base 0.
- **ucrt api-set forward** (hle `lookupExport`): a ucrt binary imports the C
  runtime through `api-ms-win-crt-*.dll` api-set names that forward to the same
  implementation `msvcrt.dll` exports. An unresolved api-set symbol now retries
  under `msvcrt.dll` — a name forward to a real implementation, not a synth.
- **Unserved-import IAT binding** (exec64): a `mov reg,[slot]; call reg` through
  an *unserved* import's IAT slot jumped to the raw import-name RVA (data) and
  faulted. Every import slot is now bound: a served import to its HLE thunk
  (resolving the api-set forward too), an unserved import to a per-import
  sentinel that yields a clean `import_present` naming the symbol.
- **New served exports**: `rand_s`, `__p__acmdln`/`__p__wcmdln`,
  `_ismbblead`/`_ismbbtrail`, `shell32!CommandLineToArgvW` (real Windows argv
  tokenizer), `shlwapi!PathIsRelativeW`, and SDL's private libc
  (`SDL_strlen/wcslen/memcpy/memmove/memset/malloc/calloc/realloc/free`,
  `SDL_iconv_string` UTF-16↔UTF-8). Each carries a conformance case; the
  "every served export has a case" gate stays complete.

### Result
Chocolate Doom: 186 → 987 instructions. Stop moved from `entry_return` (before
`main`) to `import_present` at `sdl2.dll!SDL_SetHint` — now inside the game's own
`main`, past CRT init, argv construction (CommandLineToArgvW + SDL_main's
iconv), and into SDL setup. No SDL window is created yet and no framebuffer is
drawn; the frontier is the SDL video/hint/query surface (and, beyond it, the WAD
file I/O + a staged Freedoom IWAD, not yet reached).

Corpus: 9 at entry, 2 loaded — unchanged (no regression). `npm run gate` green
(584 pass, 1 skip, 0 fail). Freedoom WAD: not yet staged (frontier is upstream
of W_Init).
