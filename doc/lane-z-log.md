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
(584 pass, 1 skip, 0 fail).

## Cycle 2 — serve the banner/stdio + heap so Doom passes Z_Init

Continuing the same run, serving what Doom reaches after entering `main`:
- `SDL_SetHint`/`SDL_SetHintWithPriority` (advisory, accepted).
- `putchar`/`puts`, and a full-width-pointer fix for `__stdio_common_vsprintf`/
  `__stdio_common_vfprintf` (they truncated their format/destination pointers to
  a dword; on x64 those are .rdata/stack addresses above 4 GiB). Doom now prints
  its real banner and the `Z_Init` messages.
- **Process default heap size** (hle): the default heap was 64 KiB, but Doom's
  `Z_Init` zone allocator asks for several MiB in one `malloc` and gave up
  ("Unable to allocate %i MiB of RAM for zone", exit -1). The default heap now
  sizes to ¾ of the arena (≈24 MiB in the real 32 MiB arena; ≈1.5 MiB in the
  2 MiB conformance arena). The heap base is the arena cursor, independent of
  size, so no allocation address moves and conformance is unchanged. Doom's zone
  now allocates ("zone memory: %p, %x allocated for zone") and it proceeds.

### Result and exact frontier
Chocolate Doom now runs its real startup through `Z_Init`: banner + zone
allocator succeed. It stops at **`unsupported_opcode 0x0f12` — `F2 0F 12`
MOVDDUP (SSE3), at RVA 0x25334**, ~2338 instructions in. MOVDDUP is outside the
served x86-64 lift subset, and the SSE decoder (lib/lift64.mjs, lib/simd.mjs,
lib/x64decode.mjs) is off-limits to Lane Z — this is a handoff to the lift/simd
lane, not an exec64/hle gap.

Because the SSE3 stop is **upstream of `W_Init`** (WAD loading), the WAD file
I/O and a staged Freedoom IWAD are not yet reachable by Doom, and no SDL window
is created. Freedoom is therefore not staged this cycle (it would be untestable
against Doom's real path while the SSE3 gap stands). No synthesized frame, no
faked WAD: the stop is the real MOVDDUP.

Corpus: 9 at entry, 2 loaded — unchanged. `npm run gate` green (584 pass).
