# Lane AC log — Chocolate Doom to its WAD load and video init

Corpus: corpus-007, `chocolate-doom.exe` (x86-64, pure C + SDL2, GPL). Driven
through `executeProbe64` over `mapPe64State` at a 10,000,000 instruction budget.

## Cycle 1 — past the filesystem gap, honest to the IWAD search

Base: `943d0c3` (build/product-first).

Doom instruction_count / stop advanced across this cycle:

| stage | instruction_count | stop_reason |
| --- | --- | --- |
| start of cycle | 2,623 | import_present `_wmkdir` |
| after this cycle | 583,900 | process_exit code 0xffffffff (I_Error "No IWAD file was found") |

What moved it, each change verified by re-probing:

1. **`_wmkdir`/`_mkdir`** served over the bounded virtual drive (a `virtualDir`
   node, never a host mkdir). Doom creates `C:\game\` and threads on. This alone
   jumped 2,623 → 45,084, then hit the 4,096-entry HLE call-trace bound; raised
   `trace_count` to 1,048,576 for the deeper run.
2. **x64 string-pointer truncation fix.** `readByte` (strcmp/strncmp/_strnicmp)
   and `strcpy`/`strncpy` truncated their pointer with `unsigned()`; on x64 the
   compared string lives on the stack above 4 GiB, so this faulted at `0xffa80`.
   Switched to the full-width `blockAddress`. 45,084 → 63,275.
3. **A real bounded printf %-engine** (`formatPrintf`) over the x64 va_list, wired
   into `__stdio_common_vsprintf`/`_vfprintf`. This is load-bearing, not cosmetic:
   Doom builds config-variable names with `sprintf("...%i", index)` and matches
   them against its table, so an unexpanded `%i` aborted startup with I_Error.
   63,275 → 304,367.
4. **`MultiByteToWideChar`/`WideCharToMultiByte`** count params masked to 32-bit
   int and pointers taken full-width. A dirty 64-bit stack slot delivered
   `cchWideChar = 0x1_0000_0000`, defeating the NULL-destination query test and
   writing to address 0. Fixed the null-deref. 304,393 → 304,710.
5. **`_wgetenv`** served over the environment map (Doom queries `DOOMWADDIR`).
6. **`_stricmp`** served (WAD/IWAD name matching).
7. **`fopen`/`_wfopen` honor their mode string** (`crtFopenOflag`). They had
   hardcoded `_O_RDWR|_O_CREAT`, so a read-probe of the absent `doom2.wad`
   *created* an empty file and Doom wrongly "found" it. Now a read of an absent
   file returns NULL; Doom honestly reaches "Game mode indeterminate. No IWAD
   file was found." and exits — the correct state with no WAD staged.
8. **`feof`** tracks a real file's read position (0 for a standard stream).

Reached in Doom's own output this cycle: banner, `Z_Init`, `V_Init`,
`M_LoadDefaults` (config dir created + `saving config in C:\game\default.cfg`),
`W_Init: Init WADfiles`, and the IWAD search. Not yet reached: `W_Init` success,
`I_InitGraphics`, `SDL_CreateWindow`, a drawn frame — all gated on a staged IWAD
and the file-read path (fseek/ftell/fread over real bytes), which is cycle 2.

Tests added (bounded, in test/hle.test.mjs): printf va_list expansion; printf
width/precision/flags; fopen mode; `_wmkdir` + feof. Conformance cases added for
every new export. `npm run gate` exits 0. No WAD is committed.

## Cycle 2 — the real Freedoom IWAD loads; Doom reaches the x64-lifter frontier

| stage | instruction_count | stop_reason |
| --- | --- | --- |
| start of cycle | 583,900 | process_exit (No IWAD) |
| after this cycle | 4,864,227 | unsupported_opcode 0x0FAC (SHRD) at 0x140020a04 |

WAD staged: **Freedoom `freedoom1.wad`** (BSD-style free/redistributable), the
real 28,795,076-byte file, sha256 `7323bcc168c5a45ff10749b339960e98314740a734c30d4b9f3337001f9e703d`, extracted from
`freedoom-0.13.0.zip`. It lives OUTSIDE the repo at
`/Users/angelonrevelo/Code/bptk-corpus/stage/corpus-007/wad/freedoom1.wad` and is
never committed; the probe injects it read-only through the new host-file store.

What moved it:

1. **A read-only host-file store** in the HLE (`option.host_file`, a Map of
   c:\ path → real Buffer) plus an **initial environment** (`option.environment`),
   threaded through `executeProbe64`/`runImage64`. `openFile`/`virtualFileSize`/
   the directory glob consult it; a read of a staged file returns the real bytes
   at real size, bypassing the small writable-drive bounds; a write still goes to
   the bounded writable drive, never the host.
2. **fseek/ftell/fread/rewind** over real file records — the WAD-size and
   directory/lump reads W_AddFile performs.
3. **A real scanf %-engine** (`scanfInput`) wired into `__stdio_common_vsscanf`
   (string) and `__stdio_common_vfscanf` (file). Doom parses its WAD's DEHACKED
   lump with sscanf("...", "%19s", …) / sscanf("...", "%d", …), so this drove
   656,838 → 1,964,576.
4. **SDL_GetBasePath / SDL_GetPrefPath** (the app + writable home path, rooted at
   the one bounded volume) and a **SDL2_mixer no-audio surface** (Mix_OpenAudio
   Device reports -1 so sound disables and the run stays on the graphics path).
5. **FindFirstFileW / FindFirstFileExW / FindNextFileW** (wide directory glob,
   host files included), **_time64**, DOOMWADDIR seeded to `C:\game`.

Doom's own output now reaches: the **Freedoom: Phase 1** IWAD banner (the WAD is
identified and W_Init succeeds), `I_Init: Setting up machine state.`, the sound
init (gracefully disabled — no audio device), and `NET_Init: Init network
subsystem.` It then stops at instruction 4,864,227 on an **x86-64 SHRD (0x0FAC)
the lifter does not serve** — a `lib/lift64.mjs` / `lib/x64decode.mjs` gap, which
is another lane's surface (FORBIDDEN here), not a filesystem/HLE gap. So
`I_InitGraphics` / `SDL_CreateWindow` / a drawn frame are gated on the lifter
adding SHRD, not on anything this lane owns.

Tests added: host-file read (fopen/fseek/ftell/fread over real bytes); DOOMWADDIR
via _wgetenv; the scanf `%s`/`%d` path. Conformance cases added for all new
exports (0 coverage holes). `npm run gate` exits 0. `passing` stays 0 (no
playability claim). No WAD or payload committed.
