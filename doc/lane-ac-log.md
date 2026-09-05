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
