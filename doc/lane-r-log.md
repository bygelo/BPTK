# Lane R log — Win64 CRT heap and startup imports to WinMain

Serve the Win64 CRT heap and the remaining startup imports for the x86-64 (Win64
ABI) dispatch path so the x64 games execute through heap allocation and CRT init
toward their program entry. Base tip `ccf4f8d`.

## Cycle 1 — Win64 CRT heap + WinSock/comctl32 load surface

### What was served (all over the one real process default heap / module table)
- ucrt heap DLL (`api-ms-win-crt-heap-l1-1-0.dll`): `malloc`, `calloc`,
  `realloc`, `free`, `_msize`, `_recalloc`, `_callnewh` — spread from the
  existing msvcrt heap emulation over `[crtHeapLibrary, msvcrt]`, so the block
  bytes are real, distinct, non-overlapping, and a later free/`_msize` finds
  them. `_msize`/`_recalloc` added to the guest (`crtMsize`/`crtRecalloc`).
- `LoadLibraryA/W` now matches on the Windows basename, so a guest that loads a
  system DLL by full path (`C:\Windows\System32\ws2_32.dll`) resolves the
  module. Added `ws2_32.dll` and `comctl32.dll` to the module table (both are
  served libraries), so `LoadLibrary` + `GetProcAddress` succeed.
- `comctl32.dll!InitCommonControls` / `InitCommonControlsEx` (lib/user.mjs) — the
  GUI common-control startup a program calls before opening its window.
- Conformance cases added for every new (library, symbol); coverage stays
  complete (gate green).

### Frontier before → after (execution:{profile:i386_probe_v1, budget:10,000,000})
- PuTTY (001): 28238 → 26318. Before: import_present at
  `user32.dll!MessageBoxA` — actually the error dialog "Unable to load any
  WinSock library" (root cause: `LoadLibraryA` of the WinSock DLL by full path
  returned 0). After the WinSock/comctl32 load surface, PuTTY runs its real
  startup: loads ws2_32, resolves the Winsock exports, `InitCommonControls`,
  then reaches **`user32.dll!CreateDialogParamA`** — its WinMain creating the
  configuration dialog. WinMain window-creation milestone reached; full dialog
  template instantiation is the next stretch, so this is the named honest stop.
- OpenTTD (005): 30603 → 30603 (unchanged; does not link the ucrt heap DLL).
  Honest stop: fault, null dereference `mov rdi,[r14]` at rva 0x2b9d deep in
  C++/global-constructor init — r14 is the null result of an internal
  singleton-getter (rva 0x1ff150) that returns 0 on a fully-supported path, a
  downstream symptom of an as-yet-unserved init dependency, not a faked stop.
- Dwarf Fortress (006): 543 → 642. Served past `crt!malloc` and the CRT heap;
  now import_present at **`sdl.dll!SDL_CreateSemaphore`** — a bundled
  third-party SDL threading primitive outside the Win32 HLE, a named honest stop.

### Guarantees
`npm run gate` exits 0 (validate.py + 544 tests + check:package). `corpus run`
keeps 9 at `entry`, 2 `loaded` — no regression. `passing` stays 0 (reaching
WinMain is not playable). Allocator is real (correct size, distinct blocks,
frees reusable); instruction counts are real; every stop is a NAMED honest gap.
