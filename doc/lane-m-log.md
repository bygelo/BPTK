# Lane M log — HLE breadth for Win64 CRT-init depth (BPTK-031)

Front 1 (priority) — serve the Win64 CRT-init imports so the x86-64 corpus binaries
execute through ucrt startup (`__scrt_common_main_seh`) toward `main`/`WinMain`,
measured by instruction_count climbing past the prior first-import stops. Front 2
(i386 breadth to `entry`) is scoped and deferred with evidence below.

## Cycle 1 (2026-09-06)

Base: `1ac0e38` (lane K merge). Gate green (`npm run gate` exit 0; 522 pass, 1 skip).

### What was served
- `lib/hle.mjs`:
  - kernel32 fiber-local storage: `FlsAlloc`/`FlsFree`/`FlsGetValue`/`FlsSetValue`
    (single-fiber value slots + recorded destructor callback), `InitializeCriticalSectionEx`.
  - Universal CRT startup stubs under the api-set names (and `msvcrt.dll` aliases):
    `_configure_narrow_argv`/`_configure_wide_argv`, `_initialize_narrow_environment`/
    `_initialize_wide_environment`, `_get_initial_narrow_environment`/`_get_initial_wide_environment`,
    `_get_narrow_winmain_command_line`/`_get_wide_winmain_command_line`, `_set_app_type`/
    `__set_app_type`, `_set_invalid_parameter_handler`/`_get_invalid_parameter_handler`,
    `__setusermatherr`, `_set_new_mode`, `_crt_atexit`/`_crt_at_quick_exit`/
    `_register_thread_local_exe_atexit_callback`/`_initialize_onexit_table`/`_register_onexit_function`,
    the `__p___argc`/`__p___argv`/`__p___wargv`/`__p__environ`/`__p__wenviron`/`__p__commode`/
    `__p__fmode`/`_errno` pointer accessors (over a fixed CRT block at the top of the arena),
    `___mb_cur_max_func`, `_configthreadlocale`, `_set_fmode`/`_get_fmode`.
  - vcruntime140: `__vcrt_InitializeCriticalSectionEx`/`__vcrt_Enter/Leave/DeleteCriticalSection`,
    and the `memset`/`memcpy`/`memmove`/`memcmp`/`memchr` intrinsics (real guest-memory ops)
    also under the crt-string / crt-private api-sets.
  - One conformance case per (library, symbol) pair; coverage gate stays complete.
- `lib/exec64.mjs`: `_initterm`/`_initterm_e` are driven as genuine guest control flow —
  the harness walks the initializer table and runs each guest initializer through its own
  interpreter loop (return-sentinel re-entry), so the C/C++ global constructors actually run
  before `main`; `_initterm_e` aborts on a non-zero initializer result.
- `test/exec64.test.mjs`: FlsAlloc dispatch, `_initterm` runs an initializer, `_initterm_e`
  abort-on-error.

### Measured x86-64 depth (runPackage, i386_probe_v1, 10,000,000 budget)
| corpus | before ic / stop | after ic / stop |
|---|---|---|
| 001 PuTTY x64 | 1646 / import FlsAlloc | 22670 / fault (jmp to HLE thunk addr 0x12dc2e) |
| 002 Plink x64 | 1647 / import FlsAlloc | 21506 / fault |
| 003 jq amd64 | 33 / import _initterm | 259 / unsupported_opcode 0xdb (x87, lib/lift64 subset) |
| 005 OpenTTD 13.4 win64 | 1635 / import FlsAlloc | 30545 / fault (null-pointer deref) |
| 006 Dwarf Fortress | 169 / import _initterm_e | 508 / fault (deref of a CRT-internal pointer) |
| 007 Chocolate Doom | 102 / import _set_invalid_parameter_handler | 103 / unsupported_opcode 0xdb (x87) |

Remaining x64 stops are honest ceilings outside this lane's ownership: jq and Chocolate
Doom hit x87 (opcode `0xdb`) in `lib/lift64.mjs` (forbidden); PuTTY/OpenTTD/DF hit deeper
guest faults (control transfer into an HLE thunk address, and dereferences of pointers the
CRT's own heap/globals would populate) that need broader loader/thunk-execution work.

Stage: no regression — corpus run holds 8 `entry`, 3 `loaded`.

### Front 2 (i386 to `entry`) — deferred with evidence
Reaching `entry` requires every import served (one unserved import blocks it):
- CORPUS-008 OpenTTD 1.10.3 win32: 160 unserved across gdi32/user32/kernel32/winmm(MIDI+wave
  audio)/ws2_32(ordinal-only Winsock)/usp10(Uniscribe)/imm32 — much of it (live audio, network)
  cannot be honestly served in a bounded probe.
- CORPUS-010 jq i386: 123 unserved, 107 of them the full `msvcrt.dll` C runtime (stdio, malloc,
  math, locale) — a subsystem-scale surface.
- CORPUS-011 PuTTYgen: 63 unserved, mostly user32 dialog/menu (44) + gdi/comdlg/shell.
None is achievable to zero in this lane without subsystem-scale work; left for dedicated lanes.
