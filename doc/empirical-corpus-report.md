# Empirical corpus report

Status: **first acquisition and run pass**, 2026-09-05. This report records the
GS-104 corpus acquisition (BPTK-083) and the GS-105 run harness pass (BPTK-084)
over nine lawfully-redistributable freeware payload. It is evidence for the
generalization and breadth work, not a compatibility claim: a reached stage is
not a playable claim, and every payload remains DRM-free, offline, and staged
outside the repository.

## Corpus identity

The manifest is [data/corpus.json](../data/corpus.json); every entry resolves to
a named source, a redistribution basis, a license, and a pinned sha256, and
`bptk corpus acquire` verifies the staged byte against the pin (9 / 9 verified,
0 refused, byte-stable across re-acquisition). The run record is
[data/corpus-run.json](../data/corpus-run.json); payloads stay out of git.

| Entry | Kind | Payload | Machine | Reached stage | Named generic gap |
|---|---|---|---|---|---|
| CORPUS-001 PuTTY | program | executable | x86-64 | packaged | machine_x86_64 → BPTK-031 |
| CORPUS-002 Plink | program | executable | x86-64 | packaged | machine_x86_64 → BPTK-031 |
| CORPUS-003 jq | program | executable | x86-64 | packaged | machine_x86_64 → BPTK-031 |
| CORPUS-004 7-Zip extra | program | 7z container | n/a | classified | unsupported_executable_format → BPTK-007 |
| CORPUS-005 OpenTTD 13.4 | game | zip archive | x86-64 | packaged | machine_x86_64 → BPTK-031 |
| CORPUS-006 Dwarf Fortress 0.47 | game | zip archive | x86-64 | packaged | machine_x86_64 → BPTK-031 |
| CORPUS-007 Chocolate Doom 3.1.1 | game | zip archive | x86-64 | packaged | machine_x86_64 → BPTK-031 |
| CORPUS-008 OpenTTD 1.10.3 win32 | game | zip archive | i386 | loaded | import_present → BPTK-010 |
| CORPUS-009 Plink 0.74 win32 | program | executable | i386 | loaded | import_present → BPTK-010 |

## What the first pass ranks

The gap tally across the nine entry: **BPTK-031 × 6** (the x86-64 research lane
carries six of nine payload, including every game main executable in its modern
build), **BPTK-010 × 2** (the two i386 entry map cleanly and then stop at the
partially served Win32 HLE — OpenTTD 1.10.3 win32 imports 302 function of which
the core serves 62, Plink 0.74 win32 imports 142 of which the core serves 45),
and **BPTK-007 × 1** (the 7z container is outside the import classification).
The breadth ranking is therefore: the x86-64 lane, then the unserved Win32
breadth (console, file, locale, SEH unwind, module loading — ranked per symbol
by `corpus coverage`), then import container breadth.

## Coverage-ledger raise after the Win32 core HLE (2026-09-05)

`corpus coverage` joined the real 356-symbol import surface against the Win32
core HLE registry. After the process/core slice: **62 covered / 294 absent**,
ranked by how many corpus entry import each unserved symbol: SetFilePointerEx,
GetFileType, SetStdHandle, GetACP, GetConsoleMode, ReadConsoleW, GetConsoleCP,
RtlUnwind, MultiByteToWideChar, CreateFileW, CloseHandle, GetLocaleInfoW,
LoadLibraryA, FreeLibrary, ReadFile, WaitForSingleObject. After the storage
slice (virtual drive + registry + console mode): **79 covered / 277 absent** —
OpenTTD i386 serves 75 of 302 import, Plink i386 61 of 142. After the locale
and codepage slice (BPTK-103): **93 covered / 263 absent** — OpenTTD i386
serves 89 of 302 import, Plink i386 75 of 142. After the module-loading and
memory-probe slice (LoadLibraryA/W/ExW, FreeLibrary, IsBadReadPtr, Sleep,
GetThreadTimes): **100 covered / 256 absent** — OpenTTD i386 serves 96 of 302
import, Plink i386 79 of 142. After the synchronization and enumeration slice
(events, waits, OpenProcess, FindFirstFileExA/FindNextFileA, IsValidLocale,
winmm timers): **113 covered / 243 absent** — OpenTTD i386 serves 109 of 302
import, Plink i386 86 of 142. The remaining unserved set is concentrated in
what its roadmap item own honestly: threads and thread creation
(CreateThread → BPTK-025), SEH unwind (RtlUnwind, UnhandledExceptionFilter →
GS-008), user32 and gdi32 window surfaces (→ BPTK-011/012), audio (→
BPTK-014), sockets (→ BPTK-026), and locale enumeration that needs guest
callback dispatch (EnumSystemLocalesW).

## Generic guard finding the corpus produced

The first pass refused two lawful payload at the declared extraction bound, and
both refusals were bound calibration bug rather than genuine risk:

- A 196662-byte zip entry tripped the 32:1 amplification guard. A small
  high-ratio entry cannot exhaust anything, so the guard now carries an
  absolute floor (`ratio_floor_byte`, 1 MiB): below the floor the guard does
  not apply.
- A bitmap-heavy archive entry at roughly 33:1 also tripped the guard. Genuine
  bomb input sits near 1000:1, so the frozen `ratio_max` is now 64; the 8 MiB
  bomb fixture still refuses, and the total output bound still caps every
  extraction regardless of ratio.

Both refinements are generic (they change the guard for every archive, not one
title) and are covered by the corpus run record, which is exactly the
generalization discipline the roadmap imposes on a fix.

## Generalization gate

`bptk corpus generalize <before> <after>` accepts a candidate fix only when it
raises the reached stage of at least the declared number of distinct entry and
regresses none. Run against the identical record set, it refuses with
`refused_single_beneficiary` (0 distinct beneficiary, minimum 2), which is the
gate holding honestly on real record. The gate is covered by test for the
single-beneficiary, multi-beneficiary, regression, and sandboxed-adapter case.

## 2026-09-12 pass (14 entry)

The manifest grew to fourteen hash-pinned lawful freeware entry. Inspect and
security file-size limits match the 512 MiB download bound; ingest distinguishes
`archive_input_byte` (whole zip/7z) from `chunk_input_byte` (one inflate). A zip
or 7z now reports the selected executable's machine instead of defaulting every
archive to i386.

| Entry | Kind | Machine | Reached stage | Named generic gap |
|---|---|---|---|---|
| CORPUS-001 PuTTY | program | x86-64 | entry | machine_x86_64 → BPTK-031 |
| CORPUS-002 Plink | program | x86-64 | entry | runtime_game_loop_absent → BPTK-010 |
| CORPUS-003 jq | program | x86-64 | entry | machine_x86_64 → BPTK-031 |
| CORPUS-004 7-Zip extra | program | x86-64 | entry | runtime_game_loop_absent → BPTK-010 |
| CORPUS-005 OpenTTD | game | x86-64 | entry | runtime_game_loop_absent → BPTK-010 |
| CORPUS-006 Dwarf Fortress classic | game | x86-64 | entry | runtime_game_loop_absent → BPTK-010 |
| CORPUS-007 Chocolate Doom | game | x86-64 | entry | runtime_game_loop_absent → BPTK-010 |
| CORPUS-008 OpenTTD 1.10.3 win32 | game | i386 | loaded | import_present → BPTK-010 |
| CORPUS-009 Plink 0.74 win32 | program | i386 | entry | process_exit 0 on --version (766759 instruction, `plink: Release 0.74`); no-arg is process_exit 1 with the real usage banner → BPTK-010 |
| CORPUS-010 jq 1.7.1 win32 | program | i386 | entry | process_exit 0 on --version (4648 instruction, `jq-1.7.1`) and on `-n 1` (4361398 instruction, colored `1`) → BPTK-010 |
| CORPUS-011 PuTTYgen 0.81 win32 | program | i386 | loaded | import_present → BPTK-010 |
| CORPUS-012 curl 8.22.0 win64 | program | x86-64 | entry | machine_x86_64 → BPTK-031 |
| CORPUS-013 ripgrep 14.1.1 win32 | program | i386 | entry | process_exit 0 on --version (181697 instruction) and on PCRE2 search of the staged README (1701493 instruction, real hits) → BPTK-009 |
| CORPUS-014 SuperTux 0.7.0 win32 | game | i386 | entry | instruction_budget_exhausted in openal32 table init after 10000000 instruction (9.46 s / 1.06M insn/s at `0x280ab69f`; 25M is 20.1 s / 1.25M insn/s at `0x280abeb1`) → BPTK-009 |

Reached: staged 0, classified 0, packaged 0, loaded 2, **entry 12**, interactive 0.
Gap tally: **BPTK-031 × 3**, **BPTK-010 × 9**, **BPTK-009 × 2**. Playability is
not claimed. SuperTux's IAT is fully served (sidecar + OpenGL HLE + leftover
kernel32/shell32/dbghelp). Sidecar DllMain and cdecl CRT ABI now run: the
old NX-stack fetch at 1498 was `_initterm` RET after a stdcall-popped cdecl
frame. The 4261-insn `0xe06d7363` was `std::bad_alloc` from `HeapAlloc(NULL)`
while `__acrt_heap` was still zero, not a missing EH dispatcher. The 32245-insn
locale `read_fault` was `WideCharToMultiByte(CP_ACP=0)` refused as invalid.
The SuperTux stop is now the 10M instruction cap inside a finite OpenAL
power-series table init, not FSTENV. The register-only decode cache retires
that series at **9.46 s / 1.06M insn/s** (25M at 20.1 s / 1.25M insn/s) and
does not leave OpenAL. Ripgrep `--version` is `process_exit` 0
after printing `ripgrep 14.1.1` (181697 instruction); a `PCRE2` search of
the staged README is `process_exit` 0 with the real line-numbered hits
(1701493 instruction). jq `--version` is `process_exit` 0 (`jq-1.7.1`,
4648 instruction); `jq -n 1` is `process_exit` 0 after 4361398 instruction
with the colored `1`. The next generic SuperTux work is still interpreter
throughput through that OpenAL series (BPTK-009), not another missing x87 form.

## Boundary statement

- Every payload is DRM-free, runs offline, and is lawfully redistributable; the
  manifest records the basis for each.
- No copy protection was present, and none would be circumvented; the census
  refuse route stays intact.
- Every staged byte was hash-verified against the manifest pin before use.
- No payload byte, trace content, or personal data is committed; the records
  carry identity, hash, stage, and gap only.
