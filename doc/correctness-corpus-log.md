# Correctness & compatibility lane (Pillar 3) — build log

Lane `lane/correctness-corpus`, off `build/product-first`. Verifier: `npm run gate` exit 0 after every commit; `passing` stays 0 (no real benchmark passes).

## Cycle 1 — Pillar 3 planned items promoted to implemented

Started: 43 implemented / 0 passing. Ended: **50 implemented / 0 passing**, gate green.
Every Pillar-3 gold-standard item is now `implemented` (real generic apparatus + active red contract). All stay red because the real inputs (captured traces, recorded runs, live ratings) come from the absent Win32 runtime (BPTK-010); the apparatus is exercised against synthetic fixtures only.

| Item | GS | Deliverable | Where |
| --- | --- | --- | --- |
| BPTK-077 | GS-037 | Captured API-trace corpus admission gate: provenance + redaction proof + byte-stable canonical form | `lib/conformance.mjs` (`verifyTrace`, `verifyTraceCorpus`, `canonicalizeTrace`) |
| BPTK-078 | GS-038 | Compatibility rating ladder broken→…→complete, rung only on a passing evidence-backed predicate, no rating above highest contiguously-passing rung | `lib/report.mjs` (`computeCompatibilityRating`) |
| BPTK-079 | GS-039 | Deterministic reference/replay artifact: hash-only checkpoints, byte-stable artifact hash, first-divergence comparator, no embedded asset/PII | `lib/report.mjs` (`buildReplayArtifact`, `compareReplay`, `verifyReplayArtifact`) |
| BPTK-080 / BPTK-123 | GS-040 / GS-080 | Public compatibility database: every row regenerates from evidence, revision-pinned, byte-stable export, no unbacked/stale/PII row | `lib/report.mjs` (`buildCompatibilityDatabase`, `exportCompatibilityDatabase`, `verifyCompatibilityRow`, `regenerateRow`) |
| BPTK-119 | GS-075 | Compatibility-ratings site display rule: shown only when a reproducible recorded run backs it at the current browser+revision, greys out when stale, hidden when unbacked | `lib/report.mjs` (`resolveRatingDisplay`) |
| BPTK-082 | GS-042 | No-false-green promotion self-audit: five sabotage fixtures (wrong return, out-of-tolerance frame, inflated rating, stale provenance, non-deterministic replay) each rejected by its real predicate | `lib/benchmark.mjs` (`runPromotionSelfAudit`) |

Already implemented before this lane (verified green): BPTK-076 (conformance suite), BPTK-081 (export-coverage ledger), BPTK-083/084/085 (corpus acquire/run/generalize).

Tests: added `test/report.test.mjs` (16 tests) + trace tests in `test/corpus.test.mjs` + self-audit tests in `test/benchmark.test.mjs`. New exports registered in `lib/index.mjs` and `data/sdk-api.json`; `test/report.test.mjs` registered in `tool/validate.py`.

## Cycle 2 — corpus growth (GS-104 scoreboard)

`data/corpus.json`: 9 → **11** lawful DRM-free entries. Added two real, project-official-served **i386** PE32 binaries with verified pins (payloads never enter git):
- CORPUS-010 jq 1.7.1 win32 i386 (MIT, console) — sha256 `e4efdd6a…5166df`, 1027584 B, jqlang GitHub release.
- CORPUS-011 PuTTYgen 0.81 win32 i386 (MIT, GUI) — sha256 `577de7e2…072480`, 883480 B, the.earth.li official mirror. GUI binary broadens the user32/gdi32 import surface in the export-coverage ledger.

## Cycle 3 — corpus growth + generic HLE/api-set (2026-09-12)

`data/corpus.json`: 11 → **14** lawful DRM-free entries. Added three project-official-served binaries with verified pins (payloads never enter git):
- CORPUS-012 curl 8.22.0 win64 (curl license, console) — sha256 `7f23b039…efb714`, 8691604 B, curl.se official Windows zip. Ingest now reports the selected executable's machine, so this archive is `x86_64` at `entry` (BPTK-031), not a false i386.
- CORPUS-013 ripgrep 14.1.1 win32 i386 (MIT OR Unlicense, console) — sha256 `1e5c99e4…185f8e`, 1918749 B, GitHub release. Reaches `entry` after the kernel32/ntdll/userenv/bcryptprimitives widening; stops on unsupported `0x0f 0xc7` (CMPXCHG8B / rdrand group).
- CORPUS-014 SuperTux 0.7.0 win32 (GPL-3.0-or-later, SDL platformer) — sha256 `0207949f…dfc9eb`, 307358208 B, project portable zip. Ingest required a distinct `archive_input_byte` (512 MiB) so a zip is not mistaken for one inflate chunk. Loaded; 190 of 722 import served. Remaining unserved are bundled game DLLs (msvcp140, sdl2 leftovers, glew, physfs, opengl, openal) plus C++ CRT — the BottleShip-class next work is mapping sidecar PE modules, not more kernel32 rows.

The archive-vs-chunk bound split, inspect/security file-size alignment to the 512 MiB download bound, and api-set/ntdll name-forward in `computeImportService` are generic (they change every title, not one).

## Cycle 4 — sidecar PE mapping + CMPXCHG8B (2026-09-12)

Package-local DLLs now map as real PE modules (`lib/sidecar.mjs`): parse the
export directory, place each image at a non-overlapping base starting
`0x28000000`, bind the guest IAT to `load_base + export.rva`, and recurse that
DLL's own non-system imports. System libraries stay on the Win32 HLE. Api-set
CRT names that the HLE does not serve forward to a shipped `ucrtbase.dll`.
DllMain and sidecar TLS are not run. `createImportCatalog` allows two IAT slots
to share one export VA so api-set forwards and duplicate imports do not refuse
as `duplicate_import_address`. The probe maps sidecar bytes with the same
section permissions as the main image, so a `call [IAT]` into a sidecar is
real code, not an HLE thunk.

i386 `0x0F C7 /1` is CMPXCHG8B m64: equality writes ECX:EBX and sets ZF,
mismatch loads EDX:EAX and clears ZF, register form is `#UD`, `/6` rdrand and
`/7` rdseed stay refusals.

Measured on the staged corpus (payloads still out of git):
- CORPUS-013 ripgrep: still `entry`, but the stop moved from unsupported
  `0x0f c7` to `read_fault` at address 0 after **20467** instruction.
- CORPUS-014 SuperTux: still `loaded`, served **190/722 → 668/722** with
  **21** sidecar module. Leftover: opengl32 (29), kernel32 (17), dbghelp (7),
  shell32!ShellExecuteA (1).

## Cycle 5 — SuperTux IAT close + MOVLPS (2026-09-12)

Bounded OpenGL 1.1 HLE (`lib/gl.mjs`) plus leftover kernel32 file/locale,
shell32, and dbghelp rows close SuperTux's main IAT. GL identity strings intern
on first `glGetString` so they do not slide GetCommandLine off the pinned
conformance addresses. `GetTickCount64` writes EDX. i386 `0x0F 12/13/16/17`
is the MOVLPS/MOVHPS family the MSVC CRT used at instruction 19.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux: **722/722** served, 21 sidecar module, reaches `entry`,
  executes **1498** instruction and 9 HLE CRT calls, then `fetch_fault`
  ("Stack memory is not executable"). `glDrawArrays` is still not a playable
  frame. DllMain is still not run.
- CORPUS-013 ripgrep: unchanged `read_fault` at address 0 after **20467**
  instruction (181 HLE calls).

## Cycle 6 — cdecl, HMODULE, sidecar DllMain (2026-09-12)

The 1498-insn NX-stack fetch was cdecl ABI: HLE `_crt_atexit` popped the
caller frame, so `_initterm` RET fetched the leftover stack slot. CRT and
SDL rows are now cdecl. `GetModuleHandle(NULL)` returns the mapped load
base. Package-local exports win over HLE so ucrt `_initterm` is the real
walker. Sidecar TLS then DllMain(DLL_PROCESS_ATTACH) run dependency-first.
`DisableThreadLibraryCalls` binds the IAT that was jumping to RVA 0x22588.
EnterCriticalSection adopts a zeroed CRITICAL_SECTION on first use.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux: **722/722** served, 21 sidecar module, reaches `entry`,
  executes **4261** instruction and 99 HLE calls through DllMain, then
  `guest_exception` 0xe06d7363 (MSVC C++ EH) at vcruntime140. `glDrawArrays`
  is still not a playable frame.
- CORPUS-013 ripgrep: unchanged `read_fault` at address 0 after **20467**
  instruction (181 HLE calls).

## Cycle 7 — process heap, FLS, VirtualProtect, version, locale (2026-09-12)

The 4261-insn `0xe06d7363` was `std::bad_alloc`: ucrt called
`HeapAlloc(NULL)` while `__acrt_heap` was still zero, then
`FlsGetValue(0xFFFFFFFF)` because `__vcrt_flsindex` stayed
`FLS_OUT_OF_INDEXES`. Both now follow the Win32 contract. i386 `0x8C`/`0x8E`
MOV Sreg serves the Win32 selectors. `VirtualProtect` on a mapped PE image
or sidecar succeeds (ucrt's `.fptable` is not an HLE `VirtualAlloc` region).
`LoadLibrary` appends `.dll`, honors `LOAD_LIBRARY_SEARCH_SYSTEM32`, and
resolves api-set / `kernelbase` names to kernel32. `VerSetConditionMask` /
`VerifyVersionInfoW` bind the ucrt IAT that still held name RVA `0x105860`.
Counted `LCMapString` no longer returns length+1; `LCMapStringEx` and
`LocaleNameToLCID` serve the Vista GetProcAddress path.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux: **722/722** served, 21 sidecar module, reaches `entry`,
  executes **32245** instruction and 508 HLE calls through DllMain and locale
  init, then `read_fault` at `0xD81D1B4C` (eip `0x3502d9a3` in ucrt) after
  `GetCPInfo`. `glDrawArrays` is still not a playable frame.
- CORPUS-013 ripgrep: `read_fault` at address 0 after **20790** instruction
  (181 HLE calls).

## Cycle 8 — CP_ACP, heap align, SSE convert/unpack, FRNDINT (2026-09-12)

The 32245-insn locale `read_fault` was `WideCharToMultiByte(CP_ACP=0)`:
conversion and `GetCPInfo` now resolve 0/1/3 to the declared 1252 page.
`HeapAlloc` size is 8-byte aligned. Vista locale-name / AppPolicy /
`FlsGetValue2` bind. i386 CVTDQ2PD, STMXCSR/LDMXCSR, PEXTRW, UNPCKLP*/HP*,
and x87 FRNDINT let OpenAL and ucrt libm run.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux: **722/722** served, 21 sidecar module, reaches `entry`,
  executes **643190** instruction and 1043 HLE calls through DllMain, locale,
  and OpenAL CRT math, then `unsupported_opcode` x87 `FSTENV` (`D9 /6`) at
  eip `0x3505054e`. `glDrawArrays` is still not a playable frame.
- CORPUS-013 ripgrep: `read_fault` at address 0 after **20999** instruction
  (185 HLE calls).

## Cycle 9 — FSTENV, PE TLS, SHUFPS, GetConsoleMode ABI (2026-09-12)

i386 `D9 /6` `/4` is FSTENV/FLDENV (32-bit protected-mode environment).
`GetModuleFileName(NULL)` is the current image. `fs:[0x2C]` is a live PE TLS
array whose slots point at one bounded block (template-copied when the PE
declares TLS). `0F C6` is SHUFPS/SHUFPD. `GetConsoleMode` takes two arguments,
writes the mode, and returns BOOL — the old one-argument stdcall pop left the
pointer on the stack so the next RET fetched it as code.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux: **722/722** served, 21 sidecar module, reaches `entry`,
  runs past ucrt `FSTENV`, then `instruction_budget_exhausted` at **10000000**
  (1045 HLE) and **25000000** (1047 HLE) inside a finite OpenAL table-init
  series at `openal32` `0x280ab69f` / `0x280abeb1`. `glDrawArrays` is still
  not a playable frame.
- CORPUS-013 ripgrep: `read_fault` at `0x6FFFF000` after **214704** instruction
  (889 HLE calls). `WriteConsoleW` fired. The fault is a stack probe below
  the mapped stack, not a null TLS table.

## Remaining

`passing` stays 1 (BPTK-001 only). No corpus entry is interactive. SuperTux
now reaches `entry` through sidecar DllMain, locale, FSTENV, and OpenAL CRT
math; the next named gap is interpreter throughput through OpenAL table init
(BPTK-009), not FSTENV. OpenTTD 1.10.3 and PuTTYgen stay at `loaded` on
unserved imports. Ripgrep's next named gap is the stack probe after 214704
instruction. More lawful i386 game binaries can now be admitted without
piling up on bundled-DLL imports.

## Cycle 10 — WriteConsoleW character count + command_line (2026-09-12)

`WriteConsoleW` stored the UTF-16 byte count in `lpNumberOfCharsWritten`.
Rust treated `100 !== 50` as a short write and re-panicked (`thread 'panicked
at` ×110) until the 1MB stack probe at `0x6FFFF000`. The out pointer now
receives the character count. The i386 probe forwards `command_line`.

Measured on the staged corpus (payloads still out of git):
- CORPUS-013 ripgrep `--version`: prints `ripgrep 14.1.1 (rev 4649aa9700)` and
  `PCRE2 10.43 is available (JIT is unavailable)`, **181688** instruction,
  454 HLE, then `read_fault` at eip `0x6f83d6` (`mov eax,[eax+8]` with eax 0)
  during CRT teardown. No-arg prints `rg: ripgrep requires at least one
  pattern to execute a search` (176640 instruction) and stops at the same
  teardown fault. Not `process_exit`.
- CORPUS-014 SuperTux: unchanged 10M OpenAL budget stop.

## Remaining

`passing` stays 1 (BPTK-001 only). No corpus entry is interactive. Ripgrep
prints its real `--version` text; the next named gap is the null `[eax+8]`
during CRT teardown, not the stack probe. SuperTux's next named gap is
interpreter throughput through OpenAL table init.

## Cycle 11 — PEB.ProcessParameters, ripgrep process_exit (2026-09-12)

CRT teardown did `fs:[0x18] → PEB → +0x10 → [eax+8]` (ProcessParameters
Flags). The PEB pointer was NULL. The PEB page now carries a parameters
block at `+0x200` and `PEB+0x10` points at it.

Measured on the staged corpus (payloads still out of git):
- CORPUS-013 ripgrep `--version`: **process_exit 0**, **181840** instruction,
  458 HLE, output `ripgrep 14.1.1 (rev 4649aa9700)` plus PCRE2 line.
  No-arg: **process_exit 2**, **176792** instruction, output
  `rg: ripgrep requires at least one pattern to execute a search`.
- CORPUS-014 SuperTux: unchanged 10M OpenAL budget stop.

`passing` stays 1 (BPTK-001 only). Ripgrep `--version` is a measured 1:1
console completion (ExitProcess 0 with the real banner). It is not an
interactive session and does not search a corpus file. SuperTux is still
not a playable frame; the next named gap is interpreter throughput through
OpenAL table init.

## Cycle 12 — PMOVMSKB src, mapped VAD, ripgrep search (2026-09-12)

`66 0F D7 /r` was reading `xmm[reg]` instead of the r/m source, so
hashbrown's `pmovmskb edi, xmm0` scanned xmm7 and never left the probe
loop. `MapViewOfFile` now allocates a granularity-aligned committed VAD
(MEM_MAPPED) so rust memmap's `VirtualProtect` is not ERROR_INVALID_ADDRESS
487. i386 `executeProbe` forwards `host_file`.

Measured on the staged corpus (payloads still out of git):
- CORPUS-013 ripgrep `--version`: **process_exit 0**, **181697** instruction,
  458 HLE, same real banner.
- CORPUS-013 ripgrep `PCRE2 C:\game\README.md` with the staged README as a
  host file: **process_exit 0**, **1701493** instruction, 8219 HLE, real
  line-numbered hits (136, 139, 140, …) with ANSI color. MapView +
  VirtualProtect + UnmapViewOfFile succeed.
- CORPUS-014 SuperTux: unchanged 10M OpenAL budget stop.

`passing` stays 1 (BPTK-001 only). Ripgrep `--version` and a one-file
search are measured 1:1 console completions. They are not an interactive
session. SuperTux is still not a playable frame; the next named gap is
interpreter throughput through OpenAL table init.

## Cycle 13 — i386 interpreter cache, thunk writes, CRT argv (2026-09-12)

The probe reuses the per-instruction undo/trace scratch and caches the last
mapped PE section. SuperTux 10M in OpenAL is **33.4 s** at `0x280ab69f`
(1045 HLE) — still the named throughput gap, not a missing opcode. The HLE
thunk page is a writable 1 MiB backing (fetch still refused). i386 CRT argv
uses 4-byte slots; `__getmainargs` / `__wgetmainargs` write the real argc.

Measured on the staged corpus (payloads still out of git):
- CORPUS-013 ripgrep `--version`: **process_exit 0**, **181697** instruction.
- CORPUS-014 SuperTux: 10M OpenAL budget stop, 33.4 s.
- CORPUS-010 jq: **process_exit 2**, **23258** instruction, 753 HLE. fputc
  of `help.\n` returns EOF because `_iob` is bound as a code thunk
  (`FILE*` `0xfe000b64`). Next generic gap is data-import binding for
  `_iob`, not another CPU opcode.

`passing` stays 1 (BPTK-001 only). No title is interactive. SuperTux is
still not a playable frame.

## Cycle 14 — CRT data imports, _initterm walk, jq 1:1 (2026-09-12)

msvcrt `_iob` (and `_tzname` / `__mb_cur_max` / `_environ` / `__winitenv`)
bind to the live FILE table, not a code thunk. i386 `_initterm` walks each
guest constructor so mingw CRT can call `__wgetmainargs`. FLD1 is the real
`D9 E8` (the old form `0x08` was FXCH ST(0)); `FSTP ST(i)` copies then pops.
`hle_inspect` now also reports `output_latin1` because fputc is ANSI.

Measured on the staged corpus (payloads still out of git):
- CORPUS-010 jq `--version`: **process_exit 0**, **4648** instruction, 110 HLE, output `jq-1.7.1\n`.
- CORPUS-010 jq `-n 1`: **process_exit 0**, **4361398** instruction, 22842 HLE, colored `1` (UTF-16 console). Needs a probe budget above the package 2M default.
- CORPUS-010 jq no-arg: **process_exit 2**, **26971** instruction, real usage banner. argv[0] prints as `C:\game\jq-windows-i386.exe` plus a trailing wide-garbage glitch.
- CORPUS-013 ripgrep `--version`: unchanged **process_exit 0**, **181697** instruction.
- CORPUS-014 SuperTux: unchanged 10M OpenAL budget stop.

`passing` stays 1 (BPTK-001 only). Ripgrep and jq `--version` are measured
1:1 console completions. jq `-n 1` is a measured filter completion, not an
interactive session. SuperTux is still not a playable frame; the next named
gap is interpreter throughput through OpenAL table init.

## Cycle 15 — in-place SSE, SuperTux 2.3x, Plink --version (2026-09-12)

Register-register MOVAPS / scalar ADDSD/MULSD/DIVSD / CVTDQ2PD write the
xmm file directly instead of allocating a Buffer per instruction. The
OpenAL table-init series is the same finite loop at the same sites; it
just retires faster.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 10M: budget exhausted at `0x280ab69f`, **1045** HLE, **14.2 s / 705k insn/s** (was 33.4 s).
- CORPUS-014 SuperTux 25M: budget exhausted at `0x280abeb1`, **1047** HLE, **33.0 s / 758k insn/s**.
- CORPUS-009 Plink `--version`: **process_exit 0**, **766759** instruction, 1794 HLE, output `plink: Release 0.74` plus build/compiler/commit lines.
- CORPUS-009 Plink no-arg / `--help`: **process_exit 1**, **1054390** / **1055370** instruction, real usage banner.
- CORPUS-010 jq `--version`: unchanged **process_exit 0**, **4648** instruction.
- CORPUS-013 ripgrep `--version`: unchanged **process_exit 0**, **181697** instruction.

`passing` stays 1 (BPTK-001 only). SuperTux is still not a playable frame.
The next named SuperTux gap is still throughput through OpenAL table init
(or an i386 SSE tier), not a missing opcode at these sites.

## Cycle 16 — register-only decode cache (2026-09-12)

A direct-mapped 64k decode cache replays register-only INC/DEC, Jcc rel8,
LAHF, TEST AH,imm8, MOVAPS/MOVAPD, MOVD xmm,r32, CVTDQ2PD, and scalar
ADD/MUL/SUB/DIV SS/SD plus UCOMISD. Memory operands and 67/64/65/F0 still
fall through to `executeInstruction`. Hits copy the cached bytes into the
trace scratch so `trace_sha256` stays bit-exact. This is generic, not an
OpenAL stub.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 10M: budget exhausted at `0x280ab69f`, **1045** HLE, **9.46 s / 1.06M insn/s** (was 14.2 s / 705k).
- CORPUS-014 SuperTux 25M: budget exhausted at `0x280abeb1`, **1047** HLE, **20.1 s / 1.25M insn/s** (was 33.0 s / 758k).
- CORPUS-009 Plink `--version`: unchanged **process_exit 0**, **766759** instruction.
- CORPUS-010 jq `--version`: unchanged **process_exit 0**, **4648** instruction.

`passing` stays 1 (BPTK-001 only). SuperTux is still not a playable frame.
The next named SuperTux gap is still throughput through OpenAL table init
(or an i386 SSE/WASM tier), not a missing opcode at these sites.

## Cycle 17 — PuTTYgen dialog HLE (2026-09-12)

Generic ANSI / resource / dialog HLE, not PuTTYgen-shaped stubs. `findResource`
walks the PE resource tree by type and name. `DialogBoxParamA` loads
`RT_DIALOG`, instantiates the template, and the i386 probe re-enters the
guest `DLGPROC` for `WM_INITDIALOG`. comdlg32 file pickers return 0 (cancel).
Non-`MB_OK` MessageBox returns 0. A modal dialog that never calls `EndDialog`
is `hle_dialog_modal_idle`, not a fake `IDOK`.

Measured on the staged corpus (payloads still out of git):
- CORPUS-011 PuTTYgen: IAT **174/174** (was 118/174). `executeProbe` 10M:
  **instruction_budget_exhausted**, **1233** HLE, **8.8 s**, EIP `0x41743f`.
  `DialogBoxParamA` (template 201) then `CreateWindowExA` 34 / `MapDialogRect`
  35 / `AppendMenuA` 36. Still inside guest `WM_INITDIALOG`. Not a shown
  window. No `EndDialog`.
- CORPUS-008 OpenTTD: unchanged **161/302** unserved. Serving stubs to pass
  that gate is misaligned.
- CORPUS-014 SuperTux / CORPUS-009 Plink / CORPUS-010 jq: not remesured this
  cycle; prior numbers stand.

`passing` stays 1 (BPTK-001 only). No corpus entry is interactive.

## Cycle 18 — PINSRW, SuperTux leaves OpenAL (2026-09-12)

`0F C4` / `66 0F C4` PINSRW inserts the low 16 bits of a GPR or memory word
into the selected MMX or XMM lane. Other lanes stay put. The selector wraps
(`imm8 & 7` on xmm, `imm8 & 3` on mm). The `F2`/`F3` encodings stay a
structured refusal. Generic, not an OpenAL or ucrt stub.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 10M: unchanged OpenAL budget stop at `0x280ab69f`.
- CORPUS-014 SuperTux 50M: leaves OpenAL at **30017849** (`ucrtbase`
  `0x35090719` was the first PINSRW). Then CRT argv. Then **fetch_fault**
  at `0x1397bc` after **31124264** instruction, **3061** HLE, **32.0 s**.
  `0x1397bc` is the image RVA of `.text` `0x5397bc` (`1f 44 00 00 …`), not
  a mapped VA.
- CORPUS-011 PuTTYgen / CORPUS-009 Plink / CORPUS-010 jq: not remesured
  this cycle; prior numbers stand.

`passing` stays 1 (BPTK-001 only). SuperTux is still not a playable frame.
The next named SuperTux gap is the post-OpenAL fetch at `0x1397bc`, not
another missing SSE form at the OpenAL site.

## Cycle 19 — sidecar IAT: SHGetFolderPath and OpenProcessToken (2026-09-12)

The `0x1397bc` fetch was not an unrelocated SuperTux RVA. SDL2
`call dword [0x2C0F8218]` used an **unbound** `shell32!SHGetFolderPathW`
IAT slot that still held the hint/name RVA. `previous_eip` on a fetch_fault
named `sdl2+0xd74cc`. The next hole was physfs `OpenProcessToken`.

`SHGetFolderPathW`/`A` write a declared virtual profile (CSIDL_APPDATA →
`C:\Users\Guest\AppData\Roaming`; unknown CSIDL is `E_INVALIDARG`).
`OpenProcessToken` issues a closeable token handle for
`GetCurrentProcess` (`0xffffffff`). `RegisterClassExA` /
`UnregisterClassA` are the ANSI twins. `ShellExecuteW` is the wide twin
of the existing honest refusal.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 10M: unchanged OpenAL budget stop.
- CORPUS-014 SuperTux 50M: `SHGetFolderPathW(0x801A)` returns `S_OK`,
  `OpenProcessToken` succeeds, then **guest_exception `0xe06d7363`** after
  **31359444** instruction, **3944** HLE, **24.0 s** (`vcruntime140`
  `0x34004971`). Not a frame. SDL2 still has 156 unserved imports.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is that
C++ throw after pref-path init, not another hint-RVA fetch at these two
slots.

## Cycle 20 — relative CreateFile, directory open, GetFullPathName (2026-09-12)

The post-OpenProcessToken throw was CreateFileW of a path our
`normalizeDrivePath` refused as 87 (relative / empty / no
BACKUP_SEMANTICS directory). Win32 CreateFile("") is PATH_NOT_FOUND, not
INVALID_PARAMETER. `.` / `..` resolve inside `c:\` and refuse escape past
the root. OPEN_EXISTING + `FILE_FLAG_BACKUP_SEMANTICS` opens `c:`,
`c:\game`, a `virtualDir`, or a host-file prefix as a directory handle;
`GetFileInformationByHandle` reports `0x10`. GetFullPathName("") writes
the current directory.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 10M: unchanged OpenAL budget stop.
- CORPUS-014 SuperTux 50M: console.out/console.err create under the
  virtual profile, then **guest_exception `0xe06d7363`** after
  **31359471** instruction, **3944** HLE. The failing CreateFileW path is
  empty (32 zero bytes); last_error is now 3. `--datadir C:\game\data`
  plus 5134 real portable host files does not change that empty
  CreateFile (msvcp140 `canonical` does not call GetFullPathNameW). Not a
  frame.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is why
msvcp140 CreateFileW's an empty path during datadir canonicalization.

## Cycle 21 — counted MB2WC, CreateFile2, FileTime, physfs bind (2026-09-12)

The empty CreateFile during `canonical` was counted `MultiByteToWideChar`
returning the character count but writing nothing (`writeWideString`
refused because it always appends a NUL). Counted Win32 MB2WC does not
null-terminate. After that write, `CreateFileW("C:\game\data")` succeeds
when the real portable tree is seeded and `--datadir` is passed.

physfs then `call [IAT]` of unbound `FileTimeToSystemTime` (hint RVA
`0x1d484`). That converter, `SystemTimeToTzSpecificLocalTime`,
`DeleteFileW`, and `RemoveDirectoryW` are now served. physfs unserved
dropped **4 → 0**.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir`: **guest_exception
  `0xe06d7363`** after **31435057** instruction, **4362** HLE. Canonical
  of `c:\game\data` succeeded. The throw is `ReaderDocument::from_file("config")`
  after CreateFile2 FILE_NOT_FOUND on the userdir then datadir `config`.
  SuperTux `ConfigSubsystem` catches `std::exception` and continues with
  defaults; our `RaiseException` has no guest `__CxxFrameHandler` catch
  (BPTK-053). Not a frame. Do not invent a config file.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is MSVC
C++ catch of `0xe06d7363`, not another file alias.

## Cycle 22 — guest FS:[0] C++ catch (2026-09-12)

`RaiseException` now walks the live `FS:[0]` chain (TEB+0) and re-enters
each frame handler as guest code. Frame handlers return
`EXCEPTION_DISPOSITION` (0 continue, 1 search), not `__except` filter
codes. `RtlUnwind(TargetFrame, TargetIp, …)` cuts the live chain and
transfers to `TargetIp` without returning.

The first SuperTux frame is a GS-checked `__CxxFrameHandler3` thunk at
`0x89a511`. Treating disposition 1 as resume had returned into
`_CxxThrowException`'s `ret 8` and fetched INT3 padding at `0x64be05`.
`RtlUnwind` closed over a module-level `layout` that does not exist;
it now uses `guest.layout` / `guest.memory`.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir`: **fetch_fault `0x807de`**
  after **31590080** instruction, **4924** HLE. `RtlUnwind` ran. The
  missing-`config` `0xe06d7363` was caught and init continued
  (`GetSystemTimeAsFileTime`, `VerifyVersionInfoW`, `GetProcAddress`).
  The fault is libcurl `call [IAT]` of unbound
  `secur32.dll!InitSecurityInterfaceW` (hint RVA `0x807de`, previous
  `0x2e012d89`). Not a frame. Do not stub SSPI.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is the
libcurl SSPI import, not another C++ EH alias.

## Cycle 23 — SSPI table and ws2_32 ordinal bind (2026-09-12)

`InitSecurityInterfaceW` returns a real version-3 `SecurityFunctionTableW`
on the CRT data page. Every slot is an HLE thunk. Acquire/query/encrypt
return `SEC_E_SECPKG_NOT_FOUND`; enumerate reports zero packages. Same
posture as ws2_32: the DLL exists, TLS does not.

libcurl then `call [IAT]` of `ws2_32` **ordinal** 115 (`WSAStartup`).
Sidecar bind only resolved named HLE exports, so the slot kept
`0x80000073`. Served ws2_32 rows now carry their documented ordinal,
and `resolveHleExport` / sidecar bind join on it.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir`: **fetch_fault `0x8083e`**
  after **31592894** instruction, **4946** HLE. `InitSecurityInterfaceW`
  returned the table; `WSAStartup` ran. The fault is libcurl
  `ws2_32.dll!WSACreateEvent` (hint RVA `0x8083e`, previous `0x2e0353f4`).
  Not a frame. Do not stub a signaled network event.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is the
WSA event family (`WSACreateEvent` / `WSAEventSelect`), not another
SSPI alias.

## Cycle 24 — WSA events, x87 log, SuperTux writes config (2026-09-12)

`WSACreateEvent` / `WSACloseEvent` / `WSASetEvent` / `WSAResetEvent` /
`WSAWaitForMultipleEvents` are the existing kernel event machine under
the Winsock names (manual-reset, initially unset). `WSAEventSelect`
records a socket→event mask on the guest; `WSAEnumNetworkEvents` writes
a 44-byte zero `WSANETWORKEVENTS` and resets the event. Offline guest:
no FD_* bits. Failures set both `last_error` and `WSAGetLastError`.

ucrt `log()` then encoded the D9 constant family plus `FXCH ST(i)` and
`FYL2X`. The bounded x87 subset still stores 64-bit values, not 80-bit.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir`: **process_exit 1** after
  **33273860** instruction, **15672** HLE. First-run `config` is written
  under Roaming. `RegisterClassW` / `CreateWindowExW` return a class atom
  and HWND. `console.err` is the SuperTux fatal at
  `src/supertux/main.cpp:833`:
  `Couldn't initialize SDL: Not enough resources to create thread`.
  That is `CreateThread` / `_beginthreadex` refused (ERROR_MAX_THRDS_REACHED
  164). Not a frame. Do not return a handle that never runs.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is a
guest thread scheduler so SDL_Init can create its thread, not another
Winsock alias or a fake `config`.

## Cycle 25 — guest thread context + WaitOnAddress (2026-09-12)

`CreateThread` allocates a real second i386 context: a virtual-arena stack
and TEB, the start address on that stack with a return sentinel, and a
cooperative switch when the creator waits. `WaitForSingleObject` /
`WaitForMultipleObjects` / `Sleep` / `WaitOnAddress` park the current
context and run a ready worker. `SetEvent` / `ReleaseSemaphore` /
`WakeByAddress*` wake waiters and hand off. `ExitThread` on a worker
terminates that context only. Isolated HLE (no probe loop) still returns
a handle; the start address is not entered there. TLS/FLS values are
per-tid. Bound: 8 workers. A handle that never executes is still refused
by the bound, not by returning success and stalling.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir`: **fetch_fault `0x105be0`**
  after **31709266** instruction, **5597** HLE. `CreateThread` returned
  handle `65550` (start in SDL2). `WaitOnAddress` parked. The old
  `console.err` fatal is gone. Previous EIP is `ucrtbase` `0x350808da`.
  Not a frame. Do not invent a mapped page at `0x105be0`.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is that
ucrt fetch, not another CreateThread refusal.

## Cycle 26 — console ctrl, resources, virtual display, keyboard (2026-09-12)

The SuperTux stop after the guest thread scheduler was a cascade of
unbound SDL2 IAT hint RVAs, not a new CPU gap. Each named hole is a
generic Win32 row with a conformance case (user32/gdi32 on both local
tables and `buildConformanceCaseTable`).

- `kernel32!SetConsoleCtrlHandler` records a handler (bound 16) or the
  NULL ignore-ctrl flag. It never delivers `CTRL_C_EVENT`.
- `user32!GetDoubleClickTime` is the documented 500 ms default.
- `kernel32!EnumResourceNamesW` lists names under a type via
  `listResourceNames`. Missing type → 1813, no invented name. A live
  name re-enters `ENUMRESNAMEPROC` through `pending_guest_call`.
- One virtual desktop: `EnumDisplayMonitors` (one `HMONITOR`),
  `GetMonitorInfoW`/`A`, `EnumDisplaySettingsW`/`A` (one 1920×1080×32@60
  mode), `EnumDisplayDevicesW`/`A` (`\\.\DISPLAY1`, flags 5),
  `gdi32!CreateDCW`/`A` (`DISPLAY` or `\\.\DISPLAY1` in either slot;
  printer refused).
- `MapVirtualKeyW`/`A` is a US 101 set-1 table. `GetKeyState` /
  `GetAsyncKeyState` are 0 (no host keyboard). `LoadCursorW` /
  `LoadIconW` are the existing A twins.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir`: **fetch_fault
  `gdi32!CreateDIBSection`** after **31870988** instruction, **5963**
  HLE. Previous EIP `sdl2` `0x2c0d0c5c`. `CreateDCW` `0x40000`,
  `GetDeviceCaps` 1920/1080, `GetDIBits` ran, `GetDC` `0x40008`.
  Not a frame. Do not invent DIB bits in host-only GDI memory.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is
`CreateDIBSection` (guest-visible bits pointer), not another display
query.

## Cycle 27 — DIB bits, cursor handles, mouse SPI, CVTPS2DQ (2026-09-12)

The SuperTux stop after Cycle 26 was the SDL cursor-create path, then
one SSE convert in the same SDL2 mouse helper. Each named hole is a
generic Win32 or i386 row with a conformance / microprogram case.

- `gdi32!CreateDIBSection` reads `BITMAPINFOHEADER`, serves BI_RGB and
  BI_BITFIELDS at 24/32 bpp, and `VirtualAlloc`s guest bits. `hSection`
  ≠ 0 is 50. Guest BGRA syncs into the host RGBA cache on GetPixel /
  BitBlt / GetDIBits. `DeleteObject` `VirtualFree`s the bits.
- `gdi32!CreateBitmap` serves planes=1 and bitCount 1/24/32. NULL bits
  is a zeroed surface. Other depths refuse 87.
- `user32!CreateIconIndirect` allocates `0x8200+4n` when `hbmMask` is
  set. `DestroyIcon` frees a created handle and no-ops a stock
  LoadCursor/LoadIcon handle. `CopyImage` copies a bitmap 1:1 or
  allocates a new icon/cursor handle, including a requested size
  (SDL passes the cursor dimensions). Resize of a bitmap is 50.
- `user32!SystemParametersInfoW`/`A` writes `SPI_GETMOUSESPEED` (10),
  `SPI_GETMOUSE` (6, 10, 1), `SPI_GETWORKAREA` (0,0,1920,1080),
  `SPI_GETWHEELSCROLLLINES` (3), and `SPI_GETDOUBLECLICKTIME` (500).
  NULL `pvParam` or an unknown action is 87.
- `user32!RegisterWindowMessageA`/`W` maps a name to `0xC000+`.
  Empty/NULL is 87. The same name returns the same id.
- i386 `0F 5B` is `CVTPS2DQ` (np), `CVTPD2DQ` (66), `CVTTPS2DQ` (f3).
  `F2 0F 5B` stays `#UD`.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir`: **fetch_fault
  `kernel32!SetThreadExecutionState`** after **31878842** instruction,
  **5994** HLE. Previous EIP `sdl2` `0x2c0d3752`. `CreateDIBSection`
  `0x4000c`, `CreateBitmap` `0x40010`, `CreateIconIndirect` `0x8200`,
  `CopyImage` `0x8204`, both `SystemParametersInfoW` returned 1,
  `RegisterWindowMessageA` `0xC000`. Not a frame. Do not invent a
  display-required sleep state.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is
`SetThreadExecutionState`, not another cursor query.

## Cycle 28 — SetThreadExecutionState (2026-09-12)

The SuperTux stop after Cycle 27 was SDL2 inhibiting the display sleep
through unbound `kernel32!SetThreadExecutionState`. The row is generic:
CONTINUOUS is stored and returned as the previous state; a one-shot is
accepted and forgotten; the host never sleeps. USER_PRESENT cannot
combine with CONTINUOUS; AWAYMODE requires it. Zero or unknown bits
refuse 87.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **fetch_fault `user32!GetKeyboardState`** after **31884911**
  instruction, **6005** HLE. Previous EIP `sdl2` `0x2c0cdffa`.
  `SetThreadExecutionState` returned `0x80000000`. `CreateDCW` `0x40000`,
  `CreateDIBSection` `0x4000c`, `GetDC` `0x40008`. Not a frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is
`GetKeyboardState` (all keys up, matching `GetKeyState`), not another
execution-state flag.

## Cycle 29 — GetKeyboardState (2026-09-12)

The SuperTux stop after Cycle 28 was SDL2 reading the 256-byte key table
through unbound `user32!GetKeyboardState`. The row is generic: a NULL dest
refuses 87; otherwise 256 zero bytes (every virtual key up, matching
`GetKeyState` / `GetAsyncKeyState`) and return 1. No host keyboard is
mapped.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **fetch_fault `user32!ToUnicode`** after **31884931**
  instruction, **6007** HLE. Previous EIP `sdl2` `0x2c0ce031`
  (`mov ebx, [0x2c0f8394]; call ebx`). `GetKeyboardState` returned 1.
  `MapVirtualKeyW` returned 57. Not a frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is
`ToUnicode` (US layout, key-state modifiers), not another key-table dump.

## Cycle 30 — ToUnicode (2026-09-12)

The SuperTux stop after Cycle 29 was SDL2 translating virtual keys through
unbound `user32!ToUnicode`. The row is generic: US 101 layout, Shift and
Caps Lock, Ctrl/Alt produce no character, no dead-key state. A NULL dest
or a non-positive count refuses 87.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **fetch_fault `user32!AdjustWindowRectEx`** after **39445309**
  instruction, **7822** HLE. Previous EIP `sdl2` `0x2c0d4136`.
  `ToUnicode` returned 1. `GetMonitorInfoW` and `MulDiv` (1280, 800)
  ran. Not a frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is
`AdjustWindowRectEx` (identity twin of `AdjustWindowRect`; this HLE
has no nonclient frame), not another keyboard translator.

## Cycle 31 — AdjustWindowRectEx (2026-09-12)

The SuperTux stop after Cycle 30 was SDL2 converting a client rect through
unbound `user32!AdjustWindowRectEx`. The row is generic: the same
no-nonclient-frame contract as `AdjustWindowRect`; a NULL dest refuses 87.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **fetch_fault `user32!GetWindowLongW`** after **39445578**
  instruction, **7829** HLE. Previous EIP `sdl2` `0x2c0d3b5a`.
  `AdjustWindowRectEx` returned 1. `RegisterClassExW` `0xC001`.
  `CreateWindowExW` `0x10014`. `GetDC` `0x4001c`. A HWND is not a
  presented frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is
`GetWindowLongW` (A-twin plus `GWL_HINSTANCE`), not another rect helper.

## Cycle 32 — GetWindowLongW (2026-09-12)

The SuperTux stop after Cycle 31 was SDL2 reading `GWL_HINSTANCE` through
unbound `user32!GetWindowLongW`. The W rows are the existing A twins;
`CreateWindowEx` now stores `hInstance` / `ex_style` / parent / title
so `-6` is the instance the guest passed (`0x400000` for SuperTux).

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **fetch_fault `user32!SetPropW`** after **39450640**
  instruction, **7834** HLE. Previous EIP `sdl2` `0x2c0d3c21`.
  `GetWindowLongW` returned `0x400000`. `CreateWindowExW` `0x10014`.
  A HWND is not a presented frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is
`SetPropW` (per-window property table, with `GetPropW` / `RemovePropW`),
not another GWL index.

## Cycle 33 — SetPropW (2026-09-12)

The SuperTux stop after Cycle 32 was SDL2 attaching window userdata through
unbound `user32!SetPropW`. The slice is generic: one HANDLE table per
window, keyed by a name string or an atom; `GetProp`/`RemoveProp` (A and
W) share it. A NULL name refuses 87.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **fetch_fault `user32!ClientToScreen`** after **39450685**
  instruction, **7837** HLE. Previous EIP `sdl2` `0x2c0d3d66`.
  `SetPropW` returned 1. `GetClientRect` returned 1. A HWND is not a
  presented frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is
`ClientToScreen` (with `ScreenToClient`; no nonclient frame), not
another property API.

## Cycle 34 — ClientToScreen (2026-09-12)

The SuperTux stop after Cycle 33 was SDL2 converting the window origin
through unbound `user32!ClientToScreen`. The slice is generic: add or
subtract the window origin (this HLE has no nonclient frame). A NULL
POINT refuses 87. `ScreenToClient` is the inverse twin.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **fetch_fault `gdi32!GetICMProfileW`** after **39451090**
  instruction, **7840** HLE. Previous EIP `sdl2` `0x2c0d3de8`.
  `ClientToScreen` returned 1. `GetMonitorInfoW` returned 1.
  `CreateDCW` returned `0x40020`. A HWND is not a presented frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is
`GetICMProfileW` (with `GetICMProfileA`; a declared ICC path on the
virtual display DC), not another USER32 geometry API.

## Cycle 35 — GetICMProfileW (2026-09-12)

The SuperTux stop after Cycle 34 was SDL2 reading the display ICC profile
through unbound `gdi32!GetICMProfileW`. The slice is generic: one declared
sRGB path for every virtual-display DC. A NULL size pointer refuses 87;
a short or NULL dest writes the required TCHAR count and refuses 122.
`GetICMProfileA` is the ANSI twin.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **fetch_fault `user32!SetWindowTextW`** after **39455072**
  instruction, **7851** HLE. Previous EIP `sdl2` `0x2c0d5222`.
  `GetICMProfileW` returned 1. `SetWindowPos` returned 1. `DeleteDC`
  returned 1. A HWND is not a presented frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is
`SetWindowTextW` (with `GetWindowTextW` / `GetWindowTextLengthW`;
`GetWindowTextA` is already served), not another GDI ICM row.

## Cycle 36 — SetWindowTextW (2026-09-12)

The SuperTux stop after Cycle 35 was SDL2 setting the window caption through
unbound `user32!SetWindowTextW`. The slice is generic: store the caption
`GetWindowText` / `GetWindowTextLength` (A and W) then report. An invalid
HWND refuses. `SetWindowTextA` is the ANSI twin.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **fetch_fault `shell32!DragAcceptFiles`** after **39455186**
  instruction, **7853** HLE. Previous EIP `sdl2` `0x2c0d3f27`.
  `SetWindowTextW` returned 1. A HWND is not a presented frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is
`DragAcceptFiles` (record whether a HWND accepts dropped files), not
another caption API.

## Cycle 37 — DragAcceptFiles (2026-09-12)

The SuperTux stop after Cycle 36 was SDL2 enabling file drop through
unbound `shell32!DragAcceptFiles`. The slice is generic: record
`is_drop_accepted` on the HWND. An invalid HWND refuses. No host drop
target exists, so `WM_DROPFILES` is never posted. `DragQueryFileW` /
`DragFinish` stay unserved until a drop arrives.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **unsupported_opcode x87 `FLD ST(0)` (`0xd9 0xc0`)** after **39550744**
  instruction, **8099** HLE. EIP `sdl2` `0x2c0f691a`. `DragAcceptFiles`
  returned 0. `ShowWindow` returned 0 (was hidden). Last
  `CreateWindowExW` `0x1001c`. A shown HWND is not a presented frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is
x87 `FLD ST(i)` (`D9 C0+i`), not another shell32 drop API. Present path
still unbound (`ChoosePixelFormat` / `SetPixelFormat` / `SwapBuffers` /
`wglGetProcAddress`).

## Cycle 38 — FLD ST(i) and FSTP m80 (2026-09-12)

The SuperTux stop after Cycle 37 was SDL2 `FLD ST(0)` (`D9 C0`) then
`FSTP m80` (`DB /7`). The slice is generic: `FLD ST(i)` pushes a copy of a
live slot; `FSTP m80` / `FLD m80` convert the 64-bit stack value through the
80-bit memory format (double identity, not 80-bit arithmetic).

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **fetch_fault `user32!GetClassInfoExW`** after **40003291**
  instruction, **10088** HLE. Previous EIP `sdl2` `0x2c0c9455`.
  `ShowWindow` returned 1 (was visible). Last `CreateWindowExW`
  `0x1001c`. A shown HWND is not a presented frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is
`GetClassInfoExW` (report a registered class), not another x87 row.
Present path still unbound (`ChoosePixelFormat` / `SetPixelFormat` /
`SwapBuffers` / `wglGetProcAddress`).

## Cycle 39 — GetClassInfoExW (2026-09-12)

The SuperTux stop after Cycle 38 was SDL2 querying a registered class through
unbound `user32!GetClassInfoExW`. The slice is generic: write the stored
`WNDCLASSEX`/`WNDCLASS` fields (style, WndProc, extras, instance, icon,
cursor, brush) for a registered name. A NULL dest refuses 87; an unknown
name refuses 1411. `GetClassInfoW`/`A` and `GetClassInfoExA` are the twins.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **process_exit 1** after **41435616** instruction, **19524** HLE.
  `GetClassInfoExW` returned 1. `ShowWindow` returned 1 (was visible).
  Last `CreateWindowExW` `0x1001c`. SDL `LoadLibraryW("OPENGL32.DLL")`
  is 0 / last_error 126, then `ExitProcess(1)`. A shown HWND is not a
  presented frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is
`LoadLibraryW("OPENGL32.DLL")` (OpenGL HLE is IAT-bound but not in the
LoadLibrary module table), not another class-info API. Present path
still unbound (`ChoosePixelFormat` / `SetPixelFormat` / `SwapBuffers` /
`wglGetProcAddress`).

## Cycle 40 — LoadLibrary opengl32 (2026-09-12)

The SuperTux stop after Cycle 39 was SDL2 `LoadLibraryW("OPENGL32.DLL")`
returning 0 / last_error 126. The slice is generic: `opengl32.dll` joins
the LoadLibrary module table (handle `0x2000c`) the same way `ws2_32.dll`
and `comctl32.dll` already do, so GetProcAddress can resolve the existing
OpenGL HLE exports. No title-specific branch.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **process_exit 1** after **41500008** instruction, **19608** HLE.
  `LoadLibraryW("OPENGL32.DLL")` returned `0x2000c`. `GetProcAddress` of
  `wglGetProcAddress` / `wglCreateContext` / `wglMakeCurrent` /
  `wglDeleteContext` / `wglShareLists` is 0 / last_error 127, then
  `ExitProcess(1)`. `ChoosePixelFormat` is never reached. A shown HWND is
  not a presented frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is
`wglGetProcAddress` / `wglCreateContext` / `wglMakeCurrent` (SDL
GetProcAddress of those WGL symbols is 127), not another module-table
row. Present path still unbound (`ChoosePixelFormat` / `SetPixelFormat` /
`SwapBuffers` / `wglGetProcAddress`).

## Cycle 41 — WGL GetProcAddress (2026-09-12)

The SuperTux stop after Cycle 40 was SDL2 GetProcAddress of
`wglGetProcAddress` / `wglCreateContext` / `wglMakeCurrent` /
`wglDeleteContext` / `wglShareLists` returning 0 / last_error 127. The
slice is generic: those WGL names (plus `wglGetCurrentDC` /
`wglGetCurrentContext`) are opengl32 exports over one HGLRC table. A live
DC issues a context handle; make-current binds it; GetProcAddress of a
served `gl*` / `wgl*` name returns the thunk. No title-specific branch.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **fetch_fault `gdi32!ChoosePixelFormat`** after **39497908**
  instruction, **7947** HLE. `LoadLibraryW("OPENGL32.DLL")` returned
  `0x2000c`. GetProcAddress of the five SDL WGL names succeeded. Last
  `CreateWindowExW` `0x10018`. `GetDC` `0x40024`. Previous EIP `sdl2`
  `0x2c0d1def` (`call [0x2c0f803c]`). A shown HWND is not a presented
  frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is
`ChoosePixelFormat` (SDL `GetDC` then unbound `gdi32!ChoosePixelFormat`
IAT), not another WGL row. Present path still unbound (`ChoosePixelFormat`
/ `SetPixelFormat` / `SwapBuffers`).

## Cycle 42 — ChoosePixelFormat / SetPixelFormat (2026-09-12)

The SuperTux stop after Cycle 41 was SDL2 `call [IAT]` of unbound
`gdi32!ChoosePixelFormat`. The slice is generic: one declared OpenGL RGBA
pixel format (index 1, 32-bit color, 24 depth, 8 stencil, double-buffer)
on a live DC. `ChoosePixelFormat` returns 1; `SetPixelFormat` stores it
once; `GetPixelFormat` / `DescribePixelFormat` report it. A NULL PFD
refuses 87; an unknown index or a second SetPixelFormat refuses 2000.
No title-specific branch.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **process_exit 1** after **41716001** instruction, **19906** HLE.
  `ChoosePixelFormat` returned 1. `SetPixelFormat` 1. `wglCreateContext`
  `0x50010`. `wglMakeCurrent` 1. `DescribePixelFormat` 1. Then
  `wglDeleteContext` 1 after GetProcAddress of unserved GL 1.1 (`glBegin`
  / `glEnd` / `glVertex2f` / …) 127. `SwapBuffers` is never reached. Last
  `CreateWindowExW` `0x10034`. A WGL context is not a presented frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is
GetProcAddress of unserved GL 1.1 (`glBegin` family) so the context is
not deleted, not another PFD API. Present path still unbound
(`SwapBuffers`).

## Cycle 43 — GL 1.1 GetProcAddress (2026-09-12)

The SuperTux stop after Cycle 42 was kernel32 / `wglGetProcAddress` of
unserved GL 1.1 (`glBegin` / `glEnd` / `glVertex2f` / …) returning 0 /
last_error 127, then `wglDeleteContext` / `ExitProcess(1)`. The slice is
generic: those 1.1 names join the opengl32 export table with bounded
immediate-mode and query state. `glBegin`/`glEnd`/`glRectf` record a
draw (`draw_count`); they do not paint a playable frame. GL errors go to
`glGetError`, not Win32 last_error. No title-specific branch.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **process_exit 1** after **41406979** instruction, **19588** HLE.
  `ChoosePixelFormat` 1. `SetPixelFormat` 1. Four `wglCreateContext`
  (`0x50000`…`0x5000c`). `wglMakeCurrent` 1. SDL `wglGetProcAddress` of
  48 GL 1.1 names hits; `glGetString` / `glGetIntegerv` / `glColor4ub`
  run. Dummy context deleted after `wglGetExtensionsStringARB` 0.
  Last `CreateWindowExW` `0x10024`. `SwapBuffers` is never reached. A
  recorded `glBegin` is not a presented frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is
`wglGetExtensionsStringARB` (the only `wglGetProcAddress` miss), not
another 1.1 name. Present path still unbound (`SwapBuffers`).

## Cycle 44 — wglGetExtensionsStringARB (2026-09-12)

The SuperTux stop after Cycle 43 was `wglGetProcAddress("wglGetExtensionsStringARB")`
returning 0, then dummy-context delete. The slice is generic: a live DC
returns one declared token (`WGL_ARB_extensions_string`); hdc 0 refuses 6.
The string does not advertise `WGL_ARB_create_context` (that attribs entry
is not served). No title-specific branch.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **process_exit 1** after **41408366** instruction, **19589** HLE.
  `wglGetExtensionsStringARB` returned a guest pointer. `wglGetProcAddress`
  misses are empty. Four `wglCreateContext` (`0x50000`…`0x5000c`).
  `glGetString` VERSION (`0x1f02`) / EXTENSIONS (`0x1f03`) and `glColor4ub`
  run. Dummy context still deleted after the query. Last `CreateWindowExW`
  `0x10024`. `SwapBuffers` is never reached. A WGL extension string is not
  a presented frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is
`ExitProcess(1)` after `glGetString` VERSION `"1.1 BPTK"` / empty
`GL_EXTENSIONS` before present; `gdi32!SwapBuffers` is still unbound on
sdl2. Not another WGL GetProcAddress name.

## Cycle 45 — GL 2.1 version + SetFilePointer BOOL (2026-09-12)

The SuperTux stop after Cycle 44 was `ExitProcess(1)`. Guest
`console.err` named two stacked causes: `glGetString(GL_VERSION)` `"1.1
BPTK"` makes SuperTux auto-GL `sscanf` the major and throw `"OpenGL 2.0 or
higher is unsupported"` (SDL fallback), then SDL_image `IMG_Load` of the
window icon fails `"Can't seek in this data source"`. The slice is generic:
the declared GL version string is `"2.1 BPTK"` (compatibility, not GLSL) and
`GL_EXTENSIONS` includes `GL_ARB_texture_non_power_of_two` (NPOT already
stores). `SetFilePointerEx` returns BOOL 1 on success (it had been
forwarding `seekFile`'s 0-on-success, so every guest treat-as-BOOL seek
failed); `SetFilePointer` is the 32-bit twin. FIX-008 now checks EAX==1.
No title-specific branch.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **unsupported_opcode `0x0f 0xc8` BSWAP** at `zlib1+0x81c4` after
  **40690494** instruction, **8282** HLE. `SetFilePointerEx` 1.
  console.err empty. Last `CreateWindowExW` `0x10024`. `SwapBuffers` is
  never reached. Inflating a PNG is not a presented frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is i386
`BSWAP` (`0F C8`–`CF`) in zlib; `gdi32!SwapBuffers` is still unbound on
sdl2.

## Cycle 46 — BSWAP (2026-09-12)

The SuperTux stop after Cycle 45 was `unsupported_opcode 0x0f 0xc8` at
`zlib1+0x81c4`. BSWAP is `0F C8+rd` with no ModRM: the interpreter reverses
the operand-size bytes and leaves flags; the decode sweep consumes exactly
two bytes so a linear walk does not desync. The 16-bit form reverses AX
and leaves the high word (architecturally undefined; matches the 64-bit
oracle). No title-specific branch.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **unsupported_opcode `0x0f 0xea` PMINSW** at `libpng16+0x20ad4` after
  **42020032** instruction, **8320** HLE. `SetFilePointerEx` 1.
  console.err empty. Last `CreateWindowExW` `0x10024`. Last
  `wglCreateContext` `0x5000c`. `SwapBuffers` is never reached. Inflating a
  PNG is not a presented frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is i386
`PMINSW` (`0F EA`) in libpng; `gdi32!SwapBuffers` is still unbound on sdl2.

## Cycle 47 — PMINSW (2026-09-12)

The SuperTux stop after Cycle 46 was `unsupported_opcode 0x0f 0xea` at
`libpng16+0x20ad4`. PMINSW is packed signed-word minimum: the no-prefix form
writes an mm lane and the `66` form writes an xmm lane. No title-specific
branch.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **unsupported_opcode `0x0f 0xe0` PAVGB** at `libpng16+0x2080b` after
  **42080197** instruction, **8320** HLE. `SetFilePointerEx` 1.
  console.err empty. Last `CreateWindowExW` `0x10024`. Last
  `wglCreateContext` `0x5000c`. `SwapBuffers` is never reached. Inflating a
  PNG is not a presented frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is i386
`PAVGB` (`0F E0`) in libpng; `gdi32!SwapBuffers` is still unbound on sdl2.

## Cycle 48 — PAVGB (2026-09-12)

The SuperTux stop after Cycle 47 was `unsupported_opcode 0x0f e0` at
`libpng16+0x2080b` (`66 0F E0 C8`, SSE2 PAVGB). PAVGB is packed unsigned-byte
average: each lane is `(a + b + 1) >> 1`. The no-prefix form writes an mm lane
and the `66` form writes an xmm lane. A scan of the same libpng filter found
no further unserved packed op (PADDB / PSUBB / PUNPCKLBW / PMINSW already
served). No title-specific branch.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **fetch_fault `user32!CreateIconFromResource`** after
  **49660809** instruction, **8371** HLE. Previous EIP `sdl2` `0x2c0d4f25`
  (`call [0x2c0f82a8]`). `SetFilePointerEx` 1. console.err empty. Last
  `CreateWindowExW` `0x10024`. Last `wglCreateContext` `0x5000c`.
  `SwapBuffers` is never reached. A decoded icon PNG is not a presented frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is
`user32!CreateIconFromResource`; `gdi32!SwapBuffers` is still unbound on sdl2.

## Cycle 49 — CreateIconFromResource (2026-09-12)

The SuperTux stop after Cycle 48 was `fetch_fault user32!CreateIconFromResource`
after SDL decoded the window-icon PNG. `CreateIconFromResource` and
`CreateIconFromResourceEx` allocate from the same `0x8200+4n` pool as
`CreateIconIndirect`: RT_ICON DIB bits become a live `HICON` (documented
version `0x30000`) without decoding pixels. NULL bits, zero size, or a wrong
version refuse 87. `DestroyIcon` already frees that pool. No title-specific
branch.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **fetch_fault `kernel32!InitOnceBeginInitialize`** after
  **49661659** instruction, **8383** HLE. `CreateIconFromResource` `0x8208`;
  two `SendMessageW` (WM_SETICON). Previous EIP `openal32+0x5fbb2`
  (`call [0x280e60d4]`; IAT still held hint RVA `0x1647ec`). `SetFilePointerEx` 1.
  console.err empty. Last `CreateWindowExW` `0x10024`. Last
  `wglCreateContext` `0x5000c`. `SwapBuffers` is never reached. A window icon
  handle is not a presented frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is
`kernel32!InitOnceBeginInitialize` (same slice `InitOnceComplete`);
`gdi32!SwapBuffers` is still unbound on sdl2.

## Cycle 50 — InitOnceBeginInitialize (2026-09-12)

The SuperTux stop after Cycle 49 was `fetch_fault kernel32!InitOnceBeginInitialize`
from OpenAL one-time init. `InitOnceBeginInitialize` and `InitOnceComplete`
are generic: NULL once or pending dest refuse 87, unknown flags 87,
CHECK_ONLY on an uninitialized cell returns 0, a first Begin sets pending
and returns 1, Complete stores an aligned context with the complete bit,
and a later Begin reports pending false. The single-thread world never
waits. No title-specific branch.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **fetch_fault `shell32!SHGetKnownFolderPath`** after
  **49667853** instruction, **8406** HLE. `InitOnceBeginInitialize` 1;
  `CreateIconFromResource` `0x8208`. Previous EIP `openal32+0xda5bb`
  (`jmp [0x280e63bc]`; IAT still held hint RVA `0x16174e`). `SetFilePointerEx` 1.
  console.err empty. Last `CreateWindowExW` `0x10024`. Last
  `wglCreateContext` `0x5000c`. `SwapBuffers` is never reached. A pending
  InitOnce is not a presented frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is
`shell32!SHGetKnownFolderPath` (same slice `CoTaskMemFree`);
`gdi32!SwapBuffers` is still unbound on sdl2.

## Cycle 51 — SHGetKnownFolderPath (2026-09-12)

The SuperTux stop after Cycle 50 was `fetch_fault shell32!SHGetKnownFolderPath`
from OpenAL looking up a known folder. `SHGetKnownFolderPath` writes the same
declared virtual profile `SHGetFolderPath` already serves, allocated with
`CoTaskMemAlloc` so the caller `CoTaskMemFree`s the PWSTR. NULL GUID or dest
refuse `E_INVALIDARG` 87; an unknown GUID is the same. No title-specific branch.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **unsupported_opcode CPUID leaf `0x80000000`** at `openal32+0xb1e79` after
  **49675227** instruction, **8464** HLE. `SHGetKnownFolderPath` S_OK;
  `CoTaskMemFree` ran; OpenAL `CreateFileW` of
  `C:\Users\Guest\AppData\Roaming\alsoft.ini`. `CreateIconFromResource` `0x8208`;
  `InitOnceBeginInitialize` 1. `SetFilePointerEx` 1. console.err empty. Last
  `CreateWindowExW` `0x10024`. Last `wglCreateContext` `0x5000c`. `SwapBuffers`
  is never reached. A known-folder path is not a presented frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is
CPUID leaf `0x80000000` (OpenAL extended-leaf probe);
`gdi32!SwapBuffers` is still unbound on sdl2.

## Cycle 52 — SwapBuffers present (2026-09-12)

Generic `gdi32!SwapBuffers` and `opengl32!wglSwapLayerBuffers`. A live DC
that already holds the declared double-buffered OpenGL format (index 1)
returns 1 and copies the GL color buffer to a presented front buffer.
`composeGuestSurface` and the live session blit that snapshot (browser
`putImageData`). A NULL DC refuses 6; a DC without a pixel format refuses
2000. No title-specific branch. A recorded `glDrawArrays` is still not a
rasterized frame; a `glClear` followed by SwapBuffers is a real presented
frame.

Not remesured: SuperTux on origin is at CPUID leaf `0x80000000` in OpenAL.
The present path is served so the next remesure that reaches SwapBuffers
can show pixels. `passing` stays 1 (BPTK-001 only).

## Cycle 53 — CPUID leaf 0x80000000 (2026-09-12)

The SuperTux stop after Cycle 51 was `unsupported_opcode CPUID leaf 0x80000000`
from OpenAL's extended-leaf probe. Leaf `0x80000000` is now in the declared
processor table: EAX reports that leaf as the highest extended function, EBX/ECX/EDX
are zero, so a guest that probes for AMD extras or the brand string sees no
further extended leaves. Undeclared leaves still stop. The 64-bit oracle and
WASM tier answer the same leaf. No title-specific branch.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **hle_wait_deadlock `kernel32!SleepConditionVariableSRW`** after
  **49691538** instruction, **8550** HLE. `CreateIconFromResource` `0x8208`;
  `InitOnceBeginInitialize` 1; `SHGetKnownFolderPath` S_OK. OpenAL
  `CreateThread` `0x10010` then `AcquireSRWLockExclusive`. Previous stop was
  CPUID at **49675227** / **8464** HLE. `SetFilePointerEx` 1. console.err empty.
  Last `CreateWindowExW` `0x10024`. Last `wglCreateContext` `0x5000c`.
  `SwapBuffers` is never reached. A CPUID max-extended answer is not a presented
  frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is
`kernel32!SleepConditionVariableSRW` (OpenAL worker wait; infinite timeout is a
structured deadlock because the other thread does not run);
`gdi32!SwapBuffers` is served but SuperTux never reaches it.

## Cycle 54 — live GL present (2026-09-12)

The live session and `composeGuestSurface` now treat a current WGL context /
`gdi32!SwapBuffers` front buffer as video. `hasVideo` and `presentCount` follow
GL, not only an SDL software framebuffer. The browser host `putImageData` blit
is that swapped color buffer. `SDL_GL_SwapBuffers` copies the same buffer. A
recorded `glDrawArrays` is still not a rasterized frame. No title-specific
branch.

Not remesured: SuperTux on origin is at `hle_wait_deadlock
kernel32!SleepConditionVariableSRW` in OpenAL. The present path is served so the
next remesure that reaches SwapBuffers can show pixels. `passing` stays 1
(BPTK-001 only).

## Cycle 55 — SleepConditionVariableSRW (2026-09-12)

The SuperTux stop after Cycle 53 was `hle_wait_deadlock
kernel32!SleepConditionVariableSRW` from OpenAL waiting on a worker it had
already `CreateThread`'d. `SleepConditionVariableSRW` / `SleepConditionVariableCS`
now park on the guest-thread scheduler the way `WaitOnAddress` already does:
an infinite wait switches to the other ready context. `WakeConditionVariable`
and `WakeAllConditionVariable` resume matching waiters; a wake with no waiter
is credited so it is not lost. NULL condition or lock refuse 87. No
title-specific branch.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **guest_exception `0x406d1388`** (MSVC `SetThreadName`) after
  **49907791** instruction, **8894** HLE. OpenAL `CreateThread` last `0x10011`;
  `InitOnceComplete` 1; SRW lock acquire/release after the wait. Previous stop
  was SleepConditionVariableSRW at **49691538** / **8550** HLE.
  `CreateIconFromResource` `0x8208`. `SetFilePointerEx` 1. console.err empty.
  Last `CreateWindowExW` `0x10024`. Last `wglCreateContext` `0x5000c`.
  `SwapBuffers` is never reached. A woken worker is not a presented frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is
`RaiseException` `0x406d1388` (MSVC thread-name; continue if no debugger);
`gdi32!SwapBuffers` is served but SuperTux never reaches it.

## Cycle 56 — MSVC SetThreadName continues (2026-09-12)

The SuperTux stop after Cycle 55 was `guest_exception 0x406d1388` from the
OpenAL worker's MSVC `SetThreadName`. `RaiseException` of that code now
continues when no debugger is attached (an empty FS:[0] chain is not a
stop). Dispatch also walks the current guest thread's TEB, not only the
main TEB, so a worker's `__try` frames are the ones that run. No
title-specific branch.

Measured on the staged corpus (payloads still out of git):
- CORPUS-014 SuperTux 50M + data + `--datadir` (5134 host files):
  **instruction_budget_exhausted** after **50000000** instruction, **8955**
  HLE (~61.7 s) at `vcruntime140+0xef25`. `RaiseException` 0;
  `SleepConditionVariableSRW` 1; `InitOnceComplete` 1; OpenAL `CreateThread`
  last `0x10012`; last `WaitOnAddress` 0 then `HeapAlloc`. Previous stop was
  `0x406d1388` at **49907791** / **8894** HLE. `CreateIconFromResource`
  `0x8208`. Last `CreateWindowExW` `0x10024`. Last `wglCreateContext`
  `0x5000c`. `SwapBuffers` is never reached. A continued thread name is not a
  presented frame.
- CORPUS-011 PuTTYgen 10M: unchanged **instruction_budget_exhausted**
  inside guest `WM_INITDIALOG` (**10000000** instruction, **1233** HLE,
  **7.4 s**, IAT 174/174). Not a shown window.

`passing` stays 1 (BPTK-001 only). The next named SuperTux gap is the 50M
cap in `vcruntime140` after `WaitOnAddress` (higher-budget remesure to name
the next IAT or fault); `gdi32!SwapBuffers` is served but SuperTux never
reaches it.

## Known x86 fidelity gap: DIV/IDIV quotient overflow

Found while compiling `div`/`idiv` into the WASM tier, and worth recording
because it is a **wrong-answer** gap, not a missing feature.

On real x86, `div`/`idiv` raise **#DE** when the quotient does not fit the
destination width — the same vector as divide-by-zero. `lib/exec64.mjs` raises a
structured fault for a zero divisor, but for quotient overflow it does not: it
computes the quotient and writes it **masked**:

```js
writeAccumulatorPair(machine, size, quotient & mask, remainder & mask);
```

so an overflowing quotient is silently truncated where hardware would fault.

### Why the tier reproduces the gap rather than fixing it

The tier's contract is bit-exactness **against this interpreter**, not against
hardware. Emitting the architectural #DE in the compiled path would have made the
tier disagree with the oracle and broken the 1:1 test on a real binary. So the
codegen reproduces the masking exactly, and the gap stays where it belongs — in
the oracle.

### What it costs

A guest that relies on #DE for a range check, or that faults deliberately, gets a
truncated quotient and keeps running instead of trapping. No corpus binary is
known to depend on it, and none of the recorded run reach it, so this is a latent
divergence rather than an observed failure. Fixing it means changing `exec64`'s
`div`/`idiv` to raise the fault **and** re-proving every 1:1 case at once, since
both engine must move together — the tier's masking would then be the bug.

Recorded rather than fixed: a one-sided change here would silently break the
tier's equivalence proof, which is the more valuable property.
