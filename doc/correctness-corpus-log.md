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

## Remaining

`passing` stays 1 (BPTK-001 only). No corpus entry is interactive. SuperTux
now reaches `entry` through sidecar DllMain and locale init; the next named
gap is locale/codepage state (BPTK-103), not C++ EH. OpenTTD 1.10.3 and
PuTTYgen stay at `loaded` on unserved imports. Ripgrep's next named gap is
the null read after 20790 instruction. More lawful i386 game binaries can
now be admitted without piling up on bundled-DLL imports.

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
