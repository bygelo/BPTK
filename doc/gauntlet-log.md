# Gauntlet log

The honest run record: every cycle re-derives the buildable work-list from the
corpus run records and the coverage ledger, implements the top item, proves it
against real payload, and gates before the commit. A reached stage is not a
playable claim; implemented is not passing.

## 2026-09-05 — cycle 1

### Baseline

- `npm run gate` exit 0 on a clean tree at `fc131ed`.
- Manifest: 37 implemented, 0 passing, 108 planned.
- Corpus: 7 of 9 entry stopped at `machine_x86_64` (the P4 x86-64 lane), the
  7z container at `unsupported_executable_format`, and the two real i386 entry
  (OpenTTD 1.10.3 win32, Plink 0.74 win32) at `import_present` → BPTK-010 with
  "302 import, no Win32 HLE".
- Coverage ledger: 356 real imported symbol, 0 covered.

### Implemented: BPTK-010 — the Win32 core HLE (the named keystone)

- `lib/hle.mjs` (new): one generic registry of 67 kernel32 and ole32 export,
  each a real emulator over a guest memory interface with no per-title branch —
  process and module lookup, heap (first-fit free list) and virtual memory
  (reserve/commit/decommit/release with region map), time from the one
  monotonic clock, critical sections, TLS, lock-free singly linked list over
  guest memory, pointer encoding, standard handle with bounded output capture,
  environment block, and the COM apartment trio. Every bound is declared
  (`hleBound`); exceeding one is a structured fault, never unbounded growth.
- `lib/runtime.mjs`: the probe now maps the HLE address block (arena, virtual
  arena, read-only thunk page) into its checked memory model with full rollback,
  dispatches guest `call`/`jmp` through the thunk page with the correct stdcall
  frame (args read, callee cleanup, EAX result), maps a guest exit or exception
  into the structured stop with the guest code, and fires TLS callback before
  the entry as their own bounded phases over one instruction budget.
- `lib/run.mjs`: an image whose every import is served executes against the
  HLE; a partially served image is refused with the exact unserved surface
  named ("N of M import are served (library (k) unserved)").
- `lib/corpus.mjs`: the coverage ledger joins the real import surface against
  the HLE registry with per-symbol conformance case count and an unserved
  ranking ordered by corpus import count.

### Proof

- Conformance (GS-036 discipline): 84 case over all 67 served export, zero
  uncovered export, zero failing case.
- FIX-003 exerciser (`test/hle.test.mjs`): a generated PE32 with a real
  two-library import directory executes 26 guest call through the full golden
  sequence — starts, allocates, synchronizes, times, calls COM, writes captured
  output, resolves a procedure through GetProcAddress, and exits through the
  resolved pointer with code 0x5a5a — and repeat runs stay stable in call-trace,
  instruction-trace, and memory hash. TLS callback ordering and the structured
  RaiseException stop are covered too.
- Real payload: the two i386 corpus entry now report `served` import against
  the HLE (OpenTTD i386 62 of 302, Plink i386 45 of 142) and their refusal note
  names the unserved surface. The coverage ledger on the real corpus import
  surface moved from **0 covered / 356 absent** to **62 covered / 294 absent** —
  the generic coverage raise this cycle is measured on real binaries, not
  fixtures. Reached stage of the two entry is honestly unchanged (`loaded`);
  stage movement waits on the unserved breadth plus a wider CPU subset.
- Full suite: 119 test, 0 failing. `npm run gate` exit 0 after the commit.

### Ranking for the next cycle (from the unserved ledger)

The unserved surface clusters into family-sized slices, each with a roadmap
owner: console + file + storage (SetFilePointerEx, GetFileType, SetStdHandle,
GetConsoleMode, ReadConsoleW, GetConsoleCP, CreateFileW, CloseHandle, ReadFile
→ BPTK-015), locale and codepage (GetACP, GetLocaleInfoW, MultiByteToWideChar →
BPTK-059), SEH unwind (RtlUnwind → GS-008), module loading (LoadLibraryA,
FreeLibrary), and synchronization (WaitForSingleObject → BPTK-025). The i386
CPU subset (BPTK-009) is the other lever: real CRT startup uses operand-size
override and SSE, so real binaries cannot reach `entry` until both widen.

## 2026-09-05 — cycle 2

### Implemented: BPTK-015 slice 1 — the Win32 storage surface (virtual drive + registry + console mode)

- The unserved ledger ranked the file/console family first (SetFilePointerEx,
  GetFileType, SetStdHandle, GetConsoleMode, ReadConsoleW, GetConsoleCP,
  CreateFileW, CloseHandle, ReadFile, WaitForSingleObject — each imported by
  both real i386 entry), so the cycle took the roadmap owner BPTK-015's Win32
  half: one bounded virtual drive in guest memory (open dispositions, cursor
  reads and writes, 64-bit seek with negative-seek refusal, truncate, flush,
  type, close), a declared output-only console (modes served, input honestly
  refused), and an in-memory advapi32 hive under the real predefined roots
  (create/open/query with the MORE_DATA contract/set/close). Traversal and UNC
  fail closed; storage bounds are declared constants. The copy-on-write
  overlay, quota transaction, reload persistence, and OPFS bridge stay red —
  they need the browser runtime host.
- Proof: 26 new conformance case (110 total, all 84 served export covered);
  the FIX-008 storage exerciser reaches a normal exit through a 13-call golden
  trace (file lifecycle + registry round-trip) with hash-stable repeats; full
  suite 121 test, 0 failing.
- Real payload: coverage ledger 62 → **79 covered** of the real 356-symbol
  import surface (OpenTTD i386 serves 75 of 302 import, Plink i386 61 of 142).
  Reached stage of the two i386 entry stays honestly at `loaded`.

## 2026-09-05 — cycle 3

### Implemented: BPTK-103 slice 1 — locale, codepage, and Unicode conversion

- The unserved ledger ranked the locale family next (GetACP, GetCPInfo,
  GetOEMCP, IsValidCodePage, MultiByteToWideChar, WideCharToMultiByte,
  CompareStringW, GetStringTypeW, LCMapStringW, GetLocaleInfoW,
  GetUserDefaultLCID, GetTimeZoneInformation, GetDateFormatW, GetTimeFormatW —
  every one imported by both real i386 entry), so the cycle took the roadmap
  owner BPTK-103's conversion half: one declared locale with the real 1252
  best-fit table and real UTF-8 conversion, byte-exact both directions with
  the required-size and insufficient-buffer contracts, real comparison, case
  mapping, CTYPE1 classification, a real SYSTEMTIME token formatter over the
  one guest clock, and sortkey/enumeration honestly refused. The double-byte
  fixture stays red — the declared environment has no double-byte code page
  yet.
- Proof: 23 new conformance case (133 total, all 96 served export covered);
  the euro code point (0x80 ↔ U+20AC) round-trips byte-exact through the 1252
  table; full suite 121 test, 0 failing.
- Real payload: coverage ledger 79 → **93 covered** of the real 356-symbol
  import surface (OpenTTD i386 serves 89 of 302 import, Plink i386 75 of 142).
  Reached stage of the two i386 entry stays honestly at `loaded`.

## 2026-09-05 — cycle 4

### Implemented: BPTK-010 slice 2 — module loading and the memory/time probe

- The unserved ledger ranked module loading next (LoadLibraryA, FreeLibrary,
  each imported by both real i386 entry), so the cycle extended the Win32 core
  HLE inside BPTK-010's own surface: LoadLibraryA/W/ExW over a declared
  known-DLL set with real refcount and a no-file-system refusal for anything
  else, FreeLibrary, IsBadReadPtr implemented the honest way (probe the range,
  any fault answers bad), Sleep as declared guest time only, GetThreadTimes
  from the one monotonic clock, and system DLL file names resolving to the
  declared system directory.
- Proof: 14 new conformance case (147 total, all 105 served export covered);
  full suite 121 test, 0 failing.
- Real payload: coverage ledger 93 → **100 covered** of the real 356-symbol
  import surface (OpenTTD i386 serves 96 of 302 import, Plink i386 79 of 142).
  Reached stage of the two i386 entry stays honestly at `loaded`.

## 2026-09-05 — cycle 5

### Implemented: synchronization, enumeration, and timer slice

- The unserved ledger after cycle 4 still ranked waits and events first, so
  the cycle took the parts that a declared single-thread world can serve
  honestly: a real event state machine (CreateEventW named and unnamed,
  SetEvent, ResetEvent, WaitForSingleObject/Ex where a finite wait advances
  the one guest clock and an infinite wait on a silent event is a structured
  deadlock stop), OpenProcess opening only the declared process,
  FindFirstFileExA/FindNextFileA enumerating the virtual drive with the real
  PATH_NOT_FOUND and no-more-files contract, IsValidLocale, and the winmm
  timer family (timeGetTime, timeBeginPeriod, timeEndPeriod, timeKillEvent)
  over the one monotonic time source. CreateThread stays refused — a served
  thread creation without a thread model would be a lie.
- Proof: 22 new conformance case (169 total, all 118 served export covered);
  full suite 121 test, 0 failing.
- Real payload: coverage ledger 100 → **113 covered** of the real 356-symbol
  import surface (OpenTTD i386 serves 109 of 302 import, Plink i386 86 of
  142). Reached stage of the two i386 entry stays honestly at `loaded`.

## 2026-09-05 — cycle 6

### Widened: BPTK-009 — the operand-size override (0x66)

- The remaining unserved families (threads, SEH, windows, audio, sockets) all
  need the models their item own, so the cycle took the other lever: the CPU
  subset. The probe now executes the operand-size override (0x66) — the
  prefix every real i386 binary uses constantly and which the probe refused
  outright before: 16-bit register push and pop adjust the stack by exactly
  two byte, 16-bit arithmetic and immediate forms set the 16-bit carry, zero,
  sign, and overflow flags exactly, the high word of the 32-bit register is
  preserved (the rule that must not be confused with the 64-bit zero-extend
  rule), and the rare 16-bit control forms (ret16, call16, jmp16, pushf16,
  popf16, r/m16 call and jump) stay structured unsupported rather than
  mis-executing.
- Proof: four runtime check through the real run surface (high-word
  preservation 0x12345678 with AX overwritten to 0x12341234, 16-bit carry-out
  wrapping 0xffff + 2 to 0x0001 with CF set, the exact two-byte stack
  adjustment captured mid-run through EDX, and the structured refusals); full
  suite 125 test, 0 failing. No real binary reaches `entry` yet — real CRT
  startup also needs SSE and the exception model — so the corpus reached
  stage and coverage are honestly unchanged this cycle; the advance is the
  widened measured instruction subset.
- One expected-value bug was mine, not the probe's: two assertions first
  encoded a carry propagation into the high word that the real architecture
  does not do; the probe had the architecture right.

### State after the commit

- Implemented count stays 40; the cycle widened BPTK-009. Passing stays 0 (no
  benchmark runner exists yet).
- Next highest-leverage target: the BPTK-009 instruction-subset widening
  (operand-size override first) toward a real binary reaching `entry`, since
  the remaining unserved families need the thread, exception, window, audio,
  and socket models their item own.
