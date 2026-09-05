# Lane Q log — jq i386 (corpus-010) to `entry`

## Mission
Serve the `msvcrt.dll` C runtime (plus jq's remaining `kernel32.dll` and
`shlwapi.dll` imports) for the i386 probe so jq (corpus-010) becomes
fully-served and the bounded probe executes it from `entry`.

## Cycle 1 — msvcrt/kernel32/shlwapi breadth

### What changed (lib/hle.mjs, test/hle.test.mjs)
- Registered every jq import the Win32 core HLE did not yet serve: 98 `msvcrt.dll`
  symbols, 15 `kernel32.dll` symbols, and `shlwapi.dll!PathIsRelativeA`.
- Real bounded behavior over the existing arena/heap/virtual-FS:
  - Heap: `malloc`/`calloc`/`realloc`/`free`/`_strdup` on the process default heap.
  - String/mem: `strlen`/`strcmp`/`strncmp`/`_strnicmp`/`strcpy`/`strncpy`/`strchr`/
    `strrchr`/`strspn`/`strstr`/`strerror`/`wcslen`/`wcstombs` (memcpy/memmove/
    memset/memcmp/memchr were already served).
  - ctype: `isalnum`/`isalpha`/`isspace`; numbers: `atoi`/`_ultoa`; `rand` (LCG).
  - stdio the tool calls: `fwrite`/`fputc`/`printf`/`fprintf`/`vfprintf`/`perror`
    route real bytes to the captured console or virtual drive; `_open`/`_write`/
    `_close`/`_fdopen`/`_wfopen`/`_fileno`/`_isatty`/`_get_osfhandle`/`_setmode`/
    `_fullpath`/`_stati64`/`_fstati64`; `fread`/`getc`/`fgets`/`feof`/`ferror`/
    `clearerr`/`fflush`/`fclose` bounded honestly (no input stream).
  - locale/time/errno: `setlocale`/`localeconv`/`___`-style data cells, `time`/
    `gmtime`/`localtime`/`_mkgmtime32`/`strftime`/`_tzset`, `_errno` cell.
  - CRT startup/teardown: `__wgetmainargs`/`__setusermatherr`/`_initterm`/`_cexit`/
    `_amsg_exit`/`_assert`/`exit`/`_onexit`/`_lock`/`_unlock`, and data exports
    `_iob`/`_environ`/`_tzname`/`__mb_cur_max`/`__winitenv` resolving to live cells.
  - kernel32 thread/semaphore breadth: affinity/priority/handle-info,
    `CreateSemaphoreA`/`ReleaseSemaphore` (counted), `WaitForMultipleObjects`,
    `AreFileApisANSI`, `IsDBCSLeadByteEx`, `DuplicateHandle`.
- Named structured refusals where a bounded integer probe genuinely cannot serve:
  - x87 double return (`acos`/`asin`/`atan`/`cosh`/`sinh`/`tan`/`tanh`/`log10`/
    `_hypot`/`_nextafter`/`_j0`/`_j1`/`_jn`/`_y0`/`_y1`/`_yn`) — no EAX carry.
  - guest comparator callback (`qsort`), spawned OS thread (`_beginthreadex`),
    non-local jump (`longjmp`).
- One conformance case per new (library, symbol) — coverage gate stays complete
  (575 cases pass). Behavioral unit tests prove the real memory side effects the
  oracle does not inspect (heap round-trip, string bytes, stdio capture, virtual
  drive write, gmtime decomposition, refusal shape, semaphore counting).

### Result
- jq i386 served-count: 170 of 170 imports served (was 56/170; msvcrt.dll 98,
  kernel32.dll 15, shlwapi.dll 1 newly served).
- Probe: `state=probe_executed`, `stop_reason=fetch_fault`, `instruction_count=294`,
  7 real HLE calls (InitializeCriticalSection, _initterm×2,
  SetUnhandledExceptionFilter, malloc, GetModuleHandleA, _onexit).
- `bin/bptk.mjs corpus run`: CORPUS-010 moves `loaded` → `entry`; other entries
  unchanged (reached: loaded 2, entry 9). Adding exports is monotonic, so no
  stage regression is possible.
- `npm run gate` exits 0; `passing` stays 0.

### Known bound (not owned by this lane)
The cdecl msvcrt calls over-clean the guest stack by their argument dword count:
the shared i386 dispatch in the read-only `lib/runtime.mjs` cleans the callee
frame (stdcall) while a cdecl caller also cleans it, so after the first CRT call
the stack pointer drifts and a later `ret` fetches an unmapped address — the
`fetch_fault` at 294 instructions. Each served function still reads its correct
arguments and performs real work; decoupling read-count from clean-count needs a
cdecl flag in the dispatch, which is outside this lane's file ownership.
