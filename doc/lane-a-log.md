# Lane A log — widen the Win32 core HLE to reach the Plink entry stage

Mission: drive the real i386 freeware binary Plink (win32) to the `entry`
execution stage for the first time by serving every import the bounded probe
refuses. Success = `runPackage` returns `state: probe_executed`.

## Cycle 1 — serve all 53 unserved imports (BPTK-146)

Baseline: `probe_blocked` / `import_present`, 89 of 142 imports served, 53
unserved (kernel32 36, user32 9, advapi32 8), 0 instructions executed.

Served the full 53 honestly, each with real behaviour over the same bounded
guest state as its sibling and a matching conformance case (the coverage gate
requires one case per served export):

- kernel32 ANSI file surface: `CreateFileA`, `DeleteFileA`, `FindFirstFileA`,
  `FindClose`, `GetFileAttributesExA`, `LoadLibraryExA` — reuse the virtual
  drive and module table the wide siblings already own.
- kernel32 kernel objects: `CreateEventA`, `CreateMutexA` / `ReleaseMutex`
  (real ownership count), `CreateFileMappingA` / `MapViewOfFile` /
  `UnmapViewOfFile` (zero-filled or file-backed guest memory, flushed on
  unmap), `CreatePipe` (in-memory pipe pair), `LocalAlloc` / `LocalFree`
  (default process heap), `LocalFileTimeToFileTime`, `SetConsoleMode`,
  `SetHandleInformation`, `GetWindowsDirectoryA`, `GlobalMemoryStatus`,
  `GetProcessTimes`, `FormatMessageA`, `GetOverlappedResult`.
- kernel32 honest refusals (the confined single-thread probe genuinely cannot
  serve these, so each names the reason in its last error rather than faking
  success): `CreateThread` (ERROR_MAX_THRDS_REACHED), `CreateProcessA`
  (ERROR_ACCESS_DENIED — process is a denied capability), `CreateNamedPipeA` /
  `ConnectNamedPipe` / `WaitNamedPipeA` (no named-pipe namespace), the serial
  surface `GetCommState` / `SetCommState` / `SetCommTimeouts` / `SetCommBreak`
  / `ClearCommBreak` (no comm device), `EnumSystemLocalesW` (cannot re-enter a
  guest callback), `UnhandledExceptionFilter` (EXCEPTION_EXECUTE_HANDLER, no
  debugger), `RtlUnwind` (host-side chain unwind only).
- advapi32 SID and security descriptor, all self-contained byte structures over
  guest memory: `AllocateAndInitializeSid`, `CopySid`, `EqualSid`,
  `GetLengthSid`, `GetUserNameA`, `InitializeSecurityDescriptor`,
  `SetSecurityDescriptorDacl`, `SetSecurityDescriptorOwner`.
- user32 window/input/queue queries: `FindWindowA`, `GetCapture`,
  `GetClipboardOwner`, `GetForegroundWindow`, `GetQueueStatus`, `GetCursorPos`,
  `MsgWaitForMultipleObjects`, `PeekMessageA`, `SendMessageA` — the honest
  empty answer with no window and no host input device.

Result: **142 of 142 imports served, 0 unserved.** The bounded probe now
executes from the entry point:

```
state: probe_executed | stop: write_fault | executed: true | instr: 67
```

The probe runs the MSVC CRT `__security_init_cookie` prologue — 4 HLE calls:
`GetSystemTimeAsFileTime`, `GetCurrentThreadId`, `GetCurrentProcessId`,
`QueryPerformanceCounter` — then faults writing the computed cookie:

```
guest_exception_code c0000005 (access violation), fault_address 0, eip 0x44784e
```

This is a named NULL-write fault in the CPU/loader path (lib/runtime.mjs /
lib/i386.mjs, other lanes' territory), not an HLE gap: every import is served,
the imports the CRT calls at startup return correct values, and the store to a
null effective address is a decode/loader concern. The `entry` stage is reached
honestly for the first time.

Files touched (all lane-owned): `lib/hle.mjs`, `lib/user.mjs`,
`test/hle.test.mjs`, `test/user.test.mjs`. Conformance suite: 364/364 (core
HLE) and 32/32 (user32) with complete coverage. `npm run gate` exits 0
(439 tests pass).

Next gap: the null-write at eip 0x44784e — a CPU/loader lane must map or decode
the cookie store target so execution continues past the CRT security prologue.
