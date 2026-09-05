# Win32 HLE lane log (lane/win32-hle)

Scope: Pillar 5 (Win32 HLE + runtime services) + BPTK-010. Converge every owned
runtime-service item to gate-green (implemented + active red contract). Owned:
lib/hle.mjs, lib/user.mjs, lib/gdi.mjs, lib/audio.mjs, lib/net.mjs,
lib/input.mjs, lib/storage.mjs, lib/clock.mjs.

Verifier: `npm run gate` exit 0. Passing stays 0 (no real benchmark passes yet).

## Remaining planned P5 items (from doc/roadmap-gold-standard.json)
- BPTK-096 3D/positional audio (XAudio2/EAX/DS3D) — lib/audio.mjs
- BPTK-097 full input (DirectInput/XInput/gamepad/touch/pointer-lock/rumble) — lib/input.mjs
- BPTK-098 storage & registry fidelity — lib/storage.mjs / lib/hle.mjs
- BPTK-099 networking (Winsock/DirectPlay→WebRTC/WebSocket) — lib/net.mjs
- BPTK-100 FMV sync & subtitles — lib/audio.mjs / lib/hle.mjs
- BPTK-101 Win32 breadth — lib/hle.mjs  **(in progress)**
- BPTK-102 installer/CD/virtual optical drive — lib/storage.mjs
- BPTK-104 frame-pacing / vblank scheduler — lib/clock.mjs
- BPTK-011 USER32 window/message/input — lib/user.mjs
- BPTK-012 GDI compatibility slice — lib/gdi.mjs

Note: the real corpus stage is not present in this worktree (no staged payload),
so `bptk corpus coverage` reports empty here; coverage deltas are measured on the
Windows corpus box, not re-measured in this lane. Local scoreboard = the
conformance suite (case-per-served-export) + served-export count + the test floor.

## Cycle 1 — BPTK-101 kernel32 breadth slice (implemented, red/active)
Added generic stdcall emulations in lib/hle.mjs:
- string family: lstrcmpA/W, lstrcmpiA/W (ordinal <0/0/>0), lstrcpyA/W,
  lstrcpynA, lstrcatA/W (return the destination pointer)
- interlocked atomics: InterlockedIncrement/Decrement (new value),
  InterlockedExchange/ExchangeAdd (prior value), InterlockedCompareExchange
  (store only on comparand match)
- MulDiv (round half away from zero; -1 on zero denominator / overflow)
- GetSystemInfo/GetNativeSystemInfo (declared single-processor SYSTEM_INFO)
- GetSystemTime/GetLocalTime (SYSTEMTIME from the one guest clock, UTC bias)
- SetErrorMode/GetErrorMode; OutputDebugStringA/W (no-observable-effect sink)

Served kernel32 export 107→130; total served 156→179. Every new export carries
a conformance case; added five memory-effect tests. Implemented count 43→44;
passing stays 0. Still red: ole32 COM marshaling, SxS activation context, and
msvbvm module slices are absent, and the real-corpus gap budget is unmeasured here.

Gate: exit 0.

## Cycle 2 — BPTK-098 registry fidelity slice (implemented, red/active)
Added generic advapi32 registry breadth over the bounded in-memory hive in
lib/hle.mjs: RegOpenKeyExA, RegCreateKeyExA/W (reporting REG_CREATED_NEW_KEY vs
REG_OPENED_EXISTING_KEY through the disposition pointer), RegQueryValueExW,
RegSetValueExW, RegDeleteValueA/W, RegDeleteKeyA/W (refusing a key that still
has subkeys with access-denied), and RegFlushKey. Served advapi32 export 6→16;
total served 179→189. Every new export carries a conformance case; added a
fidelity test proving disposition, byte-exact value round-trip, delete-then-
not-found, and the subkey-refusal rule. Implemented count 44→45; passing 0.
Still red: the copy-on-write overlay with byte-for-byte quota rollback and the
persistent OPFS bridge are not built, and the real-corpus path-alias fixture is
not staged here.

Gate: exit 0.

## Cycle 3 — BPTK-011 USER32 message loop, geometry, metrics (implemented, red/active)
Exposed the existing subsystem message queue as exports and added window
geometry in lib/user.mjs + registration in lib/hle.mjs: GetMessageW, PeekMessageW,
TranslateMessage, DispatchMessageW (MSG struct marshaled to/from guest memory),
GetClientRect, GetWindowRect, MoveWindow, AdjustWindowRect, and GetSystemMetrics
over one declared virtual-desktop profile. Served user32 export 14→23; total
189→198. Cases added to BOTH conformance suites (test/user.test.mjs subsystem +
core HLE); added an HLE-level marshaling test proving MSG/RECT round-trip through
guest memory. Implemented count 45→46; passing 0. Still red: the guest WndProc is
not yet invoked as real code (CPU core owns that; DefWindowProc fallback stands),
and the cursor/timer/browser-gesture and focus-recovery path of FIX-004 are absent.

Gate: exit 0.

## Cycle 4 — BPTK-012 GDI 2D compatibility slice (implemented, red/active)
Added generic 2D exports in lib/gdi.mjs + registration in lib/hle.mjs: FillRect
(RECT from guest memory), PatBlt (pattern-copy and black/white ops, refusing an
unrealized ternary op), GetDeviceCaps over one declared virtual-display profile,
and SetROP2/GetROP2 state. Served gdi32 export 22→27; total 198→203. Cases added
to BOTH conformance suites (test/gdi.test.mjs subsystem + core HLE); added a
pixel-effect test proving PatBlt fills with the brush, the ops paint their color,
caps report the declared display, and ROP2 round-trips. Implemented count 46→47;
passing 0. Still red: clip regions, real font metrics, DIB transfer, and the
browser present/invalidation path of FIX-005 are absent.

Gate: exit 0.

## Progress
Implemented 43→47 (BPTK-101, 098, 011, 012). Served HLE export surface 156→203.
Remaining owned planned items: BPTK-096 (3D audio), 097 (full input), 099
(networking bind), 100 (FMV), 102 (installer/optical), 104 (frame-pacing).
