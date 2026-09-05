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

## Cycle 5 — BPTK-099 ws2_32 Winsock lifecycle slice (implemented, red/active)
Bound the ws2_32 import surface in lib/hle.mjs to one offline-by-default mediated
Winsock (lib/net.mjs): WSAStartup (WSADATA marshaled), WSACleanup,
WSAGetLastError, socket/closesocket over the handle table, bind/connect
(sockaddr_in marshaled through the consent gate), send/recv, ioctlsocket FIONBIO,
and the pure htons/htonl/ntohs/ntohl and inet_addr helpers. Served ws2_32 export
0→15; total 203→218. Every export carries a conformance case; added a test
proving WSADATA marshaling, handle table, deny-by-default dial refusal (WSAEACCES),
and byte-exact helpers. Implemented count 47→48; passing 0. Still red: FIX-019
needs a consented allowlisted peer and the WebRTC/WebSocket transport binding.

Gate: exit 0.

## Cycle 6 — BPTK-096 3D positional-audio core (implemented, red/active)
Added the DS3D/X3DAudio positional math in lib/audio.mjs on the BPTK-014 mixer:
distanceAttenuation (inverse-distance rolloff), azimuthPan (left-handed right
axis from one listener + emitter), and compute3dSourceGain combining attenuation
with the constant-power pan into the mixer's left/right gain. No new HLE guest
import (library math); three tests prove the rolloff points, the left/right/
centered pan, and the combined gain. Implemented count 48→49; passing 0. Still
red: the EAX reverb send and the DirectSound3D/XAudio2 emitter-listener COM
binding are absent.

Gate: exit 0.

## Cycle 7 — BPTK-104 frame-pacing / vblank scheduler (implemented, red/active)
Added createFramePacer in lib/clock.mjs over the one monotonic clock: resolves a
frame ready at a guest time onto the next vblank boundary at the declared refresh
rate, counts presented frames, and reports the vblanks a stall skipped as dropped.
New test/clock.test.mjs (registered in validate.py); tests prove boundary sync,
presented/dropped counting on a stall, and host-independent cadence from the one
clock. Implemented count 49→50; passing 0. Still red: FIX-016 needs a live
browser frame loop (rAF + AudioWorklet clock) to measure jitter and the
yield-not-spin busy-wait.

Gate: exit 0.

## Cycle 8 — BPTK-102 virtual drive geometry / optical volume (implemented, red/active)
Added a declared drive profile in lib/hle.mjs: fixed C: (NTFS) and read-only
optical D: (CDFS, zero free) served through GetLogicalDrives, GetDriveTypeA/W,
GetVolumeInformationA/W, GetDiskFreeSpaceExA, and GetDiskFreeSpaceA. Served
kernel32 export 130→137; total 218→225. Every export carries a conformance case;
added a test proving drive presence, drive types, label/serial round-trip, and
zero free bytes on the optical volume. Implemented count 50→51; passing 0. Still
red: no ISO/CUE image is mounted (no hash-matching sector read or in-sync disc
audio).

Gate: exit 0.

## Cycle 9 — BPTK-097 XInput gamepad slice (implemented, red/active)
Added createGamepadSubsystem in lib/input.mjs (four disconnected-by-default slots
driven by injected browser Gamepad state, XInput packet-number-on-change, field
clamping, rumble) and bound xinput1_3.dll in lib/hle.mjs: XInputGetState,
XInputSetState, XInputGetCapabilities, XInputEnable marshaling XINPUT_STATE/
VIBRATION/CAPABILITIES and reporting ERROR_DEVICE_NOT_CONNECTED for empty/out-of-
range slots. Served xinput surface 0→4; total 225→229. Every export carries a
conformance case (default disconnected); a unit test proves the injected-state
byte-exact marshaling, packet-number semantics, capabilities/rumble, and
disconnect. Implemented count 51→52; passing 0. Still red: DirectInput
enumeration, pointer-lock/touch bridge, and the live browser Gamepad feed.

Gate: exit 0.

## Progress
Implemented 43→52 (BPTK-101, 098, 011, 012, 099, 096, 104, 102, 097). Served HLE
export 156→229. Remaining owned planned item: BPTK-100 (FMV sync & subtitles).
