# Lane W — bounded SDL subset toward a first frame

## Problem
The corpus x86-64 games bundle SDL and stall the moment their startup reaches
the SDL API through an IAT slot, because nothing served it. Measured before this
lane (`executeProbe64`, budget 10,000,000):

| game | bundles | stop | instr |
| --- | --- | --- | --- |
| Dwarf Fortress (corpus-006) | SDL 1.2 (`sdl.dll`) | `sdl.dll!SDL_CreateSemaphore` | 642 |
| Chocolate Doom (corpus-007) | SDL 2 (`sdl2.dll`) | `entry_return` (early CRT exit) | 186 |

## What was served
A new `lib/sdl.mjs` holds the SDL subsystem; `lib/hle.mjs` registers its export
rows (`sdlExportTable`) and attaches it as `guest.sdl`; `lib/exec64.mjs`
dispatches a reached SDL import through the existing generic Win64 marshal
(`serveImport64`); `lib/present.mjs` returns the SDL framebuffer as the display
surface. Every function behaves for real (the honesty rail):

- **Threading / sync**: `SDL_CreateSemaphore/SemWait/SemTryWait/SemPost/SemValue/
  DestroySemaphore` (a real counter that floors at zero), `SDL_CreateMutex/Lock/
  Unlock/Destroy` (a real recursive lock count), `SDL_Atomic{Set,Get,Add,CAS}` (a
  real read-modify-write of guest memory), `SDL_Create/DestroyCond` (SDL2).
- **Init / time**: `SDL_Init/InitSubSystem/QuitSubSystem/Quit/WasInit`,
  `SDL_GetTicks/Delay` (the one guest clock), `SDL_Get/SetError/ClearError`.
- **Video + surface (SDL1)**: `SDL_SetVideoMode/GetVideoSurface/Flip/UpdateRect`,
  `SDL_CreateRGBSurface/CreateRGBSurfaceFrom/FreeSurface/Lock/Unlock`,
  `SDL_FillRect/MapRGB/MapRGBA/GetRGBA/UpperBlit/SetColorKey/DisplayFormat(Alpha)/
  ConvertSurface`, and the WM/GL/info shims DF reaches.
- **Video + surface (SDL2)**: `SDL_CreateWindow/GetWindowSurface/UpdateWindowSurface`,
  `SDL_CreateRenderer/SetRenderDrawColor/RenderClear/RenderFillRect/RenderPresent`,
  `SDL_GetVersion`, window accessors.
- **Events**: `SDL_PollEvent/PeepEvents/PumpEvents/WaitEvent` return an empty
  input trace (no fabricated event); `SDL_GetMouseState/ModState/NumJoysticks`
  report no device.

The window/display surface is backed by a real ARGB8888 framebuffer in the HLE
arena. A fill or a blit writes real pixels; `guest.sdl.presentFramebuffer()`
converts them to RGBA and `lib/present.mjs` returns that as the display — an
undrawn framebuffer is honestly blank, never synthesized.

### Honest refusals
- `SDL_CreateThread` returns NULL and sets the SDL error: a single-threaded
  bounded probe cannot run a thread body, so it refuses rather than fake a
  running thread.
- `SDL_SemWait` on a zero counter cannot block a single thread; it returns
  success (the counter stays floored) as the one documented bounded
  approximation. The counter arithmetic is otherwise exact.
- `SDL_RWFromFile`/`SDL_SaveBMP_RW` fail (no game data is staged); asset bytes
  are never fabricated.

## Supporting fixes (in owned files, needed to reach past SDL)
1. **x64 pointer width in CRT block intrinsics** (`lib/hle.mjs`): `memset/memcpy/
   memmove/memcmp/memchr` truncated the destination/source with `>>> 0`. An
   x86-64 stack pointer lives above 4 GiB (`0x7ff0…`), so `memset(stackBuf,…)`
   faulted at the truncated low dword. Address operands now keep full width; the
   count/value operands stay 32-bit. `lib/sdl.mjs` applies the same rule to every
   pointer argument it marshals.
2. **BND branch prefix** (`lib/exec64.mjs`): MSVC decorates branches with the CET
   `0xf2` BND prefix (`bnd jnz`, `bnd call`, …) which the read-only lifter
   refuses. `decodeWithSegment` already strips one segment-override byte before
   the oracle; it now also strips a lone BND prefix when the following opcode is
   genuinely a control transfer (never when `0xf2` is a REPNZ/SSE prefix).
3. **CRT breadth past SDL** (`lib/hle.mjs`): the vcruntime telemetry no-ops
   (`__telemetry_main_{invoke,return}_trigger`), the ucrt standard-stream
   accessor `__acrt_iob_func`, and the stdio startup/format helpers
   (`freopen`, `setvbuf`, `setbuf`, `__stdio_common_vfprintf`,
   `__stdio_common_vsprintf(_s)`) the game reaches between SDL init and its own
   `main`.

## Result (after)

| game | stop | instr | note |
| --- | --- | --- | --- |
| Dwarf Fortress | `api-ms-win-crt-string-l1-1-0.dll!isspace` | 4,136,050 | past all 9 semaphore creations + full ucrt CRT init, now inside its own `main`; a CRT ctype/api-set breadth frontier, not SDL |
| Chocolate Doom | `entry_return` | 186 | unchanged — its CRT startup returns before `main`, so it never reaches SDL in the bounded probe |

DF advanced ~6,442× (642 → 4,136,050). Neither game created a window/surface or a
non-empty framebuffer in the live run: DF stops in CRT breadth before
`SDL_SetVideoMode`, and Chocolate Doom exits CRT startup before SDL. The SDL
video/surface/first-frame path is proven instead by `test/sdl.test.mjs`, whose
synthetic x64 image runs `SDL_SetVideoMode` + `SDL_FillRect` through
`executeProbe64` to a non-blank red framebuffer the present path returns.

`passing` stays 0 (a rendered frame is not proven playability). `corpus run`
holds 9 at `entry`. `npm run gate` exits 0 (743 conformance cases, 579 tests
pass / 1 pre-existing 7-Zip staging skip).
