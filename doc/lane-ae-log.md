# Lane AE log — SDL2 video/render pipeline (Chocolate Doom's first frame)

## Mission
Serve the SDL2 video-init + render + palette pipeline so the real Chocolate Doom
(corpus-007, x86-64) loading the real Freedoom WAD draws its first frame through
`runImageBytes` / the bounded x86-64 interpreter.

## Cycle 1 — the payoff reached

### Starting stop
Base `053e9f4`. Chocolate Doom, driven with the Win32 core HLE wired (layout +
host-file store seeded with `freedoom1.wad` + `DOOMWADDIR` + `-iwad` command
line), ran 13,021,847 instructions of its own code into `I_InitGraphics` and
stopped at `import_present sdl2.dll!SDL_GetNumVideoDisplays` — the exact video
frontier. (Before the command-line/host-file wiring it exited at 584,030 with
"No IWAD file was found".)

### What was served (lib/sdl.mjs + lib/hle.mjs registration)
- Display query: `SDL_GetNumVideoDisplays/GetNumVideoDrivers/GetCurrentVideoDriver`,
  `GetCurrentDisplayMode/GetDesktopDisplayMode/GetDisplayMode/GetNumDisplayModes`,
  `GetDisplayBounds/GetDisplayUsableBounds/GetDisplayDPI` — one 1280x720 display.
- Renderer: `CreateRenderer` (already present) + `RenderSetLogicalSize`
  (resizes the framebuffer to the logical picture), `RenderSetIntegerScale`,
  `GetRendererInfo` (reports ACCELERATED|PRESENTVSYNC|TARGETTEXTURE),
  `GetRendererOutputSize`, `SetRenderTarget/GetRenderTarget`, `RenderCopy(Ex)`
  (nearest-neighbor scale into the current target), viewport/scale stubs.
- Texture: `CreateTexture/UpdateTexture/QueryTexture/DestroyTexture`,
  `LockTexture` (returns a real writable pointer into the texture store) /
  `UnlockTexture`, blend/color/alpha-mod stubs.
- Surface + palette: 8-bit indexed surfaces (with an attached SDL_Palette),
  `AllocPalette/FreePalette/SetPaletteColors/SetSurfacePalette`,
  `CreateRGBSurfaceWithFormat(From)`, `PixelFormatEnumToMasks`.
- Blit: `SDL_LowerBlit`/`SDL_BlitSurface` do the real 8-bit-index -> 32-bit-RGBA
  conversion through the source surface's palette, reading the live
  `surface->pixels` pointer from the guest struct (Doom rebinds its argbbuffer to
  the locked streaming texture each frame) and SDL2 (Sint32) rect fields.
- Window/input: `ShowWindow` and the fullscreen/grab/position/icon/title/mouse
  stubs the init/finish path calls.

`RenderPresent` publishes the renderer framebuffer as the primary framebuffer
`lib/present.mjs` returns; `runImageBytes` now threads `host_file` /
`environment` / `command_line` through so a browser host can supply the WAD.

### Result — the frame
Verified through the uncapped interpreter entry `runImage64` (the corpus safety
bound is 10M; Doom first presents its title at ~16.03M):
- `SDL_CreateWindow` reached: yes. `SDL_RenderPresent` reached: yes.
- Instruction count: 13.02M (I_InitGraphics frontier, before) — the first
  non-blank present lands at ~16,030,000; at a 20M verify budget the run reaches
  budget exhaustion having presented 11 frames.
- `runImageBytes`/`presentFramebuffer` returns a **non-blank 320x240 framebuffer,
  76,186 of 76,800 pixels painted, 178 distinct colors**, dominated by the
  Freedoom maroon/red palette (#680000, #5c0000, #440000, …) — the real
  Freedoom Phase 1 title screen Doom drew from its own 8-bit screen buffer
  through the WAD's PLAYPAL. An ASCII luminance preview shows the title
  lettering and central artwork (structured, not noise).

### Honesty
Every pixel is the guest's own: the 8-bit screen buffer Doom rendered, converted
through the PLAYPAL it loaded, uploaded to a streaming texture, copied to the
renderer framebuffer, and presented. Nothing is synthesized or hardcoded.
`passing` stays 0 — a rendered title screen is not proven playability.

### Gate + corpus
`npm run gate` exits 0 (612 pass, 1 skipped). `bptk corpus run` keeps 9 at
`entry` (Chocolate Doom included) — no regression; the corpus path does not wire
the HLE, so it holds the historical first-import frontier.
