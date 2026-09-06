// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The bounded SDL subsystem (BPTK runtime v2, browser-first x86-64 lane W). A
// corpus x64 game (Dwarf Fortress bundles SDL 1.2 as sdl.dll; Chocolate Doom
// bundles SDL 2 as sdl2.dll) stalls the moment its startup reaches the SDL API
// through an IAT slot, because nothing served it. This file serves a bounded
// SDL subset toward the first rendered frame: the threading/sync primitives
// (semaphore, mutex, atomic) that a game creates before it opens a window, the
// tick clock, the init/quit lifecycle, and the video + surface path (SDL1
// SetVideoMode/Flip or SDL2 CreateWindow/CreateRenderer) backed by a real RGBA
// framebuffer the compositor (lib/present.mjs) presents.
//
// Every served function behaves for real, per the honesty rail: a semaphore is
// a real counter, a mutex is a real lock count, an atomic is a real
// read-modify-write of guest memory, and a surface is a real pixel buffer in
// guest memory that a blit or a fill actually writes — never a no-op that fakes
// a frame. What genuinely needs an OS resource this bounded probe cannot supply
// is refused honestly: SDL_CreateThread returns NULL with an SDL error rather
// than pretending a thread runs, because a single-threaded bounded probe cannot
// run the thread body. The one bounded approximation is that SDL_SemWait on a
// zero counter cannot block a single thread, so it returns success (documented
// at the call site); the counter arithmetic is otherwise exact.
//
// The subsystem is created per run by lib/hle.mjs (which owns the export
// registration and attaches this as guest.sdl); the export rows here delegate
// to guest.sdl so the shared HLE file stays a registration surface. Guest
// pointers arrive as unsigned numbers through the same bounded memory adapter
// the interpreter uses (lib/exec64.mjs createGuestMemoryAdapter), so an
// out-of-range access is the same structured fault as any guest access.

// SDL pixel-format enumerations the video path uses. The window/display surface
// is 32-bit ARGB8888 so the compositor reads it directly.
export const sdlPixelFormat = Object.freeze({
  ARGB8888: 0x16362004,
  INDEX8: 0x1c010001,
});

// The SDL2 event-type enumeration the scripted input trace delivers (SDL_events.h).
// SDL_QUIT ends a WaitEvent/PollEvent loop; SDL_KEYDOWN/SDL_KEYUP carry a keysym.
export const sdlEventType = Object.freeze({
  SDL_QUIT: 0x100,
  SDL_KEYDOWN: 0x300,
  SDL_KEYUP: 0x301,
  SDL_MOUSEMOTION: 0x400,
  SDL_MOUSEBUTTONDOWN: 0x401,
  SDL_MOUSEBUTTONUP: 0x402,
});

// Normalize one input-trace / live-input entry into the internal event record
// the queue stores and writeEvent marshals. Shared by loadInputTrace (a fixed
// pre-schedule) and appendInputEvent (a live, appendable injection) so both
// speak one vocabulary. `type` accepts the string aliases keydown/keyup/quit and
// mousemove/mousedown/mouseup, or a numeric SDL type; key events carry
// scancode/sym/mod, mouse events carry x/y (and button/rel). An unrecognized
// entry returns null (the caller drops it). `frame` gates delivery on a
// present-count schedule; a live injection passes frame 0 so it is due at once.
function normalizeInputEvent(entry) {
  if (entry === null || typeof entry !== "object") return null;
  const normalizeType = (t) => {
    if (typeof t === "number") return t >>> 0;
    if (t === "keydown") return sdlEventType.SDL_KEYDOWN;
    if (t === "keyup") return sdlEventType.SDL_KEYUP;
    if (t === "quit") return sdlEventType.SDL_QUIT;
    if (t === "mousemove" || t === "mousemotion") return sdlEventType.SDL_MOUSEMOTION;
    if (t === "mousedown" || t === "mousebuttondown") return sdlEventType.SDL_MOUSEBUTTONDOWN;
    if (t === "mouseup" || t === "mousebuttonup") return sdlEventType.SDL_MOUSEBUTTONUP;
    return 0;
  };
  const type = normalizeType(entry.type);
  if (type === 0) return null;
  const isKey = type === sdlEventType.SDL_KEYDOWN || type === sdlEventType.SDL_KEYUP;
  const isMouseButton = type === sdlEventType.SDL_MOUSEBUTTONDOWN || type === sdlEventType.SDL_MOUSEBUTTONUP;
  const isMouseMotion = type === sdlEventType.SDL_MOUSEMOTION;
  return {
    type,
    scancode: isKey ? (entry.scancode >>> 0) || 0 : 0,
    sym: isKey ? (entry.sym >>> 0) || 0 : 0,
    mod: isKey ? (entry.mod >>> 0) || 0 : 0,
    button: isMouseButton ? (entry.button >>> 0) || 0 : 0,
    x: (isMouseMotion || isMouseButton) ? (entry.x | 0) : 0,
    y: (isMouseMotion || isMouseButton) ? (entry.y | 0) : 0,
    xrel: isMouseMotion ? (entry.xrel | 0) : 0,
    yrel: isMouseMotion ? (entry.yrel | 0) : 0,
    state: (type === sdlEventType.SDL_KEYDOWN || type === sdlEventType.SDL_MOUSEBUTTONDOWN) ? 1 : 0, // SDL_PRESSED / SDL_RELEASED
    frame: Number.isInteger(entry.frame) && entry.frame > 0 ? entry.frame : 0,
  };
}

// SDL2 physical scancodes (SDL_scancode.h) a game's key translation reads.
// Chocolate Doom's TranslateKey switches on keysym.scancode, so these are the
// field that actually drives Doom's menu/gameplay response — the source of truth
// for a scripted keypress. Only the codes the input trace needs are named here.
export const sdlScancode = Object.freeze({
  RETURN: 40,
  ESCAPE: 41,
  BACKSPACE: 42,
  SPACE: 44,
  RIGHT: 79,
  LEFT: 80,
  DOWN: 81,
  UP: 82,
  Y: 28,
  N: 17,
  TAB: 43,
  A: 4, D: 7, E: 8, S: 22, W: 26,
  1: 30, 2: 31, 3: 32, 4: 33, 5: 34, 6: 35, 7: 36,
  LCTRL: 224, LSHIFT: 225, LALT: 226, RCTRL: 228, RSHIFT: 229, RALT: 230,
});

// SDL2 virtual keycodes (SDL_keycode.h) a game may read from keysym.sym. The
// arrow keys carry the SDLK_SCANCODE_MASK bit; the ASCII keys are their code.
export const sdlKeycode = Object.freeze({
  RETURN: 0x0d,
  ESCAPE: 0x1b,
  BACKSPACE: 0x08,
  SPACE: 0x20,
  RIGHT: 0x4000004f,
  LEFT: 0x40000050,
  DOWN: 0x40000051,
  UP: 0x40000052,
  Y: 0x79,
  N: 0x6e,
  TAB: 0x09,
  A: 0x61, D: 0x64, E: 0x65, S: 0x73, W: 0x77,
  1: 0x31, 2: 0x32, 3: 0x33, 4: 0x34, 5: 0x35, 6: 0x36, 7: 0x37,
  LCTRL: 0x400000e0, LSHIFT: 0x400000e1, LALT: 0x400000e2, RCTRL: 0x400000e4, RSHIFT: 0x400000e5, RALT: 0x400000e6,
});

// SDL_RENDERER flags a game reads from SDL_GetRendererInfo. The bounded software
// renderer reports ACCELERATED | PRESENTVSYNC but NOT TARGETTEXTURE, so a game
// (Chocolate Doom) that would create an intermediate render-target upscaled
// texture instead takes the direct RenderCopy(texture) path this file serves.
const SDL_RENDERER_SOFTWARE = 0x00000001;
const SDL_RENDERER_ACCELERATED = 0x00000002;
const SDL_RENDERER_PRESENTVSYNC = 0x00000004;
const SDL_RENDERER_TARGETTEXTURE = 0x00000008;
const SDL_TRUE = 1;

// SDL_MUTEX_TIMEDOUT: SDL_SemTryWait returns this when the counter is zero.
const SDL_MUTEX_TIMEDOUT = 1;

// Bounded video dimensions: a served window never exceeds this, so a framebuffer
// stays inside the HLE arena (32 MiB) regardless of what a game requests.
const maxVideoDimension = 4096;

// Count the trailing zero bit of a 32-bit channel mask (the channel shift), and
// the loss (8 minus the channel bit width) so a color component maps into the
// mask exactly as SDL's own SDL_MapRGB does.
function maskShift(mask) {
  if (mask === 0) return 0;
  let shift = 0;
  let m = mask >>> 0;
  while ((m & 1) === 0) { m >>>= 1; shift += 1; }
  return shift;
}
function maskLoss(mask) {
  let bit = 0;
  let m = (mask >>> 0);
  while (m !== 0) { bit += m & 1; m >>>= 1; }
  return 8 - bit;
}

// A pixel-format descriptor kept in JS so the pixel operations (map, blit, fill)
// never depend on the in-guest struct layout, which differs between SDL1 and
// SDL2. The masks are the source of truth; the guest struct is a projection.
function describeFormat(bitsPerPixel, rMask, gMask, bMask, aMask) {
  return {
    bits_per_pixel: bitsPerPixel,
    bytes_per_pixel: Math.max(1, Math.ceil(bitsPerPixel / 8)),
    r_mask: rMask >>> 0, g_mask: gMask >>> 0, b_mask: bMask >>> 0, a_mask: aMask >>> 0,
    r_shift: maskShift(rMask), g_shift: maskShift(gMask), b_shift: maskShift(bMask), a_shift: maskShift(aMask),
    r_loss: maskLoss(rMask), g_loss: maskLoss(gMask), b_loss: maskLoss(bMask), a_loss: maskLoss(aMask),
  };
}

// The canonical ARGB8888 format the display surface uses.
function argb8888() {
  return describeFormat(32, 0x00ff0000, 0x0000ff00, 0x000000ff, 0xff000000);
}

// An 8-bit paletted (indexed) format. A pixel is a 1-byte index into the
// surface's attached SDL_Palette; the RGB masks are zero because the color comes
// from the palette, not from bit fields. is_indexed drives the blit's palette
// conversion into a 32-bit destination.
function indexed8() {
  return { ...describeFormat(8, 0, 0, 0, 0), is_indexed: true };
}

// Choose the pixel format for an SDL_CreateRGBSurface(From) call. Depth 8 (with
// no channel masks) is an indexed surface; all-zero masks at a wider depth mean
// the caller wants the display's ARGB8888; explicit masks describe the format
// exactly.
function pickSurfaceFormat(depth, rMask, gMask, bMask, aMask) {
  if ((depth | 0) === 8 && (rMask | gMask | bMask | aMask) === 0) return indexed8();
  if ((rMask | gMask | bMask | aMask) === 0) return argb8888();
  return describeFormat(depth || 32, rMask, gMask, bMask, aMask);
}

// createSdlSubsystem({ memory, layout, allocate, clock }): the per-run SDL state.
// memory  — the bounded guest memory adapter (read/write Memory/Block).
// layout  — the HLE address layout (arena base/size) for the fixed struct region.
// allocate(sizeByte) — a bump allocation from the HLE arena (framebuffers).
// clock   — the one guest clock (SDL_GetTicks / SDL_Delay).
export function createSdlSubsystem(dependency) {
  const memory = dependency.memory;
  const layout = dependency.layout;
  const allocate = dependency.allocate;
  const clock = dependency.clock;

  // SDL struct records (SDL_Surface, SDL_PixelFormat) live in a fixed region
  // anchored at the top of the arena, below the CRT scratch pages (top -0x2000),
  // so their guest addresses are deterministic regardless of the arena bump
  // cursor — a conformance case can pin them exactly. Framebuffer pixel buffers
  // are large and bump-allocated from the arena proper.
  const structRegionTop = layout.arena_base + layout.arena_size_byte - 0x2000;
  const structRegionBase = layout.arena_base + layout.arena_size_byte - 0x10000;
  let structCursor = structRegionBase;
  function allocateStruct(sizeByte) {
    const size = (sizeByte + 15) & ~15;
    if (structCursor + size > structRegionTop) throw new Error(`The SDL struct region is exhausted at 0x${structCursor.toString(16)}`);
    const address = structCursor;
    structCursor += size;
    return address;
  }

  // A guest pointer argument keeps its full width. An x86-64 guest pointer to
  // the stack or TEB lives above 4 GiB (the interpreter maps the stack at
  // 0x7ff000000000), so truncating it to a dword would fault a legitimate
  // access; an in-image or in-arena pointer is already below 4 GiB, so this is
  // identity there. Only opaque handle map keys (all below 4 GiB) keep >>> 0.
  const addr = (value) => (value < 0 ? value >>> 0 : value);

  const writePtr = (address, value) => {
    memory.writeMemory(address, 4, value >>> 0);
    memory.writeMemory(address + 4, 4, Math.floor(value / 0x100000000) >>> 0);
  };

  let initFlag = 0;
  let errorText = "";
  let errorAddress = 0;
  let nextHandle = 0x53000000; // an opaque, clearly-non-arena handle space for SDL objects
  const semaphore = new Map();
  const mutex = new Map();
  const cond = new Map();
  const window = new Map();
  const renderer = new Map();
  const surface = new Map(); // struct address -> { addr, format_addr, w, h, pitch, pixels, format, owns_pixels, palette_addr }
  const texture = new Map(); // handle -> { w, h, pitch, pixels, format, access }
  const palette = new Map(); // palette struct address -> { ncolors, colors_addr, entry: [{r,g,b,a}, ...] }
  let primaryFramebuffer = null; // { width, height, pixels, pitch, format }
  let presentCount = 0;
  let videoInfoAddress = 0;
  let rendererNameAddress = 0;
  const drawColor = { r: 0, g: 0, b: 0, a: 0xff };

  // The scripted input trace (default empty — the honest no-user probe). Each
  // event is a normalized { type, scancode, sym, mod, state, frame } record; the
  // queue is delivered in order, each event gated by a present-count (frame)
  // schedule so a caller can script "press Enter after the title has drawn".
  // eventCursor is the index of the next undelivered event; delivered/pending
  // counters feed the introspection surface a test asserts against.
  let inputEvent = [];
  let eventCursor = 0;
  let eventDelivered = 0;

  // The bounded display the video-init path reports: one display at 1280x720,
  // 60 Hz, ARGB8888. A game reads this to size its window and pick a scale; the
  // values are the one deterministic desktop the bounded world presents.
  const displayMode = Object.freeze({ format: sdlPixelFormat.ARGB8888, width: 1280, height: 720, refresh_rate: 60 });

  function newHandle() {
    const handle = nextHandle;
    nextHandle += 0x10;
    return handle;
  }

  // Write the SDL_PixelFormat struct a game reads through surface->format.
  // variant 1 = SDL 1.2 layout (BitsPerPixel@8), variant 2 = SDL2 layout
  // (format enum@0, BitsPerPixel@16). The masks live at +20..+32 in both.
  function writePixelFormat(address, format, variant) {
    memory.writeBlock(address, Buffer.alloc(64));
    if (variant === 2) {
      memory.writeMemory(address + 0, 4, sdlPixelFormat.ARGB8888);
      memory.writeMemory(address + 16, 1, format.bits_per_pixel);
      memory.writeMemory(address + 17, 1, format.bytes_per_pixel);
    } else {
      memory.writeMemory(address + 8, 1, format.bits_per_pixel);
      memory.writeMemory(address + 9, 1, format.bytes_per_pixel);
      memory.writeMemory(address + 10, 1, format.r_loss);
      memory.writeMemory(address + 11, 1, format.g_loss);
      memory.writeMemory(address + 12, 1, format.b_loss);
      memory.writeMemory(address + 13, 1, format.a_loss);
      memory.writeMemory(address + 14, 1, format.r_shift);
      memory.writeMemory(address + 15, 1, format.g_shift);
      memory.writeMemory(address + 16, 1, format.b_shift);
      memory.writeMemory(address + 17, 1, format.a_shift);
    }
    memory.writeMemory(address + 20, 4, format.r_mask);
    memory.writeMemory(address + 24, 4, format.g_mask);
    memory.writeMemory(address + 28, 4, format.b_mask);
    memory.writeMemory(address + 32, 4, format.a_mask);
  }

  // Write the SDL_Surface struct. Both SDL1 and SDL2 place format@8, w@16, h@20,
  // pitch@24, pixels@32, so one writer serves both; the pitch high word is zero
  // for any bounded width, which is also the SDL1 Uint16-plus-padding layout.
  function writeSurfaceStruct(record, variant) {
    memory.writeBlock(record.addr, Buffer.alloc(96));
    memory.writeMemory(record.addr + 0, 4, 0); // flags
    writePtr(record.addr + 8, record.format_addr);
    memory.writeMemory(record.addr + 16, 4, record.w >>> 0);
    memory.writeMemory(record.addr + 20, 4, record.h >>> 0);
    memory.writeMemory(record.addr + 24, 4, record.pitch >>> 0);
    writePtr(record.addr + 32, record.pixels);
    writePixelFormat(record.format_addr, record.format, variant);
  }

  // Allocate a surface: the struct + its pixel format from the fixed region, the
  // pixel buffer from the arena (unless the caller supplied one, SDL1
  // CreateRGBSurfaceFrom). A width/height outside the bound is refused (NULL).
  function makeSurface(width, height, format, variant, existingPixels) {
    const w = width | 0;
    const h = height | 0;
    if (w <= 0 || h <= 0 || w > maxVideoDimension || h > maxVideoDimension) return 0;
    const pitch = w * format.bytes_per_pixel;
    const structAddr = allocateStruct(96);
    const formatAddr = allocateStruct(64);
    let pixels = existingPixels ?? 0;
    let ownsPixels = false;
    if (pixels === 0) {
      pixels = allocate(pitch * h);
      memory.writeBlock(pixels, Buffer.alloc(pitch * h));
      ownsPixels = true;
    }
    const record = { addr: structAddr, format_addr: formatAddr, w, h, pitch, pixels, format, owns_pixels: ownsPixels, palette_addr: 0, variant };
    surface.set(structAddr, record);
    writeSurfaceStruct(record, variant);
    // An 8-bit indexed surface carries an SDL_Palette its format points at
    // (SDL_PixelFormat.palette @ +8 on Win64). A game fills the palette through
    // surface->format->palette (SDL_SetPaletteColors) before it blits the
    // indexed pixels into a 32-bit surface — the real color conversion.
    if (format.is_indexed) {
      const paletteAddr = allocatePalette(256);
      record.palette_addr = paletteAddr;
      writePtr(record.format_addr + 8, paletteAddr);
    }
    return structAddr;
  }

  // Allocate an SDL_Palette (ncolors entries) in the fixed struct region and
  // register its JS entry table. SDL_Palette on Win64: ncolors@0, colors ptr@8,
  // version@16, refcount@20; each SDL_Color is 4 byte r,g,b,a. Entries default
  // to opaque black until a game sets them.
  function allocatePalette(ncolors) {
    const structAddr = allocateStruct(24);
    const colorsAddr = allocateStruct(ncolors * 4);
    memory.writeBlock(structAddr, Buffer.alloc(24));
    memory.writeBlock(colorsAddr, Buffer.alloc(ncolors * 4));
    memory.writeMemory(structAddr + 0, 4, ncolors >>> 0);
    writePtr(structAddr + 8, colorsAddr);
    memory.writeMemory(structAddr + 16, 4, 1); // version
    memory.writeMemory(structAddr + 20, 4, 1); // refcount
    const entry = new Array(ncolors);
    for (let i = 0; i < ncolors; i += 1) entry[i] = { r: 0, g: 0, b: 0, a: 0xff };
    palette.set(structAddr, { ncolors, colors_addr: colorsAddr, entry });
    return structAddr;
  }

  function mapColor(format, r, g, b, a) {
    return (
      (((r >> format.r_loss) << format.r_shift) & format.r_mask) |
      (((g >> format.g_loss) << format.g_shift) & format.g_mask) |
      (((b >> format.b_loss) << format.b_shift) & format.b_mask) |
      (((a >> format.a_loss) << format.a_shift) & format.a_mask)
    ) >>> 0;
  }

  function readRect(rectAddr) {
    // SDL_Rect: Sint16 x,y,w,h for SDL1; Sint32 for SDL2. We read 16-bit signed
    // fields (SDL1); SDL2 rects that fit 16 bits read identically. A game that
    // needs full 32-bit rects is out of the served bound.
    const base = addr(rectAddr);
    const s16 = (offset) => {
      const value = memory.readMemory(base + offset, 2);
      return value >= 0x8000 ? value - 0x10000 : value;
    };
    return { x: s16(0), y: s16(2), w: memory.readMemory(base + 4, 2), h: memory.readMemory(base + 6, 2) };
  }

  // An SDL2 SDL_Rect is four Sint32 fields (x, y, w, h). The render/texture path
  // uses full 32-bit rects (a 320x200 logical size overflows the 16-bit SDL1
  // rect readRect uses), so it reads them as signed dwords.
  function readRect32(rectAddr) {
    const base = addr(rectAddr);
    const s32 = (offset) => {
      const value = memory.readMemory(base + offset, 4) >>> 0;
      return value >= 0x80000000 ? value - 0x100000000 : value;
    };
    return { x: s32(0), y: s32(4), w: s32(8), h: s32(12) };
  }

  // --- the frame path, resolved once instead of per pixel ---------------------
  //
  // Every routine below this comment moves a whole RECTANGLE of pixels, and each
  // one used to do it through the scalar guest-memory accessor: one guest address
  // resolution and one Buffer read plus one Buffer write PER PIXEL. Measured on
  // Chocolate Doom at a 120,000,000-instruction budget that was the single largest
  // cost in the process — SDL_RenderCopy alone 33% of the whole run (228 frames,
  // each one a 320x200 texture scaled up to 960x600 and then back down to the
  // 320x240 window: 149 million pixels), the surface blit 3.6%, the render clear
  // 1.8%. None of it is guest work.
  //
  // A pixel rectangle is contiguous inside ONE mapped region, so the resolution can
  // be hoisted out of the loop entirely: `pixelView` resolves the whole plane once
  // and hands back a Uint32Array over the SAME bytes the scalar accessor would have
  // written, and the loops below index it directly. Anything that cannot be proven
  // — an adapter with no `spanView` (lib/runtime.mjs, whose undo log a raw view
  // would escape), a plane that straddles two regions, a pitch or a base that is
  // not dword-aligned — returns null, and every caller keeps its original
  // element-at-a-time path unchanged. So this is a pure hoist: the bytes written,
  // their values and their order are what they were.
  function pixelView(pixels, pitch, height) {
    if (typeof memory.spanView !== "function") return null;
    if (!Number.isSafeInteger(pixels) || (pitch & 3) !== 0 || pitch <= 0 || height <= 0) return null;
    const span = memory.spanView(pixels, pitch * height);
    if (span === null) return null;
    const start = span.buf.byteOffset + span.off;
    if ((start & 3) !== 0) return null;
    return { u32: new Uint32Array(span.buf.buffer, start, (pitch * height) >>> 2), pitch32: pitch >>> 2, start, end: start + pitch * height, store: span.buf.buffer };
  }

  // Two resolved planes may be the same bytes (a game compositing a texture onto
  // itself). The row-at-a-time loops below do not visit pixels in the pixel-at-a-time
  // order the scalar path does, so an overlap is refused rather than reordered.
  function planeOverlap(a, b) {
    return a.store === b.store && a.start < b.end && b.start < a.end;
  }

  // The nearest-neighbor rectangle copy SDL_RenderCopy performs, over resolved
  // planes. Returns false when either plane will not resolve (or the two are the
  // same bytes), and the caller keeps its per-pixel loop.
  //
  // Two hoists, on top of resolving the planes once. The source COLUMN for each
  // destination column does not depend on the row, so it is computed once for the
  // whole rectangle instead of once per pixel — that is one Math.floor and one
  // divide per destination pixel removed. And an UPSCALE in y sends the same source
  // row to several consecutive destination rows, which produces byte-identical
  // destination rows: the second and later ones are a contiguous copy of the row
  // just written rather than a second gather. A 3x vertical upscale therefore
  // gathers a third of the rows it used to.
  function copyScaled32(tex, target, src, dst) {
    const srcPlane = pixelView(tex.pixels, tex.pitch, tex.h);
    if (srcPlane === null) return false;
    const dstPlane = pixelView(target.pixels, target.pitch, target.h);
    if (dstPlane === null || planeOverlap(srcPlane, dstPlane)) return false;
    const srcColumn = new Int32Array(dst.w);
    const dstColumn = new Int32Array(dst.w);
    let count = 0;
    let runnable = true;
    for (let dx = 0; dx < dst.w; dx += 1) {
      const px = dst.x + dx;
      if (px < 0 || px >= target.w) continue;
      const sx = src.x + Math.floor((dx * src.w) / dst.w);
      if (sx < 0 || sx >= tex.w) continue;
      if (count > 0 && px !== dstColumn[count - 1] + 1) runnable = false;
      dstColumn[count] = px;
      srcColumn[count] = sx;
      count += 1;
    }
    if (count === 0) return true;
    const su = srcPlane.u32;
    const du = dstPlane.u32;
    const firstColumn = dstColumn[0];
    let lastSy = -1;
    let lastRow = -1;
    for (let dy = 0; dy < dst.h; dy += 1) {
      const py = dst.y + dy;
      if (py < 0 || py >= target.h) continue;
      const sy = src.y + Math.floor((dy * src.h) / dst.h);
      if (sy < 0 || sy >= tex.h) continue;
      const dstRow = py * dstPlane.pitch32;
      if (sy === lastSy && runnable) {
        du.copyWithin(dstRow + firstColumn, lastRow + firstColumn, lastRow + firstColumn + count);
      } else {
        const srcRow = sy * srcPlane.pitch32;
        for (let i = 0; i < count; i += 1) du[dstRow + dstColumn[i]] = su[srcRow + srcColumn[i]];
      }
      lastSy = sy;
      lastRow = dstRow;
    }
    return true;
  }

  function fillSurface(record, rect, color) {
    const left = Math.max(0, rect ? rect.x : 0);
    const top = Math.max(0, rect ? rect.y : 0);
    const right = Math.min(record.w, rect ? rect.x + rect.w : record.w);
    const bottom = Math.min(record.h, rect ? rect.y + rect.h : record.h);
    const bpp = record.format.bytes_per_pixel;
    // A 32-bit surface fills a row at a time over the resolved plane; every other
    // depth, and any plane that will not resolve, keeps the scalar loop.
    const plane = bpp === 4 ? pixelView(record.pixels, record.pitch, record.h) : null;
    if (plane !== null) {
      const value = color >>> 0;
      for (let y = top; y < bottom; y += 1) {
        const row = y * plane.pitch32;
        plane.u32.fill(value, row + left, row + right);
      }
      return;
    }
    for (let y = top; y < bottom; y += 1) {
      let offset = record.pixels + y * record.pitch + left * bpp;
      for (let x = left; x < right; x += 1) {
        memory.writeMemory(offset, bpp, color);
        offset += bpp;
      }
    }
  }

  // A straight per-pixel blit of the source rect into the destination at
  // (dstX,dstY), honoring the source color key (a keyed pixel is skipped so the
  // background shows through). Alpha blending is not modeled — the copy is exact
  // pixels, which is honest for a first frame; a game that relies on per-surface
  // alpha compositing gets an opaque copy, documented here.
  function blitSurface(src, srcRect, dst, dstX, dstY) {
    const sbpp = src.format.bytes_per_pixel;
    const dbpp = dst.format.bytes_per_pixel;
    const sx0 = srcRect ? Math.max(0, srcRect.x) : 0;
    const sy0 = srcRect ? Math.max(0, srcRect.y) : 0;
    const sw = srcRect ? Math.min(src.w - sx0, srcRect.w) : src.w;
    const sh = srcRect ? Math.min(src.h - sy0, srcRect.h) : src.h;
    // An 8-bit indexed source blitted into a non-indexed destination is the real
    // palette conversion: each 1-byte index selects an RGB triple from the
    // source surface's attached palette, mapped into the destination's channel
    // layout. This is exactly how SDL renders Doom's paletted screenbuffer into
    // the 32-bit argbbuffer — the destination pixels are the colors Doom drew.
    const converting = src.format.is_indexed && !dst.format.is_indexed;
    const paletteEntry = converting ? palette.get(src.palette_addr) : null;
    // The two shapes worth hoisting, and the two a game actually drives every
    // frame: an 8-bit indexed source palette-converted into a 32-bit destination
    // (Doom's screenbuffer into its argbbuffer) and a straight 32-bit copy. The
    // palette becomes a 256-entry lookup built ONCE per blit instead of a struct
    // walk and a mapColor per pixel; the destination plane resolves once. Every
    // other depth pair keeps the scalar loop below.
    if ((sbpp === 1 || sbpp === 4) && dbpp === 4 && sh > 0 && sw > 0) {
      const dstPlane = pixelView(dst.pixels, dst.pitch, dst.h);
      const srcPlane = sbpp === 4 ? pixelView(src.pixels, src.pitch, src.h) : null;
      const srcByte = sbpp === 1 && typeof memory.spanView === "function" && Number.isSafeInteger(src.pixels)
        ? memory.spanView(src.pixels, src.pitch * src.h) : null;
      const ready = dstPlane !== null && (sbpp === 1 ? srcByte !== null : srcPlane !== null);
      if (ready && (sbpp === 1 || !planeOverlap(srcPlane, dstPlane))) {
        // The destination columns, clipped once for the whole blit rather than
        // re-tested per row: the scalar loop skips a column outside the
        // destination, and skipping it here writes exactly the same pixels.
        const col0 = Math.max(0, -dstX);
        const col1 = Math.min(sw, dst.w - dstX);
        const key = src.color_key;
        let lookup = null;
        if (converting) {
          lookup = new Uint32Array(256);
          for (let i = 0; i < 256; i += 1) {
            const color = paletteEntry && paletteEntry.entry[i] ? paletteEntry.entry[i] : { r: 0, g: 0, b: 0, a: 0xff };
            lookup[i] = mapColor(dst.format, color.r, color.g, color.b, 0xff);
          }
        }
        const du = dstPlane.u32;
        for (let row = 0; row < sh; row += 1) {
          const dy = dstY + row;
          if (dy < 0 || dy >= dst.h) continue;
          const dstRow = dy * dstPlane.pitch32 + dstX;
          if (sbpp === 1) {
            const srcRow = srcByte.off + (sy0 + row) * src.pitch + sx0;
            const sb = srcByte.buf;
            for (let col = col0; col < col1; col += 1) {
              const pixel = sb[srcRow + col];
              if (key !== undefined && pixel === key) continue;
              du[dstRow + col] = converting ? lookup[pixel] : pixel;
            }
          } else {
            const srcRow = (sy0 + row) * srcPlane.pitch32 + sx0;
            const su = srcPlane.u32;
            for (let col = col0; col < col1; col += 1) {
              const pixel = su[srcRow + col];
              if (key !== undefined && pixel === key) continue;
              du[dstRow + col] = pixel;
            }
          }
        }
        return 0;
      }
    }
    for (let row = 0; row < sh; row += 1) {
      const dy = dstY + row;
      if (dy < 0 || dy >= dst.h) continue;
      for (let col = 0; col < sw; col += 1) {
        const dx = dstX + col;
        if (dx < 0 || dx >= dst.w) continue;
        const pixel = memory.readMemory(src.pixels + (sy0 + row) * src.pitch + (sx0 + col) * sbpp, sbpp);
        if (src.color_key !== undefined && pixel === src.color_key) continue;
        let value = pixel;
        if (converting) {
          const color = paletteEntry && paletteEntry.entry[pixel] ? paletteEntry.entry[pixel] : { r: 0, g: 0, b: 0, a: 0xff };
          value = mapColor(dst.format, color.r, color.g, color.b, 0xff);
        }
        memory.writeMemory(dst.pixels + dy * dst.pitch + dx * dbpp, dbpp, value);
      }
    }
    return 0;
  }

  // Read the live pixels pointer, dimensions, and pitch from the guest
  // SDL_Surface struct (pixels@+32, w@+16, h@+20, pitch@+24 in both SDL1 and
  // SDL2 layouts). A game may re-point surface->pixels between blits — Chocolate
  // Doom rebinds its argbbuffer to a locked streaming texture each frame — so
  // the blit must honor the current struct field, not a cached JS value. The
  // format (masks, palette) stays the JS record's, the source of truth.
  function refreshSurface(record) {
    const pixels = memory.readMemory(record.addr + 32, 4) + memory.readMemory(record.addr + 36, 4) * 0x100000000;
    const w = memory.readMemory(record.addr + 16, 4) >>> 0;
    const h = memory.readMemory(record.addr + 20, 4) >>> 0;
    const pitch = memory.readMemory(record.addr + 24, 4) >>> 0;
    return {
      addr: record.addr,
      format: record.format,
      palette_addr: record.palette_addr,
      color_key: record.color_key,
      pixels: pixels || record.pixels,
      w: w || record.w,
      h: h || record.h,
      pitch: pitch || record.pitch,
    };
  }

  function setPrimary(record) {
    primaryFramebuffer = { width: record.w, height: record.h, pixels: record.pixels, pitch: record.pitch, format: record.format };
  }

  function setError(text) {
    errorText = typeof text === "string" ? text : "";
    return 0xffffffff; // SDL_SetError returns -1
  }

  const api = {
    // --- lifecycle ---------------------------------------------------------
    init(flags) { initFlag |= flags >>> 0; errorText = ""; return 0; },
    initSubSystem(flags) { initFlag |= flags >>> 0; return 0; },
    quitSubSystem(flags) { initFlag &= ~(flags >>> 0); return 0; },
    quit() { initFlag = 0; return 0; },
    wasInit(flags) { return flags === 0 ? initFlag : (initFlag & flags); },
    setMainReady() { return 0; },

    // --- error -------------------------------------------------------------
    getError() {
      if (errorAddress === 0) errorAddress = allocateStruct(256);
      const bytes = Buffer.from(errorText.slice(0, 254) + "\0", "latin1");
      memory.writeBlock(errorAddress, bytes);
      return errorAddress;
    },
    setError(text) { return setError(text); },
    clearError() { errorText = ""; return 0; },

    // --- time --------------------------------------------------------------
    getTicks() { return clock.tickCount() >>> 0; },
    delay(ms) { clock.advanceVirtualMs(ms >>> 0); return 0; },

    // --- semaphore (real counter) -----------------------------------------
    createSemaphore(initialValue) {
      const handle = newHandle();
      semaphore.set(handle, { value: initialValue >>> 0 });
      return handle;
    },
    semWait(handle) {
      const sem = semaphore.get(handle >>> 0);
      if (sem === undefined) return setError("SDL_SemWait: invalid semaphore");
      // A single-threaded bounded probe cannot block on a zero counter, so a
      // wait on zero returns success (the counter floors at zero); a wait on a
      // positive counter decrements it — the real counting semantics.
      if (sem.value > 0) sem.value -= 1;
      return 0;
    },
    semTryWait(handle) {
      const sem = semaphore.get(handle >>> 0);
      if (sem === undefined) return setError("SDL_SemTryWait: invalid semaphore");
      if (sem.value === 0) return SDL_MUTEX_TIMEDOUT;
      sem.value -= 1;
      return 0;
    },
    semPost(handle) {
      const sem = semaphore.get(handle >>> 0);
      if (sem === undefined) return setError("SDL_SemPost: invalid semaphore");
      sem.value += 1;
      return 0;
    },
    semValue(handle) {
      const sem = semaphore.get(handle >>> 0);
      return sem === undefined ? 0 : sem.value >>> 0;
    },
    destroySemaphore(handle) { semaphore.delete(handle >>> 0); return 0; },

    // --- mutex (real lock count) ------------------------------------------
    createMutex() {
      const handle = newHandle();
      mutex.set(handle, { depth: 0 });
      return handle;
    },
    lockMutex(handle) {
      const m = mutex.get(handle >>> 0);
      if (m === undefined) return setError("SDL_LockMutex: invalid mutex");
      m.depth += 1; // recursive lock: a single thread always succeeds
      return 0;
    },
    unlockMutex(handle) {
      const m = mutex.get(handle >>> 0);
      if (m === undefined) return setError("SDL_UnlockMutex: invalid mutex");
      if (m.depth > 0) m.depth -= 1;
      return 0;
    },
    destroyMutex(handle) { mutex.delete(handle >>> 0); return 0; },

    // --- condition variable ------------------------------------------------
    createCond() { const handle = newHandle(); cond.set(handle, {}); return handle; },
    condSignal() { return 0; },
    condBroadcast() { return 0; },
    // A single-threaded probe has no other thread to signal a wait, so a
    // CondWait cannot block; it returns success (the caller holds the mutex).
    condWait() { return 0; },
    destroyCond(handle) { cond.delete(handle >>> 0); return 0; },

    // --- thread (honest refusal) ------------------------------------------
    // A bounded single-threaded probe cannot run a thread body, so rather than
    // fake a running thread it returns NULL and sets the SDL error. A game that
    // requires the thread to make progress will observe the failure honestly.
    createThread() { setError("SDL_CreateThread: a bounded probe cannot start an OS thread"); return 0; },
    waitThread() { return 0; },
    threadID() { return 1; },
    getThreadID() { return 1; },

    // --- atomic (real read-modify-write of guest memory) ------------------
    atomicSet(pointer, value) {
      const previous = memory.readMemory(addr(pointer), 4);
      memory.writeMemory(addr(pointer), 4, value >>> 0);
      return previous >>> 0;
    },
    atomicGet(pointer) { return memory.readMemory(addr(pointer), 4) >>> 0; },
    atomicAdd(pointer, value) {
      const previous = memory.readMemory(addr(pointer), 4);
      memory.writeMemory(addr(pointer), 4, (previous + (value | 0)) >>> 0);
      return previous >>> 0;
    },
    atomicCAS(pointer, oldValue, newValue) {
      const current = memory.readMemory(addr(pointer), 4) >>> 0;
      if (current !== (oldValue >>> 0)) return 0; // SDL_FALSE
      memory.writeMemory(addr(pointer), 4, newValue >>> 0);
      return 1; // SDL_TRUE
    },

    // --- SDL1 video (sdl.dll) ---------------------------------------------
    setVideoMode(width, height, bpp, flags) {
      const w = Math.min(Math.max(width | 0, 1), maxVideoDimension);
      const h = Math.min(Math.max(height | 0, 1), maxVideoDimension);
      const addr = makeSurface(w, h, argb8888(), 1, 0);
      if (addr === 0) return 0;
      const record = surface.get(addr);
      setPrimary(record);
      return addr;
    },
    getVideoSurface() {
      if (primaryFramebuffer === null) return 0;
      for (const [addr, record] of surface) {
        if (record.pixels === primaryFramebuffer.pixels) return addr;
      }
      return 0;
    },
    flip(surfaceAddr) { presentCount += 1; return 0; },
    updateRect() { presentCount += 1; return 0; },
    wmSetCaption() { return 0; },
    wmSetIcon() { return 0; },
    showCursor(toggle) { return toggle | 0; },
    enableUnicode(enable) { return enable | 0; },
    enableKeyRepeat() { return 0; },
    getAppState() { return 0x03; /* SDL_APPACTIVE | SDL_APPINPUTFOCUS */ },

    // --- SDL2 video (sdl2.dll) --------------------------------------------
    createWindow(titleAddr, x, y, width, height, flags) {
      const handle = newHandle();
      const w = Math.min(Math.max(width | 0, 1), maxVideoDimension);
      const h = Math.min(Math.max(height | 0, 1), maxVideoDimension);
      window.set(handle, { w, h, surface: 0, renderer: 0 });
      return handle;
    },
    destroyWindow(handle) { window.delete(handle >>> 0); return 0; },
    getWindowSurface(handle) {
      const win = window.get(handle >>> 0);
      if (win === undefined) return 0;
      if (win.surface !== 0) return win.surface;
      const addr = makeSurface(win.w, win.h, argb8888(), 2, 0);
      if (addr === 0) return 0;
      win.surface = addr;
      setPrimary(surface.get(addr));
      return addr;
    },
    updateWindowSurface(handle) { presentCount += 1; return 0; },
    updateWindowSurfaceRects() { presentCount += 1; return 0; },
    getWindowSize(handle, wPtr, hPtr) {
      const win = window.get(handle >>> 0);
      if (win === undefined) return 0;
      if (wPtr !== 0) memory.writeMemory(addr(wPtr), 4, win.w >>> 0);
      if (hPtr !== 0) memory.writeMemory(addr(hPtr), 4, win.h >>> 0);
      return 0;
    },
    getWindowFlags() { return 0; },
    getWindowID() { return 1; },
    setWindowTitle() { return 0; },
    setWindowSize() { return 0; },
    createRenderer(windowHandle, index, flags) {
      const win = window.get(windowHandle >>> 0);
      const handle = newHandle();
      const w = win ? win.w : 640;
      const h = win ? win.h : 480;
      const pixels = allocate(w * h * 4);
      memory.writeBlock(pixels, Buffer.alloc(w * h * 4));
      renderer.set(handle, { window: windowHandle >>> 0, w, h, pixels, pitch: w * 4, format: argb8888(), logical_w: w, logical_h: h, output_w: w, output_h: h, target: 0 });
      if (win) win.renderer = handle;
      setPrimary({ w, h, pixels, pitch: w * 4, format: argb8888() });
      return handle;
    },
    destroyRenderer(handle) { renderer.delete(handle >>> 0); return 0; },
    // SDL_RenderSetLogicalSize(renderer, w, h): a game (Chocolate Doom) sets the
    // logical resolution (SCREENWIDTH x SCREENHEIGHT) that RenderCopy maps its
    // texture into. The bounded renderer resizes its framebuffer to the logical
    // size, so the presented frame is exactly the game's logical picture — the
    // real Doom screen — rather than an arbitrary window scale.
    renderSetLogicalSize(handle, width, height) {
      const rend = renderer.get(handle >>> 0);
      if (rend === undefined) return setError("SDL_RenderSetLogicalSize: invalid renderer");
      const w = Math.min(Math.max(width | 0, 1), maxVideoDimension);
      const h = Math.min(Math.max(height | 0, 1), maxVideoDimension);
      rend.logical_w = w;
      rend.logical_h = h;
      rend.w = w;
      rend.h = h;
      rend.pitch = w * 4;
      rend.pixels = allocate(w * h * 4);
      memory.writeBlock(rend.pixels, Buffer.alloc(w * h * 4));
      setPrimary({ w, h, pixels: rend.pixels, pitch: rend.pitch, format: rend.format });
      return 0;
    },
    renderSetIntegerScale() { return 0; },
    getRendererOutputSize(handle, wPtr, hPtr) {
      const rend = renderer.get(handle >>> 0);
      if (rend === undefined) return setError("SDL_GetRendererOutputSize: invalid renderer");
      if (wPtr !== 0) memory.writeMemory(addr(wPtr), 4, rend.output_w >>> 0);
      if (hPtr !== 0) memory.writeMemory(addr(hPtr), 4, rend.output_h >>> 0);
      return 0;
    },
    // SDL_GetRendererInfo(renderer, info): fill SDL_RendererInfo. The bounded
    // software renderer reports ACCELERATED | PRESENTVSYNC but NOT
    // TARGETTEXTURE, one ARGB8888 texture format, and a 4096 max texture — so a
    // game takes the direct RenderCopy path. SDL_RendererInfo: name ptr@0,
    // flags@8, num_texture_formats@12, texture_formats[16]@16, max_w@80, max_h@84.
    getRendererInfo(handle, infoAddr) {
      const rend = renderer.get(handle >>> 0);
      if (rend === undefined) return setError("SDL_GetRendererInfo: invalid renderer");
      if (infoAddr === 0) return 0;
      const base = addr(infoAddr);
      memory.writeBlock(base, Buffer.alloc(88));
      if (rendererNameAddress === 0) {
        rendererNameAddress = allocateStruct(16);
        memory.writeBlock(rendererNameAddress, Buffer.from("bptk\0", "latin1"));
      }
      writePtr(base + 0, rendererNameAddress);
      memory.writeMemory(base + 8, 4, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC | SDL_RENDERER_TARGETTEXTURE);
      memory.writeMemory(base + 12, 4, 1); // num_texture_formats
      memory.writeMemory(base + 16, 4, sdlPixelFormat.ARGB8888);
      memory.writeMemory(base + 80, 4, maxVideoDimension);
      memory.writeMemory(base + 84, 4, maxVideoDimension);
      return 0;
    },
    setRenderDrawColor(handle, r, g, b, a) {
      drawColor.r = r & 0xff; drawColor.g = g & 0xff; drawColor.b = b & 0xff; drawColor.a = a & 0xff;
      return 0;
    },
    // The current render destination: the bound target texture (SDL_SetRenderTarget)
    // or, by default, the renderer's own framebuffer. Every draw (clear, copy)
    // writes here, so a game's render-to-texture upscale path composites for real.
    renderTargetOf(rend) {
      if (rend.target !== 0) {
        const tex = texture.get(rend.target);
        if (tex !== undefined) return { pixels: tex.pixels, pitch: tex.pitch, w: tex.w, h: tex.h, format: argb8888() };
      }
      return { pixels: rend.pixels, pitch: rend.pitch, w: rend.w, h: rend.h, format: rend.format };
    },
    setRenderTarget(rendererHandle, textureHandle) {
      const rend = renderer.get(rendererHandle >>> 0);
      if (rend === undefined) return setError("SDL_SetRenderTarget: invalid renderer");
      rend.target = textureHandle >>> 0;
      return 0;
    },
    getRenderTarget(rendererHandle) {
      const rend = renderer.get(rendererHandle >>> 0);
      return rend === undefined ? 0 : rend.target >>> 0;
    },
    renderClear(handle) {
      const rend = renderer.get(handle >>> 0);
      if (rend === undefined) return setError("SDL_RenderClear: invalid renderer");
      const color = mapColor(rend.format, drawColor.r, drawColor.g, drawColor.b, drawColor.a);
      fillSurface(api.renderTargetOf(rend), null, color);
      return 0;
    },
    renderFillRect(handle, rectAddr) {
      const rend = renderer.get(handle >>> 0);
      if (rend === undefined) return setError("SDL_RenderFillRect: invalid renderer");
      const color = mapColor(rend.format, drawColor.r, drawColor.g, drawColor.b, drawColor.a);
      const record = { pixels: rend.pixels, pitch: rend.pitch, w: rend.w, h: rend.h, format: rend.format };
      const rect = rectAddr === 0 ? null : {
        x: memory.readMemory(addr(rectAddr), 4) | 0, y: memory.readMemory(addr(rectAddr) + 4, 4) | 0,
        w: memory.readMemory(addr(rectAddr) + 8, 4) | 0, h: memory.readMemory(addr(rectAddr) + 12, 4) | 0,
      };
      fillSurface(record, rect, color);
      return 0;
    },
    // SDL_RenderCopy(renderer, texture, srcrect, dstrect): copy the texture's
    // pixels into the renderer's framebuffer, nearest-neighbor scaled from the
    // (clipped) source rect to the destination rect (the whole framebuffer when
    // dstrect is NULL). This is the real composite: the texture holds the frame
    // a game uploaded (Doom's palette-converted screen), and after this call the
    // renderer framebuffer holds exactly those pixels at the presented size.
    renderCopy(handle, textureHandle, srcRectAddr, dstRectAddr) {
      const rend = renderer.get(handle >>> 0);
      const tex = texture.get(textureHandle >>> 0);
      if (rend === undefined || tex === undefined) return setError("SDL_RenderCopy: invalid renderer or texture");
      const target = api.renderTargetOf(rend);
      const src = srcRectAddr === 0 ? { x: 0, y: 0, w: tex.w, h: tex.h } : readRect32(srcRectAddr);
      const dst = dstRectAddr === 0 ? { x: 0, y: 0, w: target.w, h: target.h } : readRect32(dstRectAddr);
      if (dst.w <= 0 || dst.h <= 0 || src.w <= 0 || src.h <= 0) return 0;
      if (copyScaled32(tex, target, src, dst)) return 0;
      for (let dy = 0; dy < dst.h; dy += 1) {
        const py = dst.y + dy;
        if (py < 0 || py >= target.h) continue;
        const sy = src.y + Math.floor((dy * src.h) / dst.h);
        if (sy < 0 || sy >= tex.h) continue;
        for (let dx = 0; dx < dst.w; dx += 1) {
          const px = dst.x + dx;
          if (px < 0 || px >= target.w) continue;
          const sx = src.x + Math.floor((dx * src.w) / dst.w);
          if (sx < 0 || sx >= tex.w) continue;
          const pixel = memory.readMemory(tex.pixels + sy * tex.pitch + sx * 4, 4) >>> 0;
          memory.writeMemory(target.pixels + py * target.pitch + px * 4, 4, pixel);
        }
      }
      return 0;
    },
    renderPresent(handle) {
      const rend = renderer.get(handle >>> 0);
      if (rend !== undefined) setPrimary({ w: rend.w, h: rend.h, pixels: rend.pixels, pitch: rend.pitch, format: rend.format });
      presentCount += 1;
      return 0;
    },

    // --- display (SDL2) ----------------------------------------------------
    getNumVideoDisplays() { return 1; },
    getNumVideoDrivers() { return 1; },
    getCurrentVideoDriver() {
      if (rendererNameAddress === 0) { rendererNameAddress = allocateStruct(16); memory.writeBlock(rendererNameAddress, Buffer.from("bptk\0", "latin1")); }
      return rendererNameAddress;
    },
    getDisplayMode(displayIndex, modeAddr) { return api.writeDisplayMode(modeAddr); },
    getCurrentDisplayMode(displayIndex, modeAddr) { return api.writeDisplayMode(modeAddr); },
    getDesktopDisplayMode(displayIndex, modeAddr) { return api.writeDisplayMode(modeAddr); },
    getNumDisplayModes() { return 1; },
    writeDisplayMode(modeAddr) {
      if (modeAddr === 0) return 0;
      const base = addr(modeAddr);
      memory.writeMemory(base + 0, 4, displayMode.format);
      memory.writeMemory(base + 4, 4, displayMode.width);
      memory.writeMemory(base + 8, 4, displayMode.height);
      memory.writeMemory(base + 12, 4, displayMode.refresh_rate);
      writePtr(base + 16, 0); // driverdata
      return 0;
    },
    getDisplayBounds(displayIndex, rectAddr) {
      if (rectAddr !== 0) {
        const base = addr(rectAddr);
        memory.writeMemory(base + 0, 4, 0);
        memory.writeMemory(base + 4, 4, 0);
        memory.writeMemory(base + 8, 4, displayMode.width);
        memory.writeMemory(base + 12, 4, displayMode.height);
      }
      return 0;
    },
    getDisplayDPI(displayIndex, ddpiPtr, hdpiPtr, vdpiPtr) {
      const write = (ptr) => { if (ptr !== 0) memory.writeMemory(addr(ptr), 4, 0x42700000); }; // 96.0f
      write(ddpiPtr); write(hdpiPtr); write(vdpiPtr);
      return 0;
    },

    // --- texture (SDL2) ----------------------------------------------------
    createTexture(rendererHandle, format, access, width, height) {
      const w = Math.min(Math.max(width | 0, 1), maxVideoDimension);
      const h = Math.min(Math.max(height | 0, 1), maxVideoDimension);
      const handle = newHandle();
      const pixels = allocate(w * h * 4);
      memory.writeBlock(pixels, Buffer.alloc(w * h * 4));
      texture.set(handle, { w, h, pitch: w * 4, pixels, format: (format >>> 0) || sdlPixelFormat.ARGB8888, access: access >>> 0 });
      return handle;
    },
    // SDL_UpdateTexture(texture, rect, pixels, pitch): copy the game's uploaded
    // pixels (the argbbuffer it blitted its palette-converted frame into) row by
    // row into the texture store, honoring the source pitch. NULL rect = whole.
    updateTexture(handle, rectAddr, pixelsPtr, pitch) {
      const tex = texture.get(handle >>> 0);
      if (tex === undefined) return setError("SDL_UpdateTexture: invalid texture");
      const src = addr(pixelsPtr);
      const srcPitch = pitch >>> 0;
      const rect = rectAddr === 0 ? { x: 0, y: 0, w: tex.w, h: tex.h } : readRect32(rectAddr);
      const x0 = Math.max(0, rect.x);
      const y0 = Math.max(0, rect.y);
      const x1 = Math.min(tex.w, rect.x + rect.w);
      const y1 = Math.min(tex.h, rect.y + rect.h);
      for (let y = y0; y < y1; y += 1) {
        const rowSrc = src + (y - rect.y) * srcPitch + Math.max(0, -rect.x) * 4;
        const rowLen = (x1 - x0) * 4;
        if (rowLen > 0) memory.writeBlock(tex.pixels + y * tex.pitch + x0 * 4, memory.readBlock(rowSrc, rowLen));
      }
      return 0;
    },
    queryTexture(handle, formatPtr, accessPtr, wPtr, hPtr) {
      const tex = texture.get(handle >>> 0);
      if (tex === undefined) return setError("SDL_QueryTexture: invalid texture");
      if (formatPtr !== 0) memory.writeMemory(addr(formatPtr), 4, tex.format >>> 0);
      if (accessPtr !== 0) memory.writeMemory(addr(accessPtr), 4, tex.access >>> 0);
      if (wPtr !== 0) memory.writeMemory(addr(wPtr), 4, tex.w >>> 0);
      if (hPtr !== 0) memory.writeMemory(addr(hPtr), 4, tex.h >>> 0);
      return 0;
    },
    // SDL_LockTexture(texture, rect, pixels, pitch): hand back a writable pointer
    // into the texture's real pixel store (offset to the rect origin) and its
    // pitch. The game writes its frame directly into this guest buffer; the
    // matching SDL_UnlockTexture needs no upload because the bytes are already in
    // place. This is the exact streaming-texture path — real guest pixels.
    lockTexture(handle, rectAddr, pixelsPtrPtr, pitchPtr) {
      const tex = texture.get(handle >>> 0);
      if (tex === undefined) return setError("SDL_LockTexture: invalid texture");
      let offset = 0;
      if (rectAddr !== 0) { const rect = readRect32(rectAddr); offset = rect.y * tex.pitch + rect.x * 4; }
      if (pixelsPtrPtr !== 0) writePtr(addr(pixelsPtrPtr), tex.pixels + offset);
      if (pitchPtr !== 0) memory.writeMemory(addr(pitchPtr), 4, tex.pitch >>> 0);
      return 0;
    },
    unlockTexture() { return 0; },
    setTextureBlendMode() { return 0; },
    setTextureColorMod() { return 0; },
    setTextureAlphaMod() { return 0; },
    destroyTexture(handle) { texture.delete(handle >>> 0); return 0; },

    // --- palette (SDL2) ----------------------------------------------------
    allocPalette(ncolors) {
      const n = Math.min(Math.max(ncolors | 0, 1), 256);
      return allocatePalette(n);
    },
    freePalette(paletteAddr) { palette.delete(paletteAddr >>> 0); return 0; },
    // SDL_SetPaletteColors(palette, colors, firstcolor, ncolors): store the RGB
    // triples a game supplies (Doom's PLAYPAL) into the palette, both in the JS
    // entry table the blit reads and in the guest colors array. This is the
    // source of truth for the 8-bit -> 32-bit color conversion.
    setPaletteColors(paletteAddr, colorsAddr, firstColor, ncolors) {
      const record = palette.get(paletteAddr >>> 0);
      if (record === undefined) return setError("SDL_SetPaletteColors: invalid palette");
      const first = firstColor | 0;
      const count = ncolors | 0;
      const source = addr(colorsAddr);
      for (let i = 0; i < count; i += 1) {
        const index = first + i;
        if (index < 0 || index >= record.ncolors) continue;
        const r = memory.readMemory(source + i * 4 + 0, 1);
        const g = memory.readMemory(source + i * 4 + 1, 1);
        const b = memory.readMemory(source + i * 4 + 2, 1);
        const a = memory.readMemory(source + i * 4 + 3, 1);
        record.entry[index] = { r, g, b, a };
        memory.writeMemory(record.colors_addr + index * 4 + 0, 1, r);
        memory.writeMemory(record.colors_addr + index * 4 + 1, 1, g);
        memory.writeMemory(record.colors_addr + index * 4 + 2, 1, b);
        memory.writeMemory(record.colors_addr + index * 4 + 3, 1, a);
      }
      return 0;
    },
    setSurfacePalette(surfaceAddr, paletteAddr) {
      const record = surface.get(surfaceAddr >>> 0);
      if (record === undefined) return setError("SDL_SetSurfacePalette: invalid surface");
      record.palette_addr = paletteAddr >>> 0;
      writePtr(record.format_addr + 8, paletteAddr >>> 0);
      return 0;
    },

    // SDL_PixelFormatEnumToMasks(format, bpp, Rmask, Gmask, Bmask, Amask): the
    // helper a game (Chocolate Doom's argbbuffer setup) uses to turn a format
    // enum into the depth + channel masks it then feeds SDL_CreateRGBSurface.
    // The bounded world serves ARGB8888 exactly and returns SDL_TRUE.
    pixelFormatEnumToMasks(format, bppPtr, rPtr, gPtr, bPtr, aPtr) {
      const fmt = argb8888();
      if (bppPtr !== 0) memory.writeMemory(addr(bppPtr), 4, fmt.bits_per_pixel);
      if (rPtr !== 0) memory.writeMemory(addr(rPtr), 4, fmt.r_mask);
      if (gPtr !== 0) memory.writeMemory(addr(gPtr), 4, fmt.g_mask);
      if (bPtr !== 0) memory.writeMemory(addr(bPtr), 4, fmt.b_mask);
      if (aPtr !== 0) memory.writeMemory(addr(aPtr), 4, fmt.a_mask);
      return SDL_TRUE;
    },

    // --- window (SDL2, added) ---------------------------------------------
    showWindow() { return 0; },
    hideWindow() { return 0; },
    raiseWindow() { return 0; },
    setWindowFullscreen() { return 0; },
    setWindowGrab() { return 0; },
    setWindowMinimumSize() { return 0; },
    setWindowResizable() { return 0; },
    setWindowPosition() { return 0; },
    getWindowPixelFormat() { return sdlPixelFormat.ARGB8888; },
    setRelativeMouseMode() { return 0; },
    getRelativeMouseState(xPtr, yPtr) {
      if (xPtr !== 0) memory.writeMemory(addr(xPtr), 4, 0);
      if (yPtr !== 0) memory.writeMemory(addr(yPtr), 4, 0);
      return 0;
    },
    warpMouseInWindow() { return 0; },
    getWindowFromID() { return 0; },
    lowerBlit(srcAddr, srcRectAddr, dstAddr, dstRectAddr) {
      return api.upperBlit(srcAddr, srcRectAddr, dstAddr, dstRectAddr);
    },

    getVersion(versionAddr) {
      if (versionAddr !== 0) {
        memory.writeMemory(addr(versionAddr), 1, 2);
        memory.writeMemory(addr(versionAddr) + 1, 1, 0);
        memory.writeMemory(addr(versionAddr) + 2, 1, 22);
      }
      return 0;
    },

    // --- surfaces (both) ---------------------------------------------------
    createRGBSurface(flags, width, height, depth, rMask, gMask, bMask, aMask, variant) {
      const format = pickSurfaceFormat(depth, rMask, gMask, bMask, aMask);
      return makeSurface(width, height, format, variant ?? 1, 0);
    },
    createRGBSurfaceFrom(pixels, width, height, depth, pitch, rMask, gMask, bMask, aMask, variant) {
      const format = pickSurfaceFormat(depth, rMask, gMask, bMask, aMask);
      return makeSurface(width, height, format, variant ?? 1, addr(pixels));
    },
    // SDL_CreateRGBSurfaceWithFormat(flags, w, h, depth, format_enum): the modern
    // creation call. ARGB8888 -> the display format; an 8-bit index format ->
    // the indexed format with an attached palette. Any other enum falls back to
    // ARGB8888 (the one 32-bit format the bounded compositor reads).
    createRGBSurfaceWithFormat(flags, width, height, depth, formatEnum, variant) {
      const format = (formatEnum >>> 0) === sdlPixelFormat.INDEX8 || (depth === 8 && (formatEnum >>> 0) === 0)
        ? indexed8()
        : argb8888();
      return makeSurface(width, height, format, variant ?? 2, 0);
    },
    createRGBSurfaceWithFormatFrom(pixels, width, height, depth, pitch, formatEnum, variant) {
      const format = (formatEnum >>> 0) === sdlPixelFormat.INDEX8
        ? indexed8()
        : argb8888();
      return makeSurface(width, height, format, variant ?? 2, addr(pixels));
    },
    freeSurface(surfaceAddr) { surface.delete(surfaceAddr >>> 0); return 0; },
    lockSurface(surfaceAddr) { return surface.has(surfaceAddr >>> 0) ? 0 : 0xffffffff; },
    unlockSurface() { return 0; },
    fillRect(surfaceAddr, rectAddr, color) {
      const record = surface.get(surfaceAddr >>> 0);
      if (record === undefined) return 0xffffffff;
      fillSurface(record, rectAddr === 0 ? null : readRect(rectAddr), color >>> 0);
      return 0;
    },
    mapRGB(formatAddr, r, g, b) {
      const record = formatRecordFor(formatAddr);
      return mapColor(record, r & 0xff, g & 0xff, b & 0xff, 0xff);
    },
    mapRGBA(formatAddr, r, g, b, a) {
      const record = formatRecordFor(formatAddr);
      return mapColor(record, r & 0xff, g & 0xff, b & 0xff, a & 0xff);
    },
    getRGBA(pixel, formatAddr, rPtr, gPtr, bPtr, aPtr) {
      const fmt = formatRecordFor(formatAddr);
      const extract = (mask, shift, loss) => {
        const raw = (pixel & mask) >>> shift;
        const value = (raw << loss) & 0xff;
        return value | (loss > 0 ? (value >> (8 - loss)) : 0);
      };
      if (rPtr !== 0) memory.writeMemory(addr(rPtr), 1, extract(fmt.r_mask, fmt.r_shift, fmt.r_loss));
      if (gPtr !== 0) memory.writeMemory(addr(gPtr), 1, extract(fmt.g_mask, fmt.g_shift, fmt.g_loss));
      if (bPtr !== 0) memory.writeMemory(addr(bPtr), 1, extract(fmt.b_mask, fmt.b_shift, fmt.b_loss));
      if (aPtr !== 0) memory.writeMemory(addr(aPtr), 1, fmt.a_mask === 0 ? 0xff : extract(fmt.a_mask, fmt.a_shift, fmt.a_loss));
      return 0;
    },
    upperBlit(srcAddr, srcRectAddr, dstAddr, dstRectAddr) {
      const srcRecord = surface.get(srcAddr >>> 0);
      const dstRecord = surface.get(dstAddr >>> 0);
      if (srcRecord === undefined || dstRecord === undefined) return 0xffffffff;
      // A rect's field width follows the surface's SDL version: SDL2 (variant 2)
      // uses Sint32 fields, SDL1 (variant 1) Sint16. Reading a 320x200 SDL2 rect
      // with the 16-bit layout would misread w/h as 0 and blit nothing.
      const readRectFor = (record) => (record.variant === 2 ? readRect32 : readRect);
      const srcRect = srcRectAddr === 0 ? null : readRectFor(srcRecord)(srcRectAddr);
      let dstX = 0;
      let dstY = 0;
      if (dstRectAddr !== 0) { const r = readRectFor(dstRecord)(dstRectAddr); dstX = r.x; dstY = r.y; }
      // The blit honors the live struct fields (pixels may have been re-pointed).
      return blitSurface(refreshSurface(srcRecord), srcRect, refreshSurface(dstRecord), dstX, dstY);
    },
    setColorKey(surfaceAddr, flag, key) {
      const record = surface.get(surfaceAddr >>> 0);
      if (record === undefined) return 0xffffffff;
      if ((flag >>> 0) === 0) delete record.color_key;
      else record.color_key = key >>> 0;
      return 0;
    },
    setAlpha() { return 0; },
    displayFormat(surfaceAddr) {
      // Convert to the display format: a served copy of the same 32-bit ARGB
      // surface (already the display format), so return a fresh surface handle
      // carrying a copy of the pixels — a real allocation, not an alias.
      const record = surface.get(surfaceAddr >>> 0);
      if (record === undefined) return 0;
      const addr = makeSurface(record.w, record.h, argb8888(), 1, 0);
      if (addr === 0) return 0;
      const copy = surface.get(addr);
      memory.writeBlock(copy.pixels, memory.readBlock(record.pixels, record.pitch * record.h));
      return addr;
    },
    convertSurface(surfaceAddr) { return api.displayFormat(surfaceAddr); },

    // --- events (scripted deterministic trace) ----------------------------
    // loadInputTrace(trace): install a scripted input sequence the event API
    // delivers. Each entry is { type, scancode, sym, mod, frame } — type is
    // "keydown"/"keyup"/"quit" (or the numeric SDL type), scancode/sym/mod are
    // the SDL2 keysym fields, and frame is the present-count on/after which the
    // event becomes deliverable (default 0). The trace is normalized and kept in
    // its given order (stable-sorted by frame) so a caller can script, e.g.,
    // "press Escape after the title has drawn, then Down, then Enter". An empty
    // or absent trace leaves the honest no-user empty queue — no regression.
    loadInputTrace(trace) {
      inputEvent = [];
      eventCursor = 0;
      eventDelivered = 0;
      if (!Array.isArray(trace)) return 0;
      const decorated = [];
      let ordinal = 0;
      for (const entry of trace) {
        const record = normalizeInputEvent(entry);
        if (record === null) continue;
        decorated.push({ record, ordinal: ordinal++ });
      }
      // A stable sort by frame keeps same-frame events in authored order, so a
      // keydown always precedes its keyup within one frame's drain.
      decorated.sort((a, b) => (a.record.frame - b.record.frame) || (a.ordinal - b.ordinal));
      inputEvent = decorated.map((d) => d.record);
      return inputEvent.length;
    },

    // appendInputEvent(event | [event, ...]): inject LIVE input into the queue
    // BETWEEN frames — the interactive counterpart to loadInputTrace's fixed
    // pre-schedule. Each event is normalized by the same vocabulary, forced to
    // frame 0 (due at once, whatever the present count), and APPENDED after any
    // events already queued, so the guest's own next poll/peek drain delivers it
    // in FIFO order. Unlike loadInputTrace this does NOT reset the queue or the
    // delivered/pending counters, so a session accumulates live keypresses across
    // steps. Returns the number of events accepted.
    appendInputEvent(event) {
      const list = Array.isArray(event) ? event : [event];
      let accepted = 0;
      for (const entry of list) {
        const record = normalizeInputEvent(entry);
        if (record === null) continue;
        record.frame = 0; // live: deliverable on the next poll regardless of schedule
        inputEvent.push(record);
        accepted += 1;
      }
      return accepted;
    },

    // Marshal one normalized event into the guest SDL_Event union at eventAddr in
    // the real SDL2 layout: the common header (type@0, timestamp@4), and for a
    // key event the SDL_KeyboardEvent body (windowID@8, state@12, repeat@13,
    // keysym.scancode@16, keysym.sym@20, keysym.mod@24). The struct is zeroed
    // first (SDL_Event is a 56-byte union) so unused fields read as zero.
    writeEvent(eventAddr, record) {
      if (eventAddr === 0) return;
      const base = addr(eventAddr);
      memory.writeBlock(base, Buffer.alloc(56));
      memory.writeMemory(base + 0, 4, record.type >>> 0);
      memory.writeMemory(base + 4, 4, clock.tickCount() >>> 0); // timestamp
      if (record.type === sdlEventType.SDL_KEYDOWN || record.type === sdlEventType.SDL_KEYUP) {
        memory.writeMemory(base + 8, 4, 1); // windowID
        memory.writeMemory(base + 12, 1, record.state & 0xff); // state (PRESSED/RELEASED)
        memory.writeMemory(base + 13, 1, 0); // repeat
        memory.writeMemory(base + 16, 4, record.scancode >>> 0); // keysym.scancode
        memory.writeMemory(base + 20, 4, record.sym >>> 0); // keysym.sym
        memory.writeMemory(base + 24, 2, record.mod & 0xffff); // keysym.mod
      } else if (record.type === sdlEventType.SDL_MOUSEMOTION) {
        // SDL_MouseMotionEvent: windowID@8, which@12, state@16, x@20, y@24,
        // xrel@28, yrel@32 (SDL2 layout).
        memory.writeMemory(base + 8, 4, 1); // windowID
        memory.writeMemory(base + 16, 4, 0); // button state bitmask (no button held)
        memory.writeMemory(base + 20, 4, record.x >>> 0);
        memory.writeMemory(base + 24, 4, record.y >>> 0);
        memory.writeMemory(base + 28, 4, record.xrel >>> 0);
        memory.writeMemory(base + 32, 4, record.yrel >>> 0);
      } else if (record.type === sdlEventType.SDL_MOUSEBUTTONDOWN || record.type === sdlEventType.SDL_MOUSEBUTTONUP) {
        // SDL_MouseButtonEvent: windowID@8, which@12, button@16(u8), state@17(u8),
        // clicks@18(u8), x@20, y@24 (SDL2 layout).
        memory.writeMemory(base + 8, 4, 1); // windowID
        memory.writeMemory(base + 16, 1, record.button & 0xff);
        memory.writeMemory(base + 17, 1, record.state & 0xff);
        memory.writeMemory(base + 18, 1, 1); // clicks
        memory.writeMemory(base + 20, 4, record.x >>> 0);
        memory.writeMemory(base + 24, 4, record.y >>> 0);
      }
    },

    // The next event whose frame schedule has arrived (frame <= presentCount),
    // or null when the queue is drained or the head is still scheduled for a
    // later frame. Pending events past the schedule stay queued, so a per-frame
    // poll drain delivers exactly the events due this frame, then empties.
    nextDueEvent() {
      if (eventCursor >= inputEvent.length) return null;
      const head = inputEvent[eventCursor];
      if (head.frame > presentCount) return null;
      eventCursor += 1;
      eventDelivered += 1;
      return head;
    },

    // SDL_PollEvent(event): deliver the next due scripted event (returns 1) or
    // report the empty queue (returns 0, zeroing the event type). With no trace
    // installed this is the honest empty input trace, never a synthesized event.
    pollEvent(eventAddr) {
      const record = api.nextDueEvent();
      if (record === null) {
        if (eventAddr !== 0) memory.writeMemory(addr(eventAddr), 4, 0);
        return 0;
      }
      api.writeEvent(eventAddr, record);
      return 1;
    },
    // SDL_PeepEvents(events, numevents, action, minType, maxType). A game rarely
    // reaches this on the Doom path (it polls), so the bounded form serves the
    // GET/PEEK actions from the scripted queue within [minType,maxType] and
    // returns the count copied; ADD/other actions report zero.
    peepEvents(eventsAddr, numEvents, action, minType, maxType) {
      const SDL_PEEKEVENT = 1;
      const SDL_GETEVENT = 2;
      if (action !== SDL_PEEKEVENT && action !== SDL_GETEVENT) return 0;
      const cap = Math.max(0, numEvents | 0);
      let copied = 0;
      let cursor = eventCursor;
      while (copied < cap && cursor < inputEvent.length) {
        const record = inputEvent[cursor];
        if (record.frame > presentCount) break;
        if (record.type < (minType >>> 0) || record.type > (maxType >>> 0)) { cursor += 1; continue; }
        api.writeEvent(addr(eventsAddr) + copied * 56, record);
        copied += 1;
        cursor += 1;
        if (action === SDL_GETEVENT) { eventCursor = cursor; eventDelivered += 1; }
      }
      return copied;
    },
    pumpEvents() { return 0; }, // the scripted queue needs no OS pump
    // SDL_WaitEvent(event): a single-threaded probe cannot block, so it delivers
    // the next scripted event if one remains (ignoring the frame gate, since a
    // wait means the game has nothing else to draw) and returns 1; an empty
    // queue reports 0 so a loop keyed on WaitEvent ends rather than spinning.
    waitEvent(eventAddr) {
      if (eventCursor >= inputEvent.length) {
        if (eventAddr !== 0) memory.writeMemory(addr(eventAddr), 4, 0);
        return 0;
      }
      const record = inputEvent[eventCursor];
      eventCursor += 1;
      eventDelivered += 1;
      api.writeEvent(eventAddr, record);
      return 1;
    },

    // --- environment / string helpers (SDL's own libc shims) --------------
    // The bounded probe has an empty environment, so SDL_getenv reports every
    // variable as unset (NULL) rather than inventing a value.
    getenv() { return 0; },
    setenv() { return 0; },
    strlcpy(dstPtr, srcPtr, size) {
      const cap = (size >>> 0);
      const dst = addr(dstPtr);
      const src = addr(srcPtr);
      let length = 0;
      // Measure the source length (C strlcpy returns it) and copy up to cap-1.
      for (let i = 0; ; i += 1) {
        const byte = memory.readMemory(src + i, 1);
        if (byte === 0) { length = i; break; }
        length = i + 1;
        if (cap > 0 && i < cap - 1) memory.writeMemory(dst + i, 1, byte);
      }
      if (cap > 0) memory.writeMemory(dst + Math.min(length, cap - 1), 1, 0);
      return length;
    },
    strlcat(dstPtr, srcPtr, size) {
      const cap = (size >>> 0);
      const dst = addr(dstPtr);
      const src = addr(srcPtr);
      let dstLen = 0;
      while (dstLen < cap && memory.readMemory(dst + dstLen, 1) !== 0) dstLen += 1;
      let srcLen = 0;
      while (memory.readMemory(src + srcLen, 1) !== 0) srcLen += 1;
      let out = dstLen;
      for (let i = 0; out < cap - 1; i += 1) {
        const byte = memory.readMemory(src + i, 1);
        if (byte === 0) break;
        memory.writeMemory(dst + out, 1, byte);
        out += 1;
      }
      if (cap > 0) memory.writeMemory(dst + Math.min(out, cap - 1), 1, 0);
      return dstLen + srcLen;
    },
    setModuleHandle() { return 0; },

    // --- SDL1 GL + video info ---------------------------------------------
    getVideoInfo() {
      if (videoInfoAddress === 0) {
        videoInfoAddress = allocateStruct(32);
        memory.writeBlock(videoInfoAddress, Buffer.alloc(32));
        memory.writeMemory(videoInfoAddress + 24, 4, 1280); // current_w — the reported desktop width
        memory.writeMemory(videoInfoAddress + 28, 4, 720);  // current_h — the reported desktop height
      }
      return videoInfoAddress;
    },
    glSetAttribute() { return 0; },
    glGetAttribute(attr, valuePtr) { if (valuePtr !== 0) memory.writeMemory(addr(valuePtr), 4, 0); return 0; },
    glSwapBuffers() { presentCount += 1; return 0; },
    // The sandbox stages no game data files, so opening a data file honestly
    // fails (NULL); the probe never fabricates asset bytes it does not have.
    rwFromFile() { return 0; },
    saveBmpRw() { return 0xffffffff; },

    // --- input state (no device) ------------------------------------------
    getMouseState(xPtr, yPtr) {
      if (xPtr !== 0) memory.writeMemory(addr(xPtr), 4, 0);
      if (yPtr !== 0) memory.writeMemory(addr(yPtr), 4, 0);
      return 0;
    },
    getModState() { return 0; },
    numJoysticks() { return 0; },
    showSimpleMessageBox() { return 0; },

    // --- introspection for the present path -------------------------------
    // The live framebuffer the compositor reads: null when the game created no
    // video surface, else an RGBA snapshot converted from the guest ARGB buffer.
    // is_blank records whether the game actually drew (a non-blank framebuffer
    // is the first-frame milestone); the pixels are exactly what the guest wrote.
    presentFramebuffer() {
      if (primaryFramebuffer === null) return null;
      const { width, height, pixels, pitch } = primaryFramebuffer;
      const rgba = new Uint8Array(width * height * 4);
      let blank = true;
      for (let y = 0; y < height; y += 1) {
        for (let x = 0; x < width; x += 1) {
          const argb = memory.readMemory(pixels + y * pitch + x * 4, 4) >>> 0;
          const out = (y * width + x) * 4;
          rgba[out + 0] = (argb >>> 16) & 0xff; // R
          rgba[out + 1] = (argb >>> 8) & 0xff;  // G
          rgba[out + 2] = argb & 0xff;          // B
          rgba[out + 3] = 0xff;                 // opaque for display
          if ((argb & 0x00ffffff) !== 0) blank = false;
        }
      }
      return { width, height, rgba, is_blank: blank, present_count: presentCount };
    },
    get present_count() { return presentCount; },
    get has_video() { return primaryFramebuffer !== null; },
    // Input-trace introspection for the verify path: how many scripted events the
    // guest actually consumed, and how many remain queued. A test asserts the
    // guest drove its own input drain (delivered > 0), proving the changed frame
    // is the game reacting to injected events, not a forced screen.
    get input_delivered() { return eventDelivered; },
    get input_pending() { return Math.max(0, inputEvent.length - eventCursor); },
    get inputStat() { return { loaded: inputEvent.length, delivered: eventDelivered, pending: Math.max(0, inputEvent.length - eventCursor) }; },
  };

  function formatRecordFor(formatAddr) {
    // A game passes surface->format; find the surface whose format struct sits at
    // this address so the JS masks (the source of truth) drive the map. An
    // unknown format address falls back to the display ARGB format.
    for (const record of surface.values()) {
      if (record.format_addr === (formatAddr >>> 0)) return record.format;
    }
    return argb8888();
  }

  return api;
}

// The SDL export rows lib/hle.mjs registers. Each row names the library
// (sdl.dll for SDL 1.2, sdl2.dll for SDL 2), the symbol, the Win64 argument
// count the marshal reads, and an emulate closure over (guest, argument) that
// delegates to guest.sdl. The threading/sync/atomic/init/time/surface/event
// rows are shared verbatim under both libraries (the symbols are identical
// across SDL versions); the video rows differ by version.
export function buildSdlExportTable() {
  const table = [];
  const define = (library, symbol, argumentCount, emulate) => {
    table.push(Object.freeze({ library, symbol, argument_count: argumentCount, emulate }));
  };

  // Rows common to SDL 1.2 (sdl.dll) and SDL 2 (sdl2.dll): the same symbol and
  // behavior in both. `variant` is baked per library so surfaces carry the right
  // in-guest struct layout.
  function defineShared(library, variant) {
    define(library, "SDL_Init", 1, (guest, a) => guest.sdl.init(a[0]));
    define(library, "SDL_InitSubSystem", 1, (guest, a) => guest.sdl.initSubSystem(a[0]));
    define(library, "SDL_QuitSubSystem", 1, (guest, a) => guest.sdl.quitSubSystem(a[0]));
    define(library, "SDL_Quit", 0, (guest) => guest.sdl.quit());
    define(library, "SDL_WasInit", 1, (guest, a) => guest.sdl.wasInit(a[0]));
    define(library, "SDL_GetError", 0, (guest) => guest.sdl.getError());
    define(library, "SDL_SetError", 1, (guest, a) => guest.sdl.setError(guest.readAnsiString(a[0])));
    define(library, "SDL_ClearError", 0, (guest) => guest.sdl.clearError());
    define(library, "SDL_GetTicks", 0, (guest) => guest.sdl.getTicks());
    define(library, "SDL_Delay", 1, (guest, a) => guest.sdl.delay(a[0]));

    define(library, "SDL_CreateSemaphore", 1, (guest, a) => guest.sdl.createSemaphore(a[0]));
    define(library, "SDL_SemWait", 1, (guest, a) => guest.sdl.semWait(a[0]));
    define(library, "SDL_SemTryWait", 1, (guest, a) => guest.sdl.semTryWait(a[0]));
    define(library, "SDL_SemPost", 1, (guest, a) => guest.sdl.semPost(a[0]));
    define(library, "SDL_SemValue", 1, (guest, a) => guest.sdl.semValue(a[0]));
    define(library, "SDL_DestroySemaphore", 1, (guest, a) => guest.sdl.destroySemaphore(a[0]));

    define(library, "SDL_CreateMutex", 0, (guest) => guest.sdl.createMutex());
    define(library, "SDL_LockMutex", 1, (guest, a) => guest.sdl.lockMutex(a[0]));
    define(library, "SDL_UnlockMutex", 1, (guest, a) => guest.sdl.unlockMutex(a[0]));
    define(library, "SDL_DestroyMutex", 1, (guest, a) => guest.sdl.destroyMutex(a[0]));

    define(library, "SDL_CreateThread", 3, (guest) => guest.sdl.createThread());
    define(library, "SDL_WaitThread", 2, (guest) => guest.sdl.waitThread());

    define(library, "SDL_AtomicSet", 2, (guest, a) => guest.sdl.atomicSet(a[0], a[1]));
    define(library, "SDL_AtomicGet", 1, (guest, a) => guest.sdl.atomicGet(a[0]));
    define(library, "SDL_AtomicAdd", 2, (guest, a) => guest.sdl.atomicAdd(a[0], a[1]));
    define(library, "SDL_AtomicCAS", 3, (guest, a) => guest.sdl.atomicCAS(a[0], a[1], a[2]));

    define(library, "SDL_CreateRGBSurface", 8, (guest, a) => guest.sdl.createRGBSurface(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], variant));
    define(library, "SDL_CreateRGBSurfaceFrom", 9, (guest, a) => guest.sdl.createRGBSurfaceFrom(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], variant));
    define(library, "SDL_FreeSurface", 1, (guest, a) => guest.sdl.freeSurface(a[0]));
    define(library, "SDL_LockSurface", 1, (guest, a) => guest.sdl.lockSurface(a[0]));
    define(library, "SDL_UnlockSurface", 1, (guest, a) => guest.sdl.unlockSurface(a[0]));
    define(library, "SDL_FillRect", 3, (guest, a) => guest.sdl.fillRect(a[0], a[1], a[2]));
    define(library, "SDL_MapRGB", 4, (guest, a) => guest.sdl.mapRGB(a[0], a[1], a[2], a[3]));
    define(library, "SDL_MapRGBA", 5, (guest, a) => guest.sdl.mapRGBA(a[0], a[1], a[2], a[3], a[4]));
    define(library, "SDL_GetRGBA", 6, (guest, a) => guest.sdl.getRGBA(a[0], a[1], a[2], a[3], a[4], a[5]));
    define(library, "SDL_UpperBlit", 4, (guest, a) => guest.sdl.upperBlit(a[0], a[1], a[2], a[3]));
    define(library, "SDL_SetColorKey", 3, (guest, a) => guest.sdl.setColorKey(a[0], a[1], a[2]));

    define(library, "SDL_PollEvent", 1, (guest, a) => guest.sdl.pollEvent(a[0]));
    define(library, "SDL_PeepEvents", 6, (guest, a) => guest.sdl.peepEvents(a[0], a[1], a[2], a[3], a[4]));
    define(library, "SDL_PumpEvents", 0, (guest) => guest.sdl.pumpEvents());
    define(library, "SDL_WaitEvent", 1, (guest, a) => guest.sdl.waitEvent(a[0]));
    define(library, "SDL_GetMouseState", 2, (guest, a) => guest.sdl.getMouseState(a[0], a[1]));
    define(library, "SDL_GetModState", 0, (guest) => guest.sdl.getModState());
    define(library, "SDL_NumJoysticks", 0, (guest) => guest.sdl.numJoysticks());
    define(library, "SDL_ShowCursor", 1, (guest, a) => guest.sdl.showCursor(a[0]));
  }

  // --- SDL 1.2 (sdl.dll) ---------------------------------------------------
  defineShared("sdl.dll", 1);
  define("sdl.dll", "SDL_SetVideoMode", 4, (guest, a) => guest.sdl.setVideoMode(a[0], a[1], a[2], a[3]));
  define("sdl.dll", "SDL_GetVideoSurface", 0, (guest) => guest.sdl.getVideoSurface());
  define("sdl.dll", "SDL_Flip", 1, (guest, a) => guest.sdl.flip(a[0]));
  define("sdl.dll", "SDL_UpdateRect", 5, (guest, a) => guest.sdl.updateRect(a[0], a[1], a[2], a[3], a[4]));
  define("sdl.dll", "SDL_WM_SetCaption", 2, (guest) => guest.sdl.wmSetCaption());
  define("sdl.dll", "SDL_WM_SetIcon", 2, (guest) => guest.sdl.wmSetIcon());
  define("sdl.dll", "SDL_EnableUNICODE", 1, (guest, a) => guest.sdl.enableUnicode(a[0]));
  define("sdl.dll", "SDL_EnableKeyRepeat", 2, (guest) => guest.sdl.enableKeyRepeat());
  define("sdl.dll", "SDL_GetAppState", 0, (guest) => guest.sdl.getAppState());
  define("sdl.dll", "SDL_DisplayFormat", 1, (guest, a) => guest.sdl.displayFormat(a[0]));
  define("sdl.dll", "SDL_DisplayFormatAlpha", 1, (guest, a) => guest.sdl.displayFormat(a[0]));
  define("sdl.dll", "SDL_ConvertSurface", 3, (guest, a) => guest.sdl.convertSurface(a[0]));
  define("sdl.dll", "SDL_SetAlpha", 3, (guest) => guest.sdl.setAlpha());
  define("sdl.dll", "SDL_ThreadID", 0, (guest) => guest.sdl.threadID());
  define("sdl.dll", "SDL_getenv", 1, (guest) => guest.sdl.getenv());
  define("sdl.dll", "SDL_strlcpy", 3, (guest, a) => guest.sdl.strlcpy(a[0], a[1], a[2]));
  define("sdl.dll", "SDL_strlcat", 3, (guest, a) => guest.sdl.strlcat(a[0], a[1], a[2]));
  define("sdl.dll", "SDL_SetModuleHandle", 1, (guest) => guest.sdl.setModuleHandle());
  define("sdl.dll", "SDL_GetVideoInfo", 0, (guest) => guest.sdl.getVideoInfo());
  define("sdl.dll", "SDL_GL_SetAttribute", 2, (guest) => guest.sdl.glSetAttribute());
  define("sdl.dll", "SDL_GL_GetAttribute", 2, (guest, a) => guest.sdl.glGetAttribute(a[0], a[1]));
  define("sdl.dll", "SDL_GL_SwapBuffers", 0, (guest) => guest.sdl.glSwapBuffers());
  define("sdl.dll", "SDL_RWFromFile", 2, (guest) => guest.sdl.rwFromFile());
  define("sdl.dll", "SDL_SaveBMP_RW", 3, (guest) => guest.sdl.saveBmpRw());

  // --- SDL 2 (sdl2.dll) ----------------------------------------------------
  defineShared("sdl2.dll", 2);
  define("sdl2.dll", "SDL_SetMainReady", 0, (guest) => guest.sdl.setMainReady());
  // Hints are advisory configuration; the bounded world accepts and ignores them,
  // returning SDL_TRUE as a real SDL build does when the hint is accepted.
  define("sdl2.dll", "SDL_SetHint", 2, () => 1);
  define("sdl2.dll", "SDL_SetHintWithPriority", 3, () => 1);

  // SDL's own libc: SDL ships private strlen/wcslen/mem*/malloc-family wrappers
  // that games call directly (Chocolate Doom's SDL_GetBasePath/argv handling
  // reaches them before any video call). Each performs the real byte work over
  // guest memory or the process default heap, so the behavior is genuine, not a
  // stub. A full-width pointer is kept intact: on x64 a string or block argument
  // may live on the guest stack above 4 GiB.
  const wide = (value) => (value < 0 ? value >>> 0 : value);
  define("sdl2.dll", "SDL_strlen", 1, (guest, a) => guest.readAnsiString(wide(a[0]))?.length ?? 0);
  define("sdl2.dll", "SDL_wcslen", 1, (guest, a) => guest.readWideString(wide(a[0]))?.length ?? 0);
  define("sdl2.dll", "SDL_memcpy", 3, (guest, a) => { if (a[2] > 0) guest.memory.writeBlock(wide(a[0]), guest.memory.readBlock(wide(a[1]), a[2])); return a[0]; });
  define("sdl2.dll", "SDL_memmove", 3, (guest, a) => { if (a[2] > 0) guest.memory.writeBlock(wide(a[0]), guest.memory.readBlock(wide(a[1]), a[2])); return a[0]; });
  define("sdl2.dll", "SDL_memset", 3, (guest, a) => { if (a[2] > 0) guest.memory.writeBlock(wide(a[0]), Buffer.alloc(a[2], a[1] & 0xff)); return a[0]; });
  define("sdl2.dll", "SDL_malloc", 1, (guest, a) => guest.crtMalloc(a[0]));
  define("sdl2.dll", "SDL_calloc", 2, (guest, a) => guest.crtCalloc(a[0], a[1]));
  define("sdl2.dll", "SDL_realloc", 2, (guest, a) => guest.crtRealloc(a[0], a[1]));
  define("sdl2.dll", "SDL_free", 1, (guest, a) => { guest.crtFree(a[0]); return 0; });
  // SDL_iconv_string(tocode, fromcode, inbuf, inbytesleft): the encoding convert
  // SDL_main runs to turn the wide command line into UTF-8 argv before it calls
  // the game's own main. It returns a freshly SDL_malloc'd, null-terminated
  // string in the target encoding. The bounded world serves the two encodings the
  // startup actually uses — UTF-16LE and UTF-8/ASCII — over real guest bytes.
  const isWideCode = (code) => code.includes("UTF-16") || code.includes("UCS-2") || code.includes("UNICODE") || code.includes("WCHAR");
  define("sdl2.dll", "SDL_iconv_string", 4, (guest, a) => {
    const toCode = (guest.readAnsiString(wide(a[0])) ?? "UTF-8").toUpperCase();
    const fromCode = (guest.readAnsiString(wide(a[1])) ?? "UTF-8").toUpperCase();
    const inByte = guest.memory.readBlock(wide(a[2]), a[3] >>> 0);
    const text = (isWideCode(fromCode) ? Buffer.from(inByte).toString("utf16le") : Buffer.from(inByte).toString("utf8")).replace(/\0+$/, "");
    const outByte = isWideCode(toCode)
      ? Buffer.from(text + "\0", "utf16le")
      : Buffer.concat([Buffer.from(text, "utf8"), Buffer.alloc(1)]);
    const dest = guest.crtMalloc(outByte.length);
    if (dest === 0) return 0;
    guest.memory.writeBlock(dest, outByte);
    return dest;
  });
  // SDL_GetBasePath/SDL_GetPrefPath: the application directory and the writable
  // preference directory a game reads at startup. Chocolate Doom searches the
  // base path for its IWAD and stores its configuration/savegame under the pref
  // path. Both return a freshly SDL_malloc'd, NUL-terminated UTF-8 path with a
  // trailing separator (the SDL contract, caller SDL_free's it), rooted at the
  // one bounded guest volume — never a host path. The org/app of GetPrefPath
  // are advisory in the single bounded home.
  const allocPath = (guest, text) => {
    const bytes = Buffer.concat([Buffer.from(text, "utf8"), Buffer.alloc(1)]);
    const dest = guest.crtMalloc(bytes.length);
    if (dest === 0) return 0;
    guest.memory.writeBlock(dest, bytes);
    return dest;
  };
  define("sdl2.dll", "SDL_GetBasePath", 0, (guest) => allocPath(guest, "C:\\game\\"));
  define("sdl2.dll", "SDL_GetPrefPath", 2, (guest) => allocPath(guest, "C:\\game\\"));
  // SDL2_mixer: the bounded world serves no audio device. Mix_OpenAudioDevice /
  // Mix_OpenAudio report failure (-1) so a game's sound init disables sound and
  // proceeds to video — the honest "no audio hardware" path, not a fabricated
  // device. Mix_Init returns the empty set of loaded decoders; the lifecycle and
  // query calls are inert. This keeps the run on the graphics path.
  define("sdl2_mixer.dll", "Mix_Init", 1, () => 0);
  define("sdl2_mixer.dll", "Mix_Quit", 0, () => 0);
  define("sdl2_mixer.dll", "Mix_OpenAudio", 4, () => 0xffffffff);
  define("sdl2_mixer.dll", "Mix_OpenAudioDevice", 6, () => 0xffffffff);
  define("sdl2_mixer.dll", "Mix_CloseAudio", 0, () => 0);
  define("sdl2_mixer.dll", "Mix_QuerySpec", 3, () => 0);
  define("sdl2_mixer.dll", "Mix_GetError", 0, (guest) => guest.sdl.getError());
  define("sdl2_mixer.dll", "Mix_SetError", 1, (guest, a) => guest.sdl.setError(guest.readAnsiString(a[0] < 0 ? a[0] >>> 0 : a[0])));
  define("sdl2.dll", "SDL_CreateWindow", 6, (guest, a) => guest.sdl.createWindow(a[0], a[1], a[2], a[3], a[4], a[5]));
  define("sdl2.dll", "SDL_DestroyWindow", 1, (guest, a) => guest.sdl.destroyWindow(a[0]));
  define("sdl2.dll", "SDL_GetWindowSurface", 1, (guest, a) => guest.sdl.getWindowSurface(a[0]));
  define("sdl2.dll", "SDL_UpdateWindowSurface", 1, (guest, a) => guest.sdl.updateWindowSurface(a[0]));
  define("sdl2.dll", "SDL_UpdateWindowSurfaceRects", 3, (guest, a) => guest.sdl.updateWindowSurfaceRects(a[0]));
  define("sdl2.dll", "SDL_GetWindowSize", 3, (guest, a) => guest.sdl.getWindowSize(a[0], a[1], a[2]));
  define("sdl2.dll", "SDL_GetWindowFlags", 1, (guest) => guest.sdl.getWindowFlags());
  define("sdl2.dll", "SDL_GetWindowID", 1, (guest) => guest.sdl.getWindowID());
  define("sdl2.dll", "SDL_SetWindowTitle", 2, (guest) => guest.sdl.setWindowTitle());
  define("sdl2.dll", "SDL_SetWindowSize", 3, (guest) => guest.sdl.setWindowSize());
  define("sdl2.dll", "SDL_CreateRenderer", 3, (guest, a) => guest.sdl.createRenderer(a[0], a[1], a[2]));
  define("sdl2.dll", "SDL_DestroyRenderer", 1, (guest, a) => guest.sdl.destroyRenderer(a[0]));
  define("sdl2.dll", "SDL_SetRenderDrawColor", 5, (guest, a) => guest.sdl.setRenderDrawColor(a[0], a[1], a[2], a[3], a[4]));
  define("sdl2.dll", "SDL_RenderClear", 1, (guest, a) => guest.sdl.renderClear(a[0]));
  define("sdl2.dll", "SDL_RenderFillRect", 2, (guest, a) => guest.sdl.renderFillRect(a[0], a[1]));
  define("sdl2.dll", "SDL_RenderPresent", 1, (guest, a) => guest.sdl.renderPresent(a[0]));
  define("sdl2.dll", "SDL_GetVersion", 1, (guest, a) => guest.sdl.getVersion(a[0]));
  define("sdl2.dll", "SDL_CreateCond", 0, (guest) => guest.sdl.createCond());
  define("sdl2.dll", "SDL_CondSignal", 1, (guest) => guest.sdl.condSignal());
  define("sdl2.dll", "SDL_CondBroadcast", 1, (guest) => guest.sdl.condBroadcast());
  define("sdl2.dll", "SDL_CondWait", 2, (guest) => guest.sdl.condWait());
  define("sdl2.dll", "SDL_DestroyCond", 1, (guest, a) => guest.sdl.destroyCond(a[0]));
  define("sdl2.dll", "SDL_ShowSimpleMessageBox", 4, (guest) => guest.sdl.showSimpleMessageBox());

  // --- SDL 2 video-init + render pipeline (lane AE: toward Doom's first frame)
  // The display query I_InitGraphics runs before it opens a window.
  define("sdl2.dll", "SDL_GetNumVideoDisplays", 0, (guest) => guest.sdl.getNumVideoDisplays());
  define("sdl2.dll", "SDL_GetNumVideoDrivers", 0, (guest) => guest.sdl.getNumVideoDrivers());
  define("sdl2.dll", "SDL_GetCurrentVideoDriver", 0, (guest) => guest.sdl.getCurrentVideoDriver());
  define("sdl2.dll", "SDL_GetCurrentDisplayMode", 2, (guest, a) => guest.sdl.getCurrentDisplayMode(a[0], a[1]));
  define("sdl2.dll", "SDL_GetDesktopDisplayMode", 2, (guest, a) => guest.sdl.getDesktopDisplayMode(a[0], a[1]));
  define("sdl2.dll", "SDL_GetDisplayMode", 3, (guest, a) => guest.sdl.getDisplayMode(a[0], a[2]));
  define("sdl2.dll", "SDL_GetNumDisplayModes", 1, (guest) => guest.sdl.getNumDisplayModes());
  define("sdl2.dll", "SDL_GetDisplayBounds", 2, (guest, a) => guest.sdl.getDisplayBounds(a[0], a[1]));
  define("sdl2.dll", "SDL_GetDisplayUsableBounds", 2, (guest, a) => guest.sdl.getDisplayBounds(a[0], a[1]));
  define("sdl2.dll", "SDL_GetDisplayDPI", 4, (guest, a) => guest.sdl.getDisplayDPI(a[0], a[1], a[2], a[3]));

  // Renderer configuration + info.
  define("sdl2.dll", "SDL_RenderSetLogicalSize", 3, (guest, a) => guest.sdl.renderSetLogicalSize(a[0], a[1], a[2]));
  define("sdl2.dll", "SDL_RenderSetIntegerScale", 2, (guest) => guest.sdl.renderSetIntegerScale());
  define("sdl2.dll", "SDL_GetRendererInfo", 2, (guest, a) => guest.sdl.getRendererInfo(a[0], a[1]));
  define("sdl2.dll", "SDL_GetRendererOutputSize", 3, (guest, a) => guest.sdl.getRendererOutputSize(a[0], a[1], a[2]));
  define("sdl2.dll", "SDL_RenderCopy", 4, (guest, a) => guest.sdl.renderCopy(a[0], a[1], a[2], a[3]));
  define("sdl2.dll", "SDL_RenderCopyEx", 6, (guest, a) => guest.sdl.renderCopy(a[0], a[1], a[2], a[3]));
  define("sdl2.dll", "SDL_SetRenderTarget", 2, (guest, a) => guest.sdl.setRenderTarget(a[0], a[1]));
  define("sdl2.dll", "SDL_GetRenderTarget", 1, (guest, a) => guest.sdl.getRenderTarget(a[0]));
  define("sdl2.dll", "SDL_RenderSetViewport", 2, () => 0);
  define("sdl2.dll", "SDL_RenderSetScale", 3, () => 0);
  define("sdl2.dll", "SDL_RenderGetViewport", 2, () => 0);

  // Texture lifecycle + upload.
  define("sdl2.dll", "SDL_CreateTexture", 5, (guest, a) => guest.sdl.createTexture(a[0], a[1], a[2], a[3], a[4]));
  define("sdl2.dll", "SDL_UpdateTexture", 4, (guest, a) => guest.sdl.updateTexture(a[0], a[1], a[2], a[3]));
  define("sdl2.dll", "SDL_QueryTexture", 5, (guest, a) => guest.sdl.queryTexture(a[0], a[1], a[2], a[3], a[4]));
  define("sdl2.dll", "SDL_DestroyTexture", 1, (guest, a) => guest.sdl.destroyTexture(a[0]));
  define("sdl2.dll", "SDL_LockTexture", 4, (guest, a) => guest.sdl.lockTexture(a[0], a[1], a[2], a[3]));
  define("sdl2.dll", "SDL_UnlockTexture", 1, (guest) => guest.sdl.unlockTexture());
  define("sdl2.dll", "SDL_SetTextureBlendMode", 2, (guest) => guest.sdl.setTextureBlendMode());
  define("sdl2.dll", "SDL_SetTextureColorMod", 4, (guest) => guest.sdl.setTextureColorMod());
  define("sdl2.dll", "SDL_SetTextureAlphaMod", 2, (guest) => guest.sdl.setTextureAlphaMod());

  // Palette + surface color conversion.
  define("sdl2.dll", "SDL_AllocPalette", 1, (guest, a) => guest.sdl.allocPalette(a[0]));
  define("sdl2.dll", "SDL_FreePalette", 1, (guest, a) => guest.sdl.freePalette(a[0]));
  define("sdl2.dll", "SDL_SetPaletteColors", 4, (guest, a) => guest.sdl.setPaletteColors(a[0], a[1], a[2], a[3]));
  define("sdl2.dll", "SDL_SetSurfacePalette", 2, (guest, a) => guest.sdl.setSurfacePalette(a[0], a[1]));
  define("sdl2.dll", "SDL_PixelFormatEnumToMasks", 6, (guest, a) => guest.sdl.pixelFormatEnumToMasks(a[0], a[1], a[2], a[3], a[4], a[5]));
  define("sdl2.dll", "SDL_CreateRGBSurfaceWithFormat", 5, (guest, a) => guest.sdl.createRGBSurfaceWithFormat(a[0], a[1], a[2], a[3], a[4], 2));
  define("sdl2.dll", "SDL_CreateRGBSurfaceWithFormatFrom", 6, (guest, a) => guest.sdl.createRGBSurfaceWithFormatFrom(a[0], a[1], a[2], a[3], a[4], a[5], 2));

  // Blit (SDL_BlitSurface is SDL_UpperBlit, already shared; SDL_LowerBlit is the
  // unclipped fast path Chocolate Doom's I_FinishUpdate uses for the paletted ->
  // ARGB convert).
  define("sdl2.dll", "SDL_BlitSurface", 4, (guest, a) => guest.sdl.upperBlit(a[0], a[1], a[2], a[3]));
  define("sdl2.dll", "SDL_LowerBlit", 4, (guest, a) => guest.sdl.lowerBlit(a[0], a[1], a[2], a[3]));

  // Window presentation + input the init/finish path touches.
  define("sdl2.dll", "SDL_ShowWindow", 1, (guest) => guest.sdl.showWindow());
  define("sdl2.dll", "SDL_HideWindow", 1, (guest) => guest.sdl.hideWindow());
  define("sdl2.dll", "SDL_RaiseWindow", 1, (guest) => guest.sdl.raiseWindow());
  define("sdl2.dll", "SDL_SetWindowFullscreen", 2, (guest) => guest.sdl.setWindowFullscreen());
  define("sdl2.dll", "SDL_SetWindowGrab", 2, (guest) => guest.sdl.setWindowGrab());
  define("sdl2.dll", "SDL_SetWindowMinimumSize", 3, (guest) => guest.sdl.setWindowMinimumSize());
  define("sdl2.dll", "SDL_SetWindowResizable", 2, (guest) => guest.sdl.setWindowResizable());
  define("sdl2.dll", "SDL_SetWindowPosition", 3, (guest) => guest.sdl.setWindowPosition());
  define("sdl2.dll", "SDL_GetWindowPixelFormat", 1, (guest) => guest.sdl.getWindowPixelFormat());
  define("sdl2.dll", "SDL_GetWindowFromID", 1, (guest) => guest.sdl.getWindowFromID());
  define("sdl2.dll", "SDL_SetRelativeMouseMode", 1, (guest) => guest.sdl.setRelativeMouseMode());
  define("sdl2.dll", "SDL_GetRelativeMouseState", 2, (guest, a) => guest.sdl.getRelativeMouseState(a[0], a[1]));
  define("sdl2.dll", "SDL_WarpMouseInWindow", 3, (guest) => guest.sdl.warpMouseInWindow());
  define("sdl2.dll", "SDL_SetWindowIcon", 2, () => 0);
  define("sdl2.dll", "SDL_GetWindowTitle", 1, (guest) => guest.sdl.getCurrentVideoDriver());
  define("sdl2.dll", "SDL_MaximizeWindow", 1, () => 0);
  define("sdl2.dll", "SDL_MinimizeWindow", 1, () => 0);
  define("sdl2.dll", "SDL_RestoreWindow", 1, () => 0);
  define("sdl2.dll", "SDL_GetWindowPosition", 3, (guest, a) => { if (a[1] !== 0) guest.memory.writeMemory(a[1] < 0 ? a[1] >>> 0 : a[1], 4, 0); if (a[2] !== 0) guest.memory.writeMemory(a[2] < 0 ? a[2] >>> 0 : a[2], 4, 0); return 0; });
  define("sdl2.dll", "SDL_GetWindowDisplayIndex", 1, () => 0);
  define("sdl2.dll", "SDL_DisableScreenSaver", 0, () => 0);
  define("sdl2.dll", "SDL_EnableScreenSaver", 0, () => 0);
  define("sdl2.dll", "SDL_RenderGetLogicalSize", 3, () => 0);

  return table;
}

export const sdlExportTable = Object.freeze(buildSdlExportTable());
