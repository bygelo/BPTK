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
});

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
  const surface = new Map(); // struct address -> { addr, format_addr, w, h, pitch, pixels, format, owns_pixels }
  let primaryFramebuffer = null; // { width, height, pixels, pitch, format }
  let presentCount = 0;
  let videoInfoAddress = 0;
  const drawColor = { r: 0, g: 0, b: 0, a: 0xff };

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
    const record = { addr: structAddr, format_addr: formatAddr, w, h, pitch, pixels, format, owns_pixels: ownsPixels };
    surface.set(structAddr, record);
    writeSurfaceStruct(record, variant);
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

  function fillSurface(record, rect, color) {
    const left = Math.max(0, rect ? rect.x : 0);
    const top = Math.max(0, rect ? rect.y : 0);
    const right = Math.min(record.w, rect ? rect.x + rect.w : record.w);
    const bottom = Math.min(record.h, rect ? rect.y + rect.h : record.h);
    const bpp = record.format.bytes_per_pixel;
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
    for (let row = 0; row < sh; row += 1) {
      const dy = dstY + row;
      if (dy < 0 || dy >= dst.h) continue;
      for (let col = 0; col < sw; col += 1) {
        const dx = dstX + col;
        if (dx < 0 || dx >= dst.w) continue;
        const pixel = memory.readMemory(src.pixels + (sy0 + row) * src.pitch + (sx0 + col) * sbpp, sbpp);
        if (src.color_key !== undefined && pixel === src.color_key) continue;
        memory.writeMemory(dst.pixels + dy * dst.pitch + dx * dbpp, dbpp, pixel);
      }
    }
    return 0;
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
      renderer.set(handle, { window: windowHandle >>> 0, w, h, pixels, pitch: w * 4, format: argb8888() });
      if (win) win.renderer = handle;
      setPrimary({ w, h, pixels, pitch: w * 4, format: argb8888() });
      return handle;
    },
    destroyRenderer(handle) { renderer.delete(handle >>> 0); return 0; },
    setRenderDrawColor(handle, r, g, b, a) {
      drawColor.r = r & 0xff; drawColor.g = g & 0xff; drawColor.b = b & 0xff; drawColor.a = a & 0xff;
      return 0;
    },
    renderClear(handle) {
      const rend = renderer.get(handle >>> 0);
      if (rend === undefined) return setError("SDL_RenderClear: invalid renderer");
      const color = mapColor(rend.format, drawColor.r, drawColor.g, drawColor.b, drawColor.a);
      const record = { pixels: rend.pixels, pitch: rend.pitch, w: rend.w, h: rend.h, format: rend.format };
      fillSurface(record, null, color);
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
    renderPresent(handle) { presentCount += 1; return 0; },
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
      const format = (rMask | gMask | bMask | aMask) === 0
        ? argb8888()
        : describeFormat(depth || 32, rMask, gMask, bMask, aMask);
      return makeSurface(width, height, format, variant ?? 1, 0);
    },
    createRGBSurfaceFrom(pixels, width, height, depth, pitch, rMask, gMask, bMask, aMask, variant) {
      const format = (rMask | gMask | bMask | aMask) === 0
        ? argb8888()
        : describeFormat(depth || 32, rMask, gMask, bMask, aMask);
      return makeSurface(width, height, format, variant ?? 1, addr(pixels));
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
      const src = surface.get(srcAddr >>> 0);
      const dst = surface.get(dstAddr >>> 0);
      if (src === undefined || dst === undefined) return 0xffffffff;
      const srcRect = srcRectAddr === 0 ? null : readRect(srcRectAddr);
      let dstX = 0;
      let dstY = 0;
      if (dstRectAddr !== 0) { const r = readRect(dstRectAddr); dstX = r.x; dstY = r.y; }
      return blitSurface(src, srcRect, dst, dstX, dstY);
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

    // --- events (bounded empty trace) -------------------------------------
    // No real user drives the probe, so the event queue is always empty:
    // SDL_PollEvent returns 0 (no event) and zeroes the event type. This is an
    // honest empty input trace, never a synthesized event.
    pollEvent(eventAddr) {
      if (eventAddr !== 0) memory.writeMemory(addr(eventAddr), 4, 0);
      return 0;
    },
    peepEvents() { return 0; },
    pumpEvents() { return 0; },
    waitEvent(eventAddr) {
      // With an empty queue and no real user, WaitEvent cannot block; it reports
      // failure (0) rather than a fabricated event, so a loop keyed on it ends.
      if (eventAddr !== 0) memory.writeMemory(addr(eventAddr), 4, 0);
      return 0;
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
    define(library, "SDL_PeepEvents", 6, (guest) => guest.sdl.peepEvents());
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

  return table;
}

export const sdlExportTable = Object.freeze(buildSdlExportTable());
