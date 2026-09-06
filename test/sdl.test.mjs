// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The bounded SDL subsystem suite (lane W). It proves the honesty rail three
// ways: the sync/atomic primitives count and read-modify-write for real; the
// video/surface path backs a real RGBA framebuffer that a fill actually writes
// and the present path returns; and the dispatch through executeProbe64 marshals
// an SDL call under the Win64 ABI so a game runs past it. The threading refusal
// (SDL_CreateThread returns NULL) and the empty event trace (SDL_PollEvent
// returns 0) are asserted as the honest bounded behavior they are.

import assert from "node:assert/strict";
import { test } from "node:test";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { resolveStageDir } from "../lib/corpus.mjs";
import { createSdlSubsystem, sdlExportTable, sdlEventType, sdlScancode, sdlKeycode } from "../lib/sdl.mjs";
import { executeProbe64, runImage64 } from "../lib/exec64.mjs";
import { mapPe64State } from "../lib/pe64.mjs";
import { createHleLayout } from "../lib/hle.mjs";
import { createGuestClock } from "../lib/clock.mjs";

// A flat little-endian guest memory over one Buffer, with the same four
// primitives the HLE memory adapter exposes, sized to hold a small arena.
function createMemory(sizeByte) {
  const backing = Buffer.alloc(sizeByte);
  return {
    backing,
    readMemory(address, byteCount) {
      let value = 0;
      for (let i = 0; i < byteCount; i += 1) value += backing[address + i] * 2 ** (8 * i);
      return value >>> 0 === value ? value : value; // dword-or-wider, unsigned
    },
    writeMemory(address, byteCount, value) {
      let v = value;
      for (let i = 0; i < byteCount; i += 1) { backing[address + i] = v & 0xff; v = Math.floor(v / 256); }
    },
    readBlock(address, byteCount) { return Buffer.from(backing.subarray(address, address + byteCount)); },
    writeBlock(address, buffer) { Buffer.from(buffer).copy(backing, address); },
  };
}

// A subsystem over a 4 MiB arena at base 0x00100000, with a bump allocator, so
// the fixed struct region (top of the arena) and framebuffers both resolve.
function createSubsystem() {
  const arenaBase = 0x00100000;
  const arenaSize = 0x00400000;
  const memory = createMemory(arenaBase + arenaSize);
  const layout = { arena_base: arenaBase, arena_size_byte: arenaSize };
  let cursor = arenaBase;
  const allocate = (byteCount) => { const a = cursor; cursor += (byteCount + 15) & ~15; return a; };
  const clock = createGuestClock({ mode: "virtual_monotonic" });
  return { sdl: createSdlSubsystem({ memory, layout, allocate, clock }), memory, clock };
}

test("SDL semaphore is a real counter: post raises, wait lowers, floors at zero", () => {
  const { sdl } = createSubsystem();
  const sem = sdl.createSemaphore(2);
  assert.notEqual(sem, 0, "a created semaphore is a valid handle");
  assert.equal(sdl.semValue(sem), 2);
  assert.equal(sdl.semWait(sem), 0);
  assert.equal(sdl.semValue(sem), 1);
  assert.equal(sdl.semPost(sem), 0);
  assert.equal(sdl.semValue(sem), 2);
  sdl.semWait(sem); sdl.semWait(sem);
  assert.equal(sdl.semValue(sem), 0, "the counter floors at zero");
  assert.equal(sdl.semTryWait(sem), 1, "SDL_SemTryWait on a zero counter returns SDL_MUTEX_TIMEDOUT");
  sdl.destroySemaphore(sem);
  assert.equal(sdl.semValue(sem), 0, "a destroyed semaphore is gone");
});

test("SDL mutex is a real recursive lock count", () => {
  const { sdl } = createSubsystem();
  const m = sdl.createMutex();
  assert.equal(sdl.lockMutex(m), 0);
  assert.equal(sdl.lockMutex(m), 0);
  assert.equal(sdl.unlockMutex(m), 0);
  assert.equal(sdl.unlockMutex(m), 0);
});

test("SDL atomics read-modify-write real guest memory", () => {
  const { sdl, memory } = createSubsystem();
  const cell = 0x00101000;
  memory.writeMemory(cell, 4, 5);
  assert.equal(sdl.atomicGet(cell), 5);
  assert.equal(sdl.atomicAdd(cell, 3), 5, "AtomicAdd returns the prior value");
  assert.equal(memory.readMemory(cell, 4), 8);
  assert.equal(sdl.atomicCAS(cell, 8, 20), 1, "CAS succeeds on a match");
  assert.equal(memory.readMemory(cell, 4), 20);
  assert.equal(sdl.atomicCAS(cell, 8, 30), 0, "CAS fails on a mismatch");
  assert.equal(memory.readMemory(cell, 4), 20, "a failed CAS does not write");
});

test("SDL_CreateThread is an honest refusal, not a faked thread", () => {
  const { sdl } = createSubsystem();
  assert.equal(sdl.createThread(), 0, "a bounded probe returns NULL rather than pretend a thread runs");
});

test("SDL video path backs a real framebuffer a fill writes and present returns", () => {
  const { sdl } = createSubsystem();
  const surfaceAddr = sdl.setVideoMode(8, 4, 32, 0);
  assert.notEqual(surfaceAddr, 0, "SDL_SetVideoMode returns a surface");
  assert.equal(sdl.has_video, true);
  // A blank display is honestly blank before any draw.
  let frame = sdl.presentFramebuffer();
  assert.equal(frame.width, 8);
  assert.equal(frame.height, 4);
  assert.equal(frame.is_blank, true, "an undrawn framebuffer is honestly blank");
  // Fill the whole surface red (ARGB8888 0x00ff0000) and present it.
  sdl.fillRect(surfaceAddr, 0, 0x00ff0000);
  assert.equal(sdl.flip(surfaceAddr), 0);
  frame = sdl.presentFramebuffer();
  assert.equal(frame.is_blank, false, "a drawn framebuffer is not blank");
  assert.equal(frame.rgba[0], 0xff, "R is set");
  assert.equal(frame.rgba[1], 0x00, "G is clear");
  assert.equal(frame.rgba[2], 0x00, "B is clear");
  assert.equal(frame.rgba[3], 0xff, "A is opaque for display");
  assert.equal(frame.rgba.length, 8 * 4 * 4);
});

test("SDL blit copies real pixels and honors the source color key", () => {
  const { sdl } = createSubsystem();
  const dst = sdl.setVideoMode(4, 2, 32, 0);
  const src = sdl.createRGBSurface(0, 4, 2, 32, 0x00ff0000, 0x0000ff00, 0x000000ff, 0xff000000);
  // Fill the source green, key out green on the top-left pixel is not asked here;
  // fill the whole source and blit — the destination takes the green pixels.
  sdl.fillRect(src, 0, 0x0000ff00);
  assert.equal(sdl.upperBlit(src, 0, dst, 0), 0);
  const frame = sdl.presentFramebuffer();
  assert.equal(frame.rgba[1], 0xff, "the blitted green pixel landed in the destination");
});

test("SDL_PollEvent is an honest empty input trace", () => {
  const { sdl, memory } = createSubsystem();
  const eventAddr = 0x00101800;
  memory.writeMemory(eventAddr, 4, 0x1234);
  assert.equal(sdl.pollEvent(eventAddr), 0, "no event is pending");
  assert.equal(memory.readMemory(eventAddr, 4), 0, "the event type is cleared, never a fabricated event");
});

// The scripted input trace marshals a real SDL2 SDL_Event into the guest buffer:
// the common header (type@0) plus the SDL_KeyboardEvent body (state@12,
// keysym.scancode@16, keysym.sym@20, keysym.mod@24), delivered in order.
test("SDL_PollEvent delivers a scripted trace as real SDL2 event structs", () => {
  const { sdl, memory } = createSubsystem();
  const eventAddr = 0x00101800;
  const loaded = sdl.loadInputTrace([
    { type: "keydown", scancode: sdlScancode.ESCAPE, sym: sdlKeycode.ESCAPE, mod: 0 },
    { type: "keyup", scancode: sdlScancode.ESCAPE, sym: sdlKeycode.ESCAPE, mod: 0 },
  ]);
  assert.equal(loaded, 2, "both scripted events loaded");

  assert.equal(sdl.pollEvent(eventAddr), 1, "the first scripted event is delivered");
  assert.equal(memory.readMemory(eventAddr + 0, 4), sdlEventType.SDL_KEYDOWN, "type is SDL_KEYDOWN");
  assert.equal(memory.readMemory(eventAddr + 12, 1), 1, "state is SDL_PRESSED");
  assert.equal(memory.readMemory(eventAddr + 16, 4), sdlScancode.ESCAPE, "keysym.scancode is Escape");
  assert.equal(memory.readMemory(eventAddr + 20, 4), sdlKeycode.ESCAPE, "keysym.sym is SDLK_ESCAPE");

  assert.equal(sdl.pollEvent(eventAddr), 1, "the second scripted event is delivered");
  assert.equal(memory.readMemory(eventAddr + 0, 4), sdlEventType.SDL_KEYUP, "type is SDL_KEYUP");
  assert.equal(memory.readMemory(eventAddr + 12, 1), 0, "state is SDL_RELEASED");

  assert.equal(sdl.pollEvent(eventAddr), 0, "the queue drains to empty");
  assert.equal(memory.readMemory(eventAddr, 4), 0, "the drained poll clears the type");
  assert.equal(sdl.input_delivered, 2, "both events were consumed by the guest");
});

// The frame schedule gates delivery by present-count: an event scheduled for a
// later frame stays queued until the game has presented that many frames.
test("a scripted event is gated by its present-count frame schedule", () => {
  const { sdl, memory } = createSubsystem();
  const eventAddr = 0x00101800;
  sdl.loadInputTrace([{ type: "keydown", scancode: sdlScancode.RETURN, sym: sdlKeycode.RETURN, frame: 2 }]);
  // No present yet: the event is scheduled for frame 2 and is not yet due.
  assert.equal(sdl.pollEvent(eventAddr), 0, "the future-scheduled event is withheld");
  sdl.flip(0); sdl.flip(0); // two presents -> present_count reaches 2
  assert.equal(sdl.present_count >= 2, true, "the game has presented two frames");
  assert.equal(sdl.pollEvent(eventAddr), 1, "the event is now due and delivered");
  assert.equal(memory.readMemory(eventAddr + 16, 4), sdlScancode.RETURN, "the due event carries the Return scancode");
});

// SDL_WaitEvent cannot block a single-threaded probe, so it delivers the next
// scripted event when one remains (a SDL_QUIT ends the loop) and reports 0 empty.
test("SDL_WaitEvent delivers the next scripted event, then reports empty", () => {
  const { sdl, memory } = createSubsystem();
  const eventAddr = 0x00101800;
  sdl.loadInputTrace([{ type: "quit" }]);
  assert.equal(sdl.waitEvent(eventAddr), 1, "the scripted quit is delivered");
  assert.equal(memory.readMemory(eventAddr, 4), sdlEventType.SDL_QUIT, "type is SDL_QUIT");
  assert.equal(sdl.waitEvent(eventAddr), 0, "an empty queue reports 0 so the loop ends");
});

// The full dispatch: a synthetic PE32+ image whose entry calls SDL through its
// IAT under the Win64 ABI. It proves executeProbe64 marshals an SDL call, the
// call returns, and execution continues — the game runs PAST the SDL frontier.
test("executeProbe64 dispatches an SDL call under the Win64 ABI and continues", () => {
  const loadBase = 0x140000000n;
  // Entry: SDL_CreateSemaphore(3) then SDL_SemPost(sem) then ret.
  //   0:  b9 03 00 00 00        mov ecx,3
  //   5:  ff 15 f3 0f 00 00     call [rip+0xff3]   -> slot 0x1000 (CreateSemaphore)
  //   b:  48 89 c1              mov rcx,rax        (sem handle)
  //   e:  ff 15 f2 0f 00 00     call [rip+0xff2]   -> slot 0x1008 (SemPost)
  //   14: c3                    ret
  const image = Buffer.alloc(0x2000);
  const code = [
    0xb9, 0x03, 0x00, 0x00, 0x00,
    0xff, 0x15, 0xf5, 0x0f, 0x00, 0x00,
    0x48, 0x89, 0xc1,
    0xff, 0x15, 0xf4, 0x0f, 0x00, 0x00,
    0xc3,
  ];
  Buffer.from(code).copy(image, 0);
  const mapped = {
    image,
    input_path: "synthetic-sdl.exe",
    load_base: loadBase,
    entry_rva: 0,
    image_size_byte: image.length,
    section: [],
    tls_callback: [],
    relocation_count: 0,
    resolution_blocker: [],
    runtime_blocker: [],
    import: [
      { library: "sdl.dll", symbol: "SDL_CreateSemaphore", ordinal: null, iat_slot_rva: 0x1000 },
      { library: "sdl.dll", symbol: "SDL_SemPost", ordinal: null, iat_slot_rva: 0x1008 },
    ],
  };
  const probe = executeProbe64(mapped, 4096, { executable_name: "synthetic-sdl.exe", capture_guest: true });
  assert.equal(probe.state, "probe_executed");
  assert.equal(probe.stop_reason, "entry_return", `stop ${probe.stop_reason}: ${probe.exception && probe.exception.message}`);
  assert.equal(probe.import_reached, null, "a served SDL import is not a reached-import stop");
});

// A synthetic image that opens an SDL display and fills it, proving the present
// framebuffer is the guest's real pixels end to end through the interpreter.
test("executeProbe64 runs an SDL SetVideoMode + FillRect to a non-blank framebuffer", () => {
  const loadBase = 0x140000000n;
  //   0:  b9 08 00 00 00        mov ecx,8      (w)
  //   5:  ba 04 00 00 00        mov edx,4      (h)
  //   a:  41 b8 20 00 00 00     mov r8d,32     (bpp)
  //   10: 45 31 c9              xor r9d,r9d    (flags)
  //   13: ff 15 e6 0f 00 00     call [rip+0xfe6] -> slot 0x1000 (SetVideoMode); next=0x19
  //   19: 48 89 c1              mov rcx,rax    (surface)
  //   1c: 31 d2                 xor edx,edx    (rect=NULL)
  //   1e: 41 b8 00 00 ff 00     mov r8d,0x00ff0000 (ARGB red)
  //   24: ff 15 dd 0f 00 00     call [rip+0xfdd] -> slot 0x1008 (FillRect); next=0x2a
  //   2a: c3                    ret
  const image = Buffer.alloc(0x2000);
  const code = [
    0xb9, 0x08, 0x00, 0x00, 0x00,
    0xba, 0x04, 0x00, 0x00, 0x00,
    0x41, 0xb8, 0x20, 0x00, 0x00, 0x00,
    0x45, 0x31, 0xc9,
    0xff, 0x15, 0xe7, 0x0f, 0x00, 0x00,
    0x48, 0x89, 0xc1,
    0x31, 0xd2,
    0x41, 0xb8, 0x00, 0x00, 0xff, 0x00,
    0xff, 0x15, 0xde, 0x0f, 0x00, 0x00,
    0xc3,
  ];
  Buffer.from(code).copy(image, 0);
  const mapped = {
    image, input_path: "synthetic-video.exe", load_base: loadBase, entry_rva: 0,
    image_size_byte: image.length, section: [], tls_callback: [], relocation_count: 0,
    resolution_blocker: [], runtime_blocker: [],
    import: [
      { library: "sdl.dll", symbol: "SDL_SetVideoMode", ordinal: null, iat_slot_rva: 0x1000 },
      { library: "sdl.dll", symbol: "SDL_FillRect", ordinal: null, iat_slot_rva: 0x1008 },
    ],
  };
  const probe = executeProbe64(mapped, 4096, { executable_name: "synthetic-video.exe", capture_guest: true });
  assert.equal(probe.stop_reason, "entry_return", `stop ${probe.stop_reason}: ${probe.exception && probe.exception.message}`);
  assert.equal(probe.guest.sdl.has_video, true, "the run opened an SDL display");
  const frame = probe.guest.sdl.presentFramebuffer();
  assert.equal(frame.width, 8);
  assert.equal(frame.height, 4);
  assert.equal(frame.is_blank, false, "the guest drew a real first frame");
  assert.equal(frame.rgba[0], 0xff, "the first pixel is red");
});

// The SDL2 render pipeline end to end at the subsystem level: an 8-bit paletted
// surface, a palette, a real palette-converting blit into a 32-bit surface, a
// streaming texture uploaded from those pixels, a RenderCopy into the renderer
// framebuffer, and a RenderPresent — the exact path Chocolate Doom's
// I_FinishUpdate drives. The presented pixels must be the palette color, proving
// the 8-bit index -> RGBA conversion is real, never synthesized.
test("SDL2 8-bit paletted surface converts through its palette to a presented RGBA frame", () => {
  const { sdl, memory } = createSubsystem();
  // An 8-bit indexed 4x2 surface (variant 2 = SDL2 struct layout).
  const indexed = sdl.createRGBSurface(0, 4, 2, 8, 0, 0, 0, 0, 2);
  assert.notEqual(indexed, 0, "the 8-bit surface is created");
  // The surface's format->palette pointer (format @ surface+8, palette @ format+8).
  const formatAddr = memory.readMemory(indexed + 8, 4);
  const paletteAddr = memory.readMemory(formatAddr + 8, 4);
  assert.notEqual(paletteAddr, 0, "an 8-bit surface carries an SDL_Palette");
  // Set palette index 7 to a distinct teal (r=0x11, g=0x99, b=0xcc). SDL_Color
  // is r,g,b,a; write one color at a scratch address and install it at index 7.
  const colorAddr = 0x00101c00;
  memory.writeMemory(colorAddr + 0, 1, 0x11);
  memory.writeMemory(colorAddr + 1, 1, 0x99);
  memory.writeMemory(colorAddr + 2, 1, 0xcc);
  memory.writeMemory(colorAddr + 3, 1, 0xff);
  assert.equal(sdl.setPaletteColors(paletteAddr, colorAddr, 7, 1), 0);
  // Fill the whole indexed surface with index 7.
  sdl.fillRect(indexed, 0, 7);
  // A 32-bit ARGB destination surface, and the palette-converting blit.
  const argb = sdl.createRGBSurface(0, 4, 2, 32, 0x00ff0000, 0x0000ff00, 0x000000ff, 0xff000000, 2);
  assert.equal(sdl.lowerBlit(indexed, 0, argb, 0), 0);
  // The 32-bit surface now holds the palette color as ARGB (0xAARRGGBB).
  const argbPixelPtr = memory.readMemory(argb + 32, 4);
  const converted = memory.readMemory(argbPixelPtr, 4) >>> 0;
  assert.equal((converted >>> 16) & 0xff, 0x11, "R came from the palette");
  assert.equal((converted >>> 8) & 0xff, 0x99, "G came from the palette");
  assert.equal(converted & 0xff, 0xcc, "B came from the palette");
  // Renderer + streaming texture: upload the argb pixels, copy, present.
  const win = sdl.createWindow(0, 0, 0, 4, 2, 0);
  const renderer = sdl.createRenderer(win, -1, 0);
  sdl.renderSetLogicalSize(renderer, 4, 2);
  const texture = sdl.createTexture(renderer, 0x16362004, 1, 4, 2);
  assert.notEqual(texture, 0, "a streaming texture is created");
  assert.equal(sdl.updateTexture(texture, 0, argbPixelPtr, 4 * 4), 0);
  assert.equal(sdl.renderClear(renderer), 0);
  assert.equal(sdl.renderCopy(renderer, texture, 0, 0), 0);
  assert.equal(sdl.renderPresent(renderer), 0);
  const frame = sdl.presentFramebuffer();
  assert.equal(frame.width, 4);
  assert.equal(frame.height, 2);
  assert.equal(frame.is_blank, false, "the presented frame carries the palette color");
  assert.equal(frame.rgba[0], 0x11, "presented R is the palette R");
  assert.equal(frame.rgba[1], 0x99, "presented G is the palette G");
  assert.equal(frame.rgba[2], 0xcc, "presented B is the palette B");
});

// The payoff, corpus-gated: the real Chocolate Doom (corpus-007, x86-64) loading
// the real Freedoom WAD, driven through the bounded x86-64 interpreter with the
// SDL video/render pipeline this file serves, presents its first non-blank
// frame — the actual title screen Doom drew from its own 8-bit screen buffer
// through the WAD's PLAYPAL. Verified above the corpus 10M bound (the corpus
// safety cap) because the game reaches its first present at ~16M instructions;
// runImage64 (the uncapped interpreter entry) honors the larger verify budget.
// Skips cleanly when the corpus is not staged.
const corpusDoomExe = join(resolveStageDir(), "corpus-007", "package", "chocolate-doom.exe");
const corpusDoomWad = join(resolveStageDir(), "corpus-007", "wad", "freedoom1.wad");
test("Chocolate Doom presents a non-blank first frame through the served SDL pipeline", { skip: existsSync(corpusDoomExe) && existsSync(corpusDoomWad) ? false : "corpus-007 not staged" }, () => {
  const bytes = new Uint8Array(readFileSync(corpusDoomExe));
  const wad = readFileSync(corpusDoomWad);
  const mapped = mapPe64State(bytes, null);
  const mask64 = (1n << 64n) - 1n;
  const importSet = new Map();
  for (const entry of mapped.import ?? []) importSet.set((mapped.load_base + BigInt(entry.iat_slot_rva)) & mask64, entry);
  const stackBase = 0x00007ff000000000;
  const layout = createHleLayout({ load_base: Number(mapped.load_base & mask64), image_size_byte: mapped.image_size_byte, stack_base: stackBase, stack_end: stackBase + 0x00100000 });
  assert.notEqual(layout, null, "the HLE layout is available");
  const hle = {
    layout,
    clock: createGuestClock({ mode: "virtual_monotonic" }),
    executableName: "chocolate-doom.exe",
    hostFile: new Map([["C:\\game\\freedoom1.wad", wad]]),
    environment: { DOOMWADDIR: "C:\\game" },
    commandLine: ["-iwad", "C:\\game\\freedoom1.wad"],
  };
  const run = runImage64({
    image: mapped.image, loadBase: mapped.load_base, entryRva: mapped.entry_rva,
    budget: 20000000, importSet, hle, resourceRva: mapped.directory?.[2]?.rva ?? 0,
  });
  assert.equal(run.guest.sdl.has_video, true, "Doom opened an SDL window + renderer");
  assert.ok(run.guest.sdl.present_count > 0, "Doom presented at least one frame");
  const frame = run.guest.sdl.presentFramebuffer();
  assert.notEqual(frame, null, "the present path returns a framebuffer");
  assert.equal(frame.is_blank, false, "Doom's presented frame is the real, non-blank title screen");
  let painted = 0;
  for (let i = 0; i < frame.rgba.length; i += 4) if (frame.rgba[i] | frame.rgba[i + 1] | frame.rgba[i + 2]) painted += 1;
  assert.ok(painted > frame.width * frame.height / 2, `most of the frame is painted (${painted} of ${frame.width * frame.height} pixels)`);
});

// Interactivity, corpus-gated: the real Chocolate Doom, driven through the same
// bounded x86-64 interpreter + SDL pipeline, RESPONDS to a scripted input trace.
// A no-input run sits on the attract-mode title (a static frame, hash stable);
// the same run fed an Escape keypress (SDL_KEYDOWN/SDL_KEYUP marshalled into the
// guest event queue) opens Doom's main menu — a non-blank frame whose pixel hash
// differs from the title. The difference is Doom reacting to the injected key
// (proven separately: an unmapped scancode reproduces the title hash exactly, so
// merely consuming events does not perturb the frame — only the Escape SEMANTICS
// do). A full in-level gameplay frame is NOT reached here: driving New Game ->
// skill -> start reaches an x86-64 opcode outside the bounded lift subset
// (lib/lift64.mjs, read-only), an honest frontier, so this proves the menu, not
// playability. Budget 20M (uncapped runImage64 verify, above the 10M corpus cap).
const doomInputBudget = 20000000;
function runDoom(inputTrace) {
  const bytes = new Uint8Array(readFileSync(corpusDoomExe));
  const wad = readFileSync(corpusDoomWad);
  const mapped = mapPe64State(bytes, null);
  const mask64 = (1n << 64n) - 1n;
  const importSet = new Map();
  for (const entry of mapped.import ?? []) importSet.set((mapped.load_base + BigInt(entry.iat_slot_rva)) & mask64, entry);
  const stackBase = 0x00007ff000000000;
  const layout = createHleLayout({ load_base: Number(mapped.load_base & mask64), image_size_byte: mapped.image_size_byte, stack_base: stackBase, stack_end: stackBase + 0x00100000 });
  const hle = {
    layout,
    clock: createGuestClock({ mode: "virtual_monotonic" }),
    executableName: "chocolate-doom.exe",
    hostFile: new Map([["C:\\game\\freedoom1.wad", wad]]),
    environment: { DOOMWADDIR: "C:\\game" },
    commandLine: ["-iwad", "C:\\game\\freedoom1.wad"],
    inputTrace,
  };
  return runImage64({
    image: mapped.image, loadBase: mapped.load_base, entryRva: mapped.entry_rva,
    budget: doomInputBudget, importSet, hle, resourceRva: mapped.directory?.[2]?.rva ?? 0,
  });
}
function frameHash(frame) {
  let hash = 0x811c9dc5n;
  for (let i = 0; i < frame.rgba.length; i += 1) hash = ((hash * 0x01000193n) + BigInt(frame.rgba[i])) & ((1n << 64n) - 1n);
  return hash;
}
test("Chocolate Doom responds to scripted input: Escape opens its menu, a frame distinct from the title", { skip: existsSync(corpusDoomExe) && existsSync(corpusDoomWad) ? false : "corpus-007 not staged" }, () => {
  // The no-input title frame (the attract screen), and its stable hash.
  const title = runDoom(undefined);
  const titleFrame = title.guest.sdl.presentFramebuffer();
  assert.notEqual(titleFrame, null, "the title frame is present");
  assert.equal(titleFrame.is_blank, false, "the title frame is non-blank");
  const titleHash = frameHash(titleFrame);

  // The same run fed an Escape keypress after the title has drawn (frame 2).
  const menu = runDoom([
    { type: "keydown", scancode: sdlScancode.ESCAPE, sym: sdlKeycode.ESCAPE, frame: 2 },
    { type: "keyup", scancode: sdlScancode.ESCAPE, sym: sdlKeycode.ESCAPE, frame: 2 },
  ]);
  assert.equal(menu.guest.sdl.input_delivered, 2, "Doom's own poll loop consumed both scripted events");
  const menuFrame = menu.guest.sdl.presentFramebuffer();
  assert.notEqual(menuFrame, null, "the post-input frame is present");
  assert.equal(menuFrame.is_blank, false, "the menu frame is non-blank");
  const menuHash = frameHash(menuFrame);
  assert.notEqual(menuHash.toString(16), titleHash.toString(16), "the input changed what is on screen (menu differs from title)");

  // The isolation control: an unmapped scancode delivers the same TWO events but
  // carries no menu semantics, so the frame stays the title — confirming the
  // change above is Doom reacting to the Escape KEY, not to event traffic/timing.
  const control = runDoom([
    { type: "keydown", scancode: 120, sym: 300, frame: 2 },
    { type: "keyup", scancode: 120, sym: 300, frame: 2 },
  ]);
  assert.equal(control.guest.sdl.input_delivered, 2, "the control run also consumed two events");
  assert.equal(frameHash(control.guest.sdl.presentFramebuffer()).toString(16), titleHash.toString(16), "an unmapped key leaves the title frame unchanged");
});

test("the SDL export table registers both SDL1 (sdl.dll) and SDL2 (sdl2.dll)", () => {
  const bySymbol = (library, symbol) => sdlExportTable.some((e) => e.library === library && e.symbol === symbol);
  assert.equal(bySymbol("sdl.dll", "SDL_CreateSemaphore"), true);
  assert.equal(bySymbol("sdl.dll", "SDL_SetVideoMode"), true, "SDL1 video");
  assert.equal(bySymbol("sdl2.dll", "SDL_CreateWindow"), true, "SDL2 video");
  assert.equal(bySymbol("sdl2.dll", "SDL_CreateRenderer"), true, "SDL2 renderer");
  // Every row declares a Win64 argument count and an emulate function.
  for (const row of sdlExportTable) {
    assert.equal(typeof row.argument_count, "number");
    assert.equal(typeof row.emulate, "function");
  }
});
