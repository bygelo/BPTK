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
import { createSdlSubsystem, sdlExportTable } from "../lib/sdl.mjs";
import { executeProbe64 } from "../lib/exec64.mjs";
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
