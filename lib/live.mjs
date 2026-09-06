// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The resumable, input-driven live session (BPTK runtime v2, x86-64 lane CA). A
// browser render loop cannot run a whole guest to completion in one blocking
// call and still stay interactive; it needs to run the guest in CHUNKS, feed
// live input between chunks, and read the current frame each chunk. This file is
// that foundation: createLiveSession(bytes, option) builds ONE persistent guest
// (the multi-region Machine + the live Win32/SDL HLE guest) once, then hands back
// a session that steps the SAME guest incrementally.
//
// The session is a thin, honest driver over three existing surfaces, so it
// invents no execution semantics of its own:
//   - lib/exec64.mjs buildGuestContext64 builds the persistent context, and
//     stepContext resumes the SAME interpreter loop for a bounded number of more
//     instructions (proven bit-identical to a single runImage64 of the summed
//     budget — see test/live.test.mjs). Guest state lives entirely in the
//     context's Machine, so a step never rebuilds or resets anything.
//   - lib/sdl.mjs presentFramebuffer() reads the current RGBA frame the guest
//     drew, and appendInputEvent injects LIVE SDL2 events into the guest's own
//     event queue so the guest's next poll drain sees them (real reaction, never
//     a synthesized frame).
//   - lib/present.mjs defaultWindowSize / the gdi desktop compositor is the
//     fallback surface before the guest opens a video window.
//
// Determinism: given the same image, options, and the same sequence of step /
// sendInput calls, a session reproduces the same architectural state and the
// same frames every run. Bounded: each step runs at most its instruction budget,
// so no single step can spin forever.

import { mapPe64State } from "./pe64.mjs";
import { buildGuestContext64, stepContext } from "./exec64.mjs";
import { createHleLayout } from "./hle.mjs";
import { createGuestClock } from "./clock.mjs";
import { defaultWindowSize } from "./present.mjs";

const MASK64 = (1n << 64n) - 1n;

// The high guest-stack window the interpreter maps (mirrors lib/exec64.mjs
// stackRegionBase / stackSizeDefault). The HLE layout scan needs the stack
// bounds so its arena/virtual/thunk pages never collide with the stack.
const STACK_BASE = 0x00007ff000000000;
const STACK_SIZE_DEFAULT = 0x00100000; // 1 MiB

// A default per-step instruction budget: large enough that a browser frame's
// worth of guest work makes real progress, small enough to stay responsive. A
// caller passes its own budget to step() to tune latency vs. throughput.
export const defaultStepBudget = 2000000;

// Compose the current RGBA present surface from the live guest, exactly as the
// present path does (lib/present.mjs): the SDL video framebuffer when the guest
// opened one, else the window-manager desktop composite, else the cleared
// fallback. Never null, never fabricated pixels — an all-zero frame is honestly
// blank, not synthesized.
function composeFrame(guest) {
  if (guest !== null && guest !== undefined && guest.sdl !== undefined && guest.sdl.has_video) {
    const frame = guest.sdl.presentFramebuffer();
    if (frame !== null) return { width: frame.width, height: frame.height, rgba: frame.rgba, is_blank: frame.is_blank, source: "sdl" };
  }
  if (guest !== null && guest !== undefined && guest.gdi !== undefined && guest.user !== undefined) {
    const snapshot = guest.user.paintSnapshot();
    if (snapshot.length > 0) {
      const surface = guest.gdi.compositeDesktop(snapshot, defaultWindowSize.width, defaultWindowSize.height);
      let blank = true;
      for (let i = 0; i < surface.rgba.length; i += 4) { if (surface.rgba[i] | surface.rgba[i + 1] | surface.rgba[i + 2]) { blank = false; break; } }
      return { width: surface.width, height: surface.height, rgba: surface.rgba, is_blank: blank, source: "gdi" };
    }
  }
  return { width: defaultWindowSize.width, height: defaultWindowSize.height, rgba: new Uint8Array(defaultWindowSize.width * defaultWindowSize.height * 4), is_blank: true, source: "cleared" };
}

// createLiveSession(bytes, option): map the PE32+ image, wire the Win32 core HLE
// (so imports are served and execution can actually run, not stop at the first
// IAT slot), build the persistent guest context ONCE, and return the session.
//
// option:
//   loadBase / requestedBase — the preferred image base (default the PE's own).
//   executableName           — the guest argv[0] name (default "game.exe").
//   hostFile                 — Map<guestPath, Buffer> the guest can open (e.g. a
//                              WAD staged at "C:\\game\\freedoom1.wad").
//   environment              — { NAME: value } the guest environment block.
//   commandLine              — [arg, ...] the guest command line (e.g. ["-iwad", ...]).
//   inputTrace               — an OPTIONAL fixed pre-schedule (loadInputTrace);
//                              live input normally goes through session.sendInput.
//   stackSizeByte            — the guest stack size (default 1 MiB).
//
// The returned session:
//   step(instructionBudget)  — resume the SAME guest for up to instructionBudget
//                              more instructions; returns { instructionCount,
//                              presentCount, stepInstructionCount, stepPresentCount,
//                              stopReason, done, reachedImport, fault }.
//   frame()                  — the current RGBA surface (callable after any step).
//   sendInput(events)        — inject one or more live SDL2 input events into the
//                              guest's event queue for the NEXT step to consume.
//   done / stopReason / instructionCount / presentCount — live status getters.
//   guest / context          — the live HLE guest and its context (for inspection).
export function createLiveSession(bytes, option = {}) {
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) throw new TypeError("createLiveSession requires an image byte buffer");

  const requestedBase = option.loadBase ?? option.requestedBase ?? null;
  const mapped = mapPe64State(bytes, requestedBase);

  const importSet = new Map();
  for (const entry of mapped.import ?? []) {
    importSet.set((mapped.load_base + BigInt(entry.iat_slot_rva)) & MASK64, entry);
  }

  const stackSizeByte = Number.isInteger(option.stackSizeByte) && option.stackSizeByte > 0 ? option.stackSizeByte : STACK_SIZE_DEFAULT;
  const layout = createHleLayout({
    load_base: Number(mapped.load_base & MASK64),
    image_size_byte: mapped.image_size_byte ?? mapped.image.length,
    stack_base: STACK_BASE,
    stack_end: STACK_BASE + stackSizeByte,
  });
  if (layout === null) throw new Error("createLiveSession could not place the Win32 core HLE layout for this image");

  const hle = {
    layout,
    clock: createGuestClock({ mode: "virtual_monotonic" }),
    executableName: typeof option.executableName === "string" ? option.executableName : "game.exe",
    hostFile: option.hostFile instanceof Map ? option.hostFile : undefined,
    environment: option.environment && typeof option.environment === "object" ? option.environment : undefined,
    commandLine: Array.isArray(option.commandLine) ? option.commandLine : undefined,
    inputTrace: Array.isArray(option.inputTrace) ? option.inputTrace : undefined,
  };

  // Build the persistent guest context ONCE. Every step resumes this exact
  // Machine + HLE guest; nothing below rebuilds it.
  const context = buildGuestContext64({
    image: mapped.image,
    loadBase: mapped.load_base,
    entryRva: mapped.entry_rva,
    stackSizeByte,
    importSet,
    hle,
    resourceRva: mapped.directory?.[2]?.rva ?? 0,
  });

  const guest = context.hleContext === null ? null : context.hleContext.guest;
  const sdl = guest === null ? null : (guest.sdl ?? null);

  const session = {
    context,
    guest,

    // Resume the SAME guest for up to instructionBudget more instructions.
    step(instructionBudget = defaultStepBudget) {
      return stepContext(context, instructionBudget);
    },

    // The current RGBA present surface. Callable at any time, including before
    // the guest has opened a window (a cleared surface) and after it exits.
    frame() {
      return composeFrame(guest);
    },

    // Inject one live SDL2 input event, or an array of them, into the guest's
    // event queue so the NEXT step's guest poll drain sees them. Each event is
    // { type: "keydown"|"keyup"|"mousemove"|"mousedown"|"mouseup"|"quit", ... }
    // with the SDL2 keysym / mouse fields. Returns the number accepted (0 when
    // the guest has no SDL subsystem, an honest no-op rather than a fake).
    sendInput(events) {
      if (sdl === null || typeof sdl.appendInputEvent !== "function") return 0;
      return sdl.appendInputEvent(events);
    },

    get done() { return context.runState !== undefined && context.runState.done === true; },
    get stopReason() { return context.runState === undefined ? null : context.runState.stopReason; },
    get instructionCount() { return context.runState === undefined ? 0 : context.runState.instructionCount; },
    get presentCount() { return sdl === null ? 0 : sdl.present_count; },
    get hasVideo() { return sdl !== null && sdl.has_video; },
    get reachedImport() { return context.runState === undefined ? null : context.runState.reachedImport; },
  };

  return session;
}
