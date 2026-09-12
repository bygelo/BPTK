// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The byte-driven present entry (browser display milestone 1: bytes -> surface).
// runImageBytes maps and runs a PE from an in-memory Uint8Array with no
// filesystem — the same bounded probe the corpus runs, minus resolvePackage and
// readExecutable — and returns the machine, the probe state, the stop reason,
// the instruction count, and the GDI RGBA surface. It is fully verifiable in
// Node (test/present.test.mjs); the browser host page that draws the surface is
// milestone 2 and is not built here.
//
// The canonical loaders (lib/pe.mjs, lib/pe64.mjs) accept a pre-read image, so
// this path reuses the exact PE parse and bounded interpreter the path-based run
// uses — no duplicated parser, no mock. The surface: the runtime does not yet
// expose the interpreter's guest, and no BeginPaint/present path is served, so
// when no window client surface is observable the honest result is a cleared
// surface at the default window size (never null, never fabricated pixels).
// Surfacing a painted guest bitmap is milestone 2 (it needs the read-only
// interpreter to expose its guest and a served paint path).

import { InputError } from "./input.mjs";
import { executionBoundDefault } from "./bound.mjs";
import { mapPe32ForRuntime } from "./pe.mjs";
import { mapPe64State } from "./pe64.mjs";
import { executeProbe64 } from "./exec64.mjs";
import { chooseStackBase, executeProbe, normalizeStackSize, refuseI386Execution, RuntimeFault } from "./i386.mjs";
import { computeImportService, createHleLayout } from "./hle.mjs";

// The default present surface when no window client surface is observable. VGA
// 640x480 is the deterministic stand-in the milestone-1 present path clears.
export const defaultWindowSize = Object.freeze({ width: 640, height: 480 });

const defaultInstructionBudget = 1000000;

// The declared byte-path execution profile. Mirrors the manifest execution
// object the corpus feeds runPackage: the single supported profile plus a
// bounded instruction budget.
function resolveProfile(option) {
  const budget = option?.instruction_budget_count ?? option?.execution?.instruction_budget_count ?? defaultInstructionBudget;
  if (!Number.isSafeInteger(budget) || budget < 1 || budget > executionBoundDefault.instruction_count) {
    throw new InputError("invalid_instruction_budget", `instruction_budget_count must be an integer from 1 through ${executionBoundDefault.instruction_count}`);
  }
  return { profile: "i386_probe_v1", instruction_budget_count: budget };
}

// A bounded, filesystem-free machine peek: read the DOS e_lfanew, verify the PE
// signature, and return the machine word. Mirrors lib/pe64.mjs peekPeMachine
// without the fs read, so the byte path never opens a file.
function peekMachineBytes(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new InputError("missing_input", "runImageBytes requires a Uint8Array image");
  if (bytes.length < 0x40) throw new InputError("invalid_dos_signature", "Image is too small for a DOS header");
  if (bytes[0] !== 0x4d || bytes[1] !== 0x5a) throw new InputError("invalid_dos_signature", "Image does not start with MZ");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const peOffset = view.getUint32(0x3c, true);
  if (peOffset + 6 > bytes.length) throw new InputError("invalid_pe_signature", "PE header is out of range");
  if (bytes[peOffset] !== 0x50 || bytes[peOffset + 1] !== 0x45 || bytes[peOffset + 2] !== 0 || bytes[peOffset + 3] !== 0) {
    throw new InputError("invalid_pe_signature", "PE signature is missing");
  }
  return view.getUint16(peOffset + 4, true);
}

// Produce a cleared RGBA surface at the given dimension. The pixel buffer is a
// plain Uint8Array of width*height*4, RGBA, zero-filled.
function clearedSurface(width, height) {
  return { width, height, rgba: new Uint8Array(width * height * 4) };
}

// The cleared fallback surface: a default-size zeroed buffer. It is returned
// only when no guest is exposed (the i386 path today) or when the run created
// no window to composite — never in place of real painted pixels.
function extractSurface() {
  return clearedSurface(defaultWindowSize.width, defaultWindowSize.height);
}

// Whether the live session should keep blitting, and which present counter
// the host reports. A WGL guest that has MakeCurrent (or has SwapBuffers'd)
// is video even when SDL never allocated a software framebuffer — an SDL2
// OpenGL window is created that way. A recorded glDrawArrays is not a present.
export function guestPresentState(guest) {
  if (guest === null || guest === undefined) {
    return { has_video: false, present_count: 0, source: "none" };
  }
  const gl = guest.gl;
  const sdl = guest.sdl;
  const isGlPresented = gl !== undefined && gl.is_presented === true;
  const glCount = typeof gl?.describe === "function" ? (gl.describe().present_count ?? 0) : 0;
  const sdlCount = sdl?.present_count ?? 0;
  const hasGlContext = typeof gl?.currentContext === "function" && (gl.currentContext() >>> 0) !== 0;
  const hasSdlVideo = sdl !== undefined && sdl.has_video === true;
  return {
    has_video: hasSdlVideo || isGlPresented || hasGlContext,
    present_count: isGlPresented ? glCount : sdlCount,
    source: isGlPresented ? "gl" : hasSdlVideo ? "sdl" : "none",
  };
}

// Composite the windows a run created into an RGBA present surface. The x64
// guest (lib/exec64.mjs exposes it under capture_guest) holds the GDI and USER
// subsystems; gdi.compositeDesktop paints the window manager's live windows
// (frame + controls, by class) into a fresh surface. When the run created no
// window (no guest, or an empty window list) the honest result is the cleared
// fallback, so a surface is always returned, never a fabricated one.
//
// A WGL title that reached gdi32!SwapBuffers publishes its GL color buffer as
// the front buffer. That snapshot is a presented frame (putImageData of those
// bytes), not a recorded glDrawArrays. The GL front buffer wins once SwapBuffers
// has run, even if SDL later opened a blank software surface; SDL software video
// still wins when the guest never swapped GL (Chocolate Doom).
export function composeGuestSurface(guest) {
  if (guest === null || guest === undefined) return extractSurface();
  if (guest.gl !== undefined && guest.gl.is_presented === true && typeof guest.gl.presentFramebuffer === "function") {
    const frame = guest.gl.presentFramebuffer();
    if (frame !== null) return { width: frame.width, height: frame.height, rgba: frame.rgba };
  }
  if (guest.sdl !== undefined && guest.sdl.has_video) {
    const frame = guest.sdl.presentFramebuffer();
    if (frame !== null) return { width: frame.width, height: frame.height, rgba: frame.rgba };
  }
  if (guest.gdi === undefined || guest.user === undefined) return extractSurface();
  const snapshot = guest.user.paintSnapshot();
  if (snapshot.length === 0) return extractSurface();
  const surface = guest.gdi.compositeDesktop(snapshot, defaultWindowSize.width, defaultWindowSize.height);
  return { width: surface.width, height: surface.height, rgba: surface.rgba };
}

// Drive a byte-mapped x86-64 image (PE32+) through the bounded interpreter, then
// composite the windows it created into the present surface.
function runImageBytes64(bytes, requestedBase, budget, hostOption) {
  const mapped = mapPe64State(bytes, requestedBase);
  const probe = executeProbe64(mapped, budget, {
    executable_name: hostOption.executable_name ?? "image.exe",
    capture_guest: true,
    host_file: hostOption.host_file,
    environment: hostOption.environment,
    command_line: hostOption.command_line,
    input_trace: hostOption.input_trace,
  });
  return {
    machine: "x86_64",
    state: probe.state,
    stop_reason: probe.stop_reason,
    instruction_count: probe.instruction_count,
    surface: composeGuestSurface(probe.guest),
  };
}

// Drive a byte-mapped i386 image (PE32) through the bounded interpreter, wiring
// the Win32 core HLE exactly as lib/run.mjs does: a fully served image executes
// against the HLE surface; a partially served image is refused with the
// unserved surface named.
function runImageBytes32(bytes, requestedBase, budget) {
  const mapped = mapPe32ForRuntime(bytes, requestedBase, null);
  let runtime;
  if (mapped.report.import_count > 0) {
    let layout = null;
    let service = null;
    try {
      const stackSizeByte = normalizeStackSize(mapped.report.stack_reserve_byte);
      const stackBase = chooseStackBase(mapped.report.load_base, mapped.report.load_base + mapped.report.image_size_byte, stackSizeByte);
      layout = createHleLayout({ ...mapped.report, stack_base: stackBase, stack_end: stackBase + stackSizeByte });
      service = layout === null ? null : computeImportService(mapped.report, layout);
    } catch (error) {
      if (error instanceof RuntimeFault) throw new InputError("hle_layout_unavailable", error.message);
      throw error;
    }
    if (service === null || !service.is_fully_served) {
      const detail = service === null
        ? "no bounded HLE address block is available for this image and stack"
        : `${service.served_count} of ${mapped.report.import_count} import are served (${service.unserved_library.join(", ")} unserved)`;
      runtime = refuseI386Execution(mapped, "import_present", `Execution requires every imported function served by the Win32 core HLE: ${detail}`);
    } else {
      const remapped = mapPe32ForRuntime(bytes, requestedBase, service.import_catalog);
      runtime = executeProbe(remapped, budget, { hle_layout: service.layout, executable_name: "image.exe", capture_guest: true });
    }
  } else {
    runtime = executeProbe(mapped, budget, { executable_name: "image.exe", capture_guest: true });
  }
  return {
    machine: "i386",
    state: runtime.state,
    stop_reason: runtime.stop_reason ?? null,
    instruction_count: runtime.instruction_count ?? 0,
    surface: composeGuestSurface(runtime.guest),
  };
}

// The host-provided run environment a game needs to find its data. A browser
// host supplies its staged data file (an IWAD), the search environment, and the
// argument tail through the same three fields the x86-64 interpreter's HLE
// reads. host_file is a Map (or plain object) of guest c:\ path -> bytes; each
// value is coerced to a Buffer so the read-only host-file store accepts it.
function resolveHostOption(option) {
  let hostFile;
  const source = option.host_file;
  if (source instanceof Map || (source && typeof source === "object")) {
    hostFile = new Map();
    const entry = source instanceof Map ? source.entries() : Object.entries(source);
    for (const [path, bytes] of entry) {
      if (typeof path !== "string") continue;
      const buffer = Buffer.isBuffer(bytes) ? bytes : bytes instanceof Uint8Array ? Buffer.from(bytes) : null;
      if (buffer !== null) hostFile.set(path, buffer);
    }
  }
  return {
    executable_name: typeof option.executable_name === "string" ? option.executable_name : undefined,
    host_file: hostFile,
    environment: option.environment && typeof option.environment === "object" ? option.environment : undefined,
    command_line: Array.isArray(option.command_line) ? option.command_line : undefined,
    input_trace: Array.isArray(option.input_trace) ? option.input_trace : undefined,
  };
}

// runImageBytes(bytes, option): map and run a PE from memory, returning
// { machine, state, stop_reason, instruction_count, surface: { rgba, width, height } }.
// option.load_base overrides the preferred base; option.instruction_budget_count
// (or option.execution.instruction_budget_count) sets the bounded budget.
export function runImageBytes(bytes, option = {}) {
  const image = bytes instanceof Uint8Array ? bytes : null;
  if (image === null) throw new InputError("missing_input", "runImageBytes requires a Uint8Array image");
  const profile = resolveProfile(option);
  const requestedBase = option.load_base ?? null;
  const machineWord = peekMachineBytes(image);
  if (machineWord === 0x8664) return runImageBytes64(image, requestedBase, profile.instruction_budget_count, resolveHostOption(option));
  if (machineWord === 0x14c) return runImageBytes32(image, requestedBase, profile.instruction_budget_count);
  throw new InputError("unsupported_machine", `PE machine 0x${machineWord.toString(16)} is neither i386 nor x86-64`);
}
