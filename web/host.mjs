// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The browser host: runs a Windows PE LIVE in the browser through the resumable
// session (lib/live.mjs) — stepping the guest in chunks, blitting its own RGBA
// surface to the canvas each chunk, and forwarding real keyboard/mouse input
// into the guest's SDL queue. No pixels are fabricated; the canvas is exactly
// what the runtime paints. node: specifiers resolve through the index.html
// import map; Buffer is installed as a global before this module loads.

import { createLiveSession } from "../lib/live.mjs";
import { sdlScancode, sdlKeycode } from "../lib/sdl.mjs";

const canvas = document.getElementById("screen");
const context2d = canvas.getContext("2d");
const status = document.getElementById("status");
const budgetInput = document.getElementById("budget");

let session = null;
let running = false;
let startedAt = 0;

function report(text) { status.textContent = text; }

function draw(frame) {
  if (canvas.width !== frame.width || canvas.height !== frame.height) {
    canvas.width = frame.width;
    canvas.height = frame.height;
  }
  const rgba = frame.rgba;
  context2d.putImageData(new ImageData(new Uint8ClampedArray(rgba.buffer, rgba.byteOffset, rgba.byteLength), frame.width, frame.height), 0, 0);
}

// Instructions per inner sub-step. Kept small so a single sub-step never
// blocks the main thread for long; the tick loops sub-steps until its time
// budget (below) is spent, so input latency stays ~one budget.
function subChunk() {
  return Math.max(2000, Math.min(200000, Number(budgetInput.value) || 8000));
}
const TICK_BUDGET_MS = 24; // ~40 ticks/sec: responsive UI + input, no long freeze.

// The live loop: within each tick, run sub-steps until the time budget is
// spent (so the guest advances as fast as the interpreter allows), then draw
// the frame and yield to the event loop so queued input + paint land. This
// keeps the tab responsive (no multi-hundred-ms freeze) at the same throughput.
function loop() {
  if (!running || session === null) return;
  const tickStart = performance.now();
  let result;
  do {
    result = session.step(subChunk());
  } while (!session.done && !(session.stopReason === "import_present" && !session.hasVideo) && performance.now() - tickStart < TICK_BUDGET_MS);
  draw(session.frame());
  const seconds = (performance.now() - startedAt) / 1000;
  const ips = Math.round(session.instructionCount / Math.max(seconds, 0.001));
  report(
    `machine ${result.machine ?? "x86_64"} · ${session.instructionCount.toLocaleString()} instruction · ` +
    `${session.presentCount} frame · ${session.hasVideo ? "video" : "no video"} · ` +
    `${(ips / 1e6).toFixed(2)}M ips · stop ${session.stopReason ?? "-"}` +
    (session.done ? " · DONE" : " · running… (click the canvas, then use the keyboard)"),
  );
  if (session.done || (session.stopReason === "import_present" && !session.hasVideo)) {
    // A non-video program (e.g. PuTTY) stops at its first import wall — one
    // frame, then done. A video program keeps looping.
    if (!session.hasVideo) { running = false; return; }
  }
  setTimeout(loop, 0);
}

function start(bytes, option, label) {
  running = false;
  report(`loading ${label}…`);
  // Defer so the "loading" text paints before the (blocking) context build.
  setTimeout(() => {
    try {
      session = createLiveSession(new Uint8Array(bytes), option);
      startedAt = performance.now();
      running = true;
      canvas.focus();
      loop();
    } catch (error) {
      report(`error: ${error?.stack ?? error}`);
      throw error;
    }
  }, 0);
}

async function fetchBytes(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`fetch ${url} -> HTTP ${response.status}`);
  return response.arrayBuffer();
}

// --- input: browser KeyboardEvent.code / mouse -> SDL2 events ---------------
// Map only the keys the sample programs use; an unmapped key is ignored.
const scanFor = (name) => (typeof sdlScancode === "object" ? sdlScancode[name] : undefined);
const symFor = (name) => (typeof sdlKeycode === "object" ? sdlKeycode[name] : undefined);
const keyByCode = {
  Escape: "ESCAPE", Enter: "RETURN", NumpadEnter: "RETURN", Space: "SPACE", Tab: "TAB", Backspace: "BACKSPACE",
  ArrowUp: "UP", ArrowDown: "DOWN", ArrowLeft: "LEFT", ArrowRight: "RIGHT",
  ControlLeft: "LCTRL", ControlRight: "RCTRL", ShiftLeft: "LSHIFT", ShiftRight: "RSHIFT",
  AltLeft: "LALT", AltRight: "RALT",
  KeyW: "W", KeyA: "A", KeyS: "S", KeyD: "D", KeyE: "E", KeyY: "Y", KeyN: "N",
  Digit1: "1", Digit2: "2", Digit3: "3", Digit4: "4", Digit5: "5", Digit6: "6", Digit7: "7",
};
function sdlKeyEvent(type, event) {
  const name = keyByCode[event.code];
  if (!name || session === null) return;
  const scancode = scanFor(name);
  if (scancode === undefined) return;
  session.sendInput([{ type, scancode, sym: symFor(name) ?? 0, mod: 0 }]);
  event.preventDefault();
}
canvas.tabIndex = 0;
canvas.addEventListener("keydown", (event) => sdlKeyEvent("keydown", event));
canvas.addEventListener("keyup", (event) => sdlKeyEvent("keyup", event));
function mouseXY(event) {
  const rect = canvas.getBoundingClientRect();
  return { x: Math.round((event.clientX - rect.left) * canvas.width / rect.width), y: Math.round((event.clientY - rect.top) * canvas.height / rect.height) };
}
canvas.addEventListener("mousemove", (event) => { if (session) { const p = mouseXY(event); session.sendInput([{ type: "mousemove", x: p.x, y: p.y }]); } });
canvas.addEventListener("mousedown", (event) => { if (session) { const p = mouseXY(event); session.sendInput([{ type: "mousedown", x: p.x, y: p.y, button: event.button + 1 }]); canvas.focus(); event.preventDefault(); } });
canvas.addEventListener("mouseup", (event) => { if (session) { const p = mouseXY(event); session.sendInput([{ type: "mouseup", x: p.x, y: p.y, button: event.button + 1 }]); } });
canvas.addEventListener("contextmenu", (event) => event.preventDefault());

// --- buttons ----------------------------------------------------------------
document.getElementById("file").addEventListener("change", async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  start(await file.arrayBuffer(), {}, file.name);
});
document.getElementById("sample").addEventListener("click", async () => {
  try { start(await fetchBytes("./payload/putty.exe"), {}, "putty.exe"); }
  catch (error) { report(`error: ${error.message} (drop a .exe with the picker instead)`); }
});
const doomButton = document.getElementById("doom");
if (doomButton) doomButton.addEventListener("click", async () => {
  try {
    report("fetching Chocolate Doom + Freedoom WAD (28 MB)…");
    const [exe, wad] = await Promise.all([fetchBytes("./payload/chocolate-doom.exe"), fetchBytes("./payload/freedoom1.wad")]);
    start(exe, {
      hostFile: new Map([["C:\\game\\freedoom1.wad", new Uint8Array(wad)]]),
      environment: { DOOMWADDIR: "C:\\game" },
      commandLine: ["-iwad", "C:\\game\\freedoom1.wad"],
    }, "Chocolate Doom (live — slow: ~a minute to first frame at interpreter speed)");
  } catch (error) { report(`error: ${error.message}`); }
});

report("ready — Run PuTTY (renders its dialog), or Run Doom (live, slow). Click the canvas, then use the keyboard.");
