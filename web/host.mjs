// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The browser host (browser display milestone 2): fetch or accept a PE image,
// run it through the byte-driven present entry, and draw the runtime's own RGBA
// surface onto a 2D canvas. No pixels are fabricated — the canvas shows exactly
// the bytes lib/present.mjs paints. node: specifiers resolve through the import
// map in index.html; Buffer is installed as a global by the boot script before
// this module loads.

import { runImageBytes } from "../lib/present.mjs";

const canvas = document.getElementById("screen");
const status = document.getElementById("status");
const budgetInput = document.getElementById("budget");

function report(text) {
  status.textContent = text;
}

function present(result) {
  const { rgba, width, height } = result.surface;
  canvas.width = width;
  canvas.height = height;
  const context = canvas.getContext("2d");
  context.putImageData(new ImageData(new Uint8ClampedArray(rgba.buffer, rgba.byteOffset, rgba.byteLength), width, height), 0, 0);
  const nonZero = countPainted(rgba);
  report(
    `machine ${result.machine} · state ${result.state} · stop ${result.stop_reason ?? "-"} · ` +
    `${result.instruction_count.toLocaleString()} instruction · surface ${width}x${height} · ` +
    `${nonZero.toLocaleString()} painted pixel`,
  );
}

// A painted pixel is any pixel whose RGB differs from pure black (the cleared
// background), so the report distinguishes a real render from a blank surface.
function countPainted(rgba) {
  let count = 0;
  for (let index = 0; index < rgba.length; index += 4) {
    if (rgba[index] !== 0 || rgba[index + 1] !== 0 || rgba[index + 2] !== 0) count += 1;
  }
  return count;
}

function runBytes(bytes) {
  const budget = Math.max(1, Math.min(10000000, Number(budgetInput.value) || 2000000));
  try {
    report("running…");
    const result = runImageBytes(bytes, { instruction_budget_count: budget });
    present(result);
  } catch (error) {
    report(`error: ${error?.message ?? error}`);
    throw error;
  }
}

// A same-origin payload dropped next to the page (payloads stay out of git, so
// this is copied in only for a test run); the file picker is the general path.
async function runUrl(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`fetch ${url} -> HTTP ${response.status}`);
  runBytes(new Uint8Array(await response.arrayBuffer()));
}

document.getElementById("file").addEventListener("change", async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  runBytes(new Uint8Array(await file.arrayBuffer()));
});

document.getElementById("sample").addEventListener("click", () => {
  runUrl("./payload/putty.exe").catch((error) => report(`error: ${error.message} (drop a .exe with the picker instead)`));
});

// A global the harness can call to run a specific same-origin payload headlessly.
globalThis.bptkRunUrl = runUrl;
report("ready — pick a Windows .exe or use the sample button");
