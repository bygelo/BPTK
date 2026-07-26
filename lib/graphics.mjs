// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { findCommand } from "./toolchain.mjs";

const chromeCandidate = [
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
];

function findChrome() {
  for (const candidate of chromeCandidate) {
    const runValue = spawnSync(candidate, ["--version"], { encoding: "utf8" });
    if (runValue.status === 0) return { path: candidate, version: runValue.stdout.trim() || runValue.stderr.trim() };
  }
  for (const command of ["google-chrome", "chromium", "chromium-browser"]) {
    const path = findCommand(command);
    if (!path) continue;
    const runValue = spawnSync(path, ["--version"], { encoding: "utf8" });
    if (runValue.status === 0) return { path, version: runValue.stdout.trim() || runValue.stderr.trim() };
  }
  return null;
}

function probeHtml() {
  return `<!doctype html>
<meta charset="utf-8">
<title>pending</title>
<canvas id="surface" width="16" height="16"></canvas>
<script>
const surface = document.getElementById("surface");
const webgl2 = surface.getContext("webgl2");
const webgl = webgl2 ? null : surface.getContext("webgl");
const audio = globalThis.AudioContext || globalThis.webkitAudioContext;
const report = {
  is_webgpu_available: Boolean(navigator.gpu),
  is_webgl2_available: Boolean(webgl2),
  is_webgl_available: Boolean(webgl2 || webgl),
  is_audio_context_available: Boolean(audio),
  is_cross_origin_isolated: globalThis.crossOriginIsolated === true,
  is_shared_array_buffer_available: typeof SharedArrayBuffer === "function",
  webgl_version: webgl2 ? webgl2.getParameter(webgl2.VERSION) : webgl ? webgl.getParameter(webgl.VERSION) : null,
  webgl_renderer: webgl2 ? webgl2.getParameter(webgl2.RENDERER) : webgl ? webgl.getParameter(webgl.RENDERER) : null
};
document.title = btoa(JSON.stringify(report));
</script>`;
}

export function probeGraphics() {
  const chrome = findChrome();
  if (!chrome) {
    return {
      schema_version: 1,
      command: "doctor --graphics",
      state: "blocked",
      browser: null,
      capability: null,
      selected_path: null,
      blocker: ["No supported Chrome or Chromium executable was found"],
      is_retained: false,
    };
  }
  const targetUrl = `data:text/html;base64,${Buffer.from(probeHtml()).toString("base64")}`;
  const runValue = spawnSync(chrome.path, [
      "--headless=new",
      "--disable-background-networking",
      "--disable-component-update",
      "--disable-default-apps",
      "--disable-sync",
      "--metrics-recording-only",
      "--no-first-run",
      "--dump-dom",
      targetUrl,
    ], { encoding: "utf8", timeout: 15000, maxBuffer: 4 * 1024 * 1024 });
  if (runValue.status !== 0) {
    return {
      schema_version: 1,
      command: "doctor --graphics",
      state: "blocked",
      browser: chrome,
      capability: null,
      selected_path: null,
      blocker: [`Browser probe failed with exit ${runValue.status}: ${(runValue.stderr || runValue.error?.message || "no diagnostic").trim().slice(0, 500)}`],
      is_retained: false,
    };
  }
  const titleMatch = runValue.stdout.match(/<title>([^<]+)<\/title>/i);
  if (!titleMatch) throw new Error("Browser probe did not return a result title");
  const capability = JSON.parse(Buffer.from(titleMatch[1], "base64").toString("utf8"));
  const selectedPath = capability.is_webgpu_available ? "webgpu" : capability.is_webgl2_available ? "webgl2" : null;
  const blocker = [];
  if (!selectedPath) blocker.push("Neither WebGPU nor WebGL2 is available in the observed browser profile");
  if (!capability.is_cross_origin_isolated) blocker.push("Cross-origin isolation is absent; threaded package must fall back or block");
  return {
    schema_version: 1,
    command: "doctor --graphics",
    state: selectedPath ? capability.is_cross_origin_isolated ? "supported" : "degraded" : "blocked",
    browser: chrome,
    capability,
    selected_path: selectedPath,
    blocker,
    is_retained: false,
  };
}

export function formatGraphicsDoctor(report) {
  return [
    "BPTK browser graphics probe",
    `State: ${report.state}`,
    `Browser: ${report.browser?.version ?? "missing"}`,
    `Selected path: ${report.selected_path ?? "none"}`,
    ...(report.capability ? [
      `WebGPU: ${report.capability.is_webgpu_available ? "available" : "unavailable"}`,
      `WebGL2: ${report.capability.is_webgl2_available ? "available" : "unavailable"}`,
      `WebGL: ${report.capability.is_webgl_available ? "available" : "unavailable"}`,
      `AudioContext: ${report.capability.is_audio_context_available ? "available" : "unavailable"}`,
      `Cross-origin isolated: ${report.capability.is_cross_origin_isolated ? "yes" : "no"}`,
      `SharedArrayBuffer: ${report.capability.is_shared_array_buffer_available ? "available" : "unavailable"}`,
      `Renderer: ${report.capability.webgl_renderer ?? "unavailable"}`,
    ] : []),
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
    "Probe input and browser profile were ephemeral and removed; no compatibility result was retained",
  ].join("\n");
}
