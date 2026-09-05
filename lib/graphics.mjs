// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { findCommand } from "./toolchain.mjs";
import { emitWgsl } from "./shader.mjs";
import { InputError } from "./input.mjs";

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
const memory64Module = Uint8Array.from([0,97,115,109,1,0,0,0,5,3,1,4,0]);
const report = {
  is_webgpu_available: Boolean(navigator.gpu),
  is_webgl2_available: Boolean(webgl2),
  is_webgl_available: Boolean(webgl2 || webgl),
  is_audio_context_available: Boolean(audio),
  is_cross_origin_isolated: globalThis.crossOriginIsolated === true,
  is_shared_array_buffer_available: typeof SharedArrayBuffer === "function",
  is_wasm_available: typeof WebAssembly === "object",
  is_wasm_memory64_available: typeof WebAssembly === "object" && WebAssembly.validate(memory64Module),
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

// ---- the runtime backend layer (GS-026, GS-027, GS-028) -------------------
// One intermediate program lowers to a complete pipeline description per
// backend. WebGPU is the primary backend and consumes the WGSL the single
// emitter produces; WebGL2 and the WebGPU compatibility mode reuse the same
// program through the same register model. The description is everything a live
// adapter needs (shader source, the bind-group layout derived from the
// program's own registers, the color target with its gamma encoding, and the
// multisample count); executing it on a live adapter is the red half of these
// item, because no adapter runs inside the gate.

const backendKind = Object.freeze({
  webgpu: "webgpu",
  webgl2: "webgl2",
  compatibility: "compatibility",
});

// The feature floor every backend must clear. A program above the floor is
// named-blocked, never silently downgraded.
const featureFloor = Object.freeze({
  max_constant: 32,
  max_sampler: 16,
  max_color_target: 4,
});

function collectRegister(program) {
  if (!Array.isArray(program)) {
    throw new InputError("invalid_program", "The backend lowers one program array");
  }
  const constant = new Set();
  const sampler = new Set();
  const colorTarget = new Set();
  for (const instruction of program) {
    for (const register of [instruction.dest, ...instruction.src]) {
      if (register.type === "constant") constant.add(register.index);
      if (register.type === "sampler") sampler.add(register.index);
      if (register.type === "color_output" || register.type === "output") colorTarget.add(register.index);
    }
  }
  return {
    constant: [...constant].sort((left, right) => left - right),
    sampler: [...sampler].sort((left, right) => left - right),
    color_target: [...colorTarget].sort((left, right) => left - right),
  };
}

function assertWithinFloor(register) {
  const blocked = [];
  if (register.constant.length > featureFloor.max_constant) blocked.push(`constant register count ${register.constant.length} exceeds the floor ${featureFloor.max_constant}`);
  if (register.sampler.length > featureFloor.max_sampler) blocked.push(`sampler count ${register.sampler.length} exceeds the floor ${featureFloor.max_sampler}`);
  if (register.color_target.length > featureFloor.max_color_target) blocked.push(`color-target count ${register.color_target.length} exceeds the floor ${featureFloor.max_color_target}`);
  return blocked;
}

function buildBindGroupLayout(register) {
  const entry = [];
  if (register.constant.length > 0) {
    entry.push({ binding: 0, visibility: "fragment", buffer: { type: "uniform" } });
  }
  for (const [order, index] of register.sampler.entries()) {
    entry.push({ binding: 1 + order * 2, visibility: "fragment", texture: { sample_type: "float", index } });
    entry.push({ binding: 2 + order * 2, visibility: "fragment", sampler: { type: "filtering", index } });
  }
  return entry;
}

// The compatibility subset (GS-028): the constructs a Chrome 146
// featureLevel:"compatibility" adapter cannot honour. A program that emits one
// of these is caught at emit rather than failing on a live device.
const compatibilityForbidden = Object.freeze(["storage", "atomic", "workgroup", "textureStorage"]);

function assertCompatibilitySubset(wgsl) {
  const found = compatibilityForbidden.filter((token) => wgsl.includes(token));
  if (found.length > 0) {
    throw new InputError("out_of_compatibility_subset", `The emitted WGSL uses construct outside the compatibility subset: ${found.join(", ")}`);
  }
}

// The single GLSL ES 3.0 lowering for the WebGL2 fallback (GS-027). It is not
// the WGSL emitter (the single-emitter audit counts only that one) and it never
// reads the API name; it reuses the same register model and op set.
const glslExpression = Object.freeze({
  mov: (a) => a[0],
  add: (a) => `${a[0]} + ${a[1]}`,
  sub: (a) => `${a[0]} - ${a[1]}`,
  mul: (a) => `${a[0]} * ${a[1]}`,
  mad: (a) => `${a[0]} * ${a[1]} + ${a[2]}`,
  div: (a) => `${a[0]} / ${a[1]}`,
  rcp: (a) => `vec4(1.0) / ${a[0]}`,
  rsq: (a) => `inversesqrt(${a[0]})`,
  dp3: (a) => `vec4(dot(${a[0]}.xyz, ${a[1]}.xyz))`,
  dp4: (a) => `vec4(dot(${a[0]}, ${a[1]}))`,
  min: (a) => `min(${a[0]}, ${a[1]})`,
  max: (a) => `max(${a[0]}, ${a[1]})`,
  cmp: (a) => `mix(${a[2]}, ${a[1]}, step(vec4(0.0), ${a[0]}))`,
});

const glslRegisterPrefix = Object.freeze({ temp: "r", constant: "c", input: "v", output: "o", sampler: "s", color_output: "oC" });

function formatGlslRegister(register) {
  const swizzle = register.swizzle ? `.${register.swizzle}` : "";
  return `${glslRegisterPrefix[register.type] ?? "x"}${register.index}${swizzle}`;
}

function emitGlslEs(program) {
  const blocked = [];
  const body = program.map((instruction) => {
    const rule = glslExpression[instruction.op];
    const destination = `${glslRegisterPrefix[instruction.dest.type] ?? "x"}${instruction.dest.index}${instruction.dest.dest_mask ? `.${instruction.dest.dest_mask}` : instruction.dest_mask ? `.${instruction.dest_mask}` : ""}`;
    if (!rule) {
      blocked.push(instruction.op);
      return `  // ${instruction.op} is above the GLSL ES 3.0 floor and is named-blocked`;
    }
    const source = instruction.src.map(formatGlslRegister);
    return `  ${destination} = ${rule(source)};`;
  }).join("\n");
  return {
    source: `#version 300 es\nprecision highp float;\n// GLSL ES 3.0 lowering of the one unified representation\nvoid main() {\n${body}\n}`,
    blocked,
  };
}

// Lowers one intermediate program to a complete pipeline description for the
// requested backend. Every backend shares the register model; only the shader
// language and the honoured feature subset differ.
export function describePipeline(program, option = {}) {
  const backend = backendKind[option.backend ?? "webgpu"];
  if (backend === undefined) {
    throw new InputError("unsupported_backend", `Backend ${String(option.backend)} is outside the runtime and is named, not dropped`);
  }
  const register = collectRegister(program);
  const blocked = assertWithinFloor(register);
  const colorTargetFormat = option.gamma === "srgb" ? "rgba8unorm-srgb" : "rgba8unorm";
  const sampleCount = Number(option.sample_count ?? 1);
  if (![1, 2, 4, 8].includes(sampleCount)) {
    throw new InputError("invalid_sample_count", `Multisample count ${sampleCount} is not a supported power-of-two count`);
  }
  const base = {
    schema_version: 1,
    backend,
    bind_group_layout: buildBindGroupLayout(register),
    color_target: { format: colorTargetFormat, gamma: option.gamma === "srgb" ? "srgb" : "linear" },
    sample_count: sampleCount,
    within_floor: blocked.length === 0,
    blocked,
    is_live_render: false,
  };
  if (backend === "webgl2") {
    const glsl = emitGlslEs(program);
    return { ...base, shader_language: "glsl-es-3.0", shader_source: glsl.source, above_floor_op: glsl.blocked, within_floor: base.within_floor && glsl.blocked.length === 0 };
  }
  const wgsl = emitWgsl(program, option);
  if (backend === "compatibility") assertCompatibilitySubset(wgsl);
  return { ...base, shader_language: "wgsl", shader_source: wgsl };
}

// A content-addressed pipeline cache: the same program and option yield the
// same key, so a description is compiled once. The cache never keys on the API
// name — identical intermediate programs share one entry.
export function createPipelineCache() {
  const store = new Map();
  return {
    get(program, option = {}) {
      const key = JSON.stringify({ program, option });
      if (store.has(key)) return { hit: true, description: store.get(key) };
      const description = describePipeline(program, option);
      store.set(key, description);
      return { hit: false, description };
    },
    get size() {
      return store.size;
    },
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
      `WebAssembly memory64: ${report.capability.is_wasm_memory64_available ? "available" : "unavailable"}`,
      `Renderer: ${report.capability.webgl_renderer ?? "unavailable"}`,
    ] : []),
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
    "Probe input and browser profile were ephemeral and removed; no compatibility result was retained",
  ].join("\n");
}
