// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { inspectPath, InputError } from "./input.mjs";
import { inspectInput } from "./inspect.mjs";
import { probeGraphics } from "./graphics.mjs";

const targetValue = new Set(["x86_64", "d3d11", "modern"]);

function findSignal(value, target) {
  if (value.type !== "file") return [];
  const text = value.prefix.toString("latin1").toLowerCase();
  const candidate = target === "x86_64"
    ? ["amd64", "x86_64"]
    : target === "d3d11"
      ? ["d3d11.dll", "dxgi.dll", "dxbc"]
      : ["d3d12.dll", "dxgi.dll", "vulkan-1.dll", "dxil", "spir-v"];
  return candidate.filter((entry) => text.includes(entry));
}

export function inspectResearch(input, target) {
  if (!targetValue.has(target)) throw new InputError("invalid_research_target", `Research target must be x86_64, d3d11, or modern: ${target}`);
  const value = inspectPath(input);
  const inspection = inspectInput(value.input_path);
  const graphics = probeGraphics();
  const signal = findSignal(value, target);
  const requirement = target === "x86_64"
    ? { is_pe32_plus: inspection.classification === "pe32_plus", is_wasm_memory64_available: graphics.capability?.is_wasm_memory64_available === true, is_cpu_runtime_available: false }
    : target === "d3d11"
      ? { is_d3d11_signal_present: signal.length > 0, is_webgpu_available: graphics.capability?.is_webgpu_available === true, is_shader_translator_available: false }
      : { is_modern_api_signal_present: signal.length > 0, is_webgpu_available: graphics.capability?.is_webgpu_available === true, is_wasm_memory64_available: graphics.capability?.is_wasm_memory64_available === true, is_modern_runtime_available: false };
  return {
    schema_version: 1,
    command: "inspect --target",
    target,
    input_path: value.input_path,
    classification: inspection.classification,
    signal,
    browser: graphics.browser,
    requirement,
    decision: "defer",
    state: "research_blocked",
    is_support_claim: false,
    blocker: [
      target === "x86_64" ? "No x86-64 CPU, exception, address-space, or JIT execution prototype exists" : target === "d3d11" ? "No DXGI, D3D10/11, DXBC, resource, or synchronization translator exists" : "x86-64 and D3D10/11 prerequisite research is incomplete, and no D3D12 or Vulkan-era browser mapping exists",
      "The observed browser capability is ephemeral and cannot substitute for a reproducible runtime prototype",
    ],
  };
}

export function formatResearch(report) {
  return [
    `Input: ${report.input_path}`,
    `Target: ${report.target}`,
    `Classification: ${report.classification}`,
    `Browser: ${report.browser?.version ?? "missing"}`,
    `Signal count: ${report.signal.length}`,
    `Decision: ${report.decision}`,
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
    "Support claim: no",
  ].join("\n");
}
