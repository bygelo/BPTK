// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { performance } from "node:perf_hooks";
import { inspectInput } from "./inspect.mjs";
import { getToolchain } from "./toolchain.mjs";

export function compareFoundation(input) {
  const startedAt = performance.now();
  const inspection = inspectInput(input);
  const toolchain = getToolchain();
  const inspectionMillisecond = performance.now() - startedAt;
  const option = [
    {
      foundation: "source_assisted",
      is_available: inspection.lane === "source" && Boolean(toolchain.emcc),
      measured_signal: { input_size_byte: inspection.size_byte, inspection_millisecond: Number(inspectionMillisecond.toFixed(3)), emcc: toolchain.emcc },
      blocker: inspection.lane !== "source" ? "Input is not a source project" : toolchain.emcc ? null : "Emscripten emcc is not installed",
    },
    {
      foundation: "component_composition",
      is_available: false,
      measured_signal: { pe_lane: inspection.lane === "binary", cpu_core: null, win32_hle: null },
      blocker: "No approved CPU core and Win32 HLE composition exists",
    },
    {
      foundation: "new_runtime",
      is_available: false,
      measured_signal: { pe_lane: inspection.lane === "binary", implementation_line: 0 },
      blocker: "A new i386 and Win32 runtime is weeks-scale and unmeasured",
    },
    {
      foundation: "static_recompilation",
      is_available: false,
      measured_signal: {
        pe_lane: inspection.lane === "binary",
        is_pe32_i386: inspection.classification === "pe32",
        per_title_pipeline: null,
        reference_pipeline: "N64Recomp, PSXRecomp, and XenonRecomp",
      },
      blocker: "No per-title static recompilation pipeline exists and no representative title comparison has been measured",
    },
  ];
  const availableOption = option.filter((entry) => entry.is_available);
  return {
    schema_version: 1,
    command: "foundation compare",
    input_path: inspection.input_path,
    classification: inspection.classification,
    option,
    recommendation: availableOption.length === 1 ? availableOption[0].foundation : "blocked",
    decision_state: "review_required",
    blocker: availableOption.length === 1 ? ["Legal, corpus, and security approval remain red"] : ["No foundation is operational for this input on the current host"],
  };
}

export function formatFoundation(report) {
  return [
    `Input: ${report.input_path}`,
    `Classification: ${report.classification}`,
    ...report.option.map((entry) => `${entry.is_available ? "AVAILABLE" : "BLOCKED"}: ${entry.foundation}${entry.blocker ? ` — ${entry.blocker}` : ""}`),
    `Recommendation: ${report.recommendation}`,
    ...report.blocker.map((entry) => `Decision blocked: ${entry}`),
  ].join("\n");
}
