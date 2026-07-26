// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { inspectInput } from "./inspect.mjs";
import { getToolchain } from "./toolchain.mjs";

export function diagnoseSourcePort(project) {
  const inspection = inspectInput(project);
  const toolchain = getToolchain();
  const blocker = [];
  if (inspection.classification !== "source_project") blocker.push("Input is not a C or C++ project with native build metadata");
  if (!toolchain.emcc) blocker.push("Emscripten emcc is not installed or not on PATH");
  if (!toolchain.emrun) blocker.push("Emscripten emrun is not installed or not on PATH");
  blocker.push("The SDL/OpenGL browser adapter and clean-browser package step are not implemented");
  return {
    schema_version: 1,
    command: "port --source",
    project_path: inspection.input_path,
    classification: inspection.classification,
    toolchain,
    state: "blocked",
    blocker,
    output_path: null,
    is_package_emitted: false,
  };
}

export function formatSourcePort(report) {
  return [
    `Project: ${report.project_path}`,
    `Classification: ${report.classification}`,
    `State: ${report.state}`,
    `clang: ${report.toolchain.clang ?? "missing"}`,
    `cmake: ${report.toolchain.cmake ?? "missing"}`,
    `ninja: ${report.toolchain.ninja ?? "missing"}`,
    `emcc: ${report.toolchain.emcc ?? "missing"}`,
    `emrun: ${report.toolchain.emrun ?? "missing"}`,
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
    "No scaffold or browser package was emitted",
  ].join("\n");
}
