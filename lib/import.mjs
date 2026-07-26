// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { inspectInput } from "./inspect.mjs";
import { InputError } from "./input.mjs";
import { runPackage } from "./run.mjs";

export function importAndRun(input) {
  const inspection = inspectInput(input);
  let launch = null;
  let launchError = null;
  if (inspection.input_type === "directory") {
    try {
      launch = runPackage(inspection.input_path);
    } catch (error) {
      if (!(error instanceof InputError)) throw error;
      launchError = { error_code: error.input_code, message: error.message };
    }
  }
  return {
    schema_version: 1,
    command: "import --run",
    input_path: inspection.input_path,
    inspection,
    launch,
    launch_error: launchError,
    state: launch?.state === "asset_ready_no_game_runtime" ? "imported_assets_no_runtime" : "classified_no_runtime",
    is_staged: false,
    is_executed: false,
    blocker: [
      ...(launch?.blocker ?? inspection.blocker),
      ...(launchError ? [`${launchError.error_code}: ${launchError.message}`] : []),
      "An interactive persistent 2D session requires the still-missing CPU, Win32, input, graphics, audio, and storage runtime",
    ],
  };
}

export function formatImport(report) {
  return [
    `Input: ${report.input_path}`,
    `Classification: ${report.inspection.classification}`,
    `State: ${report.state}`,
    "Staged: no",
    "Executed: no",
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}
