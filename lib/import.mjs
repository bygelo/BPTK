// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { detectInstaller, extractInstaller } from "./extract.mjs";
import { InputError } from "./input.mjs";
import { inspectInput } from "./inspect.mjs";
import { runPackage } from "./run.mjs";
import { assertImportSafety, inspectWithThreat } from "./security.mjs";

export function importAndRun(input, option = {}) {
  // The same import boundary as ingest, on the threat-scanned inspection.
  const inspection = inspectWithThreat(input);
  assertImportSafety(inspection);
  let launch = null;
  let launchError = null;
  let extraction = null;
  if (inspection.input_type === "directory") {
    try {
      launch = runPackage(inspection.input_path);
    } catch (error) {
      if (!(error instanceof InputError)) throw error;
      launchError = { error_code: error.input_code, message: error.message };
    }
  } else if (detectInstaller(inspection.input_path) !== null) {
    // An extraction refusal is a security boundary, so it propagates instead
    // of being reported as a soft blocker.
    extraction = extractInstaller(inspection.input_path, { extract: option.extract ?? null });
  }
  const isExtracted = extraction?.is_extracted === true;
  return {
    schema_version: 1,
    command: option.extract ? "import --extract" : "import",
    input_path: inspection.input_path,
    inspection,
    extraction,
    launch,
    launch_error: launchError,
    state: isExtracted
      ? "extracted_no_runtime"
      : extraction
        ? "extractable_no_runtime"
        : launch?.state === "asset_ready_no_game_runtime"
          ? "imported_assets_no_runtime"
          : "classified_no_runtime",
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
    ...(report.extraction
      ? [
          `Installer: ${report.extraction.installer} (${report.extraction.installer_family})`,
          `Payload entry: ${report.extraction.entry_count} (${report.extraction.output_byte} byte)`,
          ...report.extraction.entry.map((entry) => `Payload: ${entry.path} — ${entry.size_byte} byte (${entry.checksum_state})`),
          `Extracted: ${report.extraction.is_extracted ? `yes → ${report.extraction.output_dir}` : "no (plan only)"}`,
        ]
      : []),
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}
