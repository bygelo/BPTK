// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { resolve } from "node:path";
import { parsePeImportNames } from "./census.mjs";
import { detectInstaller, extractInstaller } from "./extract.mjs";
import { InputError, readPrefix } from "./input.mjs";
import { inspectInput } from "./inspect.mjs";
import { runPackage } from "./run.mjs";
import { assertImportSafety, inspectWithThreat } from "./security.mjs";

// The declared Win32 module set (GS-057). Each module is one row naming the
// tier of its emulation surface: a hosted module has a passing conformance
// slice today, a planned module is declared but not yet covered, and any
// module outside the catalog is unrecognized. The set is data, so broadening
// the surface is adding rows and their slices, never a per-title branch. The
// tiers are the honest current state: only the merged kernel32/user32/gdi32
// lanes carry a conformance slice; everything the title also needs is planned.
const win32ModuleCoverage = Object.freeze([
  { module: "kernel32.dll", tier: "hosted", slice: "process, memory, and error surface" },
  { module: "user32.dll", tier: "hosted", slice: "window class, message, and input surface" },
  { module: "gdi32.dll", tier: "hosted", slice: "device context and paint surface" },
  { module: "advapi32.dll", tier: "planned", slice: "registry and security surface" },
  { module: "ole32.dll", tier: "planned", slice: "COM apartment and marshalling surface" },
  { module: "oleaut32.dll", tier: "planned", slice: "OLE automation and variant surface" },
  { module: "comctl32.dll", tier: "planned", slice: "common control surface" },
  { module: "comdlg32.dll", tier: "planned", slice: "common dialog surface" },
  { module: "shell32.dll", tier: "planned", slice: "shell and path surface" },
  { module: "shlwapi.dll", tier: "planned", slice: "lightweight path and registry helper surface" },
  { module: "version.dll", tier: "planned", slice: "version-resource surface" },
  { module: "winmm.dll", tier: "planned", slice: "multimedia timer and legacy audio surface" },
  { module: "ws2_32.dll", tier: "planned", slice: "Winsock surface" },
  { module: "msvcrt.dll", tier: "planned", slice: "C runtime surface" },
  { module: "msvcr71.dll", tier: "planned", slice: "Visual C++ 7.1 runtime surface" },
  { module: "msvcr80.dll", tier: "planned", slice: "Visual C++ 8.0 runtime surface" },
  { module: "msvcr90.dll", tier: "planned", slice: "Visual C++ 9.0 runtime surface" },
  { module: "msvcr100.dll", tier: "planned", slice: "Visual C++ 10.0 runtime surface" },
  { module: "msvcr120.dll", tier: "planned", slice: "Visual C++ 12.0 runtime surface" },
  { module: "ucrtbase.dll", tier: "planned", slice: "universal C runtime surface" },
  { module: "msvbvm60.dll", tier: "planned", slice: "Visual Basic 6 virtual machine surface" },
  { module: "msvbvm50.dll", tier: "planned", slice: "Visual Basic 5 virtual machine surface" },
]);

const moduleTierByName = new Map(win32ModuleCoverage.map((entry) => [entry.module, entry]));

// Classifies a set of imported module names against the declared coverage.
// Pure and generic: distinct, lowercased, sorted, one tier per module.
export function classifyWin32Modules(moduleName) {
  const distinct = [...new Set(moduleName.map((name) => name.toLowerCase()))].sort();
  const module = distinct.map((name) => {
    const entry = moduleTierByName.get(name);
    return { module: name, tier: entry ? entry.tier : "unrecognized", slice: entry ? entry.slice : null };
  });
  const ledger = { hosted: 0, planned: 0, unrecognized: 0, total: module.length };
  for (const entry of module) ledger[entry.tier] += 1;
  const is_fully_hosted = module.length > 0 && module.every((entry) => entry.tier === "hosted");
  return { module, ledger, is_fully_hosted };
}

// The Win32 module coverage census over a PE's import table.
export function censusWin32Modules(input) {
  const path = resolve(input);
  let importName = [];
  let isBounded = false;
  try {
    const prefix = readPrefix(path);
    if (prefix.length > 1 && prefix[0] === 0x4d && prefix[1] === 0x5a) {
      const parsed = parsePeImportNames(prefix);
      importName = parsed.name;
      isBounded = parsed.is_bounded;
    }
  } catch {
    importName = [];
  }
  const coverage = classifyWin32Modules(importName);
  return {
    schema_version: 1,
    command: "modules",
    input_path: path,
    is_import_bounded: isBounded,
    module: coverage.module,
    ledger: coverage.ledger,
    is_fully_hosted: coverage.is_fully_hosted,
    state: "blocked",
    is_executed: false,
    note: "A hosted conformance slice is necessary but not sufficient; a title on the broader Win32 module set cannot start until every imported module carries a passing slice.",
  };
}

export function formatWin32Modules(report) {
  return [
    `Input: ${report.input_path}`,
    `Imported module: ${report.ledger.total}`,
    ...report.module.map((entry) => `Module: ${entry.module} — ${entry.tier}${entry.slice ? ` (${entry.slice})` : ""}`),
    `Ledger: ${report.ledger.hosted} hosted / ${report.ledger.planned} planned / ${report.ledger.unrecognized} unrecognized`,
    `Fully hosted: ${report.is_fully_hosted ? "yes" : "no"}`,
    report.note,
    "Executed: no; the module census never runs the input",
  ].join("\n");
}

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
