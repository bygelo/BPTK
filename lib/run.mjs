// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { existsSync, readFileSync } from "node:fs";
import { extname, relative, resolve, sep } from "node:path";
import { inspectPath, InputError } from "./input.mjs";
import { mapPe32 } from "./pe.mjs";

function resolvePackage(input) {
  const value = inspectPath(input);
  if (value.type === "file") return { executable_path: value.input_path, package_path: value.input_path, requested_base: null };
  const manifestPath = resolve(value.input_path, "bptk.json");
  if (!existsSync(manifestPath)) throw new InputError("package_manifest_missing", `Package directory has no bptk.json: ${value.input_path}`);
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  } catch (error) {
    throw new InputError("invalid_package_manifest", `bptk.json is not strict JSON: ${error.message}`);
  }
  if (manifest.schema_version !== 1 || typeof manifest.executable !== "string") throw new InputError("invalid_package_manifest", "bptk.json requires schema_version 1 and executable");
  const executablePath = resolve(value.input_path, manifest.executable);
  const pathPart = relative(value.input_path, executablePath);
  if (pathPart === ".." || pathPart.startsWith(`..${sep}`)) throw new InputError("package_path_escape", "Package executable escapes its directory");
  if (extname(executablePath).toLowerCase() !== ".exe") throw new InputError("package_executable_required", "Package executable must use the .exe suffix");
  return { executable_path: executablePath, package_path: value.input_path, requested_base: manifest.load_base ?? null };
}

export function runPackage(input) {
  const packageValue = resolvePackage(input);
  return { command: "run", package_path: packageValue.package_path, ...mapPe32(packageValue.executable_path, packageValue.requested_base) };
}

export function formatRun(report) {
  return [
    `Package: ${report.package_path}`,
    `Executable: ${report.input_path}`,
    `State: ${report.state}`,
    `Machine: ${report.machine}`,
    `Image: ${report.image_size_byte} byte at 0x${report.load_base.toString(16)}`,
    `Entry: RVA 0x${report.entry_rva.toString(16)} (not executed)`,
    ...report.section.map((entry) => `Section: ${entry.name || "<unnamed>"} RVA=0x${entry.virtual_address.toString(16)} raw=${entry.raw_size_byte}`),
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}
