// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { existsSync, readFileSync } from "node:fs";
import { extname, relative, resolve, sep } from "node:path";
import { inspectPath, InputError } from "./input.mjs";
import { mapPe32 } from "./pe.mjs";

function resolvePackage(input) {
  const value = inspectPath(input);
  if (value.type === "file") return { executable_path: value.input_path, package_path: value.input_path, requested_base: null, import: null };
  const manifestPath = resolve(value.input_path, "bptk.json");
  if (!existsSync(manifestPath)) throw new InputError("package_manifest_missing", `Package directory has no bptk.json: ${value.input_path}`);
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  } catch (error) {
    throw new InputError("invalid_package_manifest", `bptk.json is not strict JSON: ${error.message}`);
  }
  if (typeof manifest !== "object" || manifest === null || Array.isArray(manifest)) {
    throw new InputError("invalid_package_manifest", "bptk.json must contain one object");
  }
  if (manifest.schema_version === 1 && manifest.package_kind === "stream_asset" && typeof manifest.package_id === "string") {
    return { package_path: value.input_path, asset_manifest: manifest };
  }
  if (manifest.schema_version !== 1 || typeof manifest.executable !== "string") throw new InputError("invalid_package_manifest", "bptk.json requires a supported package kind or executable");
  const executablePath = resolve(value.input_path, manifest.executable);
  const pathPart = relative(value.input_path, executablePath);
  if (pathPart === ".." || pathPart.startsWith(`..${sep}`)) throw new InputError("package_path_escape", "Package executable escapes its directory");
  if (extname(executablePath).toLowerCase() !== ".exe") throw new InputError("package_executable_required", "Package executable must use the .exe suffix");
  if (manifest.import !== undefined && !Array.isArray(manifest.import)) {
    throw new InputError("invalid_package_manifest", "bptk.json import must be an array");
  }
  return {
    executable_path: executablePath,
    package_path: value.input_path,
    requested_base: manifest.load_base ?? null,
    import: manifest.import ?? null,
  };
}

export function runPackage(input) {
  const packageValue = resolvePackage(input);
  if (packageValue.asset_manifest) {
    return {
      schema_version: 1,
      command: "run",
      package_path: packageValue.package_path,
      package_id: packageValue.asset_manifest.package_id,
      state: "asset_ready_no_game_runtime",
      blocker: ["Content-addressed assets are ready, but the package has no executable browser runtime"],
      is_executed: false,
    };
  }
  return {
    command: "run",
    package_path: packageValue.package_path,
    ...mapPe32(packageValue.executable_path, packageValue.requested_base, packageValue.import),
  };
}

export function formatRun(report) {
  if (report.state === "asset_ready_no_game_runtime") {
    return [
      `Package: ${report.package_path}`,
      `Package ID: ${report.package_id}`,
      `State: ${report.state}`,
      ...report.blocker.map((entry) => `Blocked: ${entry}`),
    ].join("\n");
  }
  return [
    `Package: ${report.package_path}`,
    `Executable: ${report.input_path}`,
    `State: ${report.state}`,
    `Machine: ${report.machine}`,
    `Image: ${report.image_size_byte} byte at 0x${report.load_base.toString(16)}`,
    `Entry: RVA 0x${report.entry_rva.toString(16)} in ${report.entry_section} (not executed)`,
    ...report.section.map((entry) => `Section: ${entry.name || "<unnamed>"} RVA=0x${entry.virtual_address.toString(16)} raw=${entry.raw_size_byte}`),
    ...report.import.map((entry) => `Import: ${entry.library}!${entry.symbol ?? `#${entry.ordinal}`} — ${entry.resolution_state}${entry.address === null ? "" : ` at 0x${entry.address.toString(16)}`}`),
    ...report.tls_callback.map((entry) => `TLS callback: 0x${entry.address.toString(16)} in ${entry.section} (not executed)`),
    ...report.resolution_blocker.map((entry) => `Resolution blocked: ${entry}`),
    ...report.runtime_blocker.map((entry) => `Runtime blocked: ${entry}`),
  ].join("\n");
}
