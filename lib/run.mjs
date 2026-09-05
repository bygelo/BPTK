// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from "node:fs";
import { extname, relative, resolve, sep } from "node:path";
import { executionBoundDefault } from "./bound.mjs";
import { InputError } from "./input.mjs";
import { mapPe32, mapPe32ForRuntime } from "./pe.mjs";
import { executeProbe, refuseI386Execution } from "./i386.mjs";

// The declared guest containment policy (BPTK-045). The probe confining set
// is image plus bounded stack, and every host capability is denied by
// absence: no host script bridge, no file system, no network, no process,
// and no device reach exists for guest code. A package manifest that
// declares any other execution capability is refused outright.
const containmentPolicy = Object.freeze({
  policy: "i386_probe_v1",
  memory: "image_and_bounded_stack",
  memory_cap_byte: executionBoundDefault.stack_byte,
  storage: "none",
  denied_capability: ["host_script", "file_system", "network", "process", "device"],
  is_confined: true,
});

// The capability manifest (GS-090): a bundle may declare only the
// least-privilege set, every key must deny, and any declared grant is refused
// because the runtime grants no capability. An undeclared-capability use is
// therefore impossible by manifest construction, and the denial is surfaced.
const leastPrivilegeCapability = Object.freeze({
  host_script: false,
  file_system: false,
  network: false,
  process: false,
  device: false,
});

function assertCapabilityManifest(capability) {
  if (typeof capability !== "object" || capability === null || Array.isArray(capability)) {
    throw new InputError("containment_policy_violation", "The manifest capability must be one object of denied capability");
  }
  const unknownKey = Object.keys(capability).filter((key) => !(key in leastPrivilegeCapability));
  if (unknownKey.length > 0) {
    throw new InputError("containment_policy_violation", `The manifest declares capability outside the policy: ${unknownKey.join(", ")}`);
  }
  const grantedKey = Object.keys(capability).filter((key) => capability[key] !== false);
  if (grantedKey.length > 0) {
    throw new InputError("containment_policy_violation", `The manifest declares a granted capability the runtime never serves: ${grantedKey.join(", ")}`);
  }
}

// The per-lane containment profile model (GS-086): every bundle declares its
// lane, and a lane whose runtime does not exist is refused rather than
// mis-run on the probe lane. The probe lane carries the only live profile;
// the web-native and emulator lane profile stay declared-but-absent until
// those runtimes land, and a manifest naming them is refused with the absence
// named.
const laneProfile = Object.freeze({
  binary_probe: { is_available: true, runtime: "i386_probe_v1" },
  web_native: { is_available: false, runtime: null },
  emulator: { is_available: false, runtime: null },
});

function assertLaneProfile(lane) {
  if (lane === undefined) return;
  if (typeof lane !== "string" || !(lane in laneProfile)) {
    throw new InputError("lane_profile_unknown", `The manifest declares a lane outside the profile table: ${String(lane)}`);
  }
  if (!laneProfile[lane].is_available) {
    throw new InputError("lane_not_available", `The ${lane} lane runtime does not exist yet; the bundle is refused instead of mis-run on the probe lane`);
  }
}

function assertContainmentPolicy(execution) {
  const declaredKey = Object.keys(execution).filter((key) => key !== "profile" && key !== "instruction_budget_count");
  if (declaredKey.length > 0) {
    throw new InputError("containment_policy_violation", `The execution manifest declares capability outside the containment policy: ${declaredKey.join(", ")}`);
  }
}

const maxManifestSizeByte = 256 * 1024;

function manifestInputError(inputCode, message) {
  return new InputError(inputCode, message);
}

function normalizeManifestOpenError(error, manifestPath) {
  if (error?.code === "ENOENT") {
    return manifestInputError("package_manifest_missing", `Package directory has no bptk.json: ${manifestPath}`);
  }
  if (error?.code === "ELOOP") {
    return manifestInputError("package_manifest_symlink", `Package manifest is a symbolic link: ${manifestPath}`);
  }
  return manifestInputError("package_manifest_read_failure", `Unable to open package manifest: ${manifestPath}`);
}

function readPackageManifest(manifestPath) {
  let openFlag = constants.O_RDONLY | constants.O_NONBLOCK;
  const hasNoFollow = Number.isInteger(constants.O_NOFOLLOW);
  if (hasNoFollow) {
    openFlag |= constants.O_NOFOLLOW;
  } else {
    let linkStat;
    try {
      linkStat = lstatSync(manifestPath);
    } catch (error) {
      if (error?.code === "ENOENT") {
        throw manifestInputError("package_manifest_missing", `Package directory has no bptk.json: ${manifestPath}`);
      }
      throw manifestInputError("package_manifest_read_failure", `Unable to inspect package manifest: ${manifestPath}`);
    }
    if (linkStat.isSymbolicLink()) {
      throw manifestInputError("package_manifest_symlink", `Package manifest is a symbolic link: ${manifestPath}`);
    }
  }

  let descriptor;
  try {
    descriptor = openSync(manifestPath, openFlag);
  } catch (error) {
    throw normalizeManifestOpenError(error, manifestPath);
  }

  try {
    let manifestStat;
    try {
      manifestStat = fstatSync(descriptor);
    } catch {
      throw manifestInputError("package_manifest_read_failure", `Unable to stat package manifest: ${manifestPath}`);
    }
    if (!manifestStat.isFile()) {
      throw manifestInputError("package_manifest_not_file", `Package manifest is not a regular file: ${manifestPath}`);
    }
    if (manifestStat.size > maxManifestSizeByte) {
      throw manifestInputError("package_manifest_size_limit", `Package manifest exceeds ${maxManifestSizeByte} byte: ${manifestPath}`);
    }

    const content = Buffer.alloc(manifestStat.size);
    let readByte = 0;
    while (readByte < manifestStat.size) {
      let currentReadByte;
      try {
        currentReadByte = readSync(descriptor, content, readByte, manifestStat.size - readByte, readByte);
      } catch {
        throw manifestInputError("package_manifest_read_failure", `Unable to read package manifest: ${manifestPath}`);
      }
      if (currentReadByte <= 0) {
        throw manifestInputError("package_manifest_read_failure", `Package manifest ended before its validated size: ${manifestPath}`);
      }
      readByte += currentReadByte;
    }
    return content.toString("utf8");
  } finally {
    try {
      closeSync(descriptor);
    } catch {
      // The manifest result is already bounded and no longer needs the descriptor.
    }
  }
}

function inspectRunInput(input) {
  if (typeof input !== "string" || input.trim() === "") throw new InputError("missing_input", "A local input path is required");
  const inputPath = resolve(input);
  let inputStat;
  try {
    inputStat = lstatSync(inputPath);
  } catch (error) {
    if (error?.code === "ENOENT") throw new InputError("not_found", `Input does not exist: ${inputPath}`);
    throw new InputError("input_failure", `Unable to inspect input: ${inputPath}`);
  }
  if (inputStat.isSymbolicLink()) throw new InputError("symlink_input", `Symbolic-link input is not followed: ${inputPath}`);
  if (inputStat.isFile()) return { input_path: inputPath, type: "file" };
  if (inputStat.isDirectory()) return { input_path: inputPath, type: "directory" };
  throw new InputError("unsupported_file_type", `Input is not a regular file or directory: ${inputPath}`);
}

function resolvePackage(input) {
  const value = inspectRunInput(input);
  if (value.type === "file") return { executable_path: value.input_path, package_path: value.input_path, requested_base: null, import: null, execution: null, capability: leastPrivilegeCapability, lane: "binary_probe" };
  const manifestPath = resolve(value.input_path, "bptk.json");
  let manifest;
  try {
    manifest = JSON.parse(readPackageManifest(manifestPath));
  } catch (error) {
    if (error instanceof InputError) throw error;
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
  if (manifest.execution !== undefined) {
    if (typeof manifest.execution !== "object" || manifest.execution === null || Array.isArray(manifest.execution)) {
      throw new InputError("invalid_execution_profile", "bptk.json execution must be one object");
    }
    assertContainmentPolicy(manifest.execution);
    if (manifest.execution.profile !== "i386_probe_v1") {
      throw new InputError("unsupported_execution_profile", "Only the i386_probe_v1 execution profile is supported");
    }
    if (!Number.isSafeInteger(manifest.execution.instruction_budget_count) || manifest.execution.instruction_budget_count < 1 || manifest.execution.instruction_budget_count > 10000000) {
      throw new InputError("invalid_instruction_budget", "execution.instruction_budget_count must be an integer from 1 through 10000000");
    }
  }
  assertCapabilityManifest(manifest.capability ?? leastPrivilegeCapability);
  assertLaneProfile(manifest.lane);
  return {
    executable_path: executablePath,
    package_path: value.input_path,
    requested_base: manifest.load_base ?? null,
    import: manifest.import ?? null,
    execution: manifest.execution ?? null,
    capability: manifest.capability ?? leastPrivilegeCapability,
    lane: manifest.lane ?? "binary_probe",
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
  const capabilityReport = {
    declared: packageValue.capability,
    granted: Object.keys(packageValue.capability).filter((key) => packageValue.capability[key] !== false),
    denied: Object.keys(leastPrivilegeCapability),
    is_least_privilege: Object.values(packageValue.capability).every((value) => value === false),
  };
  if (packageValue.execution === null) {
    return {
      command: "run",
      package_path: packageValue.package_path,
      lane: packageValue.lane,
      capability_report: capabilityReport,
      ...mapPe32(packageValue.executable_path, packageValue.requested_base, packageValue.import),
    };
  }
  const mapped = mapPe32ForRuntime(packageValue.executable_path, packageValue.requested_base, packageValue.import);
  let runtime;
  if (mapped.report.import_count > 0) {
    runtime = refuseI386Execution(mapped, "import_present", "Execution requires a PE32 image with no imported function");
  } else if (mapped.report.tls_callback_count > 0) {
    runtime = refuseI386Execution(mapped, "tls_callback_present", "Execution requires zero TLS callback");
  } else {
    runtime = executeProbe(mapped, packageValue.execution.instruction_budget_count);
  }
  return {
    command: "run",
    package_path: packageValue.package_path,
    lane: packageValue.lane,
    capability_report: capabilityReport,
    ...mapped.report,
    ...runtime,
    clock: runtime.clock ?? null,
    containment: containmentPolicy,
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
    `Entry: RVA 0x${report.entry_rva.toString(16)} in ${report.entry_section} (${report.is_executed ? "probe execution attempted" : "not executed"})`,
    ...(report.clock ? [`Clock: ${report.clock.source} (${report.clock.mode}); RDTSC advances ${report.clock.rdtsc_cycle_per_read} cycle per read`] : []),
    ...(report.containment ? [`Containment: ${report.containment.memory} within ${report.containment.memory_cap_byte} byte; denied: ${report.containment.denied_capability.join(", ")}`] : []),
    ...report.section.map((entry) => `Section: ${entry.name || "<unnamed>"} RVA=0x${entry.virtual_address.toString(16)} raw=${entry.raw_size_byte}`),
    ...report.import.map((entry) => `Import: ${entry.library}!${entry.symbol ?? `#${entry.ordinal}`} — ${entry.resolution_state}${entry.address === null ? "" : ` at 0x${entry.address.toString(16)}`}`),
    ...report.tls_callback.map((entry) => `TLS callback: 0x${entry.address.toString(16)} in ${entry.section} (not executed)`),
    ...report.resolution_blocker.map((entry) => `Resolution blocked: ${entry}`),
    ...report.runtime_blocker.map((entry) => `Runtime blocked: ${entry}`),
    ...(report.stop_reason ? [`Stop: ${report.stop_reason} after ${report.instruction_count} instruction`] : []),
  ].join("\n");
}
