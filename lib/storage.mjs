// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { resolve } from "node:path";
import { InputError } from "./input.mjs";
import { readPackageManifest } from "./package.mjs";

export function diagnoseSave(packageInput, profile) {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(profile)) {
    throw new InputError("invalid_save_profile", "Save profile must be 1..64 simple character and cannot contain a path separator");
  }
  const packagePath = resolve(packageInput);
  const manifest = readPackageManifest(packagePath);
  if (!manifest) throw new InputError("package_manifest_missing", `Package has no valid bptk.json: ${packagePath}`);
  return {
    schema_version: 1,
    command: "run --save",
    package_path: packagePath,
    package_id: manifest.package_id,
    profile,
    state: "blocked_no_runtime_storage",
    is_base_read_only: true,
    is_overlay_created: false,
    is_registry_available: false,
    is_persistent: false,
    blocker: ["No game runtime, virtual drive, registry, copy-on-write overlay, or OPFS bridge exists; no save path was created"],
  };
}

export function formatSave(report) {
  return [
    `Package: ${report.package_path}`,
    `Package ID: ${report.package_id}`,
    `Save profile: ${report.profile}`,
    `State: ${report.state}`,
    "Base read-only: yes",
    "Overlay created: no",
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}
